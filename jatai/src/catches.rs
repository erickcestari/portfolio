//! What the honeypot has caught, published as `/honeypot.json` for the page at
//! `/honeypot`.
//!
//! Two records, both bounded whatever scanners send:
//! - per-day counts per trap for the last `DAYS` days, optionally saved to a
//!   file so they outlive restarts. The file is rewritten whole, never
//!   appended to, so it holds at most `DAYS` lines per trap;
//! - the last `RECENT` catches with their network prefix, in memory only.
//!
//! The page gets the last `DAILY` days day by day and the whole history summed
//! into weeks, which keeps `/honeypot.json` small however long the history.
//!
//! Only fixed trap labels and truncated prefixes are kept. Nothing a scanner
//! typed reaches the page or the file, and no full address is ever stored.

use std::{
    collections::{BTreeMap, VecDeque},
    fmt::Write as _,
    fs::{self, File},
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

const RECENT: usize = 50;
/// Days of history kept, the newest included.
const DAYS: u64 = 365;
/// Days published one by one; older ones only appear in their week's total.
const DAILY: u64 = 30;
const DAY: u64 = 86_400;
/// A saved file is at most `DAYS` lines per trap, under 500 KB even with every
/// count at `u64::MAX`. Anything bigger was not written by `save`, so it is
/// ignored instead of read.
const MAX_FILE: u64 = 1024 * 1024;

type Counts = BTreeMap<&'static str, u64>;
/// Start of a UTC day (or week), to catches per trap in it.
type Days = BTreeMap<u64, Counts>;

pub struct Catches {
    inner: Mutex<Inner>,
    file: Option<PathBuf>,
}

struct Inner {
    days: Days,
    recent: VecDeque<Catch>,
    unsaved: bool,
}

struct Catch {
    at: u64,
    label: &'static str,
    from: String,
}

impl Catches {
    /// Kept in memory only.
    pub fn new() -> Self {
        Self::with(Days::new(), None)
    }

    /// Starts from the counts saved in `file`, and `save` writes back to it. A
    /// missing, oversized or unreadable file starts the history empty.
    pub fn load(file: PathBuf) -> Self {
        let days = match read_capped(&file) {
            Ok(text) => parse(&text, day_of(unix_now())),
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    eprintln!("honeypot: not loading {}: {e}", file.display());
                }
                Days::new()
            }
        };
        Self::with(days, Some(file))
    }

    fn with(days: Days, file: Option<PathBuf>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                days,
                recent: VecDeque::with_capacity(RECENT),
                unsaved: false,
            }),
            file,
        }
    }

    pub fn record(&self, label: &'static str, peer: SocketAddr) {
        self.record_at(label, peer, unix_now());
    }

    fn record_at(&self, label: &'static str, peer: SocketAddr, at: u64) {
        let mut inner = self.lock();

        let day = day_of(at);
        // Measured from the newest day, not this catch's, so a clock stepping
        // back cannot widen the window past `DAYS` days.
        let newest = inner
            .days
            .last_key_value()
            .map_or(day, |(&d, _)| d.max(day));
        add(inner.days.entry(day).or_default(), label, 1);
        while inner
            .days
            .first_key_value()
            .is_some_and(|(&d, _)| d < first_day(newest))
        {
            inner.days.pop_first();
        }
        inner.unsaved = true;

        if inner.recent.len() == RECENT {
            inner.recent.pop_back();
        }
        inner.recent.push_front(Catch {
            at,
            label,
            from: network_prefix(peer.ip()),
        });
    }

    /// Writes the day counts to the file, if there is one and they changed.
    /// Goes through a temporary file, so a crash mid-write keeps the last save.
    pub fn save(&self) {
        let Some(file) = &self.file else { return };
        let text = {
            let mut inner = self.lock();
            if !inner.unsaved {
                return;
            }
            inner.unsaved = false;
            to_lines(&inner.days)
        };
        if let Err(e) = replace(file, &text) {
            eprintln!("honeypot: could not save {}: {e}", file.display());
            self.lock().unsaved = true;
        }
    }

    /// Labels are trap constants checked to need no escaping (see the honeypot
    /// tests) and prefixes are formatted addresses, so plain `format!` is safe.
    pub fn to_json(&self) -> String {
        let inner = self.lock();

        let newest = inner.days.last_key_value().map_or(0, |(&d, _)| d);
        let days = periods(inner.days.range(newest.saturating_sub((DAILY - 1) * DAY)..));
        let weeks = periods(by_week(&inner.days).iter());

        let recent: Vec<String> = inner
            .recent
            .iter()
            .map(|c| {
                format!(
                    "{{\"at\":{},\"label\":\"{}\",\"from\":\"{}\"}}",
                    c.at, c.label, c.from
                )
            })
            .collect();

        format!(
            "{{\"days\":[{days}],\"weeks\":[{weeks}],\"recent\":[{}]}}",
            recent.join(",")
        )
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic mid-update leaves at worst an off-by-one counter, which is
        // no reason to stop recording.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Default for Catches {
    fn default() -> Self {
        Self::new()
    }
}

fn add(counts: &mut Counts, label: &'static str, n: u64) {
    let total = counts.entry(label).or_insert(0);
    *total = total.saturating_add(n);
}

/// Days summed into weeks starting on Monday.
fn by_week(days: &Days) -> Days {
    let mut weeks = Days::new();
    for (&day, traps) in days {
        let week = weeks.entry(week_of(day)).or_default();
        for (&label, &count) in traps {
            add(week, label, count);
        }
    }
    weeks
}

/// `{"start":…,"traps":{"label":count,…}}` per day or week, comma-separated.
fn periods<'a>(periods: impl Iterator<Item = (&'a u64, &'a Counts)>) -> String {
    let mut json = String::new();
    for (i, (start, traps)) in periods.enumerate() {
        let comma = if i == 0 { "" } else { "," };
        let _ = write!(json, "{comma}{{\"start\":{start},\"traps\":{{");
        for (j, (label, count)) in traps.iter().enumerate() {
            let comma = if j == 0 { "" } else { "," };
            let _ = write!(json, "{comma}\"{label}\":{count}");
        }
        json.push_str("}}");
    }
    json
}

/// One `day<TAB>label<TAB>count` line per trap per day. Labels hold no control
/// characters (see the honeypot tests), so they never split a line.
fn to_lines(days: &Days) -> String {
    let mut text = String::new();
    for (day, traps) in days {
        for (label, count) in traps {
            let _ = writeln!(text, "{day}\t{label}\t{count}");
        }
    }
    text
}

/// Reads back what `to_lines` wrote. A line that is malformed, names a trap
/// that no longer exists or falls outside the window ending `today` is
/// skipped, so loading is bounded exactly like recording.
fn parse(text: &str, today: u64) -> Days {
    let mut days = Days::new();
    for line in text.lines() {
        let mut fields = line.split('\t');
        let (Some(day), Some(label), Some(count), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let (Ok(day), Ok(count)) = (day.parse::<u64>(), count.parse::<u64>()) else {
            continue;
        };
        let Some(label) = crate::honeypot::labels().find(|&known| known == label) else {
            continue;
        };
        if day % DAY != 0 || day < first_day(today) || day > today {
            continue;
        }
        add(days.entry(day).or_default(), label, count);
    }
    days
}

fn read_capped(path: &Path) -> io::Result<String> {
    let mut text = String::new();
    File::open(path)?
        .take(MAX_FILE + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_FILE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "larger than any saved history",
        ));
    }
    Ok(text)
}

fn replace(path: &Path, text: &str) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let mut file = File::create(&tmp)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    fs::rename(&tmp, path)
}

fn day_of(at: u64) -> u64 {
    at - at % DAY
}

/// The Monday starting `day`'s week. Day 0, 1970-01-01, was a Thursday.
fn week_of(day: u64) -> u64 {
    day.saturating_sub((day / DAY + 3) % 7 * DAY)
}

/// The oldest day kept while `newest` is the latest one.
fn first_day(newest: u64) -> u64 {
    newest.saturating_sub((DAYS - 1) * DAY)
}

/// The /24 (IPv4) or /48 (IPv6) a request came from: enough to tell scanners
/// apart, not enough to name a host.
fn network_prefix(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            format!("{a}.{b}.{c}.0/24")
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    const ENV: &str = ".env files";
    const PASSWD: &str = "/etc/passwd";

    fn peer(addr: &str) -> SocketAddr {
        addr.parse().unwrap()
    }

    fn catch(catches: &Catches, label: &'static str, at: u64) {
        catches.record_at(label, peer("203.0.113.7:1"), at);
    }

    #[test]
    fn addresses_are_cut_to_their_network() {
        assert_eq!(
            network_prefix("203.0.113.7".parse().unwrap()),
            "203.0.113.0/24"
        );
        assert_eq!(
            network_prefix("2001:db8:abcd:12::1".parse().unwrap()),
            "2001:db8:abcd::/48"
        );
        // An IPv4 client on a dual-stack socket is still an IPv4 client.
        assert_eq!(
            network_prefix("::ffff:198.51.100.9".parse().unwrap()),
            "198.51.100.0/24"
        );
    }

    #[test]
    fn an_empty_log_is_valid_json_with_nothing_caught() {
        assert_eq!(Catches::new().to_json(), EMPTY);
    }

    const EMPTY: &str = "{\"days\":[],\"weeks\":[],\"recent\":[]}";

    #[test]
    fn catches_are_counted_per_utc_day_and_trap() {
        let catches = Catches::new();
        catch(&catches, ENV, DAY + 10);
        catch(&catches, PASSWD, DAY + 20);
        catch(&catches, ENV, 2 * DAY - 1);
        catch(&catches, ENV, 2 * DAY);

        let json = catches.to_json();
        assert!(
            json.starts_with(&format!(
                "{{\"days\":[{{\"start\":{DAY},\"traps\":{{\"{ENV}\":2,\"{PASSWD}\":1}}}},\
                 {{\"start\":{},\"traps\":{{\"{ENV}\":1}}}}]",
                2 * DAY
            )),
            "{json}"
        );
    }

    #[test]
    fn weeks_run_monday_to_sunday() {
        // 1970-01-05 was a Monday.
        let monday = 4 * DAY;
        let catches = Catches::new();
        catch(&catches, ENV, monday);
        catch(&catches, ENV, monday + 7 * DAY - 1);
        catch(&catches, PASSWD, monday + 7 * DAY);

        let json = catches.to_json();
        assert!(
            json.contains(&format!(
                "\"weeks\":[{{\"start\":{monday},\"traps\":{{\"{ENV}\":2}}}},\
                 {{\"start\":{},\"traps\":{{\"{PASSWD}\":1}}}}]",
                monday + 7 * DAY
            )),
            "{json}"
        );
    }

    #[test]
    fn the_page_gets_recent_days_one_by_one_and_the_rest_by_week() {
        let monday = 4 * DAY + 1000 * 7 * DAY;
        let catches = Catches::new();
        for day in 0..DAYS {
            catch(&catches, ENV, monday + day * DAY);
        }
        let json = catches.to_json();
        let (days, weeks) = json.split_once("\"weeks\"").unwrap();
        assert_eq!(days.matches("\"start\":").count(), DAILY as usize);
        assert!(days.contains(&format!("\"start\":{}", monday + (DAYS - DAILY) * DAY)));
        assert_eq!(
            weeks.matches("\"start\":").count(),
            DAYS.div_ceil(7) as usize
        );
        assert!(weeks.contains(&format!("\"start\":{monday},\"traps\":{{\"{ENV}\":7}}")));
    }

    #[test]
    fn only_the_last_days_are_kept() {
        let catches = Catches::new();
        for day in 0..DAYS + 10 {
            catch(&catches, ENV, day * DAY);
        }
        let days = &catches.lock().days;
        assert_eq!(days.len(), DAYS as usize);
        assert_eq!(days.first_key_value().unwrap().0, &(10 * DAY));
    }

    #[test]
    fn a_clock_stepping_back_cannot_grow_the_history() {
        let catches = Catches::new();
        catch(&catches, ENV, (DAYS + 10) * DAY);
        catch(&catches, PASSWD, 0);
        assert_eq!(catches.lock().days.len(), 1);
    }

    #[test]
    fn recent_catches_are_newest_first_and_never_hold_a_full_address() {
        let catches = Catches::new();
        catches.record_at(ENV, peer("203.0.113.7:1"), 10);
        catches.record_at(PASSWD, peer("198.51.100.42:1"), 11);

        let json = catches.to_json();
        let newest = json.find("\"at\":11").unwrap();
        let oldest = json.find("\"at\":10").unwrap();
        assert!(newest < oldest);
        assert!(json.contains("\"from\":\"198.51.100.0/24\""));
        assert!(!json.contains("198.51.100.42"));
        assert!(!json.contains("203.0.113.7"));
    }

    #[test]
    fn the_recent_list_is_bounded_but_the_day_count_is_not() {
        let catches = Catches::new();
        for at in 0..(RECENT as u64 + 10) {
            catch(&catches, ENV, at);
        }
        let json = catches.to_json();
        assert_eq!(json.matches("\"at\":").count(), RECENT);
        assert!(json.contains(&format!("\"{ENV}\":{}", RECENT + 10)));
        assert!(
            !json.contains("\"at\":0,"),
            "the oldest catch should be evicted"
        );
    }

    #[test]
    fn saved_counts_survive_a_restart_but_recent_catches_do_not() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("catches.tsv");
        let today = day_of(unix_now());

        let before = Catches::load(file.clone());
        catch(&before, ENV, today + 1);
        catch(&before, ENV, today + 2);
        catch(&before, PASSWD, today - (DAYS - 1) * DAY);
        before.save();

        let after = Catches::load(file);
        assert_eq!(after.lock().days, before.lock().days);
        assert!(after.lock().recent.is_empty());
    }

    #[test]
    fn the_file_is_only_written_when_something_changed() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("catches.tsv");
        let catches = Catches::load(file.clone());

        catches.save();
        assert!(!file.exists(), "nothing caught, nothing to write");

        catch(&catches, ENV, unix_now());
        catches.save();
        fs::remove_file(&file).unwrap();
        catches.save();
        assert!(!file.exists(), "unchanged counts are not rewritten");
    }

    #[test]
    fn the_file_never_outgrows_one_line_per_trap_per_day() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("catches.tsv");
        let catches = Catches::load(file.clone());
        let labels: Vec<&'static str> = crate::honeypot::labels().collect();

        for day in 0..DAYS + 10 {
            for &label in &labels {
                catch(&catches, label, day * DAY);
            }
        }
        catches.save();

        let text = fs::read_to_string(&file).unwrap();
        assert_eq!(text.lines().count(), DAYS as usize * labels.len());
    }

    #[test]
    fn the_largest_possible_history_fits_under_the_size_cap() {
        // A full year of every trap at the highest count must still load, or a
        // busy honeypot would lose its whole history on the next restart.
        let today = 1000 * DAY;
        let days: Days = (0..DAYS)
            .map(|i| {
                let counts = crate::honeypot::labels().map(|l| (l, u64::MAX));
                (today - i * DAY, counts.collect())
            })
            .collect();
        let text = to_lines(&days);
        assert!(text.len() as u64 <= MAX_FILE, "{} bytes", text.len());
        assert_eq!(parse(&text, today), days);
    }

    #[test]
    fn loading_skips_anything_save_would_not_have_written() {
        let today = 1000 * DAY;
        let text = format!(
            "{today}\t{ENV}\t5\n\
             {today}\t<script>\t5\n\
             {}\t{ENV}\t5\n\
             {}\t{ENV}\t5\n\
             {}\t{ENV}\t5\n\
             {today}\t{PASSWD}\t-1\n\
             {today}\t{PASSWD}\t2\textra\n\
             {today}\t{PASSWD}\n\
             garbage\n\
             {}\t{PASSWD}\t3\n",
            today + 1,
            today + DAY,
            first_day(today) - DAY,
            first_day(today),
        );

        let days = parse(&text, today);
        assert_eq!(days.len(), 2);
        assert_eq!(days[&today], BTreeMap::from([(ENV, 5)]));
        assert_eq!(days[&first_day(today)], BTreeMap::from([(PASSWD, 3)]));
    }

    #[test]
    fn an_oversized_file_is_ignored() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("catches.tsv");
        let line = format!("{}\t{ENV}\t1\n", day_of(unix_now()));
        fs::write(&file, line.repeat(MAX_FILE as usize / line.len() + 1)).unwrap();

        assert_eq!(Catches::load(file).to_json(), EMPTY);
    }
}
