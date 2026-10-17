//! What the honeypot has caught since the server started, published as
//! `/honeypot.json` for the page at `/honeypot`.
//!
//! Only fixed trap labels and truncated network prefixes are kept. Nothing a
//! scanner typed reaches the page, so it cannot be used to publish text, and
//! no full address is ever shown. Memory stays bounded: one counter per trap
//! and a short ring of recent catches.

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

const RECENT: usize = 50;

pub struct Catches {
    inner: Mutex<Inner>,
}

struct Inner {
    since: u64,
    total: u64,
    by_label: HashMap<&'static str, u64>,
    recent: VecDeque<Catch>,
}

struct Catch {
    at: u64,
    label: &'static str,
    from: String,
}

impl Catches {
    pub fn new() -> Self {
        Self::starting_at(unix_now())
    }

    fn starting_at(since: u64) -> Self {
        Self {
            inner: Mutex::new(Inner {
                since,
                total: 0,
                by_label: HashMap::new(),
                recent: VecDeque::with_capacity(RECENT),
            }),
        }
    }

    pub fn record(&self, label: &'static str, peer: SocketAddr) {
        self.record_at(label, peer, unix_now());
    }

    fn record_at(&self, label: &'static str, peer: SocketAddr, at: u64) {
        let mut inner = self.lock();
        inner.total += 1;
        *inner.by_label.entry(label).or_insert(0) += 1;
        if inner.recent.len() == RECENT {
            inner.recent.pop_back();
        }
        inner.recent.push_front(Catch {
            at,
            label,
            from: network_prefix(peer.ip()),
        });
    }

    /// Labels are trap constants checked to need no escaping (see the honeypot
    /// tests) and prefixes are formatted addresses, so plain `format!` is safe.
    pub fn to_json(&self) -> String {
        let inner = self.lock();

        let mut traps: Vec<(&str, u64)> = inner.by_label.iter().map(|(l, c)| (*l, *c)).collect();
        traps.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        let traps: Vec<String> = traps
            .iter()
            .map(|(label, count)| format!("{{\"label\":\"{label}\",\"count\":{count}}}"))
            .collect();

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
            "{{\"since\":{},\"total\":{},\"traps\":[{}],\"recent\":[{}]}}",
            inner.since,
            inner.total,
            traps.join(","),
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
    use super::*;

    fn peer(addr: &str) -> SocketAddr {
        addr.parse().unwrap()
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
        let catches = Catches::starting_at(1_700_000_000);
        assert_eq!(
            catches.to_json(),
            "{\"since\":1700000000,\"total\":0,\"traps\":[],\"recent\":[]}"
        );
    }

    #[test]
    fn catches_are_counted_per_trap_most_caught_first() {
        let catches = Catches::starting_at(0);
        catches.record_at(".env files", peer("203.0.113.7:1"), 10);
        catches.record_at("/etc/passwd", peer("203.0.113.8:1"), 11);
        catches.record_at(".env files", peer("198.51.100.1:1"), 12);

        let json = catches.to_json();
        assert!(json.contains("\"total\":3"));
        assert!(json.contains(
            "\"traps\":[{\"label\":\".env files\",\"count\":2},{\"label\":\"/etc/passwd\",\"count\":1}]"
        ));
    }

    #[test]
    fn recent_catches_are_newest_first_and_never_hold_a_full_address() {
        let catches = Catches::starting_at(0);
        catches.record_at(".env files", peer("203.0.113.7:1"), 10);
        catches.record_at("/etc/passwd", peer("198.51.100.42:1"), 11);

        let json = catches.to_json();
        let newest = json.find("\"at\":11").unwrap();
        let oldest = json.find("\"at\":10").unwrap();
        assert!(newest < oldest);
        assert!(json.contains("\"from\":\"198.51.100.0/24\""));
        assert!(!json.contains("198.51.100.42"));
        assert!(!json.contains("203.0.113.7"));
    }

    #[test]
    fn the_recent_list_is_bounded_but_the_total_is_not() {
        let catches = Catches::starting_at(0);
        for at in 0..(RECENT as u64 + 10) {
            catches.record_at(".env files", peer("203.0.113.7:1"), at);
        }
        let json = catches.to_json();
        assert_eq!(json.matches("\"at\":").count(), RECENT);
        assert!(json.contains(&format!("\"total\":{}", RECENT + 10)));
        assert!(
            !json.contains("\"at\":0,"),
            "the oldest catch should be evicted"
        );
    }
}
