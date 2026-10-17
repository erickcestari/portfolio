//! Turns a post's `## Timeline` list into a drawn track.
//!
//! The markdown stays a plain list (`- **2025-08-25:** Reported.`), readable on
//! GitHub and in the published source. Only the rendered HTML changes: each
//! event gets the days elapsed since the previous one, and a `--gap` weight the
//! stylesheet turns into space, so a year of silence reads longer than a week
//! without pushing the page off-screen.

const HEADING: &str = "<h2 id=\"timeline\">";
const ITEM_DATE_OPEN: &str = "<li><strong>";
const ITEM_DATE_CLOSE: &str = ":</strong>";

struct Event<'a> {
    date: &'a str,
    days: i64,
    /// Already-rendered HTML of everything after the date.
    body: &'a str,
}

/// Rewrites the first list after the Timeline heading. Anything that does not
/// look like a dated, chronological list is left exactly as it was.
pub fn render(html: &str) -> String {
    let Some(heading) = html.find(HEADING) else {
        return html.to_string();
    };
    let Some(open_rel) = html[heading..].find("<ul>\n") else {
        return html.to_string();
    };
    let list_start = heading + open_rel;
    let items_start = list_start + "<ul>\n".len();
    let Some(close_rel) = html[items_start..].find("</ul>") else {
        return html.to_string();
    };
    let items_end = items_start + close_rel;

    let Some(events) = parse_events(&html[items_start..items_end]) else {
        return html.to_string();
    };

    let mut out = String::with_capacity(html.len() + events.len() * 96);
    out.push_str(&html[..list_start]);
    out.push_str(&render_events(&events));
    out.push_str(&html[items_end + "</ul>".len()..]);
    out
}

fn parse_events(items: &str) -> Option<Vec<Event<'_>>> {
    // A nested list would put a second `<ul>` before our `</ul>`.
    if items.contains("<ul>") {
        return None;
    }
    let mut events = Vec::new();
    for item in items.split_terminator("</li>\n") {
        let rest = item.strip_prefix(ITEM_DATE_OPEN)?;
        let (date, body) = rest.split_once(ITEM_DATE_CLOSE)?;
        let days = days_from_iso(date)?;
        if events.last().is_some_and(|prev: &Event| days < prev.days) {
            return None;
        }
        events.push(Event {
            date,
            days,
            body: body.trim(),
        });
    }
    (events.len() >= 2).then_some(events)
}

fn render_events(events: &[Event]) -> String {
    let mut out = String::from("<ol class=\"timeline\">\n");
    let mut prev: Option<i64> = None;
    for e in events {
        match prev {
            None => out.push_str("<li>"),
            Some(p) => {
                let gap = e.days - p;
                out.push_str(&format!(
                    "<li style=\"--gap:{:.2}\"><span class=\"timeline-gap\">{}</span>",
                    gap_weight(gap),
                    gap_label(gap)
                ));
            }
        }
        out.push_str(&format!(
            "<time datetime=\"{d}\">{d}</time><p>{}</p></li>\n",
            e.body,
            d = e.date
        ));
        prev = Some(e.days);
    }
    out.push_str("</ol>");
    out
}

/// Log-scaled so 8 days and 365 days both fit on screen yet stay visibly
/// different; the stylesheet owns how much space one unit is.
fn gap_weight(days: i64) -> f64 {
    (1.0 + days as f64).ln()
}

fn gap_label(days: i64) -> String {
    match days {
        0 => "same day".to_string(),
        1 => "+1 day".to_string(),
        n => format!("+{n} days"),
    }
}

/// "2025-08-25" -> days since 1970-01-01; `None` unless it is a real date.
fn days_from_iso(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let y: i64 = s[..4].parse().ok()?;
    let m: u32 = s[5..7].parse().ok()?;
    let d: u32 = s[8..10].parse().ok()?;
    if !(1..=12).contains(&m) || d == 0 || d > days_in_month(y, m) {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Howard Hinnant's `days_from_civil`: proleptic Gregorian date to Unix days.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = "<h2 id=\"timeline\">Timeline</h2>\n<ul>\n\
<li><strong>2025-08-25:</strong> Reported to <a href=\"x\">Rusty</a>.</li>\n\
<li><strong>2025-09-02:</strong> Fixed.</li>\n\
<li><strong>2026-08-25:</strong> Public disclosure.</li>\n\
</ul>\n<p>after</p>";

    #[test]
    fn unix_days_match_known_dates() {
        assert_eq!(days_from_iso("1970-01-01"), Some(0));
        assert_eq!(days_from_iso("2000-03-01"), Some(11_017));
        assert_eq!(days_from_iso("2024-02-29"), Some(19_782));
    }

    #[test]
    fn impossible_dates_are_refused() {
        for bad in [
            "2025-02-29",
            "2025-13-01",
            "2025-04-31",
            "2025-1-01",
            "soon",
        ] {
            assert_eq!(days_from_iso(bad), None, "{bad}");
        }
    }

    #[test]
    fn each_event_after_the_first_carries_the_gap_since_the_previous() {
        let out = render(LIST);
        assert!(out.contains("<ol class=\"timeline\">"));
        assert!(out.contains("<span class=\"timeline-gap\">+8 days</span>"));
        assert!(out.contains("<span class=\"timeline-gap\">+357 days</span>"));
        assert_eq!(out.matches("timeline-gap").count(), 2);
    }

    #[test]
    fn event_html_and_the_rest_of_the_page_survive() {
        let out = render(LIST);
        assert!(out.contains("<p>Reported to <a href=\"x\">Rusty</a>.</p>"));
        assert!(out.contains("<time datetime=\"2026-08-25\">2026-08-25</time>"));
        assert!(out.starts_with("<h2 id=\"timeline\">Timeline</h2>\n<ol"));
        assert!(out.ends_with("</ol>\n<p>after</p>"));
        assert!(!out.contains("<ul>"));
    }

    #[test]
    fn longer_gaps_get_more_room() {
        assert!(gap_weight(357) > gap_weight(8));
        assert_eq!(gap_weight(0), 0.0);
    }

    #[test]
    fn a_list_that_is_not_a_dated_timeline_is_left_alone() {
        let undated = LIST.replace("<strong>2025-09-02:</strong>", "<strong>Later:</strong>");
        assert_eq!(render(&undated), undated);

        let backwards = LIST.replace("2025-09-02", "2024-09-02");
        assert_eq!(render(&backwards), backwards);

        let no_heading = LIST.replace("id=\"timeline\"", "id=\"history\"");
        assert_eq!(render(&no_heading), no_heading);
    }

    #[test]
    fn same_day_events_are_labelled_as_such() {
        assert_eq!(gap_label(0), "same day");
        assert_eq!(gap_label(1), "+1 day");
    }
}
