use std::net::SocketAddr;

pub struct Request {
    pub path: String,
    pub accepts_gzip: bool,
    /// Where the request came from. Carried on the request rather than read
    /// back off the socket so every protocol reports the same thing, and so
    /// the value survives into the log line and any future rate limiting.
    pub peer: SocketAddr,
}

impl Request {
    pub fn parse_h1(buf: &str, peer: SocketAddr) -> Option<Self> {
        let mut lines = buf.lines();
        let path = url_decode(lines.next()?.split_whitespace().nth(1)?);
        let accepts_gzip = lines.any(|line| {
            line.to_lowercase().starts_with("accept-encoding:")
                && line.to_lowercase().contains("gzip")
        });
        Some(Self {
            path,
            accepts_gzip,
            peer,
        })
    }

    pub fn from_h2<T>(req: &http::Request<T>, peer: SocketAddr) -> Self {
        let path = url_decode(req.uri().path());
        let accepts_gzip = req
            .headers()
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase().contains("gzip"))
            .unwrap_or(false);
        Self {
            path,
            accepts_gzip,
            peer,
        }
    }
}

/// Percent-decode until the result stops changing.
///
/// A single pass is what a URL actually means, and is what serving uses. This
/// is for the honeypot only: an attacker who wraps a path in extra layers of
/// encoding ("%252e%252e/" for "../") is still asking for the same thing, and
/// the honeypot has to see through every layer.
///
/// Terminates: each pass that changes the string removes at least two bytes.
pub(crate) fn fully_decode(input: &str) -> String {
    let mut decoded = url_decode(input);
    loop {
        let next = url_decode(&decoded);
        if next == decoded {
            return decoded;
        }
        decoded = next;
    }
}

fn url_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                result.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(result).unwrap_or_else(|_| input.to_string())
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Requests in these tests all come from the same made-up client.
    fn peer() -> SocketAddr {
        "203.0.113.7:54321".parse().unwrap()
    }

    fn h1(raw: &str) -> Option<Request> {
        Request::parse_h1(raw, peer())
    }

    #[test]
    fn parses_path_from_request_line() {
        let req = h1("GET /about.html HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert_eq!(req.path, "/about.html");
        assert!(!req.accepts_gzip);
    }

    #[test]
    fn parses_root_path() {
        assert_eq!(h1("GET / HTTP/1.1\r\n\r\n").unwrap().path, "/");
    }

    #[test]
    fn accepts_any_method() {
        assert_eq!(h1("POST /x HTTP/1.1\r\n\r\n").unwrap().path, "/x");
        assert_eq!(h1("HEAD /x HTTP/1.1\r\n\r\n").unwrap().path, "/x");
    }

    #[test]
    fn rejects_request_line_without_path() {
        assert!(h1("GET\r\n\r\n").is_none());
        assert!(h1("").is_none());
    }

    #[test]
    fn detects_gzip_in_accept_encoding() {
        let req = h1("GET / HTTP/1.1\r\nAccept-Encoding: gzip, deflate\r\n\r\n").unwrap();
        assert!(req.accepts_gzip);
    }

    #[test]
    fn accept_encoding_matching_is_case_insensitive() {
        let req = h1("GET / HTTP/1.1\r\nACCEPT-ENCODING: GZIP\r\n\r\n").unwrap();
        assert!(req.accepts_gzip);
    }

    #[test]
    fn ignores_gzip_outside_accept_encoding_header() {
        // "gzip" appearing in another header must not enable compression.
        let req = h1("GET / HTTP/1.1\r\nUser-Agent: gzip-bot\r\n\r\n").unwrap();
        assert!(!req.accepts_gzip);
    }

    #[test]
    fn ignores_accept_encoding_without_gzip() {
        let req = h1("GET / HTTP/1.1\r\nAccept-Encoding: br, deflate\r\n\r\n").unwrap();
        assert!(!req.accepts_gzip);
    }

    #[test]
    fn decodes_percent_escapes_in_path() {
        assert_eq!(h1("GET /a%20b HTTP/1.1\r\n\r\n").unwrap().path, "/a b");
        assert_eq!(h1("GET /%2e%2e/x HTTP/1.1\r\n\r\n").unwrap().path, "/../x");
    }

    #[test]
    fn decodes_uppercase_and_lowercase_hex() {
        assert_eq!(h1("GET /%2F HTTP/1.1\r\n\r\n").unwrap().path, "//");
        assert_eq!(h1("GET /%2f HTTP/1.1\r\n\r\n").unwrap().path, "//");
    }

    #[test]
    fn decodes_double_encoded_traversal_only_once() {
        // %252e decodes to "%2e", not to ".": a single pass, so honeypot
        // detection downstream sees the literal "%2e" form.
        assert_eq!(
            h1("GET /%252e%252e/ HTTP/1.1\r\n\r\n").unwrap().path,
            "/%2e%2e/"
        );
    }

    #[test]
    fn leaves_invalid_percent_escapes_untouched() {
        assert_eq!(h1("GET /100%zz HTTP/1.1\r\n\r\n").unwrap().path, "/100%zz");
        assert_eq!(
            h1("GET /trailing% HTTP/1.1\r\n\r\n").unwrap().path,
            "/trailing%"
        );
        assert_eq!(
            h1("GET /short%2 HTTP/1.1\r\n\r\n").unwrap().path,
            "/short%2"
        );
    }

    #[test]
    fn full_decode_peels_every_layer_of_encoding() {
        assert_eq!(fully_decode("/%252e%252e/"), "/../");
        assert_eq!(fully_decode("/%25252e%25252e/"), "/../");
        assert_eq!(fully_decode("/a%2520b"), "/a b");
    }

    #[test]
    fn full_decode_leaves_a_plain_path_untouched() {
        assert_eq!(fully_decode("/blog/my-post"), "/blog/my-post");
        assert_eq!(fully_decode("/100%zz"), "/100%zz");
    }

    #[test]
    fn full_decode_stops_instead_of_looping_on_a_self_encoding_input() {
        // "%25" decodes to "%", which cannot decode further: the pass that
        // produces no change ends the loop.
        assert_eq!(fully_decode("%25"), "%");
        assert_eq!(fully_decode("%2525"), "%");
    }

    #[test]
    fn falls_back_to_raw_input_on_invalid_utf8() {
        // %ff is not valid UTF-8 on its own, so the original text is kept.
        assert_eq!(h1("GET /%ff HTTP/1.1\r\n\r\n").unwrap().path, "/%ff");
    }

    #[test]
    fn h2_request_uses_uri_path_without_query() {
        let req = http::Request::builder()
            .uri("https://example.com/a%20b?q=1")
            .body(())
            .unwrap();
        let parsed = Request::from_h2(&req, peer());
        assert_eq!(parsed.path, "/a b");
        assert!(!parsed.accepts_gzip);
    }

    #[test]
    fn h2_request_detects_gzip() {
        let req = http::Request::builder()
            .uri("/")
            .header("accept-encoding", "GZIP, br")
            .body(())
            .unwrap();
        assert!(Request::from_h2(&req, peer()).accepts_gzip);
    }

    #[test]
    fn h2_request_without_accept_encoding_rejects_gzip() {
        let req = http::Request::builder().uri("/").body(()).unwrap();
        assert!(!Request::from_h2(&req, peer()).accepts_gzip);
    }
}
