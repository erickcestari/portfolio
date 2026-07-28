pub struct Request {
    pub path: String,
    pub accepts_gzip: bool,
}

impl Request {
    pub fn parse_h1(buf: &str) -> Option<Self> {
        let mut lines = buf.lines();
        let path = url_decode(lines.next()?.split_whitespace().nth(1)?);
        let accepts_gzip = lines.any(|line| {
            line.to_lowercase().starts_with("accept-encoding:")
                && line.to_lowercase().contains("gzip")
        });
        Some(Self { path, accepts_gzip })
    }

    pub fn from_h2<T>(req: &http::Request<T>) -> Self {
        let path = url_decode(req.uri().path());
        let accepts_gzip = req
            .headers()
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase().contains("gzip"))
            .unwrap_or(false);
        Self { path, accepts_gzip }
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
