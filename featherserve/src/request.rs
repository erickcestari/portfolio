pub struct Request {
    pub path: String,
    pub accepts_gzip: bool,
}

impl Request {
    pub fn parse_h1(buf: &str) -> Option<Self> {
        let mut lines = buf.lines();
        let path = lines.next()?.split_whitespace().nth(1)?.to_string();
        let accepts_gzip = lines.any(|line| {
            line.to_lowercase().starts_with("accept-encoding:")
                && line.to_lowercase().contains("gzip")
        });
        Some(Self { path, accepts_gzip })
    }

    pub fn from_h2<T>(req: &http::Request<T>) -> Self {
        let path = req.uri().path().to_string();
        let accepts_gzip = req
            .headers()
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase().contains("gzip"))
            .unwrap_or(false);
        Self { path, accepts_gzip }
    }
}
