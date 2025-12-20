pub struct Request<'a> {
    pub path: &'a str,
    pub accepts_gzip: bool,
}

impl<'a> Request<'a> {
    pub fn parse(buf: &'a str) -> Option<Self> {
        let mut lines = buf.lines();
        let path = lines.next()?.split_whitespace().nth(1)?;
        let accepts_gzip = lines.any(|line| {
            line.to_lowercase().starts_with("accept-encoding:")
                && line.to_lowercase().contains("gzip")
        });
        Some(Self { path, accepts_gzip })
    }
}
