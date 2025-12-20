use std::io::{self, Write};

pub struct Response {
    status: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
    gzip: bool,
    cache_control: Option<&'static str>,
}

impl Response {
    pub fn ok(body: Vec<u8>, content_type: &'static str, gzip: bool) -> Self {
        Self {
            status: "200 OK",
            content_type,
            body,
            gzip,
            cache_control: None,
        }
    }

    pub fn not_found(body: Vec<u8>, content_type: &'static str, gzip: bool) -> Self {
        Self {
            status: "404 NOT FOUND",
            content_type,
            body,
            gzip,
            cache_control: None,
        }
    }

    pub fn with_cache_control(mut self, cache_control: &'static str) -> Self {
        self.cache_control = Some(cache_control);
        self
    }

    pub fn write_to<W: Write>(self, writer: &mut W) -> io::Result<()> {
        let encoding_header = if self.gzip {
            "Content-Encoding: gzip\r\n"
        } else {
            ""
        };

        let cache_header = self
            .cache_control
            .map(|cc| format!("Cache-Control: {}\r\n", cc))
            .unwrap_or_default();

        let header = format!(
            "HTTP/1.1 {}\r\nContent-Length: {}\r\nContent-Type: {}\r\n{}{}\r\n",
            self.status,
            self.body.len(),
            self.content_type,
            encoding_header,
            cache_header,
        );

        writer.write_all(header.as_bytes())?;
        writer.write_all(&self.body)
    }
}
