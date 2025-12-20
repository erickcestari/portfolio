use std::io::{self, Write};

pub struct Response {
    status: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
    gzip: bool,
}

impl Response {
    pub fn ok(body: Vec<u8>, content_type: &'static str, gzip: bool) -> Self {
        Self {
            status: "200 OK",
            content_type,
            body,
            gzip,
        }
    }

    pub fn not_found(body: Vec<u8>, content_type: &'static str, gzip: bool) -> Self {
        Self {
            status: "404 NOT FOUND",
            content_type,
            body,
            gzip,
        }
    }

    pub fn write_to<W: Write>(self, writer: &mut W) -> io::Result<()> {
        let encoding_header = if self.gzip {
            "Content-Encoding: gzip\r\n"
        } else {
            ""
        };

        let header = format!(
            "HTTP/1.1 {}\r\nContent-Length: {}\r\nContent-Type: {}\r\n{}\r\n",
            self.status,
            self.body.len(),
            self.content_type,
            encoding_header
        );

        writer.write_all(header.as_bytes())?;
        writer.write_all(&self.body)
    }
}
