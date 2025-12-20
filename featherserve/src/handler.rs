use std::{fs, io::Write, path::Path};

use flate2::{write::GzEncoder, Compression};

use crate::{Request, Response};

pub struct StaticFileHandler<'a> {
    static_dir: &'a str,
}

impl<'a> StaticFileHandler<'a> {
    pub fn new(static_dir: &'a str) -> Self {
        Self { static_dir }
    }

    pub fn handle(&self, request: &Request) -> Response {
        println!("Request: {}", request.path);

        let file_path = self.resolve_path(request.path);
        let (found, file_path) = if Path::new(&file_path).exists() {
            (true, file_path)
        } else {
            (false, format!("{}/404.html", self.static_dir))
        };

        let contents = fs::read(&file_path).unwrap_or_else(|_| b"Not Found".to_vec());
        let content_type = Self::content_type(&file_path);

        let (body, gzip) = self.maybe_compress(&contents, content_type, request.accepts_gzip);

        if found {
            Response::ok(body, content_type, gzip)
        } else {
            Response::not_found(body, content_type, gzip)
        }
    }

    fn maybe_compress(
        &self,
        contents: &[u8],
        content_type: &str,
        accepts_gzip: bool,
    ) -> (Vec<u8>, bool) {
        if accepts_gzip && Self::is_compressible(content_type) {
            if let Some(compressed) = Self::gzip_compress(contents) {
                return (compressed, true);
            }
        }
        (contents.to_vec(), false)
    }

    fn resolve_path(&self, path: &str) -> String {
        if path == "/" {
            return format!("{}/index.html", self.static_dir);
        }

        if path.contains('.') {
            return format!("{}{}", self.static_dir, path);
        }

        let index_path = format!("{}{}/index.html", self.static_dir, path);
        if Path::new(&index_path).exists() {
            index_path
        } else {
            format!("{}{}.html", self.static_dir, path)
        }
    }

    fn is_compressible(content_type: &str) -> bool {
        matches!(
            content_type,
            "text/html"
                | "text/css"
                | "text/plain; charset=utf-8"
                | "application/javascript"
                | "application/json"
                | "image/svg+xml"
        )
    }

    fn gzip_compress(data: &[u8]) -> Option<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).ok()?;
        encoder.finish().ok()
    }

    fn content_type(filename: &str) -> &'static str {
        match Path::new(filename).extension().and_then(|ext| ext.to_str()) {
            Some("html") => "text/html",
            Some("css") => "text/css",
            Some("js") => "application/javascript",
            Some("json") => "application/json",
            Some("svg") => "image/svg+xml",
            Some("png") => "image/png",
            Some("jpg" | "jpeg") => "image/jpeg",
            Some("webp") => "image/webp",
            Some("ico") => "image/x-icon",
            Some("woff") => "font/woff",
            Some("woff2") => "font/woff2",
            Some("asc") => "text/plain; charset=utf-8",
            _ => "application/octet-stream",
        }
    }
}
