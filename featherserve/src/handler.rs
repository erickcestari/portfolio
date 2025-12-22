use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use flate2::{write::GzEncoder, Compression};

use crate::{Request, Response};

enum ResolveResult {
    Found(PathBuf),
    NotFound,
    Honeypot,
    Forbidden,
}

pub struct StaticFileHandler<'a> {
    static_dir: &'a str,
}

impl<'a> StaticFileHandler<'a> {
    pub fn new(static_dir: &'a str) -> Self {
        Self { static_dir }
    }

    pub fn handle(&self, request: &Request) -> Response {
        println!("Request: {}", request.path);

        let (found, file_path) = match self.resolve_path(request.path) {
            ResolveResult::Found(path) => (true, path),
            ResolveResult::NotFound => (
                false,
                PathBuf::from(format!("{}/404.html", self.static_dir)),
            ),
            ResolveResult::Honeypot => return Response::forbidden(request.path),
            ResolveResult::Forbidden => return Response::forbidden(request.path),
        };

        let file_path_str = file_path.to_string_lossy();
        let contents = fs::read(&file_path).unwrap_or_else(|_| b"Not Found".to_vec());
        let content_type = Self::content_type(&file_path_str);
        let cache_control = Self::cache_control(&file_path_str);

        let (body, gzip) = self.maybe_compress(&contents, content_type, request.accepts_gzip);

        let response = if found {
            Response::ok(body, content_type, gzip)
        } else {
            Response::not_found(body, content_type, gzip)
        };

        if let Some(cc) = cache_control {
            response.with_cache_control(cc)
        } else {
            response
        }
    }

    fn cache_control(filename: &str) -> Option<&'static str> {
        match Path::new(filename).extension().and_then(|ext| ext.to_str()) {
            Some(
                "css" | "js" | "png" | "jpg" | "jpeg" | "webp" | "ico" | "svg" | "woff" | "woff2",
            ) => Some("public, max-age=300, must-revalidate"),

            Some("html") => Some("no-cache, must-revalidate"),
            _ => None,
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

    fn resolve_path(&self, path: &str) -> ResolveResult {
        let base = match Path::new(self.static_dir).canonicalize() {
            Ok(b) => b,
            Err(_) => return ResolveResult::NotFound,
        };

        let requested = if path == "/" {
            base.join("index.html")
        } else if path.contains('.') {
            base.join(path.trim_start_matches('/'))
        } else {
            let index_path = base.join(path.trim_start_matches('/')).join("index.html");
            if index_path.exists() {
                index_path
            } else {
                base.join(format!("{}.html", path.trim_start_matches('/')))
            }
        };

        if let Some(req_str) = requested.to_str() {
            if Self::is_honeypot(req_str) {
                return ResolveResult::Honeypot;
            }
        }

        let canonical = match requested.canonicalize() {
            Ok(c) => c,
            Err(_) => return ResolveResult::NotFound,
        };

        if !canonical.starts_with(&base) {
            return ResolveResult::Forbidden;
        }

        if let Some(canonical_str) = canonical.to_str() {
            if Self::is_honeypot(canonical_str) {
                return ResolveResult::Honeypot;
            }
        }

        ResolveResult::Found(canonical)
    }

    fn is_honeypot(path: &str) -> bool {
        path.contains("etc/passwd")
            || path.contains("etc/shadow")
            || path.contains(".env")
            || path.contains("id_rsa")
            || path.contains("ssh")
            || path.contains("wp-config")
            || path.contains("proc/self")
            || path.contains("flag")
            || path.contains("config")
            || path.contains("aws")
            || path.contains("docker")
            || path.contains(".php")
            || path.contains("../")
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
