use std::sync::Arc;

use crate::{cache::FileCache, Request, Response};

pub struct StaticFileHandler {
    cache: Arc<FileCache>,
}

impl StaticFileHandler {
    pub fn new(cache: Arc<FileCache>) -> Self {
        Self { cache }
    }

    pub fn handle(&self, request: &Request) -> Response {
        println!("Request: {}", request.path);

        // Check for honeypot patterns first
        if Self::is_honeypot(request.path) {
            return Response::forbidden(request.path);
        }

        if let Some(cached) = self.cache.get(request.path) {
            return Self::build_response(cached, request.accepts_gzip, true);
        }

        if let Some(not_found) = self.cache.get_not_found() {
            return Self::build_response(not_found, request.accepts_gzip, false);
        }

        // Fallback if 404.html isn't cached
        Response::not_found(b"Not Found".to_vec(), "text/plain", false)
    }

    fn build_response(
        cached: &crate::cache::CachedFile,
        accepts_gzip: bool,
        found: bool,
    ) -> Response {
        let (body, gzip) = if accepts_gzip && cached.body_gzip.is_some() {
            (cached.body_gzip.as_ref().unwrap().to_vec(), true)
        } else {
            (cached.body.to_vec(), false)
        };

        let response = if found {
            Response::ok(body, cached.content_type, gzip)
        } else {
            Response::not_found(body, cached.content_type, gzip)
        };

        if let Some(cc) = cached.cache_control {
            response.with_cache_control(cc)
        } else {
            response
        }
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
}
