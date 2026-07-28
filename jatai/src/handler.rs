use std::sync::Arc;

use crate::{cache::FileCache, Request, Response};

pub struct StaticFileHandler {
    cache: Arc<FileCache>,
}

/// One line per request: who asked, what they got, what they asked for.
///
/// The outcome comes before the path so `honeypot` hits group together under
/// `sort`, and the path is escaped because it is attacker-controlled and would
/// otherwise be able to write control characters into the log.
fn log(request: &Request, outcome: &str) {
    println!(
        "{} {} {}",
        request.peer,
        outcome,
        request.path.escape_default()
    );
}

impl StaticFileHandler {
    pub fn new(cache: Arc<FileCache>) -> Self {
        Self { cache }
    }

    pub fn handle(&self, request: &Request) -> Response {
        // Check the honeypot first: a matching path never reaches the cache.
        if let Some(bait) = crate::honeypot::bait_for(&request.path) {
            log(request, "honeypot");
            return Response::honeypot(bait);
        }

        if let Some(cached) = self.cache.get(&request.path) {
            log(request, "200");
            return Self::build_response(cached, request.accepts_gzip, true);
        }

        log(request, "404");

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
        let (body, gzip) = match (accepts_gzip, cached.body_gzip.as_ref()) {
            (true, Some(gz)) => (gz.to_vec(), true),
            _ => (cached.body.to_vec(), false),
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
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    fn handler(files: &[(&str, &[u8])]) -> (TempDir, StaticFileHandler) {
        let dir = TempDir::new().unwrap();
        for (rel, contents) in files {
            let path = dir.path().join(rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&path, contents).unwrap();
        }
        let cache = FileCache::load(dir.path().to_str().unwrap());
        (dir, StaticFileHandler::new(Arc::new(cache)))
    }

    fn request(path: &str, accepts_gzip: bool) -> Request {
        Request {
            path: path.to_string(),
            accepts_gzip,
            peer: "203.0.113.7:54321".parse().unwrap(),
        }
    }

    #[test]
    fn serves_a_cached_file_with_status_200() {
        let (_dir, handler) = handler(&[("index.html", b"home")]);
        let res = handler.handle(&request("/", false));
        assert_eq!(res.status, 200);
        assert_eq!(res.body, b"home");
        assert_eq!(res.content_type, "text/html");
    }

    #[test]
    fn attaches_cache_control_from_the_cached_entry() {
        let (_dir, handler) = handler(&[("style.css", b"body{}")]);
        let res = handler.handle(&request("/style.css", false));
        assert_eq!(
            res.cache_control,
            Some("public, max-age=300, must-revalidate")
        );
    }

    #[test]
    fn serves_gzip_only_when_the_client_accepts_it() {
        let body = "x".repeat(500);
        let (_dir, handler) = handler(&[("index.html", body.as_bytes())]);

        let plain = handler.handle(&request("/", false));
        assert!(!plain.gzip);
        assert_eq!(plain.body, body.as_bytes());

        let compressed = handler.handle(&request("/", true));
        assert!(compressed.gzip);
        assert!(compressed.body.len() < plain.body.len());
    }

    #[test]
    fn falls_back_to_plain_body_when_the_entry_has_no_gzip_variant() {
        let (_dir, handler) = handler(&[("logo.png", &[0x89, b'P', b'N', b'G'])]);
        let res = handler.handle(&request("/logo.png", true));
        assert!(!res.gzip);
        assert_eq!(res.body, [0x89, b'P', b'N', b'G']);
    }

    #[test]
    fn unknown_path_serves_the_404_page_with_status_404() {
        let (_dir, handler) = handler(&[("index.html", b"home"), ("404.html", b"missing")]);
        let res = handler.handle(&request("/nope", false));
        assert_eq!(res.status, 404);
        assert_eq!(res.body, b"missing");
        assert_eq!(res.content_type, "text/html");
    }

    #[test]
    fn unknown_path_falls_back_to_plain_text_without_a_404_page() {
        let (_dir, handler) = handler(&[("index.html", b"home")]);
        let res = handler.handle(&request("/nope", false));
        assert_eq!(res.status, 404);
        assert_eq!(res.body, b"Not Found");
        assert_eq!(res.content_type, "text/plain");
    }

    #[test]
    fn the_404_page_is_gzipped_for_clients_that_accept_it() {
        let body = "missing ".repeat(100);
        let (_dir, handler) = handler(&[("404.html", body.as_bytes())]);
        let res = handler.handle(&request("/nope", true));
        assert_eq!(res.status, 404);
        assert!(res.gzip);
    }

    #[test]
    fn the_honeypot_is_checked_before_the_cache() {
        // A real file whose name matches a trap must still get bait, never its
        // contents: the honeypot runs first by design.
        let (_dir, handler) = handler(&[("config.html", b"my real config page")]);
        let res = handler.handle(&request("/config.html", false));
        assert!(!res.body.starts_with(b"my real"));
        assert!(String::from_utf8_lossy(&res.body).contains("[database]"));
    }

    #[test]
    fn a_caught_attack_is_answered_with_the_bait_for_its_decoded_target() {
        // The bait is chosen from the normalised path, so an encoded attack gets
        // the same answer as the plain one it was hiding.
        let (_dir, handler) = handler(&[("index.html", b"home"), ("404.html", b"missing")]);

        let plain = handler.handle(&request("/etc/passwd", false));
        let encoded = handler.handle(&request("/%252e%252e/etc%252fpasswd", false));

        assert_eq!(plain.status, 200);
        assert_eq!(encoded.body, plain.body);
        assert!(encoded.body.starts_with(b"root:x:0:0:"));
    }

    #[test]
    fn normalisation_never_redirects_a_lookup_to_another_file() {
        // "%2561" decodes to "a" only for the honeypot; the cache is still keyed
        // by the literal request path, so no encoded path reaches a real file.
        let (_dir, handler) = handler(&[("about.html", b"about"), ("404.html", b"missing")]);
        let res = handler.handle(&request("/%2561bout", false));
        assert_eq!(res.status, 404);
        assert_eq!(res.body, b"missing");
    }

    #[test]
    fn ordinary_paths_reach_the_cache_untouched() {
        let (_dir, handler) = handler(&[("about.html", b"about"), ("404.html", b"missing")]);
        let res = handler.handle(&request("/about", false));
        assert_eq!(res.status, 200);
        assert_eq!(res.body, b"about");
    }
}
