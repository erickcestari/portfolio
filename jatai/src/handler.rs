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
        println!("Request: {}", request.path.escape_default());

        // Check the honeypot first: a matching path never reaches the cache.
        if let Some(target) = Self::honeypot(&request.path) {
            return Response::forbidden(&target);
        }

        if let Some(cached) = self.cache.get(&request.path) {
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

    /// Decide whether a path is bait for the honeypot, returning the normalised
    /// form the bait should be chosen from.
    ///
    /// Normalisation is deliberately more permissive than serving: extra layers
    /// of percent-encoding, backslash separators and capitals are all ways of
    /// writing the same attack, and matching the literal path would let each of
    /// them through. Lookups still use the literal path, so a real file is never
    /// reached by a normalised one.
    fn honeypot(path: &str) -> Option<String> {
        let candidate = crate::request::fully_decode(path)
            .replace('\\', "/")
            .to_lowercase();

        let matched = candidate.contains("etc/passwd")
            || candidate.contains("etc/shadow")
            || candidate.contains(".env")
            || candidate.contains("id_rsa")
            || candidate.contains("ssh")
            || candidate.contains("wp-config")
            || candidate.contains("proc/self")
            || candidate.contains("flag")
            || candidate.contains("config")
            || candidate.contains("aws")
            || candidate.contains("docker")
            || candidate.contains(".php")
            || candidate.contains("../");

        matched.then_some(candidate)
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
    fn honeypot_paths_are_intercepted_before_the_cache() {
        // A real file whose name matches a bait pattern must still get bait,
        // never its contents: the honeypot check runs first by design.
        let (_dir, handler) = handler(&[("config.html", b"my real config page")]);
        let res = handler.handle(&request("/config.html", false));
        assert_eq!(res.content_type, "text/plain");
        assert!(!res.body.starts_with(b"my real"));
    }

    #[test]
    fn every_bait_pattern_is_detected() {
        let attacks = [
            "/etc/passwd",
            "/etc/shadow",
            "/.env",
            "/.env.production",
            "/home/user/.ssh/id_rsa",
            "/wp-config.php",
            "/proc/self/environ",
            "/flag.txt",
            "/app/config.json",
            "/.aws/credentials",
            "/docker-compose.yml",
            "/index.php",
            "/../../etc/hosts",
        ];
        for attack in attacks {
            assert!(
                StaticFileHandler::honeypot(attack).is_some(),
                "{} should land in the honeypot",
                attack
            );
        }
    }

    #[test]
    fn ordinary_paths_are_not_treated_as_attacks() {
        let benign = [
            "/",
            "/index.html",
            "/about",
            "/blog/my-post",
            "/style.css",
            "/img/photo.png",
            "/favicon.ico",
        ];
        for path in benign {
            assert!(
                StaticFileHandler::honeypot(path).is_none(),
                "{} should be served normally",
                path
            );
        }
    }

    #[test]
    fn traversal_is_caught_however_many_times_it_is_encoded() {
        // parse_h1 decodes once, so anything beyond a single layer arrives here
        // still encoded. The honeypot keeps decoding until the path stops hiding.
        for attack in [
            "/../etc/hosts",
            "/%2e%2e/etc/hosts",
            "/%252e%252e/etc/hosts",
            "/%25252e%25252e/etc/hosts",
        ] {
            assert!(
                StaticFileHandler::honeypot(attack).is_some(),
                "{} should be caught",
                attack
            );
        }
    }

    #[test]
    fn attacks_are_caught_whatever_their_capitalisation() {
        for attack in ["/ETC/PASSWD", "/WP-Config.php", "/.AWS/credentials"] {
            assert!(
                StaticFileHandler::honeypot(attack).is_some(),
                "{} should be caught",
                attack
            );
        }
    }

    #[test]
    fn backslash_traversal_is_caught_too() {
        assert!(StaticFileHandler::honeypot("/..\\..\\windows\\win.ini").is_some());
        assert!(StaticFileHandler::honeypot("/%2e%2e%5cetc%5cpasswd").is_some());
    }

    #[test]
    fn a_caught_attack_is_answered_with_the_bait_for_its_decoded_target() {
        // The bait is chosen from the normalised path, so an encoded attack gets
        // the same answer as the plain one it was hiding.
        let (_dir, handler) = handler(&[("index.html", b"home"), ("404.html", b"missing")]);

        let plain = handler.handle(&request("/etc/passwd", false));
        let encoded = handler.handle(&request("/%252e%252e/etc%252fpasswd", false));

        assert_eq!(plain.status, 200);
        assert_eq!(encoded.status, 200);
        assert_eq!(encoded.body, plain.body);
        assert!(encoded.body.starts_with(b"root:x:0:0:"));
    }

    #[test]
    fn normalisation_never_redirects_a_lookup_to_another_file() {
        // "%2e" decodes to "." only for detection; the cache is still keyed by
        // the literal request path, so no encoded path can reach a real file.
        let (_dir, handler) = handler(&[("about.html", b"about"), ("404.html", b"missing")]);
        let res = handler.handle(&request("/%2561bout", false));
        assert_eq!(res.status, 404);
        assert_eq!(res.body, b"missing");
    }
}
