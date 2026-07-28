pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub gzip: bool,
    pub cache_control: Option<&'static str>,
}

impl Response {
    pub fn ok(body: Vec<u8>, content_type: &'static str, gzip: bool) -> Self {
        Self {
            status: 200,
            content_type,
            body,
            gzip,
            cache_control: None,
        }
    }

    pub fn not_found(body: Vec<u8>, content_type: &'static str, gzip: bool) -> Self {
        Self {
            status: 404,
            content_type,
            body,
            gzip,
            cache_control: None,
        }
    }

    /// Answer an attack with bait from the honeypot.
    ///
    /// Deliberately 200, not 403: a refusal tells a scanner the path is real
    /// and guarded, which is exactly the signal worth denying it.
    pub fn honeypot(bait: crate::honeypot::Bait) -> Self {
        Self {
            status: 200,
            content_type: bait.content_type,
            body: bait.body.as_bytes().to_vec(),
            gzip: false,
            cache_control: None,
        }
    }

    pub fn with_cache_control(mut self, cache_control: &'static str) -> Self {
        self.cache_control = Some(cache_control);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::honeypot::Bait;

    #[test]
    fn ok_response_carries_status_and_metadata() {
        let res = Response::ok(b"hi".to_vec(), "text/html", true);
        assert_eq!(res.status, 200);
        assert_eq!(res.content_type, "text/html");
        assert_eq!(res.body, b"hi");
        assert!(res.gzip);
        assert_eq!(res.cache_control, None);
    }

    #[test]
    fn not_found_response_uses_status_404() {
        let res = Response::not_found(b"gone".to_vec(), "text/html", false);
        assert_eq!(res.status, 404);
        assert!(!res.gzip);
    }

    #[test]
    fn with_cache_control_sets_the_header_value() {
        let res = Response::ok(b"x".to_vec(), "text/css", false).with_cache_control("no-store");
        assert_eq!(res.cache_control, Some("no-store"));
    }

    #[test]
    fn honeypot_answers_200_so_the_attack_looks_successful() {
        // A 403 would tell a scanner the path exists and is guarded. Returning
        // 200 with plausible bait keeps it chasing a dead end.
        let res = Response::honeypot(Bait {
            body: "root:x:0:0:root:/root:/bin/bash\n",
            content_type: "text/plain",
        });

        assert_eq!(res.status, 200);
        assert_eq!(res.content_type, "text/plain");
        assert_eq!(res.body, b"root:x:0:0:root:/root:/bin/bash\n");
        assert_eq!(res.cache_control, None);
    }

    #[test]
    fn honeypot_serves_the_content_type_of_the_file_it_fakes() {
        let res = Response::honeypot(Bait {
            body: "<html></html>",
            content_type: "text/html",
        });
        assert_eq!(res.content_type, "text/html");
    }

    #[test]
    fn honeypot_bait_is_never_compressed() {
        // Bait is small and sent as-is; compressing it would only add a header
        // that the fake file's own server would not have sent.
        let res = Response::honeypot(Bait {
            body: "x",
            content_type: "text/plain",
        });
        assert!(!res.gzip);
    }
}
