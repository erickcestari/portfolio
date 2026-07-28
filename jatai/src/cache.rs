use std::{collections::HashMap, fs, io::Write, path::Path, sync::Arc};

use flate2::{write::GzEncoder, Compression};

/// A cached file entry containing pre-computed response data
#[derive(Clone)]
pub struct CachedFile {
    pub body: Arc<[u8]>,
    pub body_gzip: Option<Arc<[u8]>>,
    pub content_type: &'static str,
    pub cache_control: Option<&'static str>,
}

/// In-memory cache for static files, keyed by request path
pub struct FileCache {
    entries: HashMap<String, CachedFile>,
    not_found: Option<CachedFile>,
}

impl FileCache {
    /// Load all static files from the given directory into memory
    pub fn load(static_dir: &str) -> Self {
        let mut entries = HashMap::new();
        let base = match Path::new(static_dir).canonicalize() {
            Ok(b) => b,
            Err(_) => {
                eprintln!("Warning: Could not canonicalize static dir: {}", static_dir);
                return Self {
                    entries,
                    not_found: None,
                };
            }
        };

        Self::load_dir(&base, &base, &mut entries);

        let not_found = Self::load_single_file(&base.join("404.html"));

        println!("Cache loaded: {} files", entries.len());

        Self { entries, not_found }
    }

    fn load_dir(base: &Path, dir: &Path, entries: &mut HashMap<String, CachedFile>) {
        let read_dir = match fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(_) => return,
        };

        for entry in read_dir.flatten() {
            let path = entry.path();

            // Prevent symlink traversal: verify resolved path stays within base
            let canonical = match path.canonicalize() {
                Ok(c) => c,
                Err(_) => continue,
            };
            if !canonical.starts_with(base) {
                eprintln!(
                    "Warning: Skipping path outside static dir: {}",
                    path.display()
                );
                continue;
            }

            if path.is_dir() {
                Self::load_dir(base, &path, entries);
            } else if path.is_file() {
                if let Some(cached) = Self::load_single_file(&path) {
                    // Generate all URL paths that should map to this file
                    let rel_path = path.strip_prefix(base).unwrap_or(&path);
                    let rel_str = rel_path.to_string_lossy();

                    // Primary path: /path/to/file.ext
                    let url_path = format!("/{}", rel_str);
                    entries.insert(url_path.clone(), cached.clone());

                    // For index.html files, also map the directory path
                    if rel_str.ends_with("index.html") {
                        let dir_path = url_path.trim_end_matches("index.html");
                        let dir_path = dir_path.trim_end_matches('/');
                        if dir_path.is_empty() {
                            entries.insert("/".to_string(), cached.clone());
                        } else {
                            entries.insert(dir_path.to_string(), cached.clone());
                            entries.insert(format!("{}/", dir_path), cached.clone());
                        }
                    }

                    // For .html files (not index.html), also map without extension
                    if rel_str.ends_with(".html") && !rel_str.ends_with("index.html") {
                        let without_ext = url_path.trim_end_matches(".html");
                        entries.insert(without_ext.to_string(), cached);
                    }
                }
            }
        }
    }

    fn load_single_file(path: &Path) -> Option<CachedFile> {
        let contents = fs::read(path).ok()?;
        let path_str = path.to_string_lossy();
        let content_type = Self::content_type(&path_str);
        let cache_control = Self::cache_control(&path_str);

        let body: Arc<[u8]> = contents.clone().into();
        let body_gzip = if Self::is_compressible(content_type) {
            Self::gzip_compress(&contents).map(|c| c.into())
        } else {
            None
        };

        Some(CachedFile {
            body,
            body_gzip,
            content_type,
            cache_control,
        })
    }

    /// Look up a cached file by request path
    pub fn get(&self, path: &str) -> Option<&CachedFile> {
        self.entries.get(path)
    }

    /// Get the cached 404 page
    pub fn get_not_found(&self) -> Option<&CachedFile> {
        self.not_found.as_ref()
    }

    fn is_compressible(content_type: &str) -> bool {
        matches!(
            content_type,
            "text/html"
                | "text/css"
                | "text/plain; charset=utf-8"
                | "application/javascript"
                | "application/json"
                | "application/xml"
                | "image/svg+xml"
        )
    }

    fn gzip_compress(data: &[u8]) -> Option<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).ok()?;
        encoder.finish().ok()
    }

    fn cache_control(filename: &str) -> Option<&'static str> {
        match Path::new(filename).extension().and_then(|ext| ext.to_str()) {
            Some(
                "css" | "js" | "png" | "jpg" | "jpeg" | "webp" | "ico" | "svg" | "woff" | "woff2",
            ) => Some("public, max-age=300, must-revalidate"),
            Some("html") => Some("public, max-age=300, must-revalidate"),
            _ => None,
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
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
            Some("asc" | "txt") => "text/plain; charset=utf-8",
            Some("xml") => "application/xml",
            _ => "application/octet-stream",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    /// Build a static dir from (relative path, contents) pairs.
    fn static_dir(files: &[(&str, &[u8])]) -> TempDir {
        let dir = TempDir::new().unwrap();
        for (rel, contents) in files {
            let path = dir.path().join(rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&path, contents).unwrap();
        }
        dir
    }

    fn load(files: &[(&str, &[u8])]) -> (TempDir, FileCache) {
        let dir = static_dir(files);
        let cache = FileCache::load(dir.path().to_str().unwrap());
        (dir, cache)
    }

    fn gunzip(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(data)
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    #[test]
    fn missing_static_dir_yields_empty_cache() {
        let cache = FileCache::load("/nonexistent/jatai/static/dir");
        assert_eq!(cache.len(), 0);
        assert!(cache.get("/").is_none());
        assert!(cache.get_not_found().is_none());
    }

    #[test]
    fn serves_file_at_its_literal_path() {
        let (_dir, cache) = load(&[("style.css", b"body{}")]);
        let entry = cache.get("/style.css").unwrap();
        assert_eq!(&*entry.body, b"body{}");
        assert_eq!(entry.content_type, "text/css");
    }

    #[test]
    fn root_index_maps_to_slash() {
        let (_dir, cache) = load(&[("index.html", b"<h1>home</h1>")]);
        assert_eq!(&*cache.get("/").unwrap().body, b"<h1>home</h1>");
        assert_eq!(&*cache.get("/index.html").unwrap().body, b"<h1>home</h1>");
    }

    #[test]
    fn nested_index_maps_to_dir_with_and_without_trailing_slash() {
        let (_dir, cache) = load(&[("blog/index.html", b"posts")]);
        for path in ["/blog", "/blog/", "/blog/index.html"] {
            assert_eq!(&*cache.get(path).unwrap().body, b"posts", "path {}", path);
        }
    }

    #[test]
    fn html_files_are_also_served_without_extension() {
        let (_dir, cache) = load(&[("about.html", b"about")]);
        assert_eq!(&*cache.get("/about").unwrap().body, b"about");
        assert_eq!(&*cache.get("/about.html").unwrap().body, b"about");
    }

    #[test]
    fn nested_html_keeps_its_directory_prefix() {
        let (_dir, cache) = load(&[("blog/post.html", b"post")]);
        assert_eq!(&*cache.get("/blog/post").unwrap().body, b"post");
        assert!(cache.get("/post").is_none());
    }

    #[test]
    fn unknown_paths_are_absent() {
        let (_dir, cache) = load(&[("index.html", b"home")]);
        assert!(cache.get("/missing").is_none());
        assert!(cache.get("").is_none());
    }

    #[test]
    fn lookup_is_case_sensitive() {
        let (_dir, cache) = load(&[("About.html", b"about")]);
        assert!(cache.get("/About").is_some());
        assert!(cache.get("/about").is_none());
    }

    #[test]
    fn not_found_page_is_loaded_separately() {
        let (_dir, cache) = load(&[("404.html", b"missing")]);
        assert_eq!(&*cache.get_not_found().unwrap().body, b"missing");
    }

    #[test]
    fn not_found_page_is_absent_when_file_is_missing() {
        let (_dir, cache) = load(&[("index.html", b"home")]);
        assert!(cache.get_not_found().is_none());
    }

    #[test]
    fn text_files_are_gzipped_and_round_trip() {
        let body = "hello ".repeat(200);
        let (_dir, cache) = load(&[("index.html", body.as_bytes())]);
        let entry = cache.get("/").unwrap();
        let gz = entry.body_gzip.as_ref().expect("html should be gzipped");
        assert_eq!(gunzip(gz), body.as_bytes());
        assert!(
            gz.len() < entry.body.len(),
            "compression should shrink text"
        );
    }

    #[test]
    fn binary_files_are_not_gzipped() {
        let (_dir, cache) = load(&[("logo.png", &[0x89, b'P', b'N', b'G'])]);
        assert!(cache.get("/logo.png").unwrap().body_gzip.is_none());
    }

    #[test]
    fn assets_and_html_carry_cache_control_but_unknown_types_do_not() {
        let (_dir, cache) = load(&[
            ("index.html", b"home"),
            ("app.js", b"1"),
            ("data.bin", b"\x00"),
        ]);
        let expected = Some("public, max-age=300, must-revalidate");
        assert_eq!(cache.get("/").unwrap().cache_control, expected);
        assert_eq!(cache.get("/app.js").unwrap().cache_control, expected);
        assert_eq!(cache.get("/data.bin").unwrap().cache_control, None);
    }

    #[test]
    fn symlinks_pointing_outside_the_static_dir_are_skipped() {
        let outside = TempDir::new().unwrap();
        let secret = outside.path().join("secret.txt");
        fs::write(&secret, b"top secret").unwrap();

        let dir = static_dir(&[("index.html", b"home")]);
        #[cfg(unix)]
        std::os::unix::fs::symlink(&secret, dir.path().join("leak.txt")).unwrap();

        let cache = FileCache::load(dir.path().to_str().unwrap());
        assert!(cache.get("/leak.txt").is_none());
        assert!(cache.get("/").is_some());
    }

    #[test]
    fn broken_symlinks_are_skipped_without_failing_the_load() {
        let dir = static_dir(&[("index.html", b"home")]);
        #[cfg(unix)]
        std::os::unix::fs::symlink("/nonexistent/target", dir.path().join("dangling.html"))
            .unwrap();

        let cache = FileCache::load(dir.path().to_str().unwrap());
        assert!(cache.get("/dangling.html").is_none());
        assert!(cache.get("/").is_some());
    }

    #[test]
    fn content_type_covers_every_known_extension() {
        let cases = [
            ("a.html", "text/html"),
            ("a.css", "text/css"),
            ("a.js", "application/javascript"),
            ("a.json", "application/json"),
            ("a.svg", "image/svg+xml"),
            ("a.png", "image/png"),
            ("a.jpg", "image/jpeg"),
            ("a.jpeg", "image/jpeg"),
            ("a.webp", "image/webp"),
            ("a.ico", "image/x-icon"),
            ("a.woff", "font/woff"),
            ("a.woff2", "font/woff2"),
            ("a.txt", "text/plain; charset=utf-8"),
            ("a.asc", "text/plain; charset=utf-8"),
            ("a.xml", "application/xml"),
            ("a.bin", "application/octet-stream"),
            ("noextension", "application/octet-stream"),
        ];
        for (name, expected) in cases {
            assert_eq!(FileCache::content_type(name), expected, "for {}", name);
        }
    }

    #[test]
    fn compressible_types_are_exactly_the_text_like_ones() {
        for ct in [
            "text/html",
            "text/css",
            "text/plain; charset=utf-8",
            "application/javascript",
            "application/json",
            "application/xml",
            "image/svg+xml",
        ] {
            assert!(FileCache::is_compressible(ct), "{} should compress", ct);
        }
        for ct in ["image/png", "font/woff2", "application/octet-stream"] {
            assert!(!FileCache::is_compressible(ct), "{} should not", ct);
        }
    }
}
