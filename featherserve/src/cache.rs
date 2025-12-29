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
            Some("html") => Some("no-cache, must-revalidate"),
            _ => None,
        }
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
