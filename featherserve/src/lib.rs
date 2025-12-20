use std::{
    fs::{self, File},
    io::{self, prelude::*, BufReader},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::Arc,
    thread,
};

use pool::ThreadPool;
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};

struct Listener {
    tcp: TcpListener,
    tls_config: Option<Arc<ServerConfig>>,
}

pub struct Featherserve {
    listeners: Vec<Listener>,
    pool: Arc<ThreadPool>,
    static_dir: String,
}

impl Default for Featherserve {
    fn default() -> Self {
        Self::new()
    }
}

impl Featherserve {
    pub fn new() -> Self {
        let num_threads = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        Self {
            listeners: Vec::new(),
            pool: Arc::new(ThreadPool::new(num_threads)),
            static_dir: "pages".to_string(),
        }
    }

    pub fn with_threads(mut self, num_threads: usize) -> Self {
        self.pool = Arc::new(ThreadPool::new(num_threads));
        self
    }

    pub fn with_static_dir(mut self, dir: impl Into<String>) -> Self {
        self.static_dir = dir.into();
        self
    }

    pub fn bind_http(mut self, addr: &str) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        self.listeners.push(Listener {
            tcp: listener,
            tls_config: None,
        });
        Ok(self)
    }

    pub fn bind_https(mut self, addr: &str, cert_path: &str, key_path: &str) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        let config = Self::load_tls_config(cert_path, key_path)?;
        self.listeners.push(Listener {
            tcp: listener,
            tls_config: Some(Arc::new(config)),
        });
        Ok(self)
    }

    fn load_tls_config(cert_path: &str, key_path: &str) -> io::Result<ServerConfig> {
        let cert_file = File::open(cert_path)?;
        let key_file = File::open(key_path)?;

        let certs: Vec<_> = certs(&mut BufReader::new(cert_file)).collect::<Result<Vec<_>, _>>()?;

        let key = private_key(&mut BufReader::new(key_file))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "No private key found"))?;

        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    pub fn run(self) {
        if self.listeners.is_empty() {
            eprintln!("No listeners configured. Use bind_http() or bind_https() to add listeners.");
            return;
        }

        for listener in &self.listeners {
            let protocol = if listener.tls_config.is_some() {
                "https"
            } else {
                "http"
            };
            println!(
                "Featherserve listening on {}://{}",
                protocol,
                listener.tcp.local_addr().unwrap()
            );
        }

        let static_dir = Arc::new(self.static_dir);
        let mut handles = Vec::new();

        for listener in self.listeners {
            let pool = Arc::clone(&self.pool);
            let static_dir = Arc::clone(&static_dir);

            let handle = thread::spawn(move || {
                for stream in listener.tcp.incoming() {
                    match stream {
                        Ok(stream) => {
                            let static_dir = Arc::clone(&static_dir);
                            let tls_config = listener.tls_config.clone();
                            pool.execute(move || {
                                if let Some(config) = tls_config {
                                    Self::handle_tls_connection(stream, &static_dir, config);
                                } else {
                                    Self::handle_connection(stream, &static_dir);
                                }
                            });
                        }
                        Err(e) => eprintln!("Connection failed: {}", e),
                    }
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.join();
        }
    }

    fn handle_tls_connection(stream: TcpStream, static_dir: &str, config: Arc<ServerConfig>) {
        let mut conn = match rustls::ServerConnection::new(config) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("TLS connection error: {}", e);
                return;
            }
        };

        let mut stream = stream;
        let mut tls_stream = rustls::Stream::new(&mut conn, &mut stream);
        Self::handle_stream(&mut tls_stream, static_dir);
    }

    fn handle_connection(stream: TcpStream, static_dir: &str) {
        let mut stream = stream;
        Self::handle_stream(&mut stream, static_dir);
    }

    fn handle_stream<S: Read + Write>(stream: &mut S, static_dir: &str) {
        let mut buf_reader = BufReader::new(Read::by_ref(stream));
        let mut request_line = String::new();
        if buf_reader.read_line(&mut request_line).is_err() {
            return;
        }

        let (_method, path, _protocol) = Self::parse_request_line(&request_line);

        println!("Request: {}", path);

        let file_path = Self::resolve_path(path, static_dir);

        let (status_line, file_path) = if Path::new(&file_path).exists() {
            ("HTTP/1.1 200 OK", file_path)
        } else {
            ("HTTP/1.1 404 NOT FOUND", format!("{}/404.html", static_dir))
        };

        let contents = match fs::read(&file_path) {
            Ok(c) => c,
            Err(_) => b"Not Found".to_vec(),
        };

        let content_type = Self::get_content_type(&file_path);
        let length = contents.len();

        let response = format!(
            "{status_line}\r\nContent-Length: {length}\r\nContent-Type: {content_type}\r\n\r\n"
        );

        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(&contents);
    }

    fn resolve_path(path: &str, static_dir: &str) -> String {
        if path == "/" {
            format!("{}/index.html", static_dir)
        } else if !path.contains('.') {
            let index_path = format!("{}{}/index.html", static_dir, path);
            let html_path = format!("{}{}.html", static_dir, path);

            if Path::new(&index_path).exists() {
                index_path
            } else {
                html_path
            }
        } else {
            format!("{}{}", static_dir, path)
        }
    }

    fn parse_request_line(request_line: &str) -> (&str, &str, &str) {
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("/");
        let protocol = parts.next().unwrap_or("");
        (method, path, protocol)
    }

    fn get_content_type(filename: &str) -> &'static str {
        match Path::new(filename).extension().and_then(|ext| ext.to_str()) {
            Some("html") => "text/html",
            Some("css") => "text/css",
            Some("js") => "application/javascript",
            Some("json") => "application/json",
            Some("svg") => "image/svg+xml",
            Some("png") => "image/png",
            Some("jpg") | Some("jpeg") => "image/jpeg",
            Some("webp") => "image/webp",
            Some("ico") => "image/x-icon",
            Some("woff") => "font/woff",
            Some("woff2") => "font/woff2",
            Some("asc") => "text/plain; charset=utf-8",
            _ => "application/octet-stream",
        }
    }
}
