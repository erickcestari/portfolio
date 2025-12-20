use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    thread,
};

use pool::ThreadPool;
use rustls::ServerConfig;

use crate::{handler::StaticFileHandler, tls, Request};

struct Listener {
    tcp: TcpListener,
    tls_config: Option<Arc<ServerConfig>>,
}

impl Listener {
    fn protocol(&self) -> &'static str {
        if self.tls_config.is_some() {
            "https"
        } else {
            "http"
        }
    }
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
        self.listeners.push(Listener {
            tcp: TcpListener::bind(addr)?,
            tls_config: None,
        });
        Ok(self)
    }

    pub fn bind_https(mut self, addr: &str, cert_path: &str, key_path: &str) -> io::Result<Self> {
        self.listeners.push(Listener {
            tcp: TcpListener::bind(addr)?,
            tls_config: Some(Arc::new(tls::load_config(cert_path, key_path)?)),
        });
        Ok(self)
    }

    pub fn run(self) {
        if self.listeners.is_empty() {
            eprintln!("No listeners configured. Use bind_http() or bind_https() to add listeners.");
            return;
        }

        for listener in &self.listeners {
            println!(
                "Featherserve listening on {}://{}",
                listener.protocol(),
                listener.tcp.local_addr().unwrap()
            );
        }

        let static_dir: Arc<str> = self.static_dir.into();
        let handles: Vec<_> = self
            .listeners
            .into_iter()
            .map(|listener| {
                let pool = Arc::clone(&self.pool);
                let static_dir = Arc::clone(&static_dir);
                thread::spawn(move || Self::accept_loop(listener, pool, static_dir))
            })
            .collect();

        for handle in handles {
            let _ = handle.join();
        }
    }

    fn accept_loop(listener: Listener, pool: Arc<ThreadPool>, static_dir: Arc<str>) {
        for stream in listener.tcp.incoming() {
            match stream {
                Ok(stream) => {
                    let static_dir = Arc::clone(&static_dir);
                    let tls_config = listener.tls_config.clone();
                    pool.execute(move || Self::handle_connection(stream, tls_config, &static_dir));
                }
                Err(e) => eprintln!("Connection failed: {}", e),
            }
        }
    }

    fn handle_connection(
        mut stream: TcpStream,
        tls_config: Option<Arc<ServerConfig>>,
        static_dir: &str,
    ) {
        if let Some(config) = tls_config {
            let Ok(mut conn) = rustls::ServerConnection::new(config) else {
                return;
            };
            let mut tls_stream = rustls::Stream::new(&mut conn, &mut stream);
            Self::handle_stream(&mut tls_stream, static_dir);
        } else {
            Self::handle_stream(&mut stream, static_dir);
        }
    }

    fn handle_stream<S: Read + Write>(stream: &mut S, static_dir: &str) {
        let mut buf = [0u8; 4096];
        let n = match stream.read(&mut buf) {
            Ok(n) if n > 0 => n,
            _ => return,
        };

        let request_str = match std::str::from_utf8(&buf[..n]) {
            Ok(s) => s,
            Err(_) => return,
        };

        let Some(request) = Request::parse(request_str) else {
            return;
        };

        let handler = StaticFileHandler::new(static_dir);
        let response = handler.handle(&request);
        let _ = response.write_to(stream);
    }
}
