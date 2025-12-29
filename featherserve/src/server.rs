use std::{
    env,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::Duration,
};

use pool::ThreadPool;
use rustls::ServerConfig;

use crate::{cache::FileCache, handler::StaticFileHandler, tls, Request};

const TCP_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Config {
    static_dir: String,
    http_bind: String,
    threads: Option<usize>,
    https: Option<HttpsConfig>,
}

struct HttpsConfig {
    bind: String,
    cert_path: String,
    key_path: String,
}

impl Config {
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();
        Self {
            static_dir: env_var("STATIC_DIR"),
            http_bind: env_var("HTTP_BIND"),
            threads: env::var("THREADS").ok().and_then(|t| t.parse().ok()),
            https: Self::parse_https_config(),
        }
    }

    fn parse_https_config() -> Option<HttpsConfig> {
        let enable_https = env::var("ENABLE_HTTPS")
            .ok()
            .and_then(|v| v.parse::<bool>().ok())
            .unwrap_or(false);

        if enable_https {
            Some(HttpsConfig {
                bind: env_var("HTTPS_BIND"),
                cert_path: env_var("CERT_PATH"),
                key_path: env_var("KEY_PATH"),
            })
        } else {
            None
        }
    }
}

fn env_var(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| panic!("{} environment variable not set", key))
}

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

impl From<Config> for Featherserve {
    fn from(config: Config) -> Self {
        let mut server = Featherserve::new()
            .with_static_dir(&config.static_dir)
            .bind_http(&config.http_bind)
            .expect("Failed to bind HTTP");

        if let Some(threads) = config.threads {
            server = server.with_threads(threads);
        }

        if let Some(https) = config.https {
            server = server
                .bind_https(&https.bind, &https.cert_path, &https.key_path)
                .expect("Failed to bind HTTPS");
        }

        server
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

        // Load all static files into memory cache at startup
        let cache = Arc::new(FileCache::load(&self.static_dir));

        for listener in &self.listeners {
            println!(
                "Featherserve listening on {}://{}",
                listener.protocol(),
                listener.tcp.local_addr().unwrap()
            );
        }

        let handles: Vec<_> = self
            .listeners
            .into_iter()
            .map(|listener| {
                let pool = Arc::clone(&self.pool);
                let cache = Arc::clone(&cache);
                thread::spawn(move || Self::accept_loop(listener, pool, cache))
            })
            .collect();

        for handle in handles {
            let _ = handle.join();
        }
    }

    fn accept_loop(listener: Listener, pool: Arc<ThreadPool>, cache: Arc<FileCache>) {
        for stream in listener.tcp.incoming() {
            match stream {
                Ok(stream) => {
                    let cache = Arc::clone(&cache);
                    let tls_config = listener.tls_config.clone();
                    pool.execute(move || Self::handle_connection(stream, tls_config, cache));
                }
                Err(e) => eprintln!("Connection failed: {}", e),
            }
        }
    }

    fn handle_connection(
        mut stream: TcpStream,
        tls_config: Option<Arc<ServerConfig>>,
        cache: Arc<FileCache>,
    ) {
        let _ = stream.set_read_timeout(Some(TCP_TIMEOUT));
        let _ = stream.set_write_timeout(Some(TCP_TIMEOUT));
        let _ = stream.set_nodelay(true);

        if let Some(config) = tls_config {
            let Ok(mut conn) = rustls::ServerConnection::new(config) else {
                return;
            };
            let mut tls_stream = rustls::Stream::new(&mut conn, &mut stream);
            Self::handle_stream(&mut tls_stream, &cache);
        } else {
            Self::handle_stream(&mut stream, &cache);
        }
    }

    fn handle_stream<S: Read + Write>(stream: &mut S, cache: &Arc<FileCache>) {
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

        let handler = StaticFileHandler::new(Arc::clone(cache));
        let response = handler.handle(&request);
        let _ = response.write_to(stream);
    }
}
