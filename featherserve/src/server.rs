use std::{env, io, sync::Arc};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::{cache::FileCache, handler::StaticFileHandler, tls, Request};

pub struct Config {
    static_dir: String,
    http_bind: String,
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
    tls_acceptor: Option<TlsAcceptor>,
}

impl Listener {
    fn protocol(&self) -> &'static str {
        if self.tls_acceptor.is_some() {
            "https"
        } else {
            "http"
        }
    }
}

pub struct Featherserve {
    listeners: Vec<Listener>,
    static_dir: String,
}

pub struct FeatherserveBuilder {
    static_dir: String,
    http_bind: Option<String>,
    https: Option<(String, String, String)>, // (bind, cert_path, key_path)
}

impl FeatherserveBuilder {
    pub fn new() -> Self {
        Self {
            static_dir: "pages".to_string(),
            http_bind: None,
            https: None,
        }
    }

    pub fn with_static_dir(mut self, dir: impl Into<String>) -> Self {
        self.static_dir = dir.into();
        self
    }

    pub fn bind_http(mut self, addr: impl Into<String>) -> Self {
        self.http_bind = Some(addr.into());
        self
    }

    pub fn bind_https(
        mut self,
        addr: impl Into<String>,
        cert_path: impl Into<String>,
        key_path: impl Into<String>,
    ) -> Self {
        self.https = Some((addr.into(), cert_path.into(), key_path.into()));
        self
    }

    pub async fn build(self) -> io::Result<Featherserve> {
        let mut listeners = Vec::new();

        if let Some(addr) = self.http_bind {
            listeners.push(Listener {
                tcp: TcpListener::bind(&addr).await?,
                tls_acceptor: None,
            });
        }

        if let Some((addr, cert_path, key_path)) = self.https {
            let config = tls::load_config(&cert_path, &key_path)?;
            listeners.push(Listener {
                tcp: TcpListener::bind(&addr).await?,
                tls_acceptor: Some(TlsAcceptor::from(Arc::new(config))),
            });
        }

        Ok(Featherserve {
            listeners,
            static_dir: self.static_dir,
        })
    }
}

impl Default for FeatherserveBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Featherserve {
    pub fn new() -> FeatherserveBuilder {
        FeatherserveBuilder::new()
    }

    pub fn with_static_dir(self, dir: impl Into<String>) -> FeatherserveBuilder {
        FeatherserveBuilder::new().with_static_dir(dir)
    }

    pub async fn run(self) {
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

        let mut handles = Vec::new();

        for listener in self.listeners {
            let cache = Arc::clone(&cache);
            handles.push(tokio::spawn(async move {
                Self::accept_loop(listener, cache).await;
            }));
        }

        for handle in handles {
            let _ = handle.await;
        }
    }

    async fn accept_loop(listener: Listener, cache: Arc<FileCache>) {
        loop {
            match listener.tcp.accept().await {
                Ok((stream, _)) => {
                    let cache = Arc::clone(&cache);
                    let tls_acceptor = listener.tls_acceptor.clone();
                    tokio::spawn(async move {
                        Self::handle_connection(stream, tls_acceptor, cache).await;
                    });
                }
                Err(e) => eprintln!("Connection failed: {}", e),
            }
        }
    }

    async fn handle_connection(
        stream: TcpStream,
        tls_acceptor: Option<TlsAcceptor>,
        cache: Arc<FileCache>,
    ) {
        let _ = stream.set_nodelay(true);

        if let Some(acceptor) = tls_acceptor {
            match acceptor.accept(stream).await {
                Ok(mut tls_stream) => {
                    Self::handle_stream(&mut tls_stream, &cache).await;
                }
                Err(_) => return,
            }
        } else {
            let mut stream = stream;
            Self::handle_stream(&mut stream, &cache).await;
        }
    }

    async fn handle_stream<S>(stream: &mut S, cache: &Arc<FileCache>)
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let mut buf = [0u8; 4096];
        let n = match stream.read(&mut buf).await {
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
        let _ = response.write_to(stream).await;
    }
}

impl From<Config> for FeatherserveBuilder {
    fn from(config: Config) -> Self {
        let mut builder = FeatherserveBuilder::new().with_static_dir(&config.static_dir);
        builder = builder.bind_http(&config.http_bind);

        if let Some(https) = config.https {
            builder = builder.bind_https(&https.bind, &https.cert_path, &https.key_path);
        }

        builder
    }
}
