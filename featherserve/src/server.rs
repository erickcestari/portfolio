use std::{env, io, sync::Arc};

use bytes::Bytes;
use h2::server;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsAcceptor;

use crate::{cache::FileCache, handler::StaticFileHandler, Request};

const READ_TIMEOUT: Duration = Duration::from_secs(30);
const H1_MAX_HEADER_SIZE: usize = 8192;

const SECURITY_HEADERS: &str = "\
X-Content-Type-Options: nosniff\r\n\
X-Frame-Options: DENY\r\n\
Referrer-Policy: strict-origin-when-cross-origin\r\n";

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
            "h2 (TLS)"
        } else {
            "http/1.1"
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
            let config = crate::tls::load_config(&cert_path, &key_path)?;
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
            match timeout(READ_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(tls_stream)) => Self::serve_h2(tls_stream, cache).await,
                _ => {}
            }
        } else {
            Self::serve_h1(stream, cache).await;
        }
    }

    async fn read_h1_headers<S: AsyncReadExt + Unpin>(stream: &mut S) -> Option<Vec<u8>> {
        let mut buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 1024];

        loop {
            let n = match timeout(READ_TIMEOUT, stream.read(&mut tmp)).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => return if buf.is_empty() { None } else { Some(buf) },
            };

            let prev_len = buf.len();
            buf.extend_from_slice(&tmp[..n]);

            if buf.len() > H1_MAX_HEADER_SIZE {
                return None;
            }

            // Only search newly added bytes plus overlap for boundary matches
            let search_start = prev_len.saturating_sub(3);
            if buf[search_start..].windows(4).any(|w| w == b"\r\n\r\n") {
                return Some(buf);
            }
        }
    }

    async fn serve_h1<S>(mut stream: S, cache: Arc<FileCache>)
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let buf = match Self::read_h1_headers(&mut stream).await {
            Some(b) => b,
            None => return,
        };

        let request_str = match std::str::from_utf8(&buf) {
            Ok(s) => s,
            Err(_) => return,
        };

        let Some(request) = Request::parse_h1(request_str) else {
            return;
        };

        let handler = StaticFileHandler::new(Arc::clone(&cache));
        let response = handler.handle(&request);

        let encoding_header = if response.gzip {
            "Content-Encoding: gzip\r\n"
        } else {
            ""
        };

        let cache_header = response
            .cache_control
            .map(|cc| format!("Cache-Control: {}\r\n", cc))
            .unwrap_or_default();

        let status_text = match response.status {
            200 => "200 OK",
            404 => "404 NOT FOUND",
            _ => "200 OK",
        };

        let header = format!(
            "HTTP/1.1 {}\r\nContent-Length: {}\r\nContent-Type: {}\r\n{}{}{}\r\n",
            status_text,
            response.body.len(),
            response.content_type,
            encoding_header,
            cache_header,
            SECURITY_HEADERS,
        );

        let _ = stream.write_all(header.as_bytes()).await;
        let _ = stream.write_all(&response.body).await;
    }

    async fn serve_h2<S>(io: S, cache: Arc<FileCache>)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut connection = match server::handshake(io).await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("H2 handshake error: {}", e);
                return;
            }
        };

        while let Some(result) = connection.accept().await {
            let (request, respond) = match result {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("H2 error: {}", e);
                    return;
                }
            };

            let cache = Arc::clone(&cache);
            tokio::spawn(async move {
                Self::handle_request(request, respond, cache);
            });
        }
    }

    fn handle_request(
        request: http::Request<h2::RecvStream>,
        mut respond: server::SendResponse<Bytes>,
        cache: Arc<FileCache>,
    ) {
        let req = Request::from_h2(&request);
        let handler = StaticFileHandler::new(cache);
        let response = handler.handle(&req);

        let mut builder = http::Response::builder().status(response.status);

        builder = builder.header("content-type", response.content_type);
        builder = builder.header("x-content-type-options", "nosniff");
        builder = builder.header("x-frame-options", "DENY");
        builder = builder.header("referrer-policy", "strict-origin-when-cross-origin");

        if response.gzip {
            builder = builder.header("content-encoding", "gzip");
        }

        if let Some(cc) = response.cache_control {
            builder = builder.header("cache-control", cc);
        }

        let end_of_stream = response.body.is_empty();
        let h2_response = builder.body(()).unwrap();

        let mut send = match respond.send_response(h2_response, end_of_stream) {
            Ok(s) => s,
            Err(_) => return,
        };

        if !end_of_stream {
            let _ = send.send_data(Bytes::from(response.body), true);
        }
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
