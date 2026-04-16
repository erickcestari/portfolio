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
    enable_h3: bool,
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
            let enable_h3 = env::var("ENABLE_H3")
                .ok()
                .and_then(|v| v.parse::<bool>().ok())
                .unwrap_or(false);

            Some(HttpsConfig {
                bind: env_var("HTTPS_BIND"),
                cert_path: env_var("CERT_PATH"),
                key_path: env_var("KEY_PATH"),
                enable_h3,
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
            "h2"
        } else {
            "http"
        }
    }
}

pub struct Featherserve {
    listeners: Vec<Listener>,
    quic_endpoint: Option<quinn::Endpoint>,
    h3_port: Option<u16>,
    static_dir: String,
}

pub struct FeatherserveBuilder {
    static_dir: String,
    http_bind: Option<String>,
    https: Option<(String, String, String)>, // (bind, cert_path, key_path)
    enable_h3: bool,
}

impl FeatherserveBuilder {
    pub fn new() -> Self {
        Self {
            static_dir: "pages".to_string(),
            http_bind: None,
            https: None,
            enable_h3: false,
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

    pub fn enable_h3(mut self) -> Self {
        self.enable_h3 = true;
        self
    }

    pub async fn build(self) -> io::Result<Featherserve> {
        let mut listeners = Vec::new();
        let mut quic_endpoint = None;
        let mut h3_port = None;

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

            if self.enable_h3 {
                let quic_config = crate::tls::load_quic_config(&cert_path, &key_path)?;
                let socket_addr: std::net::SocketAddr =
                    addr.parse().map_err(|e: std::net::AddrParseError| {
                        io::Error::new(io::ErrorKind::InvalidInput, e)
                    })?;
                h3_port = Some(socket_addr.port());
                quic_endpoint = Some(quinn::Endpoint::server(quic_config, socket_addr)?);
            }
        }

        Ok(Featherserve {
            listeners,
            quic_endpoint,
            h3_port,
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
    pub fn builder() -> FeatherserveBuilder {
        FeatherserveBuilder::new()
    }

    pub fn with_static_dir(self, dir: impl Into<String>) -> FeatherserveBuilder {
        FeatherserveBuilder::new().with_static_dir(dir)
    }

    pub async fn run(self) {
        if self.listeners.is_empty() && self.quic_endpoint.is_none() {
            eprintln!("No listeners configured.");
            return;
        }

        let cache = Arc::new(FileCache::load(&self.static_dir));

        let alt_svc: Option<Arc<str>> = self
            .h3_port
            .map(|port| Arc::from(format!("h3=\":{}\"; ma=86400", port)));

        for listener in &self.listeners {
            println!(
                "Featherserve listening on {}://{}",
                listener.protocol(),
                listener.tcp.local_addr().unwrap()
            );
        }

        if let Some(ref endpoint) = self.quic_endpoint {
            println!(
                "Featherserve listening on h3://{}",
                endpoint.local_addr().unwrap()
            );
        }

        let mut handles = Vec::new();

        for listener in self.listeners {
            let cache = Arc::clone(&cache);
            let alt_svc = alt_svc.clone();
            handles.push(tokio::spawn(async move {
                Self::accept_loop(listener, cache, alt_svc).await;
            }));
        }

        if let Some(endpoint) = self.quic_endpoint {
            let cache = Arc::clone(&cache);
            handles.push(tokio::spawn(async move {
                Self::accept_quic(endpoint, cache).await;
            }));
        }

        for handle in handles {
            let _ = handle.await;
        }
    }

    async fn accept_loop(listener: Listener, cache: Arc<FileCache>, alt_svc: Option<Arc<str>>) {
        loop {
            match listener.tcp.accept().await {
                Ok((stream, _)) => {
                    let cache = Arc::clone(&cache);
                    let tls_acceptor = listener.tls_acceptor.clone();
                    let alt_svc = alt_svc.clone();
                    tokio::spawn(async move {
                        Self::handle_connection(stream, tls_acceptor, cache, alt_svc).await;
                    });
                }
                Err(e) => eprintln!("Connection failed: {}", e),
            }
        }
    }

    async fn accept_quic(endpoint: quinn::Endpoint, cache: Arc<FileCache>) {
        while let Some(incoming) = endpoint.accept().await {
            let cache = Arc::clone(&cache);
            tokio::spawn(async move {
                let connection = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("QUIC error: {}", e);
                        return;
                    }
                };
                Self::serve_h3(connection, cache).await;
            });
        }
    }

    async fn handle_connection(
        stream: TcpStream,
        tls_acceptor: Option<TlsAcceptor>,
        cache: Arc<FileCache>,
        alt_svc: Option<Arc<str>>,
    ) {
        let _ = stream.set_nodelay(true);

        if let Some(acceptor) = tls_acceptor {
            if let Ok(Ok(tls_stream)) = timeout(READ_TIMEOUT, acceptor.accept(stream)).await {
                Self::serve_h2(tls_stream, cache, alt_svc).await;
            }
        } else {
            Self::serve_h1(stream, cache, alt_svc).await;
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

    async fn serve_h1<S>(mut stream: S, cache: Arc<FileCache>, alt_svc: Option<Arc<str>>)
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

        let alt_svc_header = alt_svc
            .as_deref()
            .map(|v| format!("Alt-Svc: {}\r\n", v))
            .unwrap_or_default();

        let status_text = match response.status {
            200 => "200 OK",
            404 => "404 NOT FOUND",
            _ => "200 OK",
        };

        let header = format!(
            "HTTP/1.1 {}\r\nContent-Length: {}\r\nContent-Type: {}\r\n{}{}{}{}\r\n",
            status_text,
            response.body.len(),
            response.content_type,
            encoding_header,
            cache_header,
            alt_svc_header,
            SECURITY_HEADERS,
        );

        let _ = stream.write_all(header.as_bytes()).await;
        let _ = stream.write_all(&response.body).await;
    }

    async fn serve_h2<S>(io: S, cache: Arc<FileCache>, alt_svc: Option<Arc<str>>)
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
            let alt_svc = alt_svc.clone();
            tokio::spawn(async move {
                Self::handle_h2_request(request, respond, cache, alt_svc);
            });
        }
    }

    fn handle_h2_request(
        request: http::Request<h2::RecvStream>,
        mut respond: server::SendResponse<Bytes>,
        cache: Arc<FileCache>,
        alt_svc: Option<Arc<str>>,
    ) {
        let req = Request::from_h2(&request);
        let handler = StaticFileHandler::new(cache);
        let response = handler.handle(&req);

        let mut builder = http::Response::builder().status(response.status);

        builder = builder.header("content-type", response.content_type);
        builder = builder.header("content-length", response.body.len());
        builder = builder.header("x-content-type-options", "nosniff");
        builder = builder.header("x-frame-options", "DENY");
        builder = builder.header("referrer-policy", "strict-origin-when-cross-origin");

        if let Some(ref alt_svc) = alt_svc {
            builder = builder.header("alt-svc", alt_svc.as_ref());
        }

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

    async fn serve_h3(conn: quinn::Connection, cache: Arc<FileCache>) {
        let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
            match h3::server::Connection::new(h3_quinn::Connection::new(conn)).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("H3 connection error: {}", e);
                    return;
                }
            };

        loop {
            match h3_conn.accept().await {
                Ok(Some(resolver)) => {
                    let cache = Arc::clone(&cache);
                    tokio::spawn(async move {
                        match resolver.resolve_request().await {
                            Ok((req, stream)) => {
                                Self::handle_h3_request(req, stream, cache).await;
                            }
                            Err(e) => eprintln!("H3 request error: {}", e),
                        }
                    });
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
    }

    async fn handle_h3_request(
        request: http::Request<()>,
        mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
        cache: Arc<FileCache>,
    ) {
        let req = Request::from_h2(&request);
        let handler = StaticFileHandler::new(cache);
        let response = handler.handle(&req);

        let mut builder = http::Response::builder().status(response.status);

        builder = builder.header("content-type", response.content_type);
        builder = builder.header("content-length", response.body.len());
        builder = builder.header("x-content-type-options", "nosniff");
        builder = builder.header("x-frame-options", "DENY");
        builder = builder.header("referrer-policy", "strict-origin-when-cross-origin");

        if response.gzip {
            builder = builder.header("content-encoding", "gzip");
        }

        if let Some(cc) = response.cache_control {
            builder = builder.header("cache-control", cc);
        }

        let h3_response = builder.body(()).unwrap();

        if stream.send_response(h3_response).await.is_err() {
            return;
        }

        if !response.body.is_empty() {
            let _ = stream.send_data(Bytes::from(response.body)).await;
        }

        let _ = stream.finish().await;
    }
}

impl From<Config> for FeatherserveBuilder {
    fn from(config: Config) -> Self {
        let mut builder = FeatherserveBuilder::new().with_static_dir(&config.static_dir);
        builder = builder.bind_http(&config.http_bind);

        if let Some(https) = config.https {
            builder = builder.bind_https(&https.bind, &https.cert_path, &https.key_path);
            if https.enable_h3 {
                builder = builder.enable_h3();
            }
        }

        builder
    }
}
