use std::{env, io, sync::Arc};

use bytes::Bytes;
use h2::server;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration, Instant};
use tokio_rustls::TlsAcceptor;

use crate::{cache::FileCache, handler::StaticFileHandler, Request};

const READ_TIMEOUT: Duration = Duration::from_secs(30);
// Total time budget to receive the complete request line and headers. Unlike a
// per-read timeout, this caps the whole header phase so a slowloris client that
// trickles bytes cannot hold the connection open indefinitely.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const H1_MAX_HEADER_SIZE: usize = 8192;

const SERVER_AGENT: &str = "jatai";

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

pub struct Jatai {
    listeners: Vec<Listener>,
    quic_endpoint: Option<quinn::Endpoint>,
    h3_port: Option<u16>,
    static_dir: String,
}

pub struct JataiBuilder {
    static_dir: String,
    http_bind: Option<String>,
    https: Option<(String, String, String)>, // (bind, cert_path, key_path)
    enable_h3: bool,
}

impl JataiBuilder {
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

    pub async fn build(self) -> io::Result<Jatai> {
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
                let endpoint = quinn::Endpoint::server(quic_config, socket_addr)?;
                // Read the port back from the endpoint instead of the requested
                // address, so an ephemeral bind (port 0) advertises the port the
                // OS actually assigned in Alt-Svc.
                h3_port = endpoint.local_addr().ok().map(|addr| addr.port());
                quic_endpoint = Some(endpoint);
            }
        }

        Ok(Jatai {
            listeners,
            quic_endpoint,
            h3_port,
            static_dir: self.static_dir,
        })
    }
}

impl Default for JataiBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Jatai {
    pub fn builder() -> JataiBuilder {
        JataiBuilder::new()
    }

    pub fn with_static_dir(self, dir: impl Into<String>) -> JataiBuilder {
        JataiBuilder::new().with_static_dir(dir)
    }

    /// Addresses the TCP listeners are bound to, in the order they were
    /// configured. Callers that bind an ephemeral port (`:0`) need this to
    /// learn the port the OS assigned.
    pub fn tcp_addrs(&self) -> Vec<std::net::SocketAddr> {
        self.listeners
            .iter()
            .filter_map(|l| l.tcp.local_addr().ok())
            .collect()
    }

    /// Address the QUIC endpoint is bound to, if HTTP/3 is enabled.
    pub fn quic_addr(&self) -> Option<std::net::SocketAddr> {
        self.quic_endpoint.as_ref()?.local_addr().ok()
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
                "Jatai listening on {}://{}",
                listener.protocol(),
                listener.tcp.local_addr().unwrap()
            );
        }

        if let Some(ref endpoint) = self.quic_endpoint {
            println!("Jatai listening on h3://{}", endpoint.local_addr().unwrap());
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
                // Dispatch on the ALPN protocol negotiated during the TLS
                // handshake. Clients that don't negotiate "h2" (e.g. plain
                // HTTP/1.1 fetchers) must be served over HTTP/1.1, otherwise
                // they receive HTTP/2 framing they can't parse.
                let is_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2");
                if is_h2 {
                    Self::serve_h2(tls_stream, cache, alt_svc).await;
                } else {
                    Self::serve_h1(tls_stream, cache, alt_svc).await;
                }
            }
        } else {
            Self::serve_h1(stream, cache, alt_svc).await;
        }
    }

    async fn read_h1_headers<S: AsyncReadExt + Unpin>(stream: &mut S) -> Option<Vec<u8>> {
        let mut buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 1024];
        let deadline = Instant::now() + HEADER_TIMEOUT;

        loop {
            // Bound each read by the remaining header budget rather than a
            // per-read timeout, so the total time to receive headers is capped.
            let remaining = match deadline.checked_duration_since(Instant::now()) {
                Some(d) if !d.is_zero() => d,
                _ => return None,
            };

            let n = match timeout(remaining, stream.read(&mut tmp)).await {
                Ok(Ok(n)) if n > 0 => n,
                // Budget exceeded or peer stalled/closed before headers were
                // complete: drop the connection instead of holding it open.
                _ => return None,
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
            "HTTP/1.1 {}\r\nServer: {}\r\nContent-Length: {}\r\nContent-Type: {}\r\n{}{}{}{}\r\n",
            status_text,
            SERVER_AGENT,
            response.body.len(),
            response.content_type,
            encoding_header,
            cache_header,
            alt_svc_header,
            SECURITY_HEADERS,
        );

        let _ = stream.write_all(header.as_bytes()).await;
        let _ = stream.write_all(&response.body).await;
        // Close the write half explicitly. Over TLS this emits close_notify;
        // without it strict clients report the response as truncated instead of
        // complete, even though every declared byte arrived.
        let _ = stream.shutdown().await;
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

        builder = builder.header("server", SERVER_AGENT);
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

        builder = builder.header("server", SERVER_AGENT);
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

impl From<Config> for JataiBuilder {
    fn from(config: Config) -> Self {
        let mut builder = JataiBuilder::new().with_static_dir(&config.static_dir);
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

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;
    use tokio::io::duplex;

    use super::*;

    fn cache_of(files: &[(&str, &[u8])]) -> (TempDir, Arc<FileCache>) {
        let dir = TempDir::new().unwrap();
        for (rel, contents) in files {
            fs::write(dir.path().join(rel), contents).unwrap();
        }
        let cache = FileCache::load(dir.path().to_str().unwrap());
        (dir, Arc::new(cache))
    }

    /// Feed `request` through `serve_h1` over an in-memory pipe and return the
    /// raw bytes the server wrote back.
    async fn h1_exchange(
        files: &[(&str, &[u8])],
        request: &str,
        alt_svc: Option<Arc<str>>,
    ) -> Vec<u8> {
        let (_dir, cache) = cache_of(files);
        let (mut client, server) = duplex(64 * 1024);

        let serving = tokio::spawn(Jatai::serve_h1(server, cache, alt_svc));

        client.write_all(request.as_bytes()).await.unwrap();
        serving.await.unwrap();

        let mut raw = Vec::new();
        client.read_to_end(&mut raw).await.unwrap();
        raw
    }

    fn split_response(raw: &[u8]) -> (String, Vec<u8>) {
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("response must terminate its header block");
        // Keep the CRLF that ends the last header line, so every header in the
        // returned block can be matched with its terminator.
        (
            String::from_utf8(raw[..split + 2].to_vec()).unwrap(),
            raw[split + 4..].to_vec(),
        )
    }

    #[tokio::test]
    async fn h1_serves_a_file_with_the_expected_status_line_and_headers() {
        let raw = h1_exchange(
            &[("index.html", b"<h1>home</h1>")],
            "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            None,
        )
        .await;
        let (head, body) = split_response(&raw);

        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(head.contains("Server: jatai\r\n"));
        assert!(head.contains("Content-Type: text/html\r\n"));
        assert!(head.contains("Content-Length: 13\r\n"));
        assert!(head.contains("X-Content-Type-Options: nosniff\r\n"));
        assert!(head.contains("X-Frame-Options: DENY\r\n"));
        assert!(head.contains("Referrer-Policy: strict-origin-when-cross-origin\r\n"));
        assert!(head.contains("Cache-Control: public, max-age=300, must-revalidate\r\n"));
        assert_eq!(body, b"<h1>home</h1>");
    }

    #[tokio::test]
    async fn h1_content_length_counts_the_bytes_actually_sent() {
        let body = "hello ".repeat(500);
        let raw = h1_exchange(
            &[("index.html", body.as_bytes())],
            "GET / HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n",
            None,
        )
        .await;
        let (head, sent) = split_response(&raw);

        assert!(head.contains("Content-Encoding: gzip\r\n"));
        let declared: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(declared, sent.len());
        assert!(sent.len() < body.len());
    }

    #[tokio::test]
    async fn h1_omits_content_encoding_when_the_client_does_not_accept_gzip() {
        let raw = h1_exchange(&[("index.html", b"home")], "GET / HTTP/1.1\r\n\r\n", None).await;
        let (head, body) = split_response(&raw);
        assert!(!head.contains("Content-Encoding"));
        assert_eq!(body, b"home");
    }

    #[tokio::test]
    async fn h1_answers_404_with_the_custom_page() {
        let raw = h1_exchange(
            &[("index.html", b"home"), ("404.html", b"nothing here")],
            "GET /missing HTTP/1.1\r\n\r\n",
            None,
        )
        .await;
        let (head, body) = split_response(&raw);
        assert!(head.starts_with("HTTP/1.1 404 NOT FOUND\r\n"));
        assert_eq!(body, b"nothing here");
    }

    #[tokio::test]
    async fn h1_advertises_alt_svc_when_h3_is_enabled() {
        let alt_svc: Arc<str> = Arc::from("h3=\":8443\"; ma=86400");
        let raw = h1_exchange(
            &[("index.html", b"home")],
            "GET / HTTP/1.1\r\n\r\n",
            Some(alt_svc),
        )
        .await;
        let (head, _) = split_response(&raw);
        assert!(head.contains("Alt-Svc: h3=\":8443\"; ma=86400\r\n"));
    }

    #[tokio::test]
    async fn h1_omits_alt_svc_when_h3_is_disabled() {
        let raw = h1_exchange(&[("index.html", b"home")], "GET / HTTP/1.1\r\n\r\n", None).await;
        let (head, _) = split_response(&raw);
        assert!(!head.contains("Alt-Svc"));
    }

    #[tokio::test]
    async fn h1_answers_attacks_with_bait_and_status_200() {
        let raw = h1_exchange(
            &[("index.html", b"home")],
            "GET /.env HTTP/1.1\r\n\r\n",
            None,
        )
        .await;
        let (head, body) = split_response(&raw);
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(head.contains("Content-Type: text/plain\r\n"));
        assert!(String::from_utf8_lossy(&body).contains("DATABASE_URL="));
    }

    #[tokio::test]
    async fn h1_closes_without_replying_to_a_malformed_request_line() {
        let raw = h1_exchange(&[("index.html", b"home")], "\r\n\r\n", None).await;
        assert!(raw.is_empty());
    }

    #[tokio::test]
    async fn h1_closes_without_replying_to_non_utf8_bytes() {
        let (_dir, cache) = cache_of(&[("index.html", b"home")]);
        let (mut client, server) = duplex(1024);

        let serving = tokio::spawn(Jatai::serve_h1(server, cache, None));
        client
            .write_all(b"GET /\xff\xfe HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        serving.await.unwrap();

        let mut raw = Vec::new();
        client.read_to_end(&mut raw).await.unwrap();
        assert!(raw.is_empty());
    }

    #[tokio::test]
    async fn headers_are_returned_once_the_blank_line_arrives() {
        let mut input = &b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"[..];
        let buf = Jatai::read_h1_headers(&mut input).await.unwrap();
        assert_eq!(buf, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    }

    #[tokio::test]
    async fn headers_split_across_reads_are_reassembled() {
        let (mut client, mut server) = duplex(64);
        tokio::spawn(async move {
            // The terminator straddles two writes, so the boundary scan has to
            // look back into bytes it already searched.
            client
                .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r")
                .await
                .unwrap();
            client.write_all(b"\n").await.unwrap();
        });

        let buf = Jatai::read_h1_headers(&mut server).await.unwrap();
        assert!(buf.ends_with(b"\r\n\r\n"));
    }

    #[tokio::test]
    async fn a_header_block_over_the_size_limit_is_refused() {
        let oversized = format!(
            "GET / HTTP/1.1\r\nX: {}\r\n",
            "a".repeat(H1_MAX_HEADER_SIZE)
        );
        let mut input = oversized.as_bytes();
        assert!(Jatai::read_h1_headers(&mut input).await.is_none());
    }

    #[tokio::test]
    async fn a_connection_closed_before_the_blank_line_is_refused() {
        let mut input = &b"GET / HTTP/1.1\r\nHost: x\r\n"[..];
        assert!(Jatai::read_h1_headers(&mut input).await.is_none());
    }

    #[tokio::test]
    async fn an_immediately_closed_connection_is_refused() {
        let mut input = &b""[..];
        assert!(Jatai::read_h1_headers(&mut input).await.is_none());
    }

    #[tokio::test]
    async fn a_builder_without_binds_reports_no_addresses() {
        let server = JataiBuilder::new().build().await.unwrap();
        assert!(server.tcp_addrs().is_empty());
        assert!(server.quic_addr().is_none());
    }

    #[tokio::test]
    async fn binding_an_ephemeral_port_reports_the_assigned_port() {
        let server = JataiBuilder::new()
            .bind_http("127.0.0.1:0")
            .build()
            .await
            .unwrap();
        let addrs = server.tcp_addrs();
        assert_eq!(addrs.len(), 1);
        assert_ne!(addrs[0].port(), 0, "the OS-assigned port must be reported");
    }

    #[tokio::test]
    async fn the_builder_entry_points_agree_on_the_static_dir() {
        let from_builder = Jatai::builder().with_static_dir("pages");
        assert_eq!(from_builder.static_dir, "pages");

        let server = Jatai::builder()
            .with_static_dir("first")
            .build()
            .await
            .unwrap();
        // `Jatai::with_static_dir` restarts from a fresh builder by design.
        assert_eq!(server.with_static_dir("second").static_dir, "second");
    }

    #[tokio::test]
    async fn a_default_builder_serves_the_pages_directory() {
        assert_eq!(JataiBuilder::default().static_dir, "pages");
    }

    #[tokio::test]
    async fn an_unparseable_https_address_fails_the_build_when_h3_is_on() {
        let result = JataiBuilder::new()
            .bind_https("localhost:8443", CERT, KEY)
            .enable_h3()
            .build()
            .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("a hostname is not a socket address"),
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn binding_a_port_already_in_use_fails() {
        let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = taken.local_addr().unwrap();

        let result = JataiBuilder::new()
            .bind_http(addr.to_string())
            .build()
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn a_plaintext_listener_reports_http_and_a_tls_one_reports_h2() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (plain, tls) = rt.block_on(async {
            let plain = Listener {
                tcp: TcpListener::bind("127.0.0.1:0").await.unwrap(),
                tls_acceptor: None,
            };
            let config = crate::tls::load_config(super::tests::CERT, super::tests::KEY).unwrap();
            let tls = Listener {
                tcp: TcpListener::bind("127.0.0.1:0").await.unwrap(),
                tls_acceptor: Some(TlsAcceptor::from(Arc::new(config))),
            };
            (plain, tls)
        });

        assert_eq!(plain.protocol(), "http");
        assert_eq!(tls.protocol(), "h2");
    }

    pub(super) const CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../example/cert.pem");
    pub(super) const KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../example/key.pem");

    /// The process environment is global, so the tests that mutate it run one
    /// at a time. Each sets every variable it reads, which also keeps a
    /// developer's local `.env` from leaking into the result.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const ENV_VARS: [&str; 7] = [
        "STATIC_DIR",
        "HTTP_BIND",
        "ENABLE_HTTPS",
        "ENABLE_H3",
        "HTTPS_BIND",
        "CERT_PATH",
        "KEY_PATH",
    ];

    fn with_env<T>(vars: &[(&str, &str)], f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // `Config::from_env` calls `dotenvy::dotenv()`, which walks up from the
        // working directory looking for a `.env`. Run from an empty directory so
        // a developer's local file cannot decide the outcome of these tests.
        let sandbox = TempDir::new().unwrap();
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(sandbox.path()).unwrap();

        for key in ENV_VARS {
            env::remove_var(key);
        }
        for (key, value) in vars {
            env::set_var(key, value);
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

        for key in ENV_VARS {
            env::remove_var(key);
        }
        env::set_current_dir(original_dir).unwrap();

        match result {
            Ok(value) => value,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    #[test]
    fn config_without_https_binds_plaintext_only() {
        let config = with_env(
            &[
                ("STATIC_DIR", "pages"),
                ("HTTP_BIND", "0.0.0.0:8080"),
                ("ENABLE_HTTPS", "false"),
            ],
            Config::from_env,
        );

        assert_eq!(config.static_dir, "pages");
        assert_eq!(config.http_bind, "0.0.0.0:8080");
        assert!(config.https.is_none());
    }

    #[test]
    fn config_reads_the_full_https_and_h3_setup() {
        let config = with_env(
            &[
                ("STATIC_DIR", "static"),
                ("HTTP_BIND", "0.0.0.0:80"),
                ("ENABLE_HTTPS", "true"),
                ("ENABLE_H3", "true"),
                ("HTTPS_BIND", "0.0.0.0:443"),
                ("CERT_PATH", "/etc/cert.pem"),
                ("KEY_PATH", "/etc/key.pem"),
            ],
            Config::from_env,
        );

        let https = config.https.expect("https should be configured");
        assert_eq!(https.bind, "0.0.0.0:443");
        assert_eq!(https.cert_path, "/etc/cert.pem");
        assert_eq!(https.key_path, "/etc/key.pem");
        assert!(https.enable_h3);
    }

    #[test]
    fn an_unparseable_boolean_flag_is_treated_as_disabled() {
        let config = with_env(
            &[
                ("STATIC_DIR", "pages"),
                ("HTTP_BIND", "0.0.0.0:8080"),
                ("ENABLE_HTTPS", "yes please"),
            ],
            Config::from_env,
        );
        assert!(config.https.is_none());
    }

    #[test]
    fn h3_defaults_to_off_when_only_https_is_enabled() {
        let config = with_env(
            &[
                ("STATIC_DIR", "pages"),
                ("HTTP_BIND", "0.0.0.0:80"),
                ("ENABLE_HTTPS", "true"),
                ("HTTPS_BIND", "0.0.0.0:443"),
                ("CERT_PATH", "/etc/cert.pem"),
                ("KEY_PATH", "/etc/key.pem"),
            ],
            Config::from_env,
        );
        assert!(!config.https.unwrap().enable_h3);
    }

    #[test]
    #[should_panic(expected = "HTTP_BIND environment variable not set")]
    fn a_missing_required_variable_fails_loudly_at_startup() {
        // Misconfiguration is a deployment error, not a runtime condition to
        // degrade around: better to refuse to start than to bind a surprise.
        with_env(&[("STATIC_DIR", "pages")], Config::from_env);
    }

    #[tokio::test]
    async fn a_config_becomes_a_builder_that_binds_every_configured_listener() {
        let config = with_env(
            &[
                ("STATIC_DIR", "pages"),
                ("HTTP_BIND", "127.0.0.1:0"),
                ("ENABLE_HTTPS", "true"),
                ("ENABLE_H3", "true"),
                ("HTTPS_BIND", "127.0.0.1:0"),
                ("CERT_PATH", CERT),
                ("KEY_PATH", KEY),
            ],
            Config::from_env,
        );

        let server = JataiBuilder::from(config).build().await.unwrap();
        assert_eq!(server.tcp_addrs().len(), 2, "one plaintext, one TLS");
        assert!(server.quic_addr().is_some(), "h3 was enabled");
        assert_eq!(server.static_dir, "pages");
    }
}
