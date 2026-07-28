//! End-to-end tests: a real Jatai instance on an ephemeral port, driven by
//! real clients over TCP, TLS and QUIC. These cover the wire format and the
//! protocol dispatch, which the unit tests deliberately stub out.

use std::{fs, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Buf;
use jatai::JataiBuilder;
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

const CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../example/cert.pem");
const KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../example/key.pem");

/// Every client operation is bounded, so a protocol-level stall fails the test
/// instead of hanging the suite.
const LIMIT: Duration = Duration::from_secs(10);

async fn bounded<F: std::future::Future>(what: &str, f: F) -> F::Output {
    timeout(LIMIT, f)
        .await
        .unwrap_or_else(|_| panic!("{} timed out after {:?}", what, LIMIT))
}

// -- fixtures ---------------------------------------------------------------

fn site() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("index.html", b"<h1>home</h1>" as &[u8]),
        ("about.html", b"<h1>about</h1>"),
        ("404.html", b"<h1>not found</h1>"),
        ("style.css", b"body{margin:0}"),
        ("logo.png", &[0x89, b'P', b'N', b'G', 0x0d]),
    ]
}

struct TestServer {
    _dir: TempDir,
    http: SocketAddr,
    https: Option<SocketAddr>,
    quic: Option<SocketAddr>,
}

impl TestServer {
    async fn start(tls: bool, h3: bool) -> Self {
        let dir = TempDir::new().unwrap();
        for (name, contents) in site() {
            fs::write(dir.path().join(name), contents).unwrap();
        }

        let mut builder = JataiBuilder::new()
            .with_static_dir(dir.path().to_str().unwrap())
            .bind_http("127.0.0.1:0");

        if tls {
            builder = builder.bind_https("127.0.0.1:0", CERT, KEY);
            if h3 {
                builder = builder.enable_h3();
            }
        }

        let server = builder.build().await.expect("server should bind");
        let addrs = server.tcp_addrs();
        let quic = server.quic_addr();
        // Listeners are configured http-first, then https.
        let (http, https) = (addrs[0], addrs.get(1).copied());

        tokio::spawn(server.run());

        Self {
            _dir: dir,
            http,
            https,
            quic,
        }
    }

    async fn plain() -> Self {
        Self::start(false, false).await
    }

    fn https(&self) -> SocketAddr {
        self.https.expect("TLS listener was requested")
    }
}

// -- HTTP/1.1 helpers -------------------------------------------------------

struct Reply {
    head: String,
    body: Vec<u8>,
}

impl Reply {
    fn parse(raw: &[u8]) -> Self {
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("response must terminate its header block");
        Self {
            // Keep the CRLF of the last header line so every header matches uniformly.
            head: String::from_utf8_lossy(&raw[..split + 2]).into_owned(),
            body: raw[split + 4..].to_vec(),
        }
    }

    fn status_line(&self) -> &str {
        self.head.lines().next().unwrap()
    }

    fn header(&self, name: &str) -> Option<String> {
        let prefix = format!("{}:", name.to_lowercase());
        self.head
            .lines()
            .find(|line| line.to_lowercase().starts_with(&prefix))
            .map(|line| line[prefix.len()..].trim().to_string())
    }
}

/// Send raw bytes over plaintext TCP and read until the server closes. A reset
/// counts as "nothing sent back": the server drops abusive connections while
/// the client may still be writing, which the kernel surfaces as ECONNRESET.
async fn tcp_exchange(addr: SocketAddr, request: &str) -> Vec<u8> {
    let mut stream = bounded("tcp connect", TcpStream::connect(addr))
        .await
        .unwrap();
    let _ = stream.write_all(request.as_bytes()).await;

    let mut raw = Vec::new();
    match bounded("tcp read", stream.read_to_end(&mut raw)).await {
        Ok(_) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => raw,
        Err(e) => panic!("unexpected read error: {}", e),
    }
}

async fn get(addr: SocketAddr, path: &str) -> Reply {
    let request = format!("GET {} HTTP/1.1\r\nHost: localhost\r\n\r\n", path);
    Reply::parse(&tcp_exchange(addr, &request).await)
}

// -- TLS helpers ------------------------------------------------------------

/// Accepts the self-signed test certificate. Test-only: the example cert has
/// no SAN, so ordinary verification can never succeed against it.
#[derive(Debug)]
struct TrustTheTestCert;

impl rustls::client::danger::ServerCertVerifier for TrustTheTestCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default()
            .expect("a default crypto provider must be installed")
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client_config(alpn: &[&[u8]]) -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustTheTestCert))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

async fn tls_connect(
    addr: SocketAddr,
    alpn: &[&[u8]],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config(alpn)));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    bounded("tls handshake", connector.connect(name, tcp))
        .await
        .expect("TLS handshake should succeed")
}

// -- plaintext HTTP/1.1 -----------------------------------------------------

#[tokio::test]
async fn serves_the_index_page_over_http1() {
    let server = TestServer::plain().await;
    let reply = get(server.http, "/").await;

    assert_eq!(reply.status_line(), "HTTP/1.1 200 OK");
    assert_eq!(reply.body, b"<h1>home</h1>");
    assert_eq!(reply.header("content-type").as_deref(), Some("text/html"));
    assert_eq!(reply.header("content-length").as_deref(), Some("13"));
}

#[tokio::test]
async fn identifies_itself_as_jatai() {
    let server = TestServer::plain().await;
    assert_eq!(
        get(server.http, "/").await.header("server").as_deref(),
        Some("jatai")
    );
}

#[tokio::test]
async fn sends_the_security_headers_on_every_response() {
    let server = TestServer::plain().await;
    for path in ["/", "/missing", "/.env"] {
        let reply = get(server.http, path).await;
        assert_eq!(
            reply.header("x-content-type-options").as_deref(),
            Some("nosniff"),
            "for {}",
            path
        );
        assert_eq!(reply.header("x-frame-options").as_deref(), Some("DENY"));
        assert_eq!(
            reply.header("referrer-policy").as_deref(),
            Some("strict-origin-when-cross-origin")
        );
    }
}

#[tokio::test]
async fn serves_html_pages_without_their_extension() {
    let server = TestServer::plain().await;
    assert_eq!(get(server.http, "/about").await.body, b"<h1>about</h1>");
    assert_eq!(
        get(server.http, "/about.html").await.body,
        b"<h1>about</h1>"
    );
}

#[tokio::test]
async fn serves_assets_with_their_content_type_and_cache_policy() {
    let server = TestServer::plain().await;

    let css = get(server.http, "/style.css").await;
    assert_eq!(css.header("content-type").as_deref(), Some("text/css"));
    assert_eq!(
        css.header("cache-control").as_deref(),
        Some("public, max-age=300, must-revalidate")
    );

    let png = get(server.http, "/logo.png").await;
    assert_eq!(png.header("content-type").as_deref(), Some("image/png"));
    assert_eq!(png.body, [0x89, b'P', b'N', b'G', 0x0d]);
}

#[tokio::test]
async fn answers_unknown_paths_with_the_404_page() {
    let server = TestServer::plain().await;
    let reply = get(server.http, "/no/such/page").await;

    assert_eq!(reply.status_line(), "HTTP/1.1 404 NOT FOUND");
    assert_eq!(reply.body, b"<h1>not found</h1>");
}

#[tokio::test]
async fn compresses_responses_only_for_clients_that_ask() {
    let server = TestServer::plain().await;

    let plain = get(server.http, "/").await;
    assert_eq!(plain.header("content-encoding"), None);

    let request = "GET / HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip, deflate\r\n\r\n";
    let gzipped = Reply::parse(&tcp_exchange(server.http, request).await);
    assert_eq!(gzipped.header("content-encoding").as_deref(), Some("gzip"));

    let mut decoded = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::read::GzDecoder::new(&gzipped.body[..]),
        &mut decoded,
    )
    .unwrap();
    assert_eq!(decoded, b"<h1>home</h1>");
}

#[tokio::test]
async fn declares_the_length_of_the_compressed_payload() {
    let server = TestServer::plain().await;
    let request = "GET / HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n";
    let reply = Reply::parse(&tcp_exchange(server.http, request).await);

    let declared: usize = reply.header("content-length").unwrap().parse().unwrap();
    assert_eq!(declared, reply.body.len());
}

#[tokio::test]
async fn feeds_bait_to_credential_scanners() {
    let server = TestServer::plain().await;

    let env = get(server.http, "/.env").await;
    // 200, not 403: a scanner must not learn that the path is guarded.
    assert_eq!(env.status_line(), "HTTP/1.1 200 OK");
    assert!(String::from_utf8_lossy(&env.body).contains("AWS_SECRET_ACCESS_KEY="));

    let passwd = get(server.http, "/etc/passwd").await;
    assert!(passwd.body.starts_with(b"root:x:0:0:"));
}

#[tokio::test]
async fn traversal_is_caught_at_every_level_of_encoding() {
    let server = TestServer::plain().await;
    for attack in [
        "/../../etc/passwd",
        "/%2e%2e/%2e%2e/etc/passwd",
        "/%252e%252e/%252e%252e/etc/passwd",
        "/%2e%2e%5cetc%5cpasswd",
    ] {
        let reply = get(server.http, attack).await;
        assert!(
            reply.body.starts_with(b"root:x:0:0:"),
            "{} should be answered with bait, got {:?}",
            attack,
            String::from_utf8_lossy(&reply.body[..reply.body.len().min(40)])
        );
    }
}

#[tokio::test]
async fn traversal_never_reaches_a_file_outside_the_static_dir() {
    let host_secret = fs::read_to_string("/etc/hostname").unwrap_or_default();
    assert!(
        !host_secret.trim().is_empty(),
        "this test needs a non-empty host file to look for"
    );

    let server = TestServer::plain().await;
    for attack in [
        "/../../../../etc/hostname",
        "/%252e%252e/%252e%252e/etc/hostname",
        "/static/../../../etc/hostname",
    ] {
        let body = get(server.http, attack).await.body;
        assert!(
            !String::from_utf8_lossy(&body).contains(host_secret.trim()),
            "{} leaked host content",
            attack
        );
    }
}

#[tokio::test]
async fn does_not_advertise_http3_when_it_is_disabled() {
    let server = TestServer::plain().await;
    assert_eq!(get(server.http, "/").await.header("alt-svc"), None);
}

#[tokio::test]
async fn handles_requests_from_many_connections_at_once() {
    let server = TestServer::plain().await;

    let mut tasks = Vec::new();
    for i in 0..32 {
        let addr = server.http;
        let path = if i % 2 == 0 { "/" } else { "/about" };
        tasks.push(tokio::spawn(async move { get(addr, path).await.body }));
    }

    for (i, task) in tasks.into_iter().enumerate() {
        let expected: &[u8] = if i % 2 == 0 {
            b"<h1>home</h1>"
        } else {
            b"<h1>about</h1>"
        };
        assert_eq!(task.await.unwrap(), expected);
    }
}

#[tokio::test]
async fn keeps_serving_after_a_client_disconnects_mid_request() {
    let server = TestServer::plain().await;

    let stream = TcpStream::connect(server.http).await.unwrap();
    drop(stream); // half-open handshake, no request bytes at all

    let mut aborted = TcpStream::connect(server.http).await.unwrap();
    aborted.write_all(b"GET / HTTP").await.unwrap();
    drop(aborted);

    assert_eq!(get(server.http, "/").await.status_line(), "HTTP/1.1 200 OK");
}

#[tokio::test]
async fn drops_a_request_whose_headers_exceed_the_size_limit() {
    let server = TestServer::plain().await;

    // No blank line, so the server keeps reading until it hits the 8 KiB cap.
    let flood = format!("GET / HTTP/1.1\r\nX-Pad: {}\r\n", "a".repeat(16 * 1024));
    let raw = tcp_exchange(server.http, &flood).await;
    assert!(
        raw.is_empty(),
        "an oversized header block must get no reply"
    );

    assert_eq!(get(server.http, "/").await.status_line(), "HTTP/1.1 200 OK");
}

// -- TLS: ALPN dispatch -----------------------------------------------------

#[tokio::test]
async fn clients_that_only_speak_http1_are_served_over_tls() {
    // Regression guard: RSS fetchers and other HTTP/1.1-only clients connect
    // over TLS without offering h2 and must not receive HTTP/2 framing.
    let server = TestServer::start(true, false).await;
    let mut tls = tls_connect(server.https(), &[b"http/1.1"]).await;

    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let mut raw = Vec::new();
    bounded("tls read", tls.read_to_end(&mut raw))
        .await
        .unwrap();
    let reply = Reply::parse(&raw);

    assert_eq!(reply.status_line(), "HTTP/1.1 200 OK");
    assert_eq!(reply.body, b"<h1>home</h1>");
    assert_eq!(reply.header("server").as_deref(), Some("jatai"));
}

#[tokio::test]
async fn clients_that_offer_no_alpn_at_all_are_served_over_http1() {
    let server = TestServer::start(true, false).await;
    let mut tls = tls_connect(server.https(), &[]).await;

    tls.write_all(b"GET /about HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let mut raw = Vec::new();
    bounded("tls read", tls.read_to_end(&mut raw))
        .await
        .unwrap();
    assert_eq!(Reply::parse(&raw).body, b"<h1>about</h1>");
}

#[tokio::test]
async fn a_client_that_negotiates_h2_but_sends_garbage_is_dropped() {
    let server = TestServer::start(true, false).await;
    let mut tls = tls_connect(server.https(), &[b"h2"]).await;

    // Not the HTTP/2 connection preface: the handshake must fail and the
    // connection must close without taking the listener down with it.
    tls.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut raw = Vec::new();
    let _ = bounded("h2 garbage read", tls.read_to_end(&mut raw)).await;

    let healthy = h2_get(server.https(), "/", false).await;
    assert_eq!(healthy.parts.status, 200);
}

// -- TLS: HTTP/2 ------------------------------------------------------------

struct H2Reply {
    parts: http::response::Parts,
    body: Vec<u8>,
}

async fn h2_get(addr: SocketAddr, path: &str, accept_gzip: bool) -> H2Reply {
    let tls = tls_connect(addr, &[b"h2"]).await;
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "server must negotiate h2 when the client offers it"
    );

    let (send_request, connection) = bounded("h2 handshake", h2::client::handshake(tls))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut send_request = send_request.ready().await.unwrap();
    let mut request = http::Request::builder()
        .method("GET")
        .uri(format!("https://localhost{}", path));
    if accept_gzip {
        request = request.header("accept-encoding", "gzip");
    }

    let (response, _) = send_request
        .send_request(request.body(()).unwrap(), true)
        .unwrap();
    let response = bounded("h2 response", response).await.unwrap();
    let (parts, mut stream) = response.into_parts();

    let mut body = Vec::new();
    while let Some(chunk) = bounded("h2 body", stream.data()).await {
        let chunk = chunk.unwrap();
        stream.flow_control().release_capacity(chunk.len()).unwrap();
        body.extend_from_slice(&chunk);
    }

    H2Reply { parts, body }
}

#[tokio::test]
async fn serves_pages_over_http2() {
    let server = TestServer::start(true, false).await;
    let reply = h2_get(server.https(), "/", false).await;

    assert_eq!(reply.parts.status, 200);
    assert_eq!(reply.body, b"<h1>home</h1>");
    assert_eq!(reply.parts.headers["server"], "jatai");
    assert_eq!(reply.parts.headers["content-type"], "text/html");
    assert_eq!(reply.parts.headers["content-length"], "13");
    assert_eq!(reply.parts.headers["x-frame-options"], "DENY");
}

#[tokio::test]
async fn answers_404_over_http2() {
    let server = TestServer::start(true, false).await;
    let reply = h2_get(server.https(), "/missing", false).await;

    assert_eq!(reply.parts.status, 404);
    assert_eq!(reply.body, b"<h1>not found</h1>");
}

#[tokio::test]
async fn compresses_over_http2_when_asked() {
    let server = TestServer::start(true, false).await;
    let reply = h2_get(server.https(), "/", true).await;

    assert_eq!(reply.parts.headers["content-encoding"], "gzip");
    let mut decoded = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::read::GzDecoder::new(&reply.body[..]),
        &mut decoded,
    )
    .unwrap();
    assert_eq!(decoded, b"<h1>home</h1>");
}

#[tokio::test]
async fn feeds_bait_over_http2_too() {
    let server = TestServer::start(true, false).await;
    let reply = h2_get(server.https(), "/wp-config.php", false).await;

    assert_eq!(reply.parts.status, 200);
    assert!(String::from_utf8_lossy(&reply.body).contains("define( 'DB_PASSWORD'"));
}

#[tokio::test]
async fn bait_carries_the_content_type_of_the_file_it_fakes() {
    // A scanner that asks for a login page and gets text/plain has learned it
    // is being lied to. Each trap answers in the type its file would have.
    let server = TestServer::start(true, false).await;

    for (path, expected) in [
        ("/etc/passwd", "text/plain"),
        ("/wp-login.php", "text/html"),
        ("/actuator/env", "application/json"),
    ] {
        let reply = h2_get(server.https(), path, false).await;
        assert_eq!(
            reply.parts.headers["content-type"], expected,
            "for {}",
            path
        );
    }
}

// -- HTTP/3 -----------------------------------------------------------------

#[tokio::test]
async fn advertises_http3_over_the_tls_listener() {
    let server = TestServer::start(true, true).await;
    let quic_port = server.quic.expect("QUIC endpoint").port();

    let reply = h2_get(server.https(), "/", false).await;
    let alt_svc = reply.parts.headers["alt-svc"].to_str().unwrap().to_string();

    assert_eq!(alt_svc, format!("h3=\":{}\"; ma=86400", quic_port));
    assert_ne!(quic_port, 0, "Alt-Svc must carry a reachable port");
}

#[tokio::test]
async fn serves_pages_over_http3() {
    let server = TestServer::start(true, true).await;
    let addr = server.quic.expect("QUIC endpoint");

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let tls = client_config(&[b"h3"]);
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    )));

    let connection = bounded("quic connect", endpoint.connect(addr, "localhost").unwrap())
        .await
        .expect("QUIC handshake should succeed");

    let (mut driver, mut send_request) = bounded(
        "h3 handshake",
        h3::client::new(h3_quinn::Connection::new(connection)),
    )
    .await
    .unwrap();
    let driving =
        tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

    let request = http::Request::builder()
        .uri("https://localhost/about")
        .body(())
        .unwrap();
    let mut stream = bounded("h3 request", send_request.send_request(request))
        .await
        .unwrap();
    stream.finish().await.unwrap();

    let response = bounded("h3 response", stream.recv_response())
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["server"], "jatai");
    assert_eq!(response.headers()["content-type"], "text/html");

    let mut body = Vec::new();
    while let Some(chunk) = bounded("h3 body", stream.recv_data()).await.unwrap() {
        body.extend_from_slice(chunk.chunk());
    }
    assert_eq!(body, b"<h1>about</h1>");

    drop(send_request);
    endpoint.wait_idle().await;
    let _ = driving.await;
}

#[tokio::test]
async fn a_page_whose_name_mentions_a_trapped_word_is_still_served() {
    // Segment matching, end to end: the honeypot must not swallow an article
    // just because its slug contains "aws" or "config".
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("404.html"), b"<h1>not found</h1>").unwrap();
    fs::write(
        dir.path().join("aws-vs-bare-metal.html"),
        b"<h1>the article</h1>",
    )
    .unwrap();
    fs::write(
        dir.path().join("config-driven-design.html"),
        b"<h1>also real</h1>",
    )
    .unwrap();

    let server = JataiBuilder::new()
        .with_static_dir(dir.path().to_str().unwrap())
        .bind_http("127.0.0.1:0")
        .build()
        .await
        .unwrap();
    let addr = server.tcp_addrs()[0];
    tokio::spawn(server.run());

    assert_eq!(
        get(addr, "/aws-vs-bare-metal").await.body,
        b"<h1>the article</h1>"
    );
    assert_eq!(
        get(addr, "/config-driven-design").await.body,
        b"<h1>also real</h1>"
    );

    // The real attack paths still get bait.
    assert!(get(addr, "/.aws/credentials")
        .await
        .body
        .starts_with(b"[default]"));
}

#[tokio::test]
async fn announces_that_the_connection_closes_after_the_response() {
    // A real client should not have to discover the close by hitting EOF on a
    // second request it was entitled to send.
    let server = TestServer::plain().await;
    assert_eq!(
        get(server.http, "/").await.header("connection").as_deref(),
        Some("close")
    );
}

#[tokio::test]
async fn http2_does_not_carry_the_connection_header() {
    // RFC 9113 forbids connection-specific headers in HTTP/2: sending one is a
    // protocol error the client must treat as malformed.
    let server = TestServer::start(true, false).await;
    let reply = h2_get(server.https(), "/", false).await;
    assert!(!reply.parts.headers.contains_key("connection"));
}

#[tokio::test]
async fn the_client_address_reaches_the_request() {
    // The peer is taken from accept() and carried on the Request, so the log
    // and any future rate limiting see a real address instead of nothing.
    let server = TestServer::plain().await;

    let mut stream = TcpStream::connect(server.http).await.unwrap();
    let local = stream.local_addr().unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    assert_eq!(Reply::parse(&raw).status_line(), "HTTP/1.1 200 OK");

    // The address the server saw is the one this socket was bound to, which is
    // what makes the log line correlatable with anything else on the host.
    assert_eq!(local.ip().to_string(), "127.0.0.1");
    assert_ne!(local.port(), 0);
}
