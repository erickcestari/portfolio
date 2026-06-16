use std::{
    fs::File,
    io::{self, BufReader},
    sync::Arc,
};

use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};

pub fn load_config(cert_path: &str, key_path: &str) -> io::Result<ServerConfig> {
    let cert_file = File::open(cert_path)?;
    let key_file = File::open(key_path)?;

    let certs: Vec<_> = certs(&mut BufReader::new(cert_file)).collect::<Result<_, _>>()?;
    let key = private_key(&mut BufReader::new(key_file))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "No private key found"))?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Offer HTTP/1.1 as well as h2: many clients (e.g. RSS fetchers using
    // undici/node-fetch) connect over TLS speaking HTTP/1.1 and never offer
    // the "h2" ALPN. Without this they get HTTP/2 framing as a reply and fail
    // to parse the response. Order matters: h2 is preferred when offered.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

pub fn load_quic_config(cert_path: &str, key_path: &str) -> io::Result<quinn::ServerConfig> {
    let cert_file = File::open(cert_path)?;
    let key_file = File::open(key_path)?;

    let certs: Vec<_> = certs(&mut BufReader::new(cert_file)).collect::<Result<_, _>>()?;
    let key = private_key(&mut BufReader::new(key_file))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "No private key found"))?;

    let mut tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic_config)))
}
