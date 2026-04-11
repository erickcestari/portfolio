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

    config.alpn_protocols = vec![b"h2".to_vec()];
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
