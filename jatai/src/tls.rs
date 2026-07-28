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

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../example/cert.pem");
    const KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../example/key.pem");

    #[test]
    fn tcp_config_offers_h2_first_then_http1() {
        // Order encodes preference: clients that offer both get HTTP/2, and
        // clients that only speak HTTP/1.1 still find a match.
        let config = load_config(CERT, KEY).unwrap();
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn quic_config_offers_only_h3() {
        assert!(load_quic_config(CERT, KEY).is_ok());
    }

    #[test]
    fn missing_certificate_file_is_an_error() {
        let err = load_config("/nonexistent/cert.pem", KEY).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn missing_key_file_is_an_error() {
        let err = load_config(CERT, "/nonexistent/key.pem").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn a_key_file_without_a_private_key_is_rejected() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, b"not a pem file\n").unwrap();
        let err = load_config(CERT, file.path().to_str().unwrap()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("No private key"));
    }

    #[test]
    fn an_empty_certificate_chain_is_rejected() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, b"").unwrap();
        let err = load_config(file.path().to_str().unwrap(), KEY).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
