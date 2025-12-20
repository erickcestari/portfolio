use std::{
    fs::File,
    io::{self, BufReader},
};

use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};

pub fn load_config(cert_path: &str, key_path: &str) -> io::Result<ServerConfig> {
    let cert_file = File::open(cert_path)?;
    let key_file = File::open(key_path)?;

    let certs: Vec<_> = certs(&mut BufReader::new(cert_file)).collect::<Result<_, _>>()?;
    let key = private_key(&mut BufReader::new(key_file))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "No private key found"))?;

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
