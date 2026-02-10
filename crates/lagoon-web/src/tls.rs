use std::path::Path;
use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tracing::info;

/// Ensure TLS certificates exist at the given directory, generating self-signed
/// ones if needed. Returns a ready-to-use TLS acceptor.
pub fn build_acceptor(
    tls_dir: &Path,
    hostname: &str,
) -> Result<TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    let cert_path = tls_dir.join("cert.pem");
    let key_path = tls_dir.join("key.pem");

    if !cert_path.exists() || !key_path.exists() {
        info!("generating self-signed TLS certificate for {hostname}");
        generate_self_signed(&cert_path, &key_path, hostname)?;
    } else {
        info!("loading TLS certificates from {}", tls_dir.display());
    }

    let cert_pem = std::fs::read(&cert_path)?;
    let key_pem = std::fs::read(&key_path)?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..]).collect::<Result<_, _>>()?;
    let key = rustls_pemfile::private_key(&mut &key_pem[..])?
        .ok_or("no private key found in key.pem")?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn generate_self_signed(
    cert_path: &Path,
    key_path: &Path,
    hostname: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::net::{IpAddr, Ipv4Addr};

    let key_pair = KeyPair::generate()?;

    // DNS SANs: the configured hostname + localhost.
    let mut params = CertificateParams::new(vec![
        hostname.to_string(),
        "localhost".to_string(),
    ])?;

    // IP SANs for convenience.
    params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));

    let cert = params.self_signed(&key_pair)?;

    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(cert_path, cert.pem())?;
    std::fs::write(key_path, key_pair.serialize_pem())?;

    info!("TLS cert written to {}", cert_path.display());
    info!("TLS key written to {}", key_path.display());

    Ok(())
}
