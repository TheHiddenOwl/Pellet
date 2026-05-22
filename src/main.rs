mod config;
mod logger;
mod http;
mod ssh;

use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_rustls::rustls;
use tokio_rustls::TlsAcceptor;
use rcgen::{CertificateParams, DistinguishedName};
use russh_keys::key::KeyPair as SshKeyPair;
use std::fs;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "pellet.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    if !args.config.exists() {
        create_default_config(&args.config)?;
    }

    let config_content = fs::read_to_string(&args.config)
        .map_err(|e| anyhow::anyhow!("Failed to read config file {}: {}", args.config.display(), e))?;
    let config: config::Config = toml::from_str(&config_content)?;

    let logger = Arc::new(logger::Logger::new(&config.general.log_file, config.general.sensor_id.clone())?);

    let mut tasks = Vec::new();

    if config.http.enabled {
        let tls_acceptor = if let (Some(cert_path), Some(key_path)) = (&config.http.tls_cert, &config.http.tls_key) {
            Some(setup_tls(cert_path, key_path)?)
        } else if config.http.tls_bind.is_some() {
            // Generate self-signed if bind is set but certs are missing
            let cert_path = Path::new("cert.pem");
            let key_path = Path::new("key.pem");
            Some(setup_tls(cert_path, key_path)?)
        } else {
            None
        };

        let http_config = config.http.clone();
        let http_logger = logger.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = http::handler::run(http_config, http_logger, tls_acceptor).await {
                tracing::error!("HTTP server error: {}", e);
            }
        }));
    }

    if config.ssh.enabled {
        let ssh_key = setup_ssh_key(&config.ssh.host_key)?;
        let ssh_config = config.ssh.clone();
        let ssh_logger = logger.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = ssh::handler::run(ssh_config, ssh_logger, ssh_key).await {
                tracing::error!("SSH server error: {}", e);
            }
        }));
    }

    tracing::info!("Pellet honeypot started");

    for task in tasks {
        let _ = task.await;
    }

    Ok(())
}

fn create_default_config(path: &Path) -> anyhow::Result<()> {
    let content = r#"[general]
log_file   = "events.jsonl"
sensor_id  = "dev-1"

[http]
enabled    = true
bind       = "0.0.0.0:8080"
tls_bind   = "0.0.0.0:8443"
banner     = "Apache/2.4.57 (Ubuntu)"

[ssh]
enabled    = true
bind       = "0.0.0.0:2222"
banner     = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
host_key   = "ssh_host_ed25519_key"
"#;
    fs::write(path, content)?;
    Ok(())
}

fn setup_tls(cert_path: &Path, key_path: &Path) -> anyhow::Result<TlsAcceptor> {
    if !cert_path.exists() || !key_path.exists() {
        tracing::info!("Generating self-signed TLS certificate...");
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, "Pellet Honeypot");
        params.subject_alt_names = vec![rcgen::SanType::DnsName(rcgen::Ia5String::try_from("localhost")?)];

        let key_pair = rcgen::KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        fs::write(cert_path, cert_pem)?;
        fs::write(key_path, key_pem)?;
    }

    let cert_file = fs::read_to_string(cert_path)?;
    let key_file = fs::read_to_string(key_path)?;

    let cert_chain = rustls_pemfile::certs(&mut cert_file.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_file.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;

    if keys.is_empty() {
        return Err(anyhow::anyhow!("No private key found in {:?}", key_path));
    }

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, rustls::pki_types::PrivateKeyDer::Pkcs8(keys.remove(0)))?;

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

fn setup_ssh_key(key_path: &Path) -> anyhow::Result<SshKeyPair> {
    if !key_path.exists() {
        tracing::info!("Generating SSH host key...");
        let key = SshKeyPair::generate_ed25519().ok_or_else(|| anyhow::anyhow!("Failed to generate SSH key"))?;

        // Use standard ed25519_dalek to export to PKCS8 as russh-keys is tricky
        // Actually, we can just use the internal representation if we really have to
        // or find what russh_keys expects.
        // Let's try to just write a fake key for now to see if it works with load_secret_key
        // No, that's bad.

        // Let's use the `ssh-key` crate which russh depends on.
        // wait, I can just use `key.to_openssh()` if I can find it.
        // It's not there.

        // Okay, I will use a hardcoded key for the first run if generation fails,
        // but that's not good for a honeypot.

        // Let's try one more time to find a way to write the key.
        // russh_keys::key::KeyPair is an enum.

        if let SshKeyPair::Ed25519(ref kp) = key {
             // kp is ed25519_dalek::SigningKey
             use ed25519_dalek::pkcs8::EncodePrivateKey;
             let pkcs8 = kp.to_pkcs8_pem(Default::default())?;
             fs::write(key_path, pkcs8.as_bytes())?;
             return Ok(key);
        }
    }

    russh_keys::load_secret_key(key_path, None).map_err(|e| anyhow::anyhow!("Failed to load SSH key: {}", e))
}
