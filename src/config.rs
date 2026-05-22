use serde::Deserialize;
use std::path::PathBuf;

fn validate_sensor_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("sensor_id cannot be empty".to_string());
    }
    if id.len() > 64 {
        return Err("sensor_id is too long (max 64 chars)".to_string());
    }
    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("sensor_id contains invalid characters (only alphanumeric, -, _ allowed)".to_string());
    }
    Ok(())
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub general: GeneralConfig,
    pub http: HttpConfig,
    pub ssh: SshConfig,
}

impl Config {
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_sensor_id(&self.general.sensor_id).map_err(|e| anyhow::anyhow!(e))?;
        Ok(())
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct GeneralConfig {
    pub log_file: PathBuf,
    pub sensor_id: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HttpConfig {
    pub enabled: bool,
    pub bind: String,
    pub tls_bind: Option<String>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub tls_cn: Option<String>,
    pub tls_san: Option<Vec<String>>,
    pub banner: String,
    pub response_body: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SshConfig {
    pub enabled: bool,
    pub bind: String,
    pub banner: String,
    pub host_key: PathBuf,
}
