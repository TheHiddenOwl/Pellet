use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub general: GeneralConfig,
    pub http: HttpConfig,
    pub ssh: SshConfig,
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
