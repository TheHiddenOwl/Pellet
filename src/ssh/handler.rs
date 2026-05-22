use crate::config::SshConfig;
use crate::logger::Logger;
use async_trait::async_trait;
use russh::server::{Auth, Session, Server as _};
use russh::{ChannelId};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::Duration;
use uuid::Uuid;
use rand::Rng;
use std::time::Instant;

pub async fn run(config: SshConfig, logger: Arc<Logger>, key: russh_keys::key::KeyPair) -> anyhow::Result<()> {
    let mut russh_config = russh::server::Config {
        server_id: russh::SshId::Standard(config.banner.clone()),
        ..Default::default()
    };
    russh_config.keys.push(key);

    let config_arc = Arc::new(russh_config);
    let mut sh = Server {
        logger,
    };

    let socket_addr: SocketAddr = config.bind.parse()?;
    sh.run_on_address(config_arc, socket_addr).await?;
    Ok(())
}

#[derive(Clone)]
struct Server {
    logger: Arc<Logger>,
}

impl russh::server::Server for Server {
    type Handler = Handler;
    fn new_client(&mut self, addr: Option<SocketAddr>) -> Self::Handler {
        let session_id = Uuid::new_v4().to_string();
        let logger = self.logger.clone();
        let ip = addr.map(|a| a.ip().to_string()).unwrap_or_else(|| "unknown".to_string());
        let port = addr.map(|a| a.port()).unwrap_or(0);

        let sid_clone = session_id.clone();
        tokio::spawn(async move {
            logger.log("ssh", ip, port, sid_clone, "connection_open", serde_json::json!({})).await;
        });

        Handler {
            logger: self.logger.clone(),
            ip: addr.map(|a| a.ip().to_string()).unwrap_or_else(|| "unknown".to_string()),
            port: addr.map(|a| a.port()).unwrap_or(0),
            session_id,
            start: Instant::now(),
        }
    }
}

pub struct Handler {
    logger: Arc<Logger>,
    ip: String,
    port: u16,
    session_id: String,
    start: Instant,
}

#[async_trait]
impl russh::server::Handler for Handler {
    type Error = anyhow::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        pass: &str,
    ) -> Result<Auth, Self::Error> {
        let logger = self.logger.clone();
        let user = user.to_string();
        let pass = pass.to_string();
        let ip = self.ip.clone();
        let port = self.port;
        let session_id = self.session_id.clone();

        // Jitter delay
        let delay = rand::thread_rng().gen_range(1000..3000);
        tokio::time::sleep(Duration::from_millis(delay)).await;

        logger.log("ssh", ip, port, session_id, "auth_attempt", serde_json::json!({
            "username": user,
            "password": pass,
        })).await;

        Ok(Auth::Reject { proceed_with_methods: None })
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &russh_keys::key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        let logger = self.logger.clone();
        let user = user.to_string();
        let fingerprint = key.fingerprint();
        let ip = self.ip.clone();
        let port = self.port;
        let session_id = self.session_id.clone();

        // Jitter delay
        let delay = rand::thread_rng().gen_range(1000..3000);
        tokio::time::sleep(Duration::from_millis(delay)).await;

        logger.log("ssh", ip, port, session_id, "auth_attempt", serde_json::json!({
            "username": user,
            "pubkey_fingerprint": fingerprint,
        })).await;

        Ok(Auth::Reject { proceed_with_methods: None })
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command_str = String::from_utf8_lossy(command).to_string();
        self.logger.log("ssh", self.ip.clone(), self.port, self.session_id.clone(), "exec_command", serde_json::json!({
            "command": command_str,
        })).await;

        let _ = session.exit_status_request(channel, 127);
        let _ = session.close(channel);
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.logger.log("ssh", self.ip.clone(), self.port, self.session_id.clone(), "exec_command", serde_json::json!({
            "command": "shell",
        })).await;

        let _ = session.exit_status_request(channel, 127);
        let _ = session.close(channel);
        Ok(())
    }
}

impl Drop for Handler {
    fn drop(&mut self) {
        let logger = self.logger.clone();
        let ip = self.ip.clone();
        let port = self.port;
        let session_id = self.session_id.clone();
        let duration = self.start.elapsed().as_millis();

        tokio::spawn(async move {
            logger.log("ssh", ip, port, session_id, "connection_close", serde_json::json!({
                "duration_ms": duration
            })).await;
        });
    }
}
