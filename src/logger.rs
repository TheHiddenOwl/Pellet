use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Serialize)]
pub struct LogEvent {
    pub ts: DateTime<Utc>,
    pub session_id: String,
    pub sensor_id: String,
    pub proto: String,
    pub src_ip: String,
    pub src_port: u16,
    pub event: String,
    pub payload: serde_json::Value,
}

pub struct Logger {
    file: Arc<Mutex<std::fs::File>>,
    sensor_id: String,
}

impl Logger {
    pub fn new(path: &Path, sensor_id: String) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
            sensor_id,
        })
    }

    pub async fn log(&self, proto: &str, src_ip: String, src_port: u16, session_id: String, event: &str, payload: serde_json::Value) {
        let log_event = LogEvent {
            ts: Utc::now(),
            session_id,
            sensor_id: self.sensor_id.clone(),
            proto: proto.to_string(),
            src_ip,
            src_port,
            event: event.to_string(),
            payload,
        };

        if let Ok(line) = serde_json::to_string(&log_event) {
            let file = self.file.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let mut f = file.blocking_lock();
                let _ = writeln!(f, "{}", line);
            }).await;
        }
    }
}
