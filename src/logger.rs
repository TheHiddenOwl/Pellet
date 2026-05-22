use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use tokio::sync::mpsc;

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
    tx: mpsc::UnboundedSender<LogEvent>,
    sensor_id: String,
}

impl Logger {
    pub fn new(path: &Path, sensor_id: String) -> anyhow::Result<(Self, tokio::task::JoinHandle<()>)> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        let (tx, mut rx) = mpsc::unbounded_channel::<LogEvent>();

        let handle = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let Ok(line) = serde_json::to_string(&event) {
                    let _ = writeln!(file, "{}", line);
                }
            }
            let _ = file.flush();
        });

        Ok((Self { tx, sensor_id }, handle))
    }

    pub fn log(&self, proto: &str, src_ip: String, src_port: u16, session_id: String, event: &str, payload: serde_json::Value) {
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

        let _ = self.tx.send(log_event);
    }

}
