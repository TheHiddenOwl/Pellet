use std::process::{Command, Stdio};
use std::time::Duration;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;

#[test]
fn test_honeypot_integration() {
    let test_dir = "tests/test_run";
    let _ = fs::create_dir_all(test_dir);

    let config_path = format!("{}/test_config.toml", test_dir);
    let log_path = format!("{}/test_events.jsonl", test_dir);
    let ssh_key_path = format!("{}/ssh_host_ed25519_key", test_dir);

    // Clean up from previous runs
    let _ = fs::remove_file(&config_path);
    let _ = fs::remove_file(&log_path);
    let _ = fs::remove_file(&ssh_key_path);
    let _ = fs::remove_file(format!("{}/cert.pem", test_dir));
    let _ = fs::remove_file(format!("{}/key.pem", test_dir));

    let config_content = format!(r#"
[general]
log_file   = "{log_path}"
sensor_id  = "integration-test"

[http]
enabled    = true
bind       = "127.0.0.1:8081"
tls_bind   = "127.0.0.1:8444"
tls_cn     = "Integration Test"
banner     = "Test-IIS"

[ssh]
enabled    = true
bind       = "127.0.0.1:2223"
banner     = "SSH-2.0-Test"
host_key   = "{ssh_key_path}"
"#);
    fs::write(&config_path, config_content).unwrap();

    // Use cargo run to start Pellet to avoid hardcoding path to debug binary
    let mut child = Command::new("cargo")
        .arg("run")
        .arg("--")
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start Pellet");

    // Poll for the ports to be open instead of a fixed sleep
    let mut success = false;
    for _ in 0..30 {
        if TcpStream::connect("127.0.0.1:8081").is_ok() {
            success = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(success, "Pellet failed to start and listen on port 8081");

    // 1. Test HTTP
    {
        let mut stream = TcpStream::connect("127.0.0.1:8081").unwrap();
        stream.write_all(b"GET /test-http HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let mut http_response = String::new();
        stream.read_to_string(&mut http_response).unwrap();
        assert!(http_response.contains("Test-IIS"));
    }

    // 2. Test SSH Banner and Login Simulation
    {
        let mut stream = TcpStream::connect("127.0.0.1:2223").unwrap();
        let mut ssh_banner = [0u8; 256];
        let n = stream.read(&mut ssh_banner).unwrap();
        let banner_str = String::from_utf8_lossy(&ssh_banner[..n]);
        assert!(banner_str.contains("SSH-2.0-Test"));

        // Simulate a basic SSH-like interaction to trigger an auth attempt log
        // We'll send a dummy client banner and a mock KEXINIT to get it moving
        stream.write_all(b"SSH-2.0-TestClient\r\n").unwrap();

        // Wait a bit for it to process
        std::thread::sleep(Duration::from_millis(500));
    }

    // Kill Pellet
    child.kill().expect("Failed to kill Pellet");
    let _ = child.wait();

    // 3. Verify logs
    let logs = fs::read_to_string(&log_path).expect("Failed to read log file");
    assert!(logs.contains("integration-test"), "Logs should contain sensor_id");
    assert!(logs.contains("connection_open"), "Logs should contain connection_open");
    assert!(logs.contains("http_request"), "Logs should contain http_request");
    assert!(logs.contains("/test-http"), "Logs should contain the HTTP path");
}
