# Pellet — Rust SSH/HTTP Honeypot

Pellet is a lightweight, high-performance honeypot designed to emulate SSH and HTTP services to deceive automated scanners and log their activities.

## Features
- **HTTP Honeypot**: Emulates an IIS default web page, logs full request details, and tags known scanners.
- **SSH Honeypot**: Completes key exchange, logs all authentication attempts with jitter, and captures `exec`/`shell` commands.
- **Structured Logging**: All events are logged in JSONL format for easy analysis.
- **Self-Generating Keys**: Automatically generates self-signed TLS certificates and SSH host keys if they are missing.
- **Static Binary**: Compiles to a single static binary for easy deployment.

## Build Instructions

### Prerequisites
- Rust (latest stable)
- `musl-tools` (for static linking)

### Compile
```bash
cargo build --release --target x86_64-unknown-linux-musl
```

## Configuration Reference (`pellet.toml`)

```toml
[general]
log_file   = "events.jsonl"
sensor_id  = "prod-1"

[http]
enabled    = true
bind       = "0.0.0.0:80"
tls_bind   = "0.0.0.0:443"
banner     = "Apache/2.4.57 (Ubuntu)"

[ssh]
enabled    = true
bind       = "0.0.0.0:22"
banner     = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
host_key   = "ssh_host_ed25519_key"
```

## Example `jq` Queries

### View all authentication attempts
```bash
tail -f events.jsonl | jq 'select(.event == "auth_attempt")'
```

### Identify top scanner IPs
```bash
jq -r '.src_ip' events.jsonl | sort | uniq -c | sort -nr
```

### List all executed commands via SSH
```bash
jq 'select(.event == "exec_command") | .payload.command' events.jsonl
```

## Security
- Pellet never forks or executes external processes.
- All file I/O is append-only for logs.
- It is recommended to run Pellet as a non-root user. If binding to ports below 1024, use `CAP_NET_BIND_SERVICE`.
