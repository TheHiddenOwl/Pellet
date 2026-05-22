# Pellet — Rust SSH/HTTP Honeypot

Pellet is a lightweight, high-performance honeypot designed to emulate SSH and HTTP services to deceive automated scanners and log their activities. Written in Rust with a focus on security and efficiency, it provides a safe way to observe adversarial behavior without risking host compromise.

## Table of Contents
- [Architecture](#architecture)
- [Features](#features)
- [Build Instructions](#build-instructions)
- [Configuration Reference](#configuration-reference)
- [Deployment](#deployment)
  - [Systemd](#systemd)
  - [Docker](#docker)
- [Logging Reference](#logging-reference)
- [Security](#security)

---

## Architecture

Pellet is built on top of the **Tokio** asynchronous runtime, allowing it to handle thousands of concurrent connections with minimal overhead.

### Key Components:
- **Independent Handlers**: The HTTP and SSH honeypot engines run as separate asynchronous tasks. A failure or hang in one does not affect the other.
- **Non-Blocking Logger**: Pellet uses an internal `mpsc` (multi-producer, single-consumer) channel to ship events to a dedicated background logging task. This ensures that slow disk I/O never blocks the network handlers or the main event loop.
- **Static Binary**: The project targets `x86_64-unknown-linux-musl`, producing a single, self-contained static binary with no external dependencies (like OpenSSL or libc).
- **Self-Management**: On startup, Pellet automatically generates self-signed TLS certificates (using `rcgen`) and SSH host keys (using `russh-keys`) if they are missing, ensuring it is always ready to accept secure connections.

---

## Features

### HTTP / HTTPS Honeypot
- **IIS Emulation**: Returns a generic IIS default web page to blend in with common corporate infrastructure.
- **Scanner Tagging**: Automatically identifies and tags requests from known scanners (e.g., Masscan, ZGrab, Shodan, Nuclei) based on User-Agent strings.
- **TLS Support**: Supports SNI-aware HTTPS with automatic certificate generation.
- **DoS Protection**: Enforces a 30-second connection timeout and a 1MB limit on request bodies to prevent memory exhaustion.
- **Chunked Decoding**: Supports manual decoding of chunked transfer-encoding for full payload capture.

### SSH Honeypot
- **Authentication Logging**: Captures both password and public-key authentication attempts.
- **Jitter**: Implements a 1-3 second random delay on authentication rejections to mimic real system behavior and slow down brute-force tools.
- **Command Capture**: Logs `exec` requests and `shell` session requests without executing any code.
- **Banner Customization**: Easily configurable SSH version string.

---

## Build Instructions

### Prerequisites
- Rust (latest stable)
- `musl-tools` (for static linking on Linux)

### Compile
To create a static binary:
```bash
cargo build --release --target x86_64-unknown-linux-musl
```
The resulting binary will be located at `target/x86_64-unknown-linux-musl/release/pellet`.

---

## Configuration Reference

Pellet uses a TOML configuration file (default: `pellet.toml`).

```toml
[general]
log_file   = "events.jsonl" # Path to the JSONL log file
sensor_id  = "prod-1"      # Unique ID for this sensor (1-64 chars, alphanumeric/hyphen/underscore)

[http]
enabled       = true
bind          = "0.0.0.0:80"
tls_bind      = "0.0.0.0:443"        # Optional: Bind address for HTTPS
tls_cert      = "cert.pem"           # Optional: Path to TLS certificate
tls_key       = "key.pem"            # Optional: Path to TLS private key
tls_cn        = "Pellet Honeypot"    # Optional: Common Name for self-signed cert
tls_san       = ["localhost"]        # Optional: Subject Alt Names for self-signed cert
banner        = "Microsoft-IIS/10.0" # Server header value
response_body = "<html..."          # Optional: Custom HTML response

[ssh]
enabled    = true
bind       = "0.0.0.0:22"
banner     = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
host_key   = "ssh_host_ed25519_key" # Path to SSH host key
```

---

## Deployment

### Systemd
A service file is provided in `pellet.service`.
1. Copy the binary to `/usr/local/bin/pellet`.
2. Copy `pellet.toml` to `/etc/pellet/pellet.toml`.
3. Create the `pellet` user: `useradd -r -s /bin/false pellet`.
4. Install and start the service:
```bash
cp pellet.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now pellet
```
*Note: The service file uses `AmbientCapabilities=CAP_NET_BIND_SERVICE` to allow binding to ports 80/443/22 as a non-root user.*

### Docker
Use the provided `Dockerfile` to build a minimal "scratch" based image.
```bash
docker build -t pellet .
docker run -d \
  -p 80:80 -p 443:443 -p 22:22 \
  -v ./logs:/var/log/pellet \
  -v ./certs:/etc/pellet/certs \
  pellet
```

---

## Logging Reference

All logs are written in JSON Lines (JSONL) format. Each line is a complete JSON object.

### Common Fields
| Field | Type | Description |
| :--- | :--- | :--- |
| `ts` | String | ISO 8601 Timestamp (UTC) |
| `session_id` | String | Unique UUID for the connection |
| `sensor_id` | String | Configured sensor identifier |
| `proto` | String | Protocol used (`http`, `https`, `ssh`) |
| `src_ip` | String | Source IP address |
| `src_port` | Number | Source port |
| `event` | String | Event type |
| `payload` | Object | Event-specific data |

### Event Types

#### `connection_open`
Logged when a new TCP connection is established.
- **Payload (HTTP)**: `{"sni": "example.com"}` (if TLS)

#### `http_request`
Logged when a full HTTP request header is parsed.
- **Payload**:
  - `method`: HTTP method (GET, POST, etc.)
  - `path`: Requested URI
  - `headers`: Map of all request headers
  - `body_b64`: Base64 encoded request body (up to 1MB)
  - `scanner_tags`: Array of identified scanner names
  - `body_truncated`: Boolean indicating if the body exceeded the 1MB limit

#### `auth_attempt` (SSH)
Logged for every SSH authentication attempt.
- **Payload (Password)**: `{"username": "...", "password": "..."}`
- **Payload (Pubkey)**: `{"username": "...", "pubkey_fingerprint": "..."}`

#### `exec_command` (SSH)
Logged when a client attempts to execute a one-off command.
- **Payload**: `{"command": "ls -la"}`

#### `shell_request` (SSH)
Logged when a client attempts to open an interactive shell.
- **Payload**: `{"command": "shell"}`

#### `connection_close`
Logged when the connection is terminated.
- **Payload**: `{"duration_ms": 1234}`

---

## Security

Pellet is designed with a "Security-First" mindset:
- **No Execution**: Pellet never uses `std::process::Command` or `fork`. It is impossible for an attacker to execute code on the host via the honeypot services.
- **Memory Safety**: Written in 100% safe Rust (excluding dependencies) to prevent buffer overflows and memory corruption.
- **Non-Root**: Specifically designed to run without root privileges using Linux Capabilities.
- **Append-Only**: The application only opens log files in append mode and never reads from them, preventing log injection from affecting application logic.
