use crate::config::HttpConfig;
use crate::logger::Logger;
use base64::{engine::general_purpose, Engine as _};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;
use tokio::net::{TcpListener};
use uuid::Uuid;
use tokio_rustls::TlsAcceptor;
use std::time::Instant;

const MAX_BODY_SIZE: usize = 1024 * 1024; // 1MB limit for honeypot payloads

pub async fn run(config: HttpConfig, logger: Arc<Logger>, tls_acceptor: Option<TlsAcceptor>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.bind).await?;
    let config_arc = Arc::new(config);

    if let Some(acceptor) = tls_acceptor {
        let tls_bind = config_arc.tls_bind.clone().unwrap_or_else(|| "0.0.0.0:8443".to_string());
        let tls_listener = TcpListener::bind(&tls_bind).await?;
        let logger_tls = logger.clone();
        let config_tls = config_arc.clone();
        tokio::spawn(async move {
            loop {
                if let Ok((stream, addr)) = tls_listener.accept().await {
                    let acceptor = acceptor.clone();
                    let logger = logger_tls.clone();
                    let config = config_tls.clone();
                    tokio::spawn(async move {
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                let (_, server_conn) = tls_stream.get_ref();
                                let sni = server_conn.server_name().map(|s| s.to_string());
                                handle_connection(Box::new(tls_stream), addr, logger, config, true, sni).await;
                            }
                            Err(e) => {
                                tracing::error!("TLS accept error: {}", e);
                            }
                        }
                    });
                }
            }
        });
    }

    loop {
        let (stream, addr) = listener.accept().await?;
        let logger = logger.clone();
        let config = config_arc.clone();
        tokio::spawn(async move {
            handle_connection(Box::new(stream), addr, logger, config, false, None).await;
        });
    }
}

trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncStream for T {}

async fn handle_connection(
    stream: Box<dyn AsyncStream>,
    addr: std::net::SocketAddr,
    logger: Arc<Logger>,
    config: Arc<HttpConfig>,
    is_tls: bool,
    sni: Option<String>,
) {
    let _ = tokio::time::timeout(Duration::from_secs(30), handle_connection_inner(stream, addr, logger, config, is_tls, sni)).await;
}

async fn handle_connection_inner(
    mut stream: Box<dyn AsyncStream>,
    addr: std::net::SocketAddr,
    logger: Arc<Logger>,
    config: Arc<HttpConfig>,
    is_tls: bool,
    sni: Option<String>,
) -> anyhow::Result<()> {
    let start = Instant::now();
    let session_id = Uuid::new_v4().to_string();
    let proto = if is_tls { "https" } else { "http" };

    logger.log(proto, addr.ip().to_string(), addr.port(), session_id.clone(), "connection_open", serde_json::json!({
        "sni": sni
    }));

    let mut buffer = [0u8; 8192];
    let mut pos = 0;

    let (amt, method, path, headers_map, user_agent) = loop {
        match stream.read(&mut buffer[pos..]).await? {
            0 => return Ok(()),
            n => {
                pos += n;
                if let Some(_) = find_subsequence(&buffer[..pos], b"\r\n\r\n") {
                    let mut headers = [httparse::EMPTY_HEADER; 64];
                    let mut req = httparse::Request::new(&mut headers);
                    match req.parse(&buffer[..pos]) {
                        Ok(httparse::Status::Complete(amt)) => {
                            let method = req.method.unwrap_or("").to_string();
                            let path = req.path.unwrap_or("").to_string();
                            let mut headers_map = HashMap::new();
                            let mut user_agent = String::new();
                            for h in req.headers {
                                let name = h.name.to_lowercase();
                                let value = String::from_utf8_lossy(h.value).to_string();
                                if name == "user-agent" {
                                    user_agent = value.clone();
                                }
                                headers_map.insert(name, value);
                            }
                            break (amt, method, path, headers_map, user_agent);
                        }
                        Ok(httparse::Status::Partial) => {
                            if pos >= buffer.len() {
                                logger.log(proto, addr.ip().to_string(), addr.port(), session_id.clone(), "oversized_header", serde_json::json!({}));
                                return Ok(());
                            }
                            continue;
                        }
                        Err(_) => return Ok(()),
                    }
                }
                if pos >= buffer.len() {
                    logger.log(proto, addr.ip().to_string(), addr.port(), session_id.clone(), "oversized_header", serde_json::json!({}));
                    return Ok(());
                }
            }
        }
    };

    let mut body = Vec::new();
    let body_start = amt;
    let already_read = &buffer[body_start..pos];

    let content_length = headers_map.get("content-length")
        .and_then(|v| v.parse::<usize>().ok());

    let is_chunked = headers_map.get("transfer-encoding")
        .map(|v| v.to_lowercase().contains("chunked"))
        .unwrap_or(false);

    if is_chunked {
        // Simple manual chunked decoding with DoS protection
        let mut current_buffer = already_read.to_vec();
        loop {
            // Limit buffer size to prevent memory exhaustion from slow-send or large non-delimited data
            if current_buffer.len() > MAX_BODY_SIZE + 1024 {
                return Err(anyhow::anyhow!("Chunked stream buffer exceeded limit"));
            }

            // Find end of chunk size line
            if let Some(pos) = find_subsequence(&current_buffer, b"\r\n") {
                let size_str = String::from_utf8_lossy(&current_buffer[..pos]);
                let chunk_size = usize::from_str_radix(size_str.trim(), 16).map_err(|_| anyhow::anyhow!("Invalid chunk size"))?;

                if chunk_size > MAX_BODY_SIZE {
                    return Err(anyhow::anyhow!("Chunk size too large"));
                }

                if chunk_size == 0 { break; }

                let chunk_start = pos + 2;
                let needed = chunk_start + chunk_size + 2;

                while current_buffer.len() < needed {
                    let mut temp = [0u8; 4096];
                    let n = stream.read(&mut temp).await?;
                    if n == 0 { break; }
                    current_buffer.extend_from_slice(&temp[..n]);
                    if current_buffer.len() > MAX_BODY_SIZE + 1024 {
                        return Err(anyhow::anyhow!("Chunked stream buffer exceeded limit during read"));
                    }
                }

                if current_buffer.len() >= needed {
                    let body_part = &current_buffer[chunk_start..chunk_start + chunk_size];
                    if body.len() + body_part.len() <= MAX_BODY_SIZE {
                        body.extend_from_slice(body_part);
                    }
                    current_buffer = current_buffer[needed..].to_vec();
                } else {
                    break;
                }
            } else {
                let mut temp = [0u8; 4096];
                let n = stream.read(&mut temp).await?;
                if n == 0 { break; }
                current_buffer.extend_from_slice(&temp[..n]);
            }
            if body.len() >= MAX_BODY_SIZE { break; }
        }
    } else if let Some(cl) = content_length {
        let body_limit = std::cmp::min(cl, MAX_BODY_SIZE);
        if already_read.len() > 0 {
            body.extend_from_slice(&already_read[..std::cmp::min(already_read.len(), body_limit)]);
        }
        if body.len() < body_limit {
            let mut remaining_body = vec![0u8; body_limit - body.len()];
            let _ = stream.read_exact(&mut remaining_body).await;
            body.extend_from_slice(&remaining_body);
        }
    }

    let scanner_tags = identify_scanners(&user_agent);

    logger.log(proto, addr.ip().to_string(), addr.port(), session_id.clone(), "http_request", serde_json::json!({
        "method": method,
        "path": path,
        "headers": headers_map,
        "body_b64": general_purpose::STANDARD.encode(&body),
        "scanner_tags": scanner_tags,
        "body_truncated": body.len() >= MAX_BODY_SIZE && content_length.map(|cl| cl > MAX_BODY_SIZE).unwrap_or(true)
    }));

    let response_body = config.response_body.as_deref().unwrap_or(DEFAULT_IIS_PAGE);
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
        Server: {}\r\n\
        Content-Type: text/html\r\n\
        Content-Length: {}\r\n\
        Connection: close\r\n\
        \r\n\
        {}",
        config.banner,
        response_body.len(),
        response_body
    );

    let _ = stream.write_all(response.as_bytes()).await;

    logger.log(proto, addr.ip().to_string(), addr.port(), session_id.clone(), "connection_close", serde_json::json!({
        "duration_ms": start.elapsed().as_millis()
    }));

    Ok(())
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn identify_scanners(ua: &str) -> Vec<&'static str> {
    let mut tags = Vec::new();
    let scanners = [
        "masscan", "zgrab", "nuclei", "shodan", "censys", "curl/", "python-requests"
    ];
    let ua_lower = ua.to_lowercase();
    for s in scanners {
        if ua_lower.contains(s) {
            tags.push(s);
        }
    }
    tags
}

const DEFAULT_IIS_PAGE: &str = r#"<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>IIS Windows Server</title>
<style type="text/css">
<!--
body {
	color:#000000;
	background-color:#0072C6;
	margin:0;
}

#container {
	margin-left:auto;
	margin-right:auto;
	text-align:center;
}

a img {
	border:none;
}

-->
</style>
</head>
<body>
<div id="container">
<a href="http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409"><img src="welcome.png" alt="IIS" width="960" height="600" /></a>
</div>
</body>
</html>"#;
