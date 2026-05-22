use crate::config::HttpConfig;
use crate::logger::Logger;
use base64::{engine::general_purpose, Engine as _};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    mut stream: Box<dyn AsyncStream>,
    addr: std::net::SocketAddr,
    logger: Arc<Logger>,
    config: Arc<HttpConfig>,
    is_tls: bool,
    sni: Option<String>,
) {
    let start = Instant::now();
    let session_id = Uuid::new_v4().to_string();
    let proto = if is_tls { "https" } else { "http" };

    logger.log(proto, addr.ip().to_string(), addr.port(), session_id.clone(), "connection_open", serde_json::json!({
        "sni": sni
    })).await;

    let mut buffer = [0u8; 8192];
    let mut pos = 0;

    loop {
        match stream.read(&mut buffer[pos..]).await {
            Ok(0) => break,
            Ok(n) => {
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

                            let mut body = Vec::new();
                            let content_length = headers_map.get("content-length")
                                .and_then(|v| v.parse::<usize>().ok())
                                .unwrap_or(0);

                            let body_limit = std::cmp::min(content_length, MAX_BODY_SIZE);

                            let body_start = amt;
                            let already_read = pos - body_start;
                            if already_read > 0 {
                                body.extend_from_slice(&buffer[body_start..std::cmp::min(pos, body_start + body_limit)]);
                            }

                            if body.len() < body_limit {
                                let mut remaining_body = vec![0u8; body_limit - body.len()];
                                if let Ok(_) = stream.read_exact(&mut remaining_body).await {
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
                                "body_truncated": content_length > MAX_BODY_SIZE
                            })).await;

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
                            break;
                        }
                        Ok(httparse::Status::Partial) => {
                            if pos >= buffer.len() {
                                break;
                            }
                            continue;
                        }
                        Err(_) => break,
                    }
                }
                if pos >= buffer.len() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    logger.log(proto, addr.ip().to_string(), addr.port(), session_id.clone(), "connection_close", serde_json::json!({
        "duration_ms": start.elapsed().as_millis()
    })).await;
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn identify_scanners(ua: &str) -> Vec<&'static str> {
    let mut tags = Vec::new();
    let scanners = [
        "masscan", "zgrab", "Nuclei", "Shodan", "censys", "curl/", "python-requests"
    ];
    for s in scanners {
        if ua.contains(s) {
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
