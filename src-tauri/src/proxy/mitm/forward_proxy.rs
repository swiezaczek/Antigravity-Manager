//! MITM Forward Proxy Server
//!
//! Handles HTTP CONNECT tunneling, TLS interception with dynamic certificates,
//! and applies rules (PASS/DROP/REWRITE) to intercepted requests.
//!
//! Architecture:
//! 1. IDE sends HTTP CONNECT host:443
//! 2. We respond 200 (tunnel established)
//! 3. We do TLS handshake with IDE using our dynamic cert for that host
//! 4. We read the plaintext HTTP request from the decrypted stream
//! 5. We apply rules (DROP native metrics, REWRITE trajectoryId, PASS rest)
//! 6. For PASS/REWRITE: connect to real server, forward request, pipe response back

use super::ca::CertificateAuthority;
use super::rules;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// Start the MITM forward proxy on the given port.
/// This function runs forever (until the tokio runtime shuts down).
pub async fn start(ca: Arc<CertificateAuthority>, port: u16) -> Result<(), String> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .map_err(|e| format!("MITM bind failed on port {}: {}", port, e))?;

    tracing::info!(
        "[MITM] Forward proxy listening on 127.0.0.1:{}",
        port
    );

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let ca = ca.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, ca).await {
                        tracing::debug!("[MITM] Connection from {} error: {}", peer, e);
                    }
                });
            }
            Err(e) => {
                tracing::error!("[MITM] Accept error: {}", e);
            }
        }
    }
}

/// Handle a single client connection (one CONNECT tunnel).
async fn handle_client(
    mut stream: TcpStream,
    ca: Arc<CertificateAuthority>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Read the CONNECT request line
    let mut reader = BufReader::new(&mut stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;

    // Parse: "CONNECT host:port HTTP/1.1\r\n"
    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 3 || parts[0] != "CONNECT" {
        // Not a CONNECT request — return 400
        stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await?;
        return Ok(());
    }

    let target = parts[1]; // "host:port"
    let (host, port) = parse_host_port(target)?;

    // Consume remaining headers (until empty line)
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    // 2. Send 200 Connection Established
    // Drop the BufReader to get direct access to stream
    drop(reader);
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // [MITM v7] Selective TLS Interception
    // Only intercept cloudcode-pa.googleapis.com (for telemetry/metrics manipulation)
    // and play.googleapis.com (to intercept and DROP Clearcut hardware metrics).
    // Everything else (oauth, unleash) passes purely as a raw TCP tunnel to avoid TLS fingerprinting
    // and HTTP parsing timeouts.
    if !host.contains("cloudcode-pa.googleapis.com") && !host.contains("play.googleapis.com") {
        let addr = format!("{}:{}", host, port);
        match TcpStream::connect(&addr).await {
            Ok(mut upstream) => {
                tracing::debug!("[MITM] Blind TCP tunnel established for {}", host);
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
            }
            Err(e) => {
                tracing::debug!("[MITM] Failed to connect to upstream {}: {}", host, e);
            }
        }
        return Ok(());
    }

    // 3. TLS handshake with the client (using our dynamic cert for this host)
    let server_config = ca.get_server_config(&host);
    let acceptor = TlsAcceptor::from(server_config);
    let mut tls_stream = acceptor.accept(stream).await?;

    // 4. Handle HTTP request(s) inside the TLS tunnel (support keep-alive)
    loop {
        match handle_tunneled_request(&mut tls_stream, &host).await {
            Ok(true) => continue,  // keep-alive: handle next request
            Ok(false) => break,    // connection closed cleanly
            Err(e) => {
                tracing::debug!("[MITM] Tunnel request error for {}: {}", host, e);
                break;
            }
        }
    }

    Ok(())
}

/// Handle a single HTTP request inside the TLS tunnel.
/// Returns Ok(true) to keep the connection alive, Ok(false) to close it.
async fn handle_tunneled_request(
    tls_stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    host: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    // Read the HTTP request line
    let mut buf_reader = BufReader::new(&mut *tls_stream);
    let mut request_line = String::new();
    let n = buf_reader.read_line(&mut request_line).await?;
    if n == 0 {
        return Ok(false); // Connection closed
    }

    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 3 {
        return Ok(false);
    }
    let method = parts[0];
    let path = parts[1];

    // Read headers
    let mut headers = Vec::new();
    let mut content_length: usize = 0;
    let mut keep_alive = true;
    loop {
        let mut line = String::new();
        buf_reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
        let trimmed = line.trim().to_string();
        if let Some(val) = trimmed.strip_prefix("Content-Length:").or_else(|| trimmed.strip_prefix("content-length:")) {
            content_length = val.trim().parse().unwrap_or(0);
        }
        if trimmed.to_lowercase().contains("connection: close") {
            keep_alive = false;
        }
        headers.push(trimmed);
    }

    // Read body
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        buf_reader.read_exact(&mut body).await?;
    }

    // 5. Apply rules
    let action = rules::evaluate(host, path);

    match action {
        rules::Action::Drop => {
            tracing::info!(
                "[MITM] ✗ Dropped: {} {} {} ({} bytes)",
                method, host, path, content_length
            );
            // Send fake 200 OK with empty JSON body
            let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\n{}";
            tls_stream.write_all(response.as_bytes()).await?;
            tls_stream.flush().await?;
            Ok(keep_alive)
        }
        rules::Action::Pass => {
            // 6. Connect to real upstream server
            let upstream_response =
                forward_to_upstream(host, method, path, &headers, &body).await?;

            tracing::debug!(
                "[MITM] ✓ Passed: {} {} {} ({} bytes → {} bytes response)",
                method, host, path, content_length, upstream_response.len()
            );

            // Pipe upstream response back to client
            tls_stream.write_all(&upstream_response).await?;
            tls_stream.flush().await?;
            Ok(keep_alive)
        }
        rules::Action::RewriteAgentTelemetry => {
            tracing::debug!("[MITM] 📝 Rewriting Agent Telemetry for {}", path);
            let (new_headers, new_body) = rewrite_agent_telemetry(headers, body);
            
            // 6. Connect to real upstream server
            let upstream_response =
                forward_to_upstream(host, method, path, &new_headers, &new_body).await?;

            tracing::debug!(
                "[MITM] ✓ Passed (Rewritten): {} {} {} ({} bytes → {} bytes response)",
                method, host, path, new_body.len(), upstream_response.len()
            );

            // Pipe upstream response back to client
            tls_stream.write_all(&upstream_response).await?;
            tls_stream.flush().await?;
            Ok(keep_alive)
        }
        rules::Action::RouteToAxum => {
            tracing::info!("[MITM] 🔀 Routing to local Axum proxy: {}", path);
            let app_port = crate::modules::config::load_app_config()
                .ok()
                .map(|c| c.proxy.port)
                .unwrap_or(3000);
            
            let mut rewritten_path = path.to_string();
            // Map v1internal to Axum's v1beta path structure so it's intercepted by Axum routers
            if path.contains("streamGenerateContent") || path.contains("generateContent") {
                rewritten_path = format!("/v1beta/models{}", path);
            }

            let local_host = format!("127.0.0.1:{}", app_port);
            let mut request = format!("{} {} HTTP/1.1\r\n", method, rewritten_path);
            
            for h in headers {
                if h.to_lowercase().starts_with("host:") {
                    request.push_str(&format!("Host: {}\r\n", local_host));
                } else {
                    request.push_str(&h);
                    request.push_str("\r\n");
                }
            }
            request.push_str("\r\n");

            let mut tcp = TcpStream::connect(&local_host).await?;
            tcp.write_all(request.as_bytes()).await?;
            if !body.is_empty() {
                tcp.write_all(&body).await?;
            }
            tcp.flush().await?;

            let mut response = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(300),
                    tcp.read(&mut buf),
                )
                .await
                {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => response.extend_from_slice(&buf[..n]),
                    Ok(Err(_)) => break,
                    Err(_) => break,
                }
            }
            
            tls_stream.write_all(&response).await?;
            tls_stream.flush().await?;
            Ok(keep_alive)
        }
    }
}

/// Forward a request to the real upstream server and return the raw HTTP response.
async fn forward_to_upstream(
    host: &str,
    method: &str,
    path: &str,
    headers: &[String],
    body: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // Connect to real server using native TLS (system trust store)
    let addr = format!("{}:443", host);
    let tcp = TcpStream::connect(&addr).await?;

    // Use rustls with system roots for upstream connection
    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    let native_certs = rustls_native_certs::load_native_certs();
    for cert in native_certs.certs {
        let _ = root_store.add(cert);
    }

    let client_config = Arc::new(
        tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    let connector = tokio_rustls::TlsConnector::from(client_config);
    let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_string())?;
    let mut upstream_tls = connector.connect(server_name, tcp).await?;

    // Build and send HTTP request
    let mut request = format!("{} {} HTTP/1.1\r\n", method, path);
    for h in headers {
        request.push_str(h);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

    upstream_tls.write_all(request.as_bytes()).await?;
    if !body.is_empty() {
        upstream_tls.write_all(body).await?;
    }
    upstream_tls.flush().await?;

    // Read the full HTTP response
    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            upstream_tls.read(&mut buf),
        )
        .await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => response.extend_from_slice(&buf[..n]),
            Ok(Err(_)) => break,
            Err(_) => break, // timeout
        }
    }

    Ok(response)
}

/// Parse "host:port" into (host, port). Defaults to port 443.
fn parse_host_port(target: &str) -> Result<(String, u16), Box<dyn std::error::Error + Send + Sync>> {
    if let Some((host, port_str)) = target.rsplit_once(':') {
        let port = port_str.parse().unwrap_or(443);
        Ok((host.to_string(), port))
    } else {
        Ok((target.to_string(), 443))
    }
}

/// Rewrite native Agent Telemetry to map to our proxy-allocated Account Token and Project ID
fn rewrite_agent_telemetry(mut headers: Vec<String>, body: Vec<u8>) -> (Vec<String>, Vec<u8>) {
    if body.is_empty() {
        return (headers, body);
    }

    let mut json_val: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("[MITM] Failed to parse telemetry JSON: {}", e);
            return (headers, body);
        }
    };

    // Helper to deeply find trajectoryId in the JSON payload
    fn find_trajectory_uuid(v: &serde_json::Value) -> Option<String> {
        if let Some(obj) = v.as_object() {
            if let Some(s) = obj.get("trajectoryId").and_then(|t| t.as_str()) {
                return Some(s.to_string());
            }
            // Fast paths for common structures
            if let Some(m) = obj.get("metrics").and_then(|m| m.as_array()) {
                for item in m {
                    if let Some(uuid) = find_trajectory_uuid(item) {
                        return Some(uuid);
                    }
                }
            }
            if let Some(co) = obj.get("conversationOffered") {
                if let Some(uuid) = find_trajectory_uuid(co) {
                    return Some(uuid);
                }
            }
            // Deep search
            for value in obj.values() {
                if let Some(uuid) = find_trajectory_uuid(value) {
                    return Some(uuid);
                }
            }
        } else if let Some(arr) = v.as_array() {
            for item in arr {
                if let Some(uuid) = find_trajectory_uuid(item) {
                    return Some(uuid);
                }
            }
        }
        None
    }

    let trajectory_uuid = find_trajectory_uuid(&json_val);
    
    if let Some(uuid) = trajectory_uuid {
        tracing::debug!("[MITM] Found trajectoryId: {}", uuid);
        if let Some(proxy_token) = crate::proxy::telemetry::registry::TelemetryRegistry::global().get(&uuid) {
            let body_mb = body.len() as f64 / 1024.0 / 1024.0;
            tracing::info!("[MITM] ✓ Rewritten telemetry ({:.2}MB) for trajectory {} mapping to proxy project id {}", body_mb, uuid, proxy_token.project_id);

            // Replace Authorization header while preserving original casing
            for h in headers.iter_mut() {
                if h.to_lowercase().starts_with("authorization:") {
                    if let Some((prefix, _)) = h.split_once(':') {
                        *h = format!("{}: Bearer {}", prefix, proxy_token.access_token);
                    } else {
                        *h = format!("Authorization: Bearer {}", proxy_token.access_token);
                    }
                }
            }

            // Replace {"project": "..."} in JSON root
            if let Some(obj) = json_val.as_object_mut() {
                if obj.contains_key("project") {
                    obj.insert("project".to_string(), serde_json::json!(proxy_token.project_id));
                }
            }

            // [OPSEC] Deep scrub of correlation fingerprints in Telemetry
            fn scrub_red_flags(v: &mut serde_json::Value) {
                if let Some(obj) = v.as_object_mut() {
                    let bad_keys = [
                        "machineId", "macAddress", "os", "osInfo", "osVersion", 
                        "hardware", "network", "clientVersion", "vscodeSessionId", 
                        "sessionId", "filePath", "fileName", "workspacePath", 
                        "repository", "remoteUrl", "gitHash"
                    ];
                    for key in bad_keys.iter() {
                        obj.remove(*key);
                    }
                    for value in obj.values_mut() {
                        scrub_red_flags(value);
                    }
                } else if let Some(arr) = v.as_array_mut() {
                    for item in arr.iter_mut() {
                        scrub_red_flags(item);
                    }
                }
            }
            scrub_red_flags(&mut json_val);

            let new_body = serde_json::to_vec(&json_val).unwrap_or(body);
            
            // Recompute content-length header while preserving original casing
            for h in headers.iter_mut() {
                if h.to_lowercase().starts_with("content-length:") {
                    if let Some((prefix, _)) = h.split_once(':') {
                        *h = format!("{}: {}", prefix, new_body.len());
                    } else {
                        *h = format!("Content-Length: {}", new_body.len());
                    }
                }
            }

            return (headers, new_body);
        } else {
            tracing::debug!("[MITM] Unmapped trajectoryId: {}", uuid);
        }
    } else {
        tracing::debug!("[MITM] No trajectoryId found in telemetry payload");
    }

    (headers, body)
}
