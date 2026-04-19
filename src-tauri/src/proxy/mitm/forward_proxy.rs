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
                let proxy_pool_clone = proxy_pool.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, ca, proxy_pool_clone).await {
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
    proxy_pool: Arc<crate::proxy::proxy_pool::ProxyPoolManager>,
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

    // [MITM v8] Universal TLS Interception
    // We intercept ALL domains (cloudcode, play, oauth, unleash) to force them through
    // the `rquest` ProxyPool routing engine. Blind TCP tunneling is disabled to prevent
    // host IP leakage for side-channel traffic.
    
    // 3. TLS handshake with the client (using our dynamic cert for this host)
    let server_config = ca.get_server_config(&host);
    let acceptor = TlsAcceptor::from(server_config);
    let mut tls_stream = acceptor.accept(stream).await?;

    // 4. Handle HTTP request(s) inside the TLS tunnel (support keep-alive)
    loop {
        match handle_tunneled_request(&mut tls_stream, &host, &proxy_pool).await {
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
    proxy_pool: &Arc<crate::proxy::proxy_pool::ProxyPoolManager>,
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
            // 6. Connect to real upstream server using ProxyPool (generic token)
            let upstream_response =
                forward_to_upstream_with_proxy(host, method, path, &headers, &body, proxy_pool, None).await?;

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
            let (new_headers, new_body, account_id) = rewrite_agent_telemetry(headers, body);
            
            // 6. Connect to real upstream server using ProxyPool mapped to the telemetry account
            let upstream_response =
                forward_to_upstream_with_proxy(host, method, path, &new_headers, &new_body, proxy_pool, account_id.as_deref()).await?;

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

async fn forward_to_upstream_with_proxy(
    host: &str,
    method: &str,
    path: &str,
    headers: &[String],
    body: &[u8],
    proxy_pool: &Arc<crate::proxy::proxy_pool::ProxyPoolManager>,
    account_id: Option<&str>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // 1. Obtain a standard proxy client (generic if account_id is None)
    let client = proxy_pool.get_effective_standard_client(account_id, 30).await;
    
    let url = format!("https://{}{}", host, path);
    // Convert method string to HTTP Method
    let reqwest_method = reqwest::Method::from_bytes(method.as_bytes())?;
    
    // 2. Build HTTP request
    let mut req_builder = client.request(reqwest_method, &url);
    for h in headers {
        if let Some((k, v)) = h.split_once(':') {
            req_builder = req_builder.header(k.trim(), v.trim());
        }
    }
    
    if !body.is_empty() {
        req_builder = req_builder.body(body.to_vec());
    }
    
    // 3. Execute
    let response = req_builder.send().await?;
    
    // 4. Reconstruct raw HTTP/1.1 response bytes for the TLS tunnel
    let mut out = Vec::new();
    let status_code = response.status().as_u16();
    let reason = response.status().canonical_reason().unwrap_or("");
    let status_line = format!("HTTP/1.1 {} {}\r\n", status_code, reason);
    out.extend_from_slice(status_line.as_bytes());
    
    for (k, v) in response.headers() {
        // Skip transfer-encoding to enforce Content-Length
        if k.as_str().eq_ignore_ascii_case("transfer-encoding") { continue; }
        // We will compute new Content-Length
        if k.as_str().eq_ignore_ascii_case("content-length") { continue; }
        
        out.extend_from_slice(k.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    
    let body_bytes = response.bytes().await?;
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body_bytes.len()).as_bytes());
    out.extend_from_slice(&body_bytes);
    
    Ok(out)
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
fn rewrite_agent_telemetry(mut headers: Vec<String>, body: Vec<u8>) -> (Vec<String>, Vec<u8>, Option<String>) {
    if body.is_empty() {
        return (headers, body, None);
    }

    let mut json_val: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("[MITM] Failed to parse telemetry JSON: {}", e);
            return (headers, body, None);
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

            // [OPSEC v2] Spoof identity fingerprints with per-account DeviceProfile
            // instead of removing fields (removal creates detectable anomalies).
            let device_profile = crate::modules::account::load_account(&proxy_token.account_id)
                .ok()
                .and_then(|acc| acc.device_profile);

            let spoof_session_id = uuid::Uuid::new_v4().to_string();

            fn spoof_identity(
                v: &mut serde_json::Value,
                profile: &Option<crate::models::DeviceProfile>,
                spoof_session: &str,
            ) {
                if let Some(obj) = v.as_object_mut() {
                    // Spoof machine identifiers with account-bound DeviceProfile
                    if let Some(dp) = profile {
                        if obj.contains_key("machineId") {
                            obj.insert("machineId".to_string(), serde_json::json!(dp.machine_id));
                        }
                        if obj.contains_key("macMachineId") || obj.contains_key("macAddress") {
                            if obj.contains_key("macMachineId") {
                                obj.insert("macMachineId".to_string(), serde_json::json!(dp.mac_machine_id));
                            }
                            if obj.contains_key("macAddress") {
                                obj.insert("macAddress".to_string(), serde_json::json!(dp.mac_machine_id));
                            }
                        }
                        if obj.contains_key("devDeviceId") {
                            obj.insert("devDeviceId".to_string(), serde_json::json!(dp.dev_device_id));
                        }
                        if obj.contains_key("sqmId") {
                            obj.insert("sqmId".to_string(), serde_json::json!(dp.sqm_id));
                        }
                    }

                    // Spoof session identifiers with fresh UUIDs
                    if obj.contains_key("sessionId") {
                        obj.insert("sessionId".to_string(), serde_json::json!(spoof_session));
                    }
                    if obj.contains_key("vscodeSessionId") {
                        obj.insert("vscodeSessionId".to_string(), serde_json::json!(spoof_session));
                    }

                    // Remove workspace/file paths (can't meaningfully spoof, reveals code)
                    let path_keys = ["filePath", "fileName", "workspacePath", "repository", "remoteUrl", "gitHash"];
                    for key in path_keys.iter() {
                        obj.remove(*key);
                    }

                    // Recurse into nested objects/arrays
                    for value in obj.values_mut() {
                        spoof_identity(value, profile, spoof_session);
                    }
                } else if let Some(arr) = v.as_array_mut() {
                    for item in arr.iter_mut() {
                        spoof_identity(item, profile, spoof_session);
                    }
                }
            }
            spoof_identity(&mut json_val, &device_profile, &spoof_session_id);

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
            return (headers, new_body, Some(proxy_token.account_id.clone()));
        } else {
            tracing::debug!("[MITM] Unmapped trajectoryId: {}", uuid);
        }
    } else {
        tracing::debug!("[MITM] No trajectoryId found in telemetry payload");
    }

    (headers, body, None)
}
