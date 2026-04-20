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
use once_cell::sync::Lazy;
use std::sync::RwLock;

// [OPSEC Phase 11] Ghost Cache Structure:
// Keys: `AccountID|Path|HeaderType` -> Value: `String`
// Preserves native HTTP 304 response caching logic without proxy cross-contamination.
static GHOST_CACHE: Lazy<RwLock<std::collections::HashMap<String, String>>> = Lazy::new(|| RwLock::new(std::collections::HashMap::new()));

/// Start the MITM forward proxy on the given port.
/// This function runs forever (until the tokio runtime shuts down).
pub async fn start(ca: Arc<CertificateAuthority>, port: u16, proxy_pool: Arc<crate::proxy::proxy_pool::ProxyPoolManager>, token_manager: Arc<crate::proxy::token_manager::TokenManager>) -> Result<(), String> {
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
                let token_manager_clone = token_manager.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, ca, proxy_pool_clone, token_manager_clone).await {
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
    token_manager: Arc<crate::proxy::TokenManager>,
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
        match handle_tunneled_request(&mut tls_stream, &host, &proxy_pool, &token_manager).await {
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
    token_manager: &Arc<crate::proxy::TokenManager>,
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

    // [OPSEC] Attempt to identify account_id from refresh_token in OAuth calls to prevent IP correlation
    let mut resolved_account_id: Option<String> = None;
    if host.contains("oauth2.googleapis.com") && path.contains("/token") && !body.is_empty() {
        if let Ok(body_str) = String::from_utf8(body.clone()) {
            let parsed: std::collections::HashMap<String, String> = url::form_urlencoded::parse(body_str.as_bytes())
                .into_owned()
                .collect();
            if let Some(refresh_token) = parsed.get("refresh_token") {
                    resolved_account_id = token_manager.get_account_id_by_refresh_token(refresh_token);
                    if resolved_account_id.is_some() {
                        tracing::debug!("[MITM] Air-Gap matched OAuth refresh to account: {:?}", resolved_account_id);
                }
            }
        }
    }

    // [OPSEC] Resolve Zero-Auth Trap: resolve account from Authorization Bearer header
    if resolved_account_id.is_none() {
        for header in &headers {
            let h_lower = header.to_lowercase();
            if h_lower.starts_with("authorization: bearer ") {
                if let Some(token) = header.get(22..) {
                    let token = token.trim();
                    resolved_account_id = token_manager.get_account_id_by_access_token(token);
                    if resolved_account_id.is_some() {
                        tracing::debug!("[MITM] Zero-Auth Trap avoided: Air-Gap matched Bearer to account: {:?}", resolved_account_id);
                        break;
                    }
                }
            }
        }
    }

    // [OPSEC] Spoof/Scrub tracking headers using DeviceProfile 
    let mut spoofed_headers = spoof_headers(headers.clone(), resolved_account_id.as_deref());

    // [OPSEC] Process Unleash payloads to scrub instanceId from JSON body
    let mut spoofed_body = spoof_unleash_body(host, path, body, resolved_account_id.as_deref());

    // [OPSEC V15] Replace product identifiers in body, rather than dropping
    if !spoofed_body.is_empty() && path.contains("/v1internal") {
        let body_str = String::from_utf8_lossy(&spoofed_body);
        if body_str.contains("antigravity") || body_str.contains("antigravity_desktop") {
            let replaced = body_str.replace("antigravity_desktop", "vscode_desktop").replace("antigravity", "vscode");
            spoofed_body = replaced.into_bytes();
            tracing::info!("[MITM] ⚠️ Body contained product identifier — spoofed to vscode for {} {}", host, path);
        }
    }

    // [OPSEC 7.5] Recalculate Content-Length after body spoofing to prevent mismatch
    if spoofed_body.len() != content_length {
        for h in spoofed_headers.iter_mut() {
            if h.to_lowercase().starts_with("content-length:") {
                *h = format!("Content-Length: {}", spoofed_body.len());
            }
        }
    }

    // [OPSEC V14] Safety net: drop any protobuf/unknown traffic that contains product identifiers
    // This catches Clearcut payloads even if Go LS resolves to unmapped IP addresses.
    if !spoofed_body.is_empty() {
        let body_preview = String::from_utf8_lossy(&spoofed_body);
        if body_preview.contains("antigravity") || body_preview.contains("antigravity_desktop") {
            tracing::warn!("[MITM] ⚠️ Body contains product identifier — force dropping: {} {}", host, path);
            let response = if path.contains("/log") || host.contains("play.googleapis.com") {
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n".to_string()
            } else {
                "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\n{}".to_string()
            };
            tls_stream.write_all(response.as_bytes()).await?;
            tls_stream.flush().await?;
            return Ok(keep_alive);
        }
    }

    // 5. Apply rules
    let action = rules::evaluate(host, path);

    match action {
        rules::Action::Drop => {
            tracing::info!(
                "[MITM] ✗ Dropped: {} {} {} ({} bytes)",
                method, host, path, content_length
            );
            // Send fake 200 OK (empty Protobuf for Clearcut, else empty JSON)
            let response = if path.contains("/log") || host.contains("play.googleapis.com") {
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n".to_string()
            } else {
                "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\n{}".to_string()
            };
            tls_stream.write_all(response.as_bytes()).await?;
            tls_stream.flush().await?;
            Ok(keep_alive)
        }
        rules::Action::Pass => {
            // 6. Connect to real upstream server using ProxyPool (isolated account if matched, generic fallback if not)
            let upstream_response =
                forward_to_upstream_with_proxy(host, method, path, &spoofed_headers, &spoofed_body, proxy_pool, resolved_account_id.as_deref()).await?;

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
            let (new_headers, new_body, account_id) = rewrite_agent_telemetry(spoofed_headers, spoofed_body);
            
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
            
            for h in spoofed_headers {
                if h.to_lowercase().starts_with("host:") {
                    request.push_str(&format!("Host: {}\r\n", local_host));
                } else {
                    request.push_str(&h);
                    request.push_str("\r\n");
                }
            }
            let content_len = spoofed_body.len();
            request.push_str(&format!("Content-Length: {}\r\n\r\n", content_len));

            let mut tcp = tokio::net::TcpStream::connect(&local_host).await?;
            tcp.write_all(request.as_bytes()).await?;
            if content_len > 0 {
                tcp.write_all(&spoofed_body).await?;
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

fn spoof_headers(headers: Vec<String>, account_id: Option<&str>) -> Vec<String> {
    let device_profile = account_id
        .and_then(|id| crate::modules::account::load_account(id).ok())
        .and_then(|acc| acc.device_profile);

    let spoof_session_id = account_id.map(|id| crate::proxy::common::session::get_or_create_vscode_session_id(id))
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let spoof_trace_id = uuid::Uuid::new_v4().to_string().replace("-", ""); // trace context uses hex

    let mut new_headers = Vec::with_capacity(headers.len());

    for line in headers {
        let h_lower = line.to_lowercase();
        if h_lower.starts_with("x-mac-machine-id:") || h_lower.starts_with("x-mac:") || h_lower.starts_with("x-machine-id:") {
            if let Some(dp) = &device_profile {
                let mac = &dp.mac_machine_id;
                let header_name = line.split(':').next().unwrap_or("x-mac-machine-id");
                new_headers.push(format!("{}: {}", header_name, mac));
                continue;
            }
            continue; // drop if no profile
        }
        if h_lower.starts_with("sqm-id:") {
            if let Some(dp) = &device_profile {
                let sqm = &dp.sqm_id;
                new_headers.push(format!("sqm-id: {}", sqm));
                continue;
            }
            continue; // drop if no profile
        }
        if h_lower.starts_with("vscode-sessionid:") {
            new_headers.push(format!("vscode-sessionid: {}", spoof_session_id));
            continue;
        }
        if h_lower.starts_with("x-cloud-trace-context:") || h_lower.starts_with("traceid:") {
            let header_name = line.split(':').next().unwrap_or("x-cloud-trace-context");
            new_headers.push(format!("{}: {}/1;o=1", header_name, spoof_trace_id));
            continue;
        }
        if h_lower.starts_with("cookie:") {
            // Air-gap cookies to avoid session linking
            continue;
        }
        if h_lower.starts_with("unleash-instanceid:") {
            // [OPSEC 7.1] Generate hostname-format instanceId to match native VS Code format
            let spoofed = account_id.map(|id| {
                let hash = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, id.as_bytes());
                let h = &hash.to_string()[..8];
                format!("DESKTOP-{}\\user-DESKTOP-{}", h.to_uppercase(), h.to_uppercase())
            }).unwrap_or_else(|| {
                let hash = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, b"AntigravityLocalMachine");
                let h = &hash.to_string()[..8];
                format!("DESKTOP-{}\\user-DESKTOP-{}", h.to_uppercase(), h.to_uppercase())
            });
            new_headers.push(format!("unleash-instanceid: {}", spoofed));
            continue;
        }
        if h_lower.starts_with("unleash-connection-id:") {
            let spoofed = account_id.map(|id| uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, id.as_bytes()).to_string()).unwrap_or_else(|| uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, b"AntigravityLocalMachine").to_string());
            new_headers.push(format!("unleash-connection-id: {}", spoofed));
            continue;
        }
        if h_lower.starts_with("user-agent:") {
            if h_lower.contains("antigravity/") {
                // [OPSEC V12] Case-insensitive User-Agent spoofing
                // Prevents leakage if the IDE sends "Antigravity/1.0" or "ANTIGRAVITY"
                static RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| regex::Regex::new(r"(?i)antigravity").unwrap());
                let spoofed = RE.replace_all(&line, "cloudcode").into_owned();
                new_headers.push(spoofed);
                continue;
            }
        }
        
        new_headers.push(line);
    }
    
    new_headers
}

fn spoof_unleash_body(host: &str, path: &str, body: Vec<u8>, account_id: Option<&str>) -> Vec<u8> {
    if !path.contains("/api/client/register") && !path.contains("/api/client/metrics") && !path.contains("/api/client/features") {
        return body;
    }
    
    if body.is_empty() {
        return body;
    }

    if let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(&body) {
        if let Some(obj) = json.as_object_mut() {
            // [OPSEC 7.1] Hostname-format instanceId matching native Go LS format
            let spoofed_instance_id = account_id.map(|id| {
                let hash = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, id.as_bytes());
                let h = &hash.to_string()[..8];
                format!("DESKTOP-{}\\user-DESKTOP-{}", h.to_uppercase(), h.to_uppercase())
            }).unwrap_or_else(|| {
                let hash = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, b"AntigravityLocalMachine");
                let h = &hash.to_string()[..8];
                format!("DESKTOP-{}\\user-DESKTOP-{}", h.to_uppercase(), h.to_uppercase())
            });
            let spoofed_conn_id = account_id.map(|id| uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, id.as_bytes()).to_string()).unwrap_or_else(|| uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, b"AntigravityLocalMachine").to_string());

            if obj.contains_key("instanceId") {
                obj.insert("instanceId".to_string(), serde_json::Value::String(spoofed_instance_id.clone()));
            }
            if obj.contains_key("connectionId") {
                obj.insert("connectionId".to_string(), serde_json::Value::String(spoofed_conn_id));
            }

            // [OPSEC V10] Per-account deterministic offset covers ±8 hours
            // This gives each account a stable, widely-spaced "process start time"
            // instead of ±5min random jitter that clusters around real system clock.
            if obj.contains_key("started") {
                let acct_seed = account_id.unwrap_or("default");
                let acct_hash = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, acct_seed.as_bytes());
                let offset_secs = (acct_hash.as_bytes()[0] as i64 * 225) - 28800; // ±8 hours, deterministic per account
                use rand::Rng;
                let noise = rand::thread_rng().gen_range(-60..60i64);
                let spoofed_time = chrono::Local::now() + chrono::Duration::seconds(offset_secs + noise);
                obj.insert("started".to_string(), serde_json::Value::String(spoofed_time.to_rfc3339_opts(chrono::SecondsFormat::Nanos, false)));
            }

            // [OPSEC 7.3] Also randomize bucket.start/stop timestamps in metrics
            if let Some(bucket) = obj.get_mut("bucket").and_then(|b| b.as_object_mut()) {
                let acct_seed = account_id.unwrap_or("default");
                let acct_hash = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, acct_seed.as_bytes());
                let offset_secs = (acct_hash.as_bytes()[1] as i64 * 225) - 28800;
                use rand::Rng;
                let noise = rand::thread_rng().gen_range(-60..60i64);
                let spoofed_time = chrono::Local::now() + chrono::Duration::seconds(offset_secs + noise);
                if bucket.contains_key("start") {
                    bucket.insert("start".to_string(), serde_json::Value::String(
                        (spoofed_time - chrono::Duration::seconds(60)).to_rfc3339_opts(chrono::SecondsFormat::Nanos, false)
                    ));
                }
                if bucket.contains_key("stop") {
                    bucket.insert("stop".to_string(), serde_json::Value::String(
                        spoofed_time.to_rfc3339_opts(chrono::SecondsFormat::Nanos, false)
                    ));
                }
            }

            tracing::debug!("[MITM] Scrubbed Unleash payload body for account ID: {:?}", account_id);
        }
        
        if let Ok(new_body) = serde_json::to_vec(&json) {
            return new_body;
        }
    }
    body
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
    // [OPSEC Phase 10] Prevent HTTP/2 downgrade fingerprinting for native Go services.
    // Unleash (api/client) and Clearcut (/log) use HTTP/2 natively via Go LS.
    // v1internal is Node.js and must stay HTTP/1.1.
    let allow_http2 = path.contains("/api/client") || path.contains("/log") || host.contains("play.googleapis.com");
    let client = proxy_pool.get_effective_standard_client(account_id, 30, allow_http2).await;
    
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
    // [OPSEC Phase 11] Ghost Cache Load Phase
    // Inject the valid caching headers specifically mapped to this Account + Path.
    if let Some(acc) = account_id {
        if let Ok(cache) = GHOST_CACHE.read() {
            let etag_key = format!("{}|{}|etag", acc, path);
            let lm_key = format!("{}|{}|last-modified", acc, path);
            
            if let Some(etag) = cache.get(&etag_key) {
                req_builder = req_builder.header("If-None-Match", etag);
                tracing::debug!("[GhostCache] Injected If-None-Match for {}", path);
            }
            if let Some(lm) = cache.get(&lm_key) {
                req_builder = req_builder.header("If-Modified-Since", lm);
                tracing::debug!("[GhostCache] Injected If-Modified-Since for {}", path);
            }
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
        // [OPSEC R5] Strip Server-Timing to defeat steganographic watermarking
        if k.as_str().eq_ignore_ascii_case("server-timing") { continue; }
        // [OPSEC Phase 10] Strip Alt-Svc to completely prevent QUIC/UDP MITM bypass (forces TCP)
        if k.as_str().eq_ignore_ascii_case("alt-svc") { continue; }

        // [OPSEC Phase 12] Chromium OS-Level Poison Prevention
        // Prevents Set-Cookie from infecting OS cookie jars across IDE restarts.
        if k.as_str().eq_ignore_ascii_case("set-cookie") { continue; }
        // Prevents Chromium from opening proxy-bypassing background sockets via HTTP Link.
        if k.as_str().eq_ignore_ascii_case("link") { continue; }

        // [OPSEC Phase 12] Trace Context Echo Prevention 
        // Eliminates backend mesh routing identifiers that could be echoed by the IDE's next ping.
        if k.as_str().eq_ignore_ascii_case("x-cloud-trace-context") { continue; }
        if k.as_str().eq_ignore_ascii_case("x-goog-hash") { continue; }
        if k.as_str().eq_ignore_ascii_case("x-goog-metageneration") { continue; }

        // [OPSEC Phase 11] Ghost Cache Save Phase
        // Save the authentic ETag and Last-Modified tied exclusively to this specific account state.
        // We DO NOT strip them here, letting the IDE cleanly cache them as native payloads.
        if let Some(acc) = account_id {
            if k.as_str().eq_ignore_ascii_case("etag") {
                if let Ok(mut cache) = GHOST_CACHE.write() {
                    cache.insert(format!("{}|{}|etag", acc, path), v.to_str().unwrap_or("").to_string());
                }
            } else if k.as_str().eq_ignore_ascii_case("last-modified") {
                if let Ok(mut cache) = GHOST_CACHE.write() {
                    cache.insert(format!("{}|{}|last-modified", acc, path), v.to_str().unwrap_or("").to_string());
                }
            }
        }

        // [OPSEC Phase 11] Spoof Trace ID to destroy telemetry loopbacks
        if k.as_str().eq_ignore_ascii_case("x-cloudaicompanion-trace-id") {
            let fake_trace_id = format!("{:016x}", rand::random::<u64>());
            out.extend_from_slice(k.as_str().as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(fake_trace_id.as_bytes());
            out.extend_from_slice(b"\r\n");
            continue;
        }
        
        out.extend_from_slice(k.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    
    let body_bytes = response.bytes().await?;

    // [OPSEC R3 + Phase 11] Deep JSON Inspection for PII & Caching Leaks
    let mut final_body = body_bytes.to_vec();

    if path.contains("loadCodeAssist") || path.contains("onboardUser") || path.contains("fetchAvailableModels") || path.contains("fetchUserInfo") || path.contains("cascadeNuxes") {
        if let Ok(mut json_val) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            
            fn spoof_response_data(v: &mut serde_json::Value, account_id: Option<&str>) {
                if let Some(obj) = v.as_object_mut() {
                    // 1. Spoof PII
                    if obj.contains_key("email") {
                        let acct_hash = account_id.unwrap_or("generic");
                        use sha2::{Digest, Sha256};
                        let mut hasher = Sha256::new();
                        hasher.update(acct_hash.as_bytes());
                        let result = format!("{:x}", hasher.finalize());
                        // [OPSEC V20] Use generic internal testing domain to avoid gmail correlation
                        let fake_email = format!("user.{}@local.dev", &result[0..6]);
                        obj.insert("email".to_string(), serde_json::json!(fake_email));
                    }
                    if obj.contains_key("fullName") {
                        obj.insert("fullName".to_string(), serde_json::json!("Developer Node"));
                    }
                    if obj.contains_key("gaiaId") {
                        // Generate a deterministic fake gaiaId based on the AccountID
                        let acct_hash = account_id.unwrap_or("generic");
                        use sha2::{Digest, Sha256};
                        let mut hasher = Sha256::new();
                        hasher.update(acct_hash.as_bytes());
                        let result = hasher.finalize();
                        let mut sum: u64 = 0;
                        for byte in &result[0..8] {
                            sum = (sum << 8) | (*byte as u64);
                        }
                        // Format it to look like a canonical gaiaId (21 digits)
                        let fake_gaia = format!("1{:020}", sum);
                        obj.insert("gaiaId".to_string(), serde_json::json!(fake_gaia));
                    }

                    // [OPSEC Phase 11] We NO LONGER eradicate experiment arrays here!
                    // Removing them breaks IDE UI elements. We pass them seamlessly into local state,
                    // relying on the outgoing Telemetry hook to strip cross-pollination.

                    for (_, val) in obj.iter_mut() {
                        spoof_response_data(val, account_id);
                    }
                } else if let Some(arr) = v.as_array_mut() {
                    for item in arr.iter_mut() {
                        spoof_response_data(item, account_id);
                    }
                }
            }

            spoof_response_data(&mut json_val, account_id);
            if let Ok(spoofed) = serde_json::to_vec(&json_val) {
                final_body = spoofed;
            }
        } else {
            // Fallback to strict regex if JSON parsing somehow fails for loadCodeAssist legacy upgrades
            let body_str = String::from_utf8_lossy(&body_bytes);
            let scrubbed = regex::Regex::new(r#"Email=[^&"]+"#)
                .map(|re| re.replace_all(&body_str, "Email=user%40example.com").to_string())
                .unwrap_or_else(|_| body_str.to_string());
            final_body = scrubbed.into_bytes();
        }
    }

    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", final_body.len()).as_bytes());
    out.extend_from_slice(&final_body);
    
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
                
                // [OPSEC Phase 11] Strip the locally cached Experiments from outgoing telemetry to prevent cross-account mapping!
                // The IDE cached Account A's experiments, but is making requests via Account B.
                // We empty it here so Account B's analytics remain clean of Account A's fingerprint.
                let exp_keys = ["clientExperiments", "experiments", "experimentIds", "activeExperiments"];
                for key in exp_keys.iter() {
                    if obj.contains_key(*key) {
                        obj.insert((*key).to_string(), serde_json::json!([]));
                    }
                }
            }

            // [OPSEC v2] Spoof identity fingerprints with per-account DeviceProfile
            // instead of removing fields (removal creates detectable anomalies).
            let device_profile = crate::modules::account::load_account(&proxy_token.account_id)
                .ok()
                .and_then(|acc| acc.device_profile);

            // [OPSEC 7.4] Use per-account cached sessionId instead of random UUID for consistency
            let spoof_session_id = crate::proxy::common::session::get_or_create_vscode_session_id(&proxy_token.account_id);

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

                    // [OPSEC Phase 10] Clamp Latency/Duration to hide MITM Proxy delays.
                    // Local Axum parsing + proxy rotation can add 2000ms-6000ms to a request.
                    // Go LS records this HTTP RTT as 'durationMs' or 'latency' and sends it.
                    // Google correlates this with server-side response times (~800ms) and detects the proxy.
                    let latency_keys = ["durationMs", "latencyMs", "latency", "roundTripTimeMs", "completionLatencyMs", "timeMs"];
                    for key in latency_keys.iter() {
                        if let Some(val) = obj.get_mut(*key) {
                            if let Some(num) = val.as_u64() {
                                // [OPSEC V22] If latency is suspiciously high (>1500ms), replace with
                                // log-normal distribution (median ~600ms) instead of uniform random
                                // to match natural API latency curves and avoid bimodal distribution.
                                if num > 1500 {
                                    use rand::Rng;
                                    let u: f64 = rand::thread_rng().gen_range(0.001..0.999_f64);
                                    // Box-Muller for log-normal: mu=6.4 (~600ms median), sigma=0.4
                                    let z = (-2.0 * (1.0 - u).ln()).sqrt() * (2.0 * std::f64::consts::PI * u).cos();
                                    let log_normal = (6.4 + 0.4 * z).exp();
                                    let realistic_ms = (log_normal as u64).clamp(200, 1400);
                                    *val = serde_json::json!(realistic_ms);
                                    tracing::debug!("[MITM] Spoofed suspected high latency {} from {} to {}", key, num, realistic_ms);
                                }
                            }
                        }
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
