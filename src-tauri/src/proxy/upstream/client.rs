// ä¸Šæ¸¸å®¢æˆ·ç«¯å®žçŽ°
// åŸºäºŽé«˜æ€§èƒ½é€šè®¯æŽ¥å£å°è£…

use dashmap::DashMap;
use rquest::{header, Client, Response, StatusCode};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Duration;

/// ç«¯ç‚¹é™çº§å°è¯•çš„è®°å½•ä¿¡æ¯
#[derive(Debug, Clone)]
pub struct FallbackAttemptLog {
    /// å°è¯•çš„ç«¯ç‚¹ URL
    pub endpoint_url: String,
    /// HTTP çŠ¶æ€ç  (ç½‘ç»œé”™è¯¯æ—¶ä¸º None)
    pub status: Option<u16>,
    /// é”™è¯¯æè¿°
    pub error: String,
}

/// ä¸Šæ¸¸è°ƒç”¨ç»“æžœï¼ŒåŒ…å«å“åº”å’Œé™çº§å°è¯•è®°å½•
pub struct UpstreamCallResult {
    /// æœ€ç»ˆçš„ HTTP å“åº”
    pub response: Response,
    /// é™çº§è¿‡ç¨‹ä¸­å¤±è´¥çš„ç«¯ç‚¹å°è¯•è®°å½• (æˆåŠŸæ—¶ä¸ºç©º)
    pub fallback_attempts: Vec<FallbackAttemptLog>,
}

/// 邮箱脱敏：只显示前3位 + *** + @域名前2位 + ***
/// 例: "userexample@gmail.com" → "use***@gm***"
pub fn mask_email(email: &str) -> String {
    if let Some(at_pos) = email.find('@') {
        let local = &email[..at_pos];
        let domain = &email[at_pos + 1..];
        let local_prefix: String = local.chars().take(3).collect();
        let domain_prefix: String = domain.chars().take(2).collect();
        format!("{}***@{}***", local_prefix, domain_prefix)
    } else {
        // 不是合法邮箱格式，直接截取前5位
        let prefix: String = email.chars().take(5).collect();
        format!("{}***", prefix)
    }
}

/// [NEW] 错误日志脱敏：抹除报错信息中的 access_token, proxy_url 等敏感凭证
#[allow(dead_code)]
pub fn sanitize_error_for_log(error_text: &str) -> String {
    // 抹除常见敏感 key 的值
    let re = regex::Regex::new(r#"(?i)(access_token|refresh_token|id_token|authorization|api_key|secret|password|proxy_url|http_proxy|https_proxy)\s*[:=]\s*[^"'\\\s,}\]]+"#).unwrap();
    let redacted_1 = re.replace_all(error_text, "$1=<redacted>");
    
    // 抹除 Bearer token
    let re_bearer = regex::Regex::new(r#"(?i)(bearer\s+)[^"'\\\s,}\]]+"#).unwrap();
    let redacted_2 = re_bearer.replace_all(&redacted_1, "$1<redacted>");
    
    // é™ åˆ¶é•¿åº¦é˜²æ­¢æ—¥å¿—ç‚¸å¼¹
    if redacted_2.len() > 1000 {
        format!("{}... (truncated)", &redacted_2[..1000])
    } else {
        redacted_2.into_owned()
    }
}

// Cloud Code v1internal endpoints (fallback order: Sandbox â†’ Daily â†’ Prod)
// ä¼˜å…ˆä½¿ç”¨ Sandbox/Daily çŽ¯å¢ƒä»¥é ¿å…  ProdçŽ¯å¢ƒçš„ 429 é”™è¯¯ (Ref: Issue #1176)
const V1_INTERNAL_BASE_URL_PROD: &str = "https://cloudcode-pa.googleapis.com/v1internal";
const V1_INTERNAL_BASE_URL_DAILY: &str = "https://daily-cloudcode-pa.googleapis.com/v1internal";
const V1_INTERNAL_BASE_URL_SANDBOX: &str =
    "https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal";

const V1_INTERNAL_BASE_URL_FALLBACKS: [&str; 3] = [
    V1_INTERNAL_BASE_URL_SANDBOX, // ä¼˜å…ˆçº§ 1: Sandbox (å·²çŸ¥æœ‰æ•ˆä¸”ç¨³å®š)
    V1_INTERNAL_BASE_URL_DAILY,   // ä¼˜å…ˆçº§ 2: Daily (å¤‡ç”¨)
    V1_INTERNAL_BASE_URL_PROD,    // ä¼˜å…ˆçº§ 3: Prod (ä»…ä½œä¸ºå…œåº•)
];

/// Deterministic FNV-1a based hash producing a 32-char hex string.
/// Used as a stable machine-id surrogate when no DeviceProfile is available.
fn md5_like_hash(data: &[u8]) -> u128 {
    let mut hash: u128 = 0xcbf29ce484222325_u128.wrapping_mul(0x100000001b3);
    for &byte in data {
        hash ^= byte as u128;
        hash = hash.wrapping_mul(0x01000000000000000000013b);
    }
    hash
}

pub struct UpstreamClient {
    default_client: Client,
    proxy_pool: Option<Arc<crate::proxy::proxy_pool::ProxyPoolManager>>,
    client_cache: DashMap<String, Client>, // proxy_id -> Client
    user_agent_override: RwLock<Option<String>>,
}

impl UpstreamClient {
    pub fn new(
        proxy_config: Option<crate::proxy::config::UpstreamProxyConfig>,
        proxy_pool: Option<Arc<crate::proxy::proxy_pool::ProxyPoolManager>>,
    ) -> Self {
        let default_client = match Self::build_client_internal(proxy_config.clone()) {
            Ok(client) => client,
            Err(err_with_proxy) => {
                tracing::error!(
                    error = %err_with_proxy,
                    "Failed to create default HTTP client with configured upstream proxy; retrying without proxy"
                );
                match Self::build_client_internal(None) {
                    Ok(client) => client,
                    Err(err_without_proxy) => {
                        tracing::error!(
                            error = %err_without_proxy,
                            "Failed to create default HTTP client without proxy; falling back to bare client"
                        );
                        Client::new()
                    }
                }
            }
        };

        Self {
            default_client,
            proxy_pool,
            client_cache: DashMap::new(),
            user_agent_override: RwLock::new(None),
        }
    }

    /// Internal helper to build a client with optional upstream proxy config
    fn build_client_internal(
        proxy_config: Option<crate::proxy::config::UpstreamProxyConfig>,
    ) -> Result<Client, rquest::Error> {
        let mut builder = Client::builder()
            .emulation(rquest_util::Emulation::Chrome123)
            // Connection settings (ä¼˜åŒ–è¿žæŽ¥å¤ç”¨ï¼Œå‡å°‘å»ºç«‹å¼€é”€)
            .connect_timeout(Duration::from_secs(20))
            .pool_max_idle_per_host(20) // æ¯ä¸»æœºæœ€å¤š 20 ä¸ªç©ºé—²è¿žæŽ¥ (å¯¹é½å®˜æ–¹æŒ‡çº¹)
            .pool_idle_timeout(Duration::from_secs(90)) // ç©ºé—²è¿žæŽ¥ä¿æŒ 90 ç§’
            .tcp_keepalive(Duration::from_secs(60)) // TCP ä¿æ´»æŽ¢æµ‹ 60 ç§’
            // å¼ºåˆ¶å¼€å¯ HTTP/2 åè®®ï¼Œå¹¶æ”¯æŒåœ¨ SOCKS/HTTPS ä»£ç†ä¸‹é€šè¿‡ ALPN å¼ºåˆ¶é™çº§/åå•†
            .timeout(Duration::from_secs(600));

        builder = Self::apply_default_user_agent(builder);

        if let Some(config) = proxy_config {
            if config.enabled && !config.url.is_empty() {
                let url = crate::proxy::config::normalize_proxy_url(&config.url);
                if let Ok(proxy) = rquest::Proxy::all(&url) {
                    builder = builder.proxy(proxy);
                    tracing::info!("UpstreamClient enabled proxy: {}", url);
                }
            }
        }

        builder.build()
    }

    /// Build a client with a specific PoolProxyConfig (from ProxyPool)
    fn build_client_with_proxy(
        &self,
        proxy_config: crate::proxy::proxy_pool::PoolProxyConfig,
    ) -> Result<Client, rquest::Error> {
        // Reuse base settings similar to default client but with specific proxy
        let builder = Client::builder()
            .emulation(rquest_util::Emulation::Chrome123)
            .connect_timeout(Duration::from_secs(20))
            .pool_max_idle_per_host(20)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(60))
            .timeout(Duration::from_secs(600))
            .proxy(proxy_config.proxy); // Apply the specific proxy

        Self::apply_default_user_agent(builder).build()
    }

    fn apply_default_user_agent(builder: rquest::ClientBuilder) -> rquest::ClientBuilder {
        let ua = crate::constants::USER_AGENT.as_str();
        if header::HeaderValue::from_str(ua).is_ok() {
            builder.user_agent(ua)
        } else {
            tracing::warn!(
                user_agent = %ua,
                "Invalid default User-Agent value, using fallback"
            );
            builder.user_agent("antigravity")
        }
    }

    /// Set dynamic User-Agent override
    pub async fn set_user_agent_override(&self, ua: Option<String>) {
        let mut lock = self.user_agent_override.write().await;
        *lock = ua;
        tracing::debug!("UpstreamClient User-Agent override updated: {:?}", lock);
    }

    /// Get current User-Agent
    pub async fn get_user_agent(&self) -> String {
        let ua_override = self.user_agent_override.read().await;
        ua_override
            .as_ref()
            .cloned()
            .unwrap_or_else(|| crate::constants::USER_AGENT.clone())
    }

    /// Get client for a specific account (or default if no proxy bound)
    pub async fn get_client(&self, account_id: Option<&str>) -> Client {
        if let Some(pool) = &self.proxy_pool {
            if let Some(acc_id) = account_id {
                // Try to get per-account proxy
                match pool.get_proxy_for_account(acc_id).await {
                    Ok(Some(proxy_cfg)) => {
                        // Check cache
                        if let Some(client) = self.client_cache.get(&proxy_cfg.entry_id) {
                            return client.clone();
                        }
                        // Build new client and cache it
                        match self.build_client_with_proxy(proxy_cfg.clone()) {
                            Ok(client) => {
                                self.client_cache
                                    .insert(proxy_cfg.entry_id.clone(), client.clone());
                                tracing::info!(
                                    "Using ProxyPool proxy ID: {} for account: {}",
                                    proxy_cfg.entry_id,
                                    acc_id
                                );
                                return client;
                            }
                            Err(e) => {
                                tracing::error!("Failed to build client for proxy {}: {}, falling back to default", proxy_cfg.entry_id, e);
                            }
                        }
                    }
                    Ok(None) => {
                        // No proxy found or required for this account, use default
                    }
                    Err(e) => {
                        tracing::error!(
                            "Error getting proxy for account {}: {}, falling back to default",
                            acc_id,
                            e
                        );
                    }
                }
            }
        }
        // Fallback to default client
        self.default_client.clone()
    }

    /// Build v1internal URL
    fn build_url(base_url: &str, method: &str, query_string: Option<&str>) -> String {
        if let Some(qs) = query_string {
            format!("{}:{}?{}", base_url, method, qs)
        } else {
            format!("{}:{}", base_url, method)
        }
    }

    /// Determine if we should try next endpoint (fallback logic)
    fn should_try_next_endpoint(status: StatusCode) -> bool {
        status == StatusCode::TOO_MANY_REQUESTS
            || status == StatusCode::REQUEST_TIMEOUT
            || status == StatusCode::NOT_FOUND
            || status.is_server_error()
    }

    /// Call v1internal API (Basic Method)
    ///
    /// Initiates a basic network request, supporting multi-endpoint auto-fallback.
    /// [UPDATED] Takes optional account_id for per-account proxy selection.
    pub async fn call_v1_internal(
        &self,
        method: &str,
        access_token: &str,
        body: Value,
        query_string: Option<&str>,
        account_id: Option<&str>, device_profile: Option<crate::models::account::DeviceProfile>,
    ) -> Result<UpstreamCallResult, String> {
        self.call_v1_internal_with_headers(
            method,
            access_token,
            body,
            query_string,
            std::collections::HashMap::new(),
            account_id,
            device_profile,
        )
        .await
    }

    /// [FIX #765] è°ƒç”¨ v1internal APIï¼Œæ”¯æŒé€ä¼ é¢å¤–çš„ Headers
    /// [ENHANCED] è¿”å›ž UpstreamCallResultï¼ŒåŒ…å«é™çº§å°è¯•è®°å½•ï¼Œç”¨äºŽ debug æ—¥å¿—
    pub async fn call_v1_internal_with_headers(
        &self,
        method: &str,
        access_token: &str,
        body: Value,
        query_string: Option<&str>,
        extra_headers: std::collections::HashMap<String, String>,
        account_id: Option<&str>, device_profile: Option<crate::models::account::DeviceProfile>,
    ) -> Result<UpstreamCallResult, String> {
        // [NEW] Get client based on account (cached in proxy pool manager)
        let client = self.get_client(account_id).await;

        // æž„å»º Headers (æ‰€æœ‰ç«¯ç‚¹å¤ ç”¨)
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!("Bearer {}", access_token))
                .map_err(|e| e.to_string())?,
        );

        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_str(&self.get_user_agent().await).unwrap_or_else(|e| {
                tracing::warn!("Invalid User-Agent header value, using fallback: {}", e);
                header::HeaderValue::from_static("antigravity")
            }),
        );

        // [OPSEC FIX] Match canonical IDE request headers exactly.
        // Verified via MITM capture (c:\test\deep_v1internal.txt): the canonical IDE sends
        // accept: */* and accept-encoding: gzip, deflate, br on ALL v1internal requests.
        // It does NOT send: x-client-name, x-client-version, x-machine-id, sqm-id,
        // x-vscode-sessionid. Those are LS-layer headers handled by MITM forward_proxy.
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("*/*"),
        );
        headers.insert(
            header::ACCEPT_ENCODING,
            header::HeaderValue::from_static("gzip, deflate, br"),
        );

        // [RESTORED] Contextual Spoofing (IDE vs LS)
        // If the upstream handler detected an x-goog-api-client header (IDE traffic), we must pass it.
        // If it's missing (Language Server traffic), we omit it to avoid "chimera" profile generation.
        if let Some(api_client) = extra_headers.get("x-goog-api-client") {
            if let Ok(api_val) = header::HeaderValue::from_str(api_client) {
                headers.insert("x-goog-api-client", api_val);
            }
        }

        // [NEW] æ·±åº¦è§£æž body ä¸­çš„ project_id å¹¶æ³¨å…¥ Header
        // åªæœ‰å½“ Body åŒ…å« project å­—æ®µä¸”éžæµ‹è¯•é¡¹ç›®æ—¶ï¼Œæ³¨å…¥ x-goog-user-project
        if let Some(proj) = body.get("project").and_then(|v| v.as_str()) {
            if !proj.is_empty() && proj != "test-project" && proj != "project-id" {
                if let Ok(hv) = header::HeaderValue::from_str(proj) {
                    headers.insert("x-goog-user-project", hv);
                }
            }
        }

        // æ³¨å…¥é¢å¤–çš„ Headers (å¦‚ anthropic-beta)
        for (k, v) in extra_headers {
            if let Ok(hk) = header::HeaderName::from_bytes(k.as_bytes()) {
                if let Ok(hv) = header::HeaderValue::from_str(&v) {
                    headers.insert(hk, hv);
                }
            }
        }

        // [DEBUG] Log headers for verification
        tracing::debug!(?headers, "Final Upstream Request Headers");

        let mut last_err: Option<String> = None;
        // [NEW] æ”¶é›†é™çº§å°è¯•è®°å½•
        let mut fallback_attempts: Vec<FallbackAttemptLog> = Vec::new();

        // éåŽ†æ‰€æœ‰ç«¯ç‚¹ï¼Œå¤±è´¥æ—¶è‡ªåŠ¨åˆ‡æ¢
        for (idx, base_url) in V1_INTERNAL_BASE_URL_FALLBACKS.iter().enumerate() {
            let url = Self::build_url(base_url, method, query_string);
            let has_next = idx + 1 < V1_INTERNAL_BASE_URL_FALLBACKS.len();

            let body_bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;

            let response = client
                .post(&url)
                .headers(headers.clone())
                // [NEW] å¼ºåˆ¶åˆ†å—ä¼ è¾“ä»¿çœŸ: åŒ…è£…ä¸ºæµä»¥è§¦å‘ Transfer-Encoding: chunked
                // è¿™å¯¹é½äº†å®˜æ–¹ Go Worker é€šè¿‡é®è”½ Content-Length æ¥æ¨¡æ‹Ÿ IDE æµé‡çš„è¡Œä¸º
                .body(rquest::Body::wrap_stream(futures::stream::once(async move { 
                    Ok::<_, std::io::Error>(body_bytes) 
                })))
                .send()
                .await;

            match response {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        if idx > 0 {
                            tracing::info!(
                                "âœ“ Upstream fallback succeeded | Endpoint: {} | Status: {} | Next endpoints available: {}",
                                base_url,
                                status,
                                V1_INTERNAL_BASE_URL_FALLBACKS.len() - idx - 1
                            );
                        } else {
                            tracing::debug!(
                                "âœ“ Upstream request succeeded | Endpoint: {} | Status: {}",
                                base_url,
                                status
                            );
                        }
                        return Ok(UpstreamCallResult {
                            response: resp,
                            fallback_attempts,
                        });
                    }

                    // å¦‚æžœæœ‰ä¸‹ä¸€ä¸ªç«¯ç‚¹ä¸”å½“å‰é”™è¯¯å¯é‡è¯•ï¼Œåˆ™åˆ‡æ¢
                    if has_next && Self::should_try_next_endpoint(status) {
                        let err_msg = format!("Upstream {} returned {}", base_url, status);
                        tracing::warn!(
                            "Upstream endpoint returned {} at {} (method={}), trying next endpoint",
                            status,
                            base_url,
                            method
                        );
                        // [NEW] è®°å½•é™çº§å°è¯•
                        fallback_attempts.push(FallbackAttemptLog {
                            endpoint_url: url.clone(),
                            status: Some(status.as_u16()),
                            error: err_msg.clone(),
                        });
                        last_err = Some(err_msg);
                        continue;
                    }

                    // ä¸å¯é‡è¯•çš„é”™è¯¯æˆ–å·²æ˜¯æœ€åŽä¸€ä¸ªç«¯ç‚¹ï¼Œç›´æŽ¥è¿”å›ž
                    return Ok(UpstreamCallResult {
                        response: resp,
                        fallback_attempts,
                    });
                }
                Err(e) => {
                    let msg = format!("HTTP request failed at {}: {}", base_url, e);
                    tracing::debug!("{}", msg);
                    // [NEW] è®°å½•ç½‘ç»œé”™è¯¯çš„é™çº§å°è¯•
                    fallback_attempts.push(FallbackAttemptLog {
                        endpoint_url: url.clone(),
                        status: None,
                        error: msg.clone(),
                    });
                    last_err = Some(msg);

                    // å¦‚æžœæ˜¯æœ€åŽä¸€ä¸ªç«¯ç‚¹ï¼Œé€€å‡ºå¾ªçŽ¯
                    if !has_next {
                        break;
                    }
                    continue;
                }
            }
        }

        Err(last_err.unwrap_or_else(|| "All endpoints failed".to_string()))
    }

    /// è°ƒç”¨ v1internal APIï¼ˆå¸¦ 429 é‡è¯•,æ”¯æŒé—­åŒ…ï¼‰
    ///
    /// å¸¦å®¹é”™å’Œé‡è¯•çš„æ ¸å¿ƒè¯·æ±‚é€»è¾‘
    ///
    /// # Arguments
    /// * `method` - API method (e.g., "generateContent")
    /// * `query_string` - Optional query string (e.g., "?alt=sse")
    /// * `get_credentials` - é—­åŒ…ï¼ŒèŽ·å–å‡­è¯ï¼ˆæ”¯æŒè´¦å·è½®æ¢ï¼‰
    /// * `build_body` - é—­åŒ…ï¼ŒæŽ¥æ”¶ project_id æž„å»ºè¯·æ±‚ä½“
    /// * `max_attempts` - æœ€å¤§é‡è¯•æ¬¡æ•°
    ///
    /// # Returns
    /// HTTP Response
    // å·²ç§»é™¤å¼ƒç”¨çš„é‡è¯•æ–¹æ³• (call_v1_internal_with_retry)

    // å·²ç§»é™¤å¼ƒç”¨çš„è¾…åŠ©æ–¹æ³• (parse_retry_delay)

    // å·²ç§»é™¤å¼ƒç”¨çš„è¾…åŠ©æ–¹æ³• (parse_duration_ms)

    /// èŽ·å–å¯ç”¨æ¨¡åž‹åˆ—è¡¨
    ///
    /// èŽ·å–è¿œç«¯æ¨¡åž‹åˆ—è¡¨ï¼Œæ”¯æŒå¤šç«¯ç‚¹è‡ªåŠ¨ Fallback
    #[allow(dead_code)] // API ready for future model discovery feature
    pub async fn fetch_available_models(
        &self,
        access_token: &str,
        account_id: Option<&str>,
    ) -> Result<Value, String> {
        // å¤ç”¨ call_v1_internalï¼Œç„¶åŽè§£æž JSON
        let result = self
            .call_v1_internal(
                "fetchAvailableModels",
                access_token,
                serde_json::json!({}),
                None,
                account_id,
                None, // No device_profile needed for model discovery
            )
            .await?;
        let json: Value = result
            .response
            .json()
            .await
            .map_err(|e| format!("Parse json failed: {}", e))?;
        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_url() {
        let base_url = "https://cloudcode-pa.googleapis.com/v1internal";

        let url1 = UpstreamClient::build_url(base_url, "generateContent", None);
        assert_eq!(
            url1,
            "https://cloudcode-pa.googleapis.com/v1internal:generateContent"
        );

        let url2 = UpstreamClient::build_url(base_url, "streamGenerateContent", Some("alt=sse"));
        assert_eq!(
            url2,
            "https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse"
        );
    }
}
