// Ã¤Â¸Å Ã¦Â¸Â¸Ã¥Â®Â¢Ã¦Ë†Â·Ã§Â«Â¯Ã¥Â®Å¾Ã§Å½Â°
// Ã¥Å¸ÂºÃ¤ÂºÅ½Ã©Â«ËœÃ¦â‚¬Â§Ã¨Æ’Â½Ã©â‚¬Å¡Ã¨Â®Â¯Ã¦Å½Â¥Ã¥ÂÂ£Ã¥Â°ÂÃ¨Â£â€¦

use dashmap::DashMap;
use rquest::{header, Client, Response, StatusCode};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Duration;

/// Ã§Â«Â¯Ã§â€šÂ¹Ã©â„¢ÂÃ§ÂºÂ§Ã¥Â°ÂÃ¨Â¯â€¢Ã§Å¡â€žÃ¨Â®Â°Ã¥Â½â€¢Ã¤Â¿Â¡Ã¦ÂÂ¯
#[derive(Debug, Clone)]
pub struct FallbackAttemptLog {
    // Ã¥Â°ÂÃ¨Â¯â€¢Ã§Å¡â€žÃ§Â«Â¯Ã§â€šÂ¹ URL
    pub endpoint_url: String,
    // HTTP Ã§Å Â¶Ã¦â‚¬ÂÃ§Â Â (Ã§Â½â€˜Ã§Â»Å“Ã©â€â„¢Ã¨Â¯Â¯Ã¦â€”Â¶Ã¤Â¸Âº None)
    pub status: Option<u16>,
    // Ã©â€â„¢Ã¨Â¯Â¯Ã¦ÂÂÃ¨Â¿Â°
    pub error: String,
}

/// Ã¤Â¸Å Ã¦Â¸Â¸Ã¨Â°Æ’Ã§â€Â¨Ã§Â»â€œÃ¦Å¾Å“Ã¯Â¼Å’Ã¥Å’â€¦Ã¥ÂÂ«Ã¥â€œÂÃ¥Âºâ€Ã¥â€™Å’Ã©â„¢ÂÃ§ÂºÂ§Ã¥Â°ÂÃ¨Â¯â€¢Ã¨Â®Â°Ã¥Â½â€¢
pub struct UpstreamCallResult {
    // Ã¦Å“â‚¬Ã§Â»Ë†Ã§Å¡â€ž HTTP Ã¥â€œÂÃ¥Âºâ€
    pub response: Response,
    // Ã©â„¢ÂÃ§ÂºÂ§Ã¨Â¿â€¡Ã§Â¨â€¹Ã¤Â¸Â­Ã¥Â¤Â±Ã¨Â´Â¥Ã§Å¡â€žÃ§Â«Â¯Ã§â€šÂ¹Ã¥Â°ÂÃ¨Â¯â€¢Ã¨Â®Â°Ã¥Â½â€¢ (Ã¦Ë†ÂÃ¥Å Å¸Ã¦â€”Â¶Ã¤Â¸ÂºÃ§Â©Âº)
    pub fallback_attempts: Vec<FallbackAttemptLog>,
}

/// é‚®ç®±è„±æ•ï¼šåªæ˜¾ç¤ºå‰3ä½ + *** + @åŸŸåå‰2ä½ + ***
/// ä¾‹: "userexample@gmail.com" â†’ "use***@gm***"
pub fn mask_email(email: &str) -> String {
    if let Some(at_pos) = email.find('@') {
        let local = &email[..at_pos];
        let domain = &email[at_pos + 1..];
        let local_prefix: String = local.chars().take(3).collect();
        let domain_prefix: String = domain.chars().take(2).collect();
        format!("{}***@{}***", local_prefix, domain_prefix)
    } else {
        // ä¸æ˜¯åˆæ³•é‚®ç®±æ ¼å¼ï¼Œç›´æŽ¥æˆªå–å‰5ä½
        let prefix: String = email.chars().take(5).collect();
        format!("{}***", prefix)
    }
}

/// [NEW] é”™è¯¯æ—¥å¿—è„±æ•ï¼šæŠ¹é™¤æŠ¥é”™ä¿¡æ¯ä¸­çš„ access_token, proxy_url ç­‰æ•æ„Ÿå‡­è¯
#[allow(dead_code)]
pub fn sanitize_error_for_log(error_text: &str) -> String {
    // æŠ¹é™¤å¸¸è§æ•æ„Ÿ key çš„å€¼
    let re = regex::Regex::new(r#"(?i)(access_token|refresh_token|id_token|authorization|api_key|secret|password|proxy_url|http_proxy|https_proxy)\s*[:=]\s*[^"'\\\s,}\]]+"#).unwrap();
    let redacted_1 = re.replace_all(error_text, "$1=<redacted>");

    // æŠ¹é™¤ Bearer token
    let re_bearer = regex::Regex::new(r#"(?i)(bearer\s+)[^"'\\\s,}\]]+"#).unwrap();
    let redacted_2 = re_bearer.replace_all(redacted_1.as_ref(), "$1<redacted>");

    // é™åˆ¶é•¿åº¦é˜²æ­¢æ—¥å¿—ç‚¸å¼¹
    if redacted_2.len() > 1000 {
        format!("{}... (truncated)", &redacted_2[..1000])
    } else {
        redacted_2.into_owned()
    }
}

// Cloud Code v1internal endpoints (fallback order: Sandbox Ã¢â€ â€™ Daily Ã¢â€ â€™ Prod)
// Ã¤Â¼ËœÃ¥â€¦Ë†Ã¤Â½Â¿Ã§â€Â¨ Sandbox/Daily Ã§Å½Â¯Ã¥Â¢Æ’Ã¤Â»Â¥Ã© Â¿Ã¥â€¦  ProdÃ§Å½Â¯Ã¥Â¢Æ’Ã§Å¡â€ž 429 Ã©â€â„¢Ã¨Â¯Â¯ (Ref: Issue #1176)
const V1_INTERNAL_BASE_URL_PROD: &str = "https://cloudcode-pa.googleapis.com/v1internal";
const V1_INTERNAL_BASE_URL_DAILY: &str = "https://daily-cloudcode-pa.googleapis.com/v1internal";
const V1_INTERNAL_BASE_URL_SANDBOX: &str =
    "https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal";

const V1_INTERNAL_BASE_URL_FALLBACKS: [&str; 3] = [
    V1_INTERNAL_BASE_URL_SANDBOX, // Ã¤Â¼ËœÃ¥â€¦Ë†Ã§ÂºÂ§ 1: Sandbox (Ã¥Â·Â²Ã§Å¸Â¥Ã¦Å“â€°Ã¦â€¢Ë†Ã¤Â¸â€Ã§Â¨Â³Ã¥Â®Å¡)
    V1_INTERNAL_BASE_URL_DAILY,   // Ã¤Â¼ËœÃ¥â€¦Ë†Ã§ÂºÂ§ 2: Daily (Ã¥Â¤â€¡Ã§â€Â¨)
    V1_INTERNAL_BASE_URL_PROD,    // Ã¤Â¼ËœÃ¥â€¦Ë†Ã§ÂºÂ§ 3: Prod (Ã¤Â»â€¦Ã¤Â½Å“Ã¤Â¸ÂºÃ¥â€¦Å“Ã¥Âºâ€¢)
];

/// Deterministic FNV-1a based hash producing a 32-char hex string.
/// Used as a stable machine-id surrogate when no DeviceProfile is available.
#[allow(dead_code)]
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

    // Internal helper to build a client with optional upstream proxy config
    fn build_client_internal(
        proxy_config: Option<crate::proxy::config::UpstreamProxyConfig>,
    ) -> Result<Client, rquest::Error> {
        let mut builder = Client::builder()
            .emulation(rquest_util::Emulation::Chrome123)
            // Connection settings (Ã¤Â¼ËœÃ¥Å’â€“Ã¨Â¿Å¾Ã¦Å½Â¥Ã¥Â¤ÂÃ§â€Â¨Ã¯Â¼Å’Ã¥â€¡ÂÃ¥Â°â€˜Ã¥Â»ÂºÃ§Â«â€¹Ã¥Â¼â‚¬Ã©â€â‚¬)
            .connect_timeout(Duration::from_secs(20))
            .pool_max_idle_per_host(20) // Ã¦Â¯ÂÃ¤Â¸Â»Ã¦Å“ÂºÃ¦Å“â‚¬Ã¥Â¤Å¡ 20 Ã¤Â¸ÂªÃ§Â©ÂºÃ©â€”Â²Ã¨Â¿Å¾Ã¦Å½Â¥ (Ã¥Â¯Â¹Ã©Â½ÂÃ¥Â®ËœÃ¦â€“Â¹Ã¦Å’â€¡Ã§ÂºÂ¹)
            .pool_idle_timeout(Duration::from_secs(90)) // Ã§Â©ÂºÃ©â€”Â²Ã¨Â¿Å¾Ã¦Å½Â¥Ã¤Â¿ÂÃ¦Å’Â 90 Ã§Â§â€™
            .tcp_keepalive(Duration::from_secs(60)) // TCP Ã¤Â¿ÂÃ¦Â´Â»Ã¦Å½Â¢Ã¦Âµâ€¹ 60 Ã§Â§â€™
            // Ã¥Â¼ÂºÃ¥Ë†Â¶Ã¥Â¼â‚¬Ã¥ÂÂ¯ HTTP/2 Ã¥ÂÂÃ¨Â®Â®Ã¯Â¼Å’Ã¥Â¹Â¶Ã¦â€Â¯Ã¦Å’ÂÃ¥Å“Â¨ SOCKS/HTTPS Ã¤Â»Â£Ã§Ââ€ Ã¤Â¸â€¹Ã©â‚¬Å¡Ã¨Â¿â€¡ ALPN Ã¥Â¼ÂºÃ¥Ë†Â¶Ã©â„¢ÂÃ§ÂºÂ§/Ã¥ÂÂÃ¥â€¢â€ 
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

    // Build a client with a specific PoolProxyConfig (from ProxyPool)
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

    // Set dynamic User-Agent override
    pub async fn set_user_agent_override(&self, ua: Option<String>) {
        let mut lock = self.user_agent_override.write().await;
        *lock = ua;
        tracing::debug!("UpstreamClient User-Agent override updated: {:?}", lock);
    }

    // Get current User-Agent
    pub async fn get_user_agent(&self) -> String {
        let ua_override = self.user_agent_override.read().await;
        ua_override
            .as_ref()
            .cloned()
            .unwrap_or_else(|| crate::constants::USER_AGENT.clone())
    }

    // Get client for a specific account (or default if no proxy bound)
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

    // Build v1internal URL
    fn build_url(base_url: &str, method: &str, query_string: Option<&str>) -> String {
        if let Some(qs) = query_string {
            format!("{}:{}?{}", base_url, method, qs)
        } else {
            format!("{}:{}", base_url, method)
        }
    }

    // Determine if we should try next endpoint (fallback logic)
    fn should_try_next_endpoint(status: StatusCode) -> bool {
        status == StatusCode::TOO_MANY_REQUESTS
            || status == StatusCode::REQUEST_TIMEOUT
            || status == StatusCode::NOT_FOUND
            || status.is_server_error()
    }

    // Call v1internal API (Basic Method)
    //
    // Initiates a basic network request, supporting multi-endpoint auto-fallback.
    // [UPDATED] Takes optional account_id for per-account proxy selection.
    pub async fn call_v1_internal(
        &self,
        method: &str,
        access_token: &str,
        body: Value,
        query_string: Option<&str>,
        account_id: Option<&str>,
        device_profile: Option<crate::models::account::DeviceProfile>,
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

    // [FIX #765] Ã¨Â°Æ’Ã§â€Â¨ v1internal APIÃ¯Â¼Å’Ã¦â€Â¯Ã¦Å’ÂÃ©â‚¬ÂÃ¤Â¼Â Ã©Â¢ÂÃ¥Â¤â€“Ã§Å¡â€ž Headers
    // [ENHANCED] Ã¨Â¿â€Ã¥â€ºÅ¾ UpstreamCallResultÃ¯Â¼Å’Ã¥Å’â€¦Ã¥ÂÂ«Ã©â„¢ÂÃ§ÂºÂ§Ã¥Â°ÂÃ¨Â¯â€¢Ã¨Â®Â°Ã¥Â½â€¢Ã¯Â¼Å’Ã§â€Â¨Ã¤ÂºÅ½ debug Ã¦â€”Â¥Ã¥Â¿â€”
    #[allow(clippy::too_many_arguments)]
    pub async fn call_v1_internal_with_headers(
        &self,
        method: &str,
        access_token: &str,
        body: Value,
        query_string: Option<&str>,
        extra_headers: std::collections::HashMap<String, String>,
        account_id: Option<&str>,
        _device_profile: Option<crate::models::account::DeviceProfile>,
    ) -> Result<UpstreamCallResult, String> {
        // [NEW] Get client based on account (cached in proxy pool manager)
        let client = self.get_client(account_id).await;

        // Ã¦Å¾â€žÃ¥Â»Âº Headers (Ã¦â€°â‚¬Ã¦Å“â€°Ã§Â«Â¯Ã§â€šÂ¹Ã¥Â¤ Ã§â€Â¨)
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
        headers.insert(header::ACCEPT, header::HeaderValue::from_static("*/*"));
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

        // [NEW] Ã¦Â·Â±Ã¥ÂºÂ¦Ã¨Â§Â£Ã¦Å¾Â body Ã¤Â¸Â­Ã§Å¡â€ž project_id Ã¥Â¹Â¶Ã¦Â³Â¨Ã¥â€¦Â¥ Header
        // Ã¥ÂÂªÃ¦Å“â€°Ã¥Â½â€œ Body Ã¥Å’â€¦Ã¥ÂÂ« project Ã¥Â­â€”Ã¦Â®ÂµÃ¤Â¸â€Ã©ÂÅ¾Ã¦Âµâ€¹Ã¨Â¯â€¢Ã©Â¡Â¹Ã§â€ºÂ®Ã¦â€”Â¶Ã¯Â¼Å’Ã¦Â³Â¨Ã¥â€¦Â¥ x-goog-user-project
        if let Some(proj) = body.get("project").and_then(|v| v.as_str()) {
            if !proj.is_empty() && proj != "test-project" && proj != "project-id" {
                if let Ok(hv) = header::HeaderValue::from_str(proj) {
                    headers.insert("x-goog-user-project", hv);
                }
            }
        }

        // Ã¦Â³Â¨Ã¥â€¦Â¥Ã©Â¢ÂÃ¥Â¤â€“Ã§Å¡â€ž Headers (Ã¥Â¦â€š anthropic-beta)
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
        // [NEW] Ã¦â€Â¶Ã©â€ºâ€ Ã©â„¢ÂÃ§ÂºÂ§Ã¥Â°ÂÃ¨Â¯â€¢Ã¨Â®Â°Ã¥Â½â€¢
        let mut fallback_attempts: Vec<FallbackAttemptLog> = Vec::new();

        // Ã©ÂÂÃ¥Å½â€ Ã¦â€°â‚¬Ã¦Å“â€°Ã§Â«Â¯Ã§â€šÂ¹Ã¯Â¼Å’Ã¥Â¤Â±Ã¨Â´Â¥Ã¦â€”Â¶Ã¨â€¡ÂªÃ¥Å Â¨Ã¥Ë†â€¡Ã¦ÂÂ¢
        for (idx, base_url) in V1_INTERNAL_BASE_URL_FALLBACKS.iter().enumerate() {
            let url = Self::build_url(base_url, method, query_string);
            let has_next = idx + 1 < V1_INTERNAL_BASE_URL_FALLBACKS.len();

            let body_bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;

            let response = client
                .post(&url)
                .headers(headers.clone())
                // [NEW] Ã¥Â¼ÂºÃ¥Ë†Â¶Ã¥Ë†â€ Ã¥Ââ€”Ã¤Â¼Â Ã¨Â¾â€œÃ¤Â»Â¿Ã§Å“Å¸: Ã¥Å’â€¦Ã¨Â£â€¦Ã¤Â¸ÂºÃ¦ÂµÂÃ¤Â»Â¥Ã¨Â§Â¦Ã¥Ââ€˜ Transfer-Encoding: chunked
                // Ã¨Â¿â„¢Ã¥Â¯Â¹Ã©Â½ÂÃ¤Âºâ€ Ã¥Â®ËœÃ¦â€“Â¹ Go Worker Ã©â‚¬Å¡Ã¨Â¿â€¡Ã©ÂÂ®Ã¨â€Â½ Content-Length Ã¦ÂÂ¥Ã¦Â¨Â¡Ã¦â€¹Å¸ IDE Ã¦ÂµÂÃ©â€¡ÂÃ§Å¡â€žÃ¨Â¡Å’Ã¤Â¸Âº
                .body(rquest::Body::wrap_stream(futures::stream::once(
                    async move { Ok::<_, std::io::Error>(body_bytes) },
                )))
                .send()
                .await;

            match response {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        if idx > 0 {
                            tracing::info!(
                                "Ã¢Å“â€œ Upstream fallback succeeded | Endpoint: {} | Status: {} | Next endpoints available: {}",
                                base_url,
                                status,
                                V1_INTERNAL_BASE_URL_FALLBACKS.len() - idx - 1
                            );
                        } else {
                            tracing::debug!(
                                "Ã¢Å“â€œ Upstream request succeeded | Endpoint: {} | Status: {}",
                                base_url,
                                status
                            );
                        }
                        return Ok(UpstreamCallResult {
                            response: resp,
                            fallback_attempts,
                        });
                    }

                    // Ã¥Â¦â€šÃ¦Å¾Å“Ã¦Å“â€°Ã¤Â¸â€¹Ã¤Â¸â‚¬Ã¤Â¸ÂªÃ§Â«Â¯Ã§â€šÂ¹Ã¤Â¸â€Ã¥Â½â€œÃ¥â€°ÂÃ©â€â„¢Ã¨Â¯Â¯Ã¥ÂÂ¯Ã©â€¡ÂÃ¨Â¯â€¢Ã¯Â¼Å’Ã¥Ë†â„¢Ã¥Ë†â€¡Ã¦ÂÂ¢
                    if has_next && Self::should_try_next_endpoint(status) {
                        let err_msg = format!("Upstream {} returned {}", base_url, status);
                        tracing::warn!(
                            "Upstream endpoint returned {} at {} (method={}), trying next endpoint",
                            status,
                            base_url,
                            method
                        );
                        // [NEW] Ã¨Â®Â°Ã¥Â½â€¢Ã©â„¢ÂÃ§ÂºÂ§Ã¥Â°ÂÃ¨Â¯â€¢
                        fallback_attempts.push(FallbackAttemptLog {
                            endpoint_url: url.clone(),
                            status: Some(status.as_u16()),
                            error: err_msg.clone(),
                        });
                        last_err = Some(err_msg);
                        continue;
                    }

                    // Ã¤Â¸ÂÃ¥ÂÂ¯Ã©â€¡ÂÃ¨Â¯â€¢Ã§Å¡â€žÃ©â€â„¢Ã¨Â¯Â¯Ã¦Ë†â€“Ã¥Â·Â²Ã¦ËœÂ¯Ã¦Å“â‚¬Ã¥ÂÅ½Ã¤Â¸â‚¬Ã¤Â¸ÂªÃ§Â«Â¯Ã§â€šÂ¹Ã¯Â¼Å’Ã§â€ºÂ´Ã¦Å½Â¥Ã¨Â¿â€Ã¥â€ºÅ¾
                    return Ok(UpstreamCallResult {
                        response: resp,
                        fallback_attempts,
                    });
                }
                Err(e) => {
                    let msg = format!("HTTP request failed at {}: {}", base_url, e);
                    tracing::debug!("{}", msg);
                    // [NEW] Ã¨Â®Â°Ã¥Â½â€¢Ã§Â½â€˜Ã§Â»Å“Ã©â€â„¢Ã¨Â¯Â¯Ã§Å¡â€žÃ©â„¢ÂÃ§ÂºÂ§Ã¥Â°ÂÃ¨Â¯â€¢
                    fallback_attempts.push(FallbackAttemptLog {
                        endpoint_url: url.clone(),
                        status: None,
                        error: msg.clone(),
                    });
                    last_err = Some(msg);

                    // Ã¥Â¦â€šÃ¦Å¾Å“Ã¦ËœÂ¯Ã¦Å“â‚¬Ã¥ÂÅ½Ã¤Â¸â‚¬Ã¤Â¸ÂªÃ§Â«Â¯Ã§â€šÂ¹Ã¯Â¼Å’Ã©â‚¬â‚¬Ã¥â€¡ÂºÃ¥Â¾ÂªÃ§Å½Â¯
                    if !has_next {
                        break;
                    }
                    continue;
                }
            }
        }

        Err(last_err.unwrap_or_else(|| "All endpoints failed".to_string()))
    }

    // Ã¨Â°Æ’Ã§â€Â¨ v1internal APIÃ¯Â¼Ë†Ã¥Â¸Â¦ 429 Ã©â€¡ÂÃ¨Â¯â€¢,Ã¦â€Â¯Ã¦Å’ÂÃ©â€”Â­Ã¥Å’â€¦Ã¯Â¼â€°
    //
    // Ã¥Â¸Â¦Ã¥Â®Â¹Ã©â€â„¢Ã¥â€™Å’Ã©â€¡ÂÃ¨Â¯â€¢Ã§Å¡â€žÃ¦Â Â¸Ã¥Â¿Æ’Ã¨Â¯Â·Ã¦Â±â€šÃ©â‚¬Â»Ã¨Â¾â€˜
    //
    // # Arguments
    // * `method` - API method (e.g., "generateContent")
    // * `query_string` - Optional query string (e.g., "?alt=sse")
    // * `get_credentials` - Ã©â€”Â­Ã¥Å’â€¦Ã¯Â¼Å’Ã¨Å½Â·Ã¥Ââ€“Ã¥â€¡Â­Ã¨Â¯ÂÃ¯Â¼Ë†Ã¦â€Â¯Ã¦Å’ÂÃ¨Â´Â¦Ã¥ÂÂ·Ã¨Â½Â®Ã¦ÂÂ¢Ã¯Â¼â€°
    // * `build_body` - Ã©â€”Â­Ã¥Å’â€¦Ã¯Â¼Å’Ã¦Å½Â¥Ã¦â€Â¶ project_id Ã¦Å¾â€žÃ¥Â»ÂºÃ¨Â¯Â·Ã¦Â±â€šÃ¤Â½â€œ
    // * `max_attempts` - Ã¦Å“â‚¬Ã¥Â¤Â§Ã©â€¡ÂÃ¨Â¯â€¢Ã¦Â¬Â¡Ã¦â€¢Â°
    //
    // # Returns
    // HTTP Response
    // Ã¥Â·Â²Ã§Â§Â»Ã©â„¢Â¤Ã¥Â¼Æ’Ã§â€Â¨Ã§Å¡â€žÃ©â€¡ÂÃ¨Â¯â€¢Ã¦â€“Â¹Ã¦Â³â€¢ (call_v1_internal_with_retry)

    // Ã¥Â·Â²Ã§Â§Â»Ã©â„¢Â¤Ã¥Â¼Æ’Ã§â€Â¨Ã§Å¡â€žÃ¨Â¾â€¦Ã¥Å Â©Ã¦â€“Â¹Ã¦Â³â€¢ (parse_retry_delay)

    // Ã¥Â·Â²Ã§Â§Â»Ã©â„¢Â¤Ã¥Â¼Æ’Ã§â€Â¨Ã§Å¡â€žÃ¨Â¾â€¦Ã¥Å Â©Ã¦â€“Â¹Ã¦Â³â€¢ (parse_duration_ms)

    // Ã¨Å½Â·Ã¥Ââ€“Ã¥ÂÂ¯Ã§â€Â¨Ã¦Â¨Â¡Ã¥Å¾â€¹Ã¥Ë†â€”Ã¨Â¡Â¨
    //
    // Ã¨Å½Â·Ã¥Ââ€“Ã¨Â¿Å“Ã§Â«Â¯Ã¦Â¨Â¡Ã¥Å¾â€¹Ã¥Ë†â€”Ã¨Â¡Â¨Ã¯Â¼Å’Ã¦â€Â¯Ã¦Å’ÂÃ¥Â¤Å¡Ã§Â«Â¯Ã§â€šÂ¹Ã¨â€¡ÂªÃ¥Å Â¨ Fallback
    #[allow(dead_code)] // API ready for future model discovery feature
    pub async fn fetch_available_models(
        &self,
        access_token: &str,
        account_id: Option<&str>,
    ) -> Result<Value, String> {
        // Ã¥Â¤ÂÃ§â€Â¨ call_v1_internalÃ¯Â¼Å’Ã§â€žÂ¶Ã¥ÂÅ½Ã¨Â§Â£Ã¦Å¾Â JSON
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
