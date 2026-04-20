use crate::modules::config::load_app_config;
use once_cell::sync::Lazy;
use rquest::{Client, Proxy};
use rquest::header::{HeaderMap, HeaderName, HeaderValue};

/// Global shared standard HTTP client (15s timeout, NO JA3 Emulation)
pub static SHARED_STANDARD_CLIENT: Lazy<Client> = Lazy::new(|| create_standard_client(15));

/// Global shared standard HTTP client (Long timeout: 60s, NO JA3 Emulation)
pub static SHARED_STANDARD_CLIENT_LONG: Lazy<Client> = Lazy::new(|| create_standard_client(60));

/// Base client creation logic strictly WITHOUT JA3 Emulation (Pure Native)
/// [OPSEC] This is the ONLY client type that should be used for Google-facing traffic.
/// Native BoringSSL fingerprint is close to Node.js OpenSSL.
fn create_standard_client(timeout_secs: u64) -> Client {
    let mut builder = Client::builder()
        // No .emulation() — pure native BoringSSL fingerprint (close to Node.js OpenSSL)
        .http1_only() // [OPSEC] Force HTTP/1.1 to match Node.js gaxios (Connection: keep-alive)
        .timeout(std::time::Duration::from_secs(timeout_secs));

    if let Ok(config) = load_app_config() {
        let proxy_config = config.proxy.upstream_proxy;
        if proxy_config.enabled && !proxy_config.url.is_empty() {
            match Proxy::all(&proxy_config.url) {
                Ok(proxy) => {
                    builder = builder.proxy(proxy);
                    tracing::info!(
                        "HTTP standard client enabled upstream proxy: {}",
                        proxy_config.url
                    );
                }
                Err(e) => {
                    tracing::error!("invalid_proxy_url: {}, error: {}", proxy_config.url, e);
                }
            }
        }
    }

    tracing::info!("Initialized Pure Native Standard Client");
    builder.build().unwrap_or_else(|_| Client::builder().http1_only().build().expect("critical: fallback standard client build failed"))
}

/// Get standard HTTP client without JA3 Emulation (15s timeout)
pub fn get_standard_client() -> Client {
    SHARED_STANDARD_CLIENT.clone()
}

/// Get long timeout standard HTTP client without JA3 Emulation (60s timeout)
pub fn get_long_standard_client() -> Client {
    SHARED_STANDARD_CLIENT_LONG.clone()
}

// ─────────────────────────────────────────────────────────────────────────────
// [OPSEC] Canonical Google header helpers
// Header ordering exactly matches Node.js gaxios (google-api-nodejs-client).
// MUST be used for ALL outbound requests to *.googleapis.com endpoints.
// ─────────────────────────────────────────────────────────────────────────────

/// Google API headers for JSON POST requests (cloudcode-pa, generativelanguage).
/// Ordering matches MITM capture of Node.js gaxios client.
pub fn google_api_headers(access_token: &str) -> HeaderMap {
    let ua = crate::constants::NATIVE_OAUTH_USER_AGENT.as_str();
    let mut h = HeaderMap::with_capacity(6);
    h.insert(HeaderName::from_static("accept"), HeaderValue::from_static("*/*"));
    h.insert(HeaderName::from_static("accept-encoding"), HeaderValue::from_static("gzip, deflate, br"));
    h.insert(
        HeaderName::from_static("authorization"),
        HeaderValue::from_str(&format!("Bearer {}", access_token))
            .expect("invalid access token for header"),
    );
    h.insert(HeaderName::from_static("content-type"), HeaderValue::from_static("application/json"));
    h.insert(
        HeaderName::from_static("user-agent"),
        HeaderValue::from_str(ua).unwrap_or_else(|_| HeaderValue::from_static("google-api-nodejs-client/10.3.0")),
    ); // [OPSEC] Wektor T Fallback CleanUp
    h.insert(HeaderName::from_static("x-goog-api-client"), HeaderValue::from_static("gl-node/20.18.0"));
    h.insert(HeaderName::from_static("connection"), HeaderValue::from_static("keep-alive"));
    h
}

/// [OPSEC v4.1.32] Headers for the official Go Language Server client 
/// MUST be used for streamGenerateContent and other Go-initiated requests.
/// Go LS uses a minimal subset of headers.
pub fn go_ls_api_headers(access_token: &str) -> HeaderMap {
    // [OPSEC v4.1.33] We replace the Antigravity hardcoded string to perfectly blend.
    // Go LS DOES NOT USE Node.js gaxios! It uses cloudcode/1.22.2 style agents.
    let ua_str = crate::constants::GO_LS_USER_AGENT.as_str().to_string();
    
    let mut h = HeaderMap::with_capacity(4);
    h.insert(HeaderName::from_static("accept-encoding"), HeaderValue::from_static("gzip"));
    h.insert(
        HeaderName::from_static("authorization"),
        HeaderValue::from_str(&format!("Bearer {}", access_token))
            .expect("invalid access token for header"),
    );
    h.insert(HeaderName::from_static("content-type"), HeaderValue::from_static("application/json"));
    h.insert(
        HeaderName::from_static("user-agent"),
        HeaderValue::from_str(&ua_str).unwrap_or_else(|_| HeaderValue::from_static("cloudcode/1.22.2 windows/amd64")),
    );
    
    // Note: Go LS does NOT send 'accept: */*', 'connection: keep-alive', or 'x-goog-api-client'
    h
}

/// Google OAuth headers for form POST requests (oauth2.googleapis.com/token).
/// No Authorization header (credentials in form body). No x-goog-api-client.
/// Content-Type will be set by `.form()` automatically.
pub fn google_oauth_headers() -> HeaderMap {
    // [OPSEC v4.1.32] OAuth token exchange uses SHORT UA (no antigravity/ prefix)
    // Official gaxios sends only "google-api-nodejs-client/10.3.0" to /token
    let ua = crate::constants::OAUTH_SHORT_UA.as_str();
    let mut h = HeaderMap::with_capacity(6);
    h.insert(HeaderName::from_static("accept"), HeaderValue::from_static("*/*"));
    h.insert(HeaderName::from_static("accept-encoding"), HeaderValue::from_static("gzip, deflate, br"));
    // [OPSEC 7.11] Explicit Content-Type with charset=UTF-8 to match native gaxios behavior
    h.insert(HeaderName::from_static("content-type"), HeaderValue::from_static("application/x-www-form-urlencoded;charset=UTF-8"));
    h.insert(
        HeaderName::from_static("user-agent"),
        HeaderValue::from_str(ua).unwrap_or_else(|_| HeaderValue::from_static("google-api-nodejs-client/10.3.0")),
    );
    // [OPSEC V5] REMOVED x-goog-api-client — canonical gaxios auth library does NOT send it on /token
    h.insert(HeaderName::from_static("connection"), HeaderValue::from_static("keep-alive")); // [OPSEC] Wektor O: keep-alive sync
    h
}

/// Google headers for GET requests with auth (userinfo, etc).
/// No Content-Type (GET has no body). No x-goog-api-client.
pub fn google_get_headers(access_token: &str) -> HeaderMap {
    let ua = crate::constants::NATIVE_OAUTH_USER_AGENT.as_str();
    let mut h = HeaderMap::with_capacity(6);
    h.insert(HeaderName::from_static("accept"), HeaderValue::from_static("*/*"));
    h.insert(HeaderName::from_static("accept-encoding"), HeaderValue::from_static("gzip, deflate, br"));
    h.insert(
        HeaderName::from_static("authorization"),
        HeaderValue::from_str(&format!("Bearer {}", access_token))
            .expect("invalid access token for header"),
    );
    h.insert(
        HeaderName::from_static("user-agent"),
        HeaderValue::from_str(ua).unwrap_or_else(|_| HeaderValue::from_static("google-api-nodejs-client/10.3.0")),
    ); // [OPSEC] Wektor T Fallback CleanUp
    // [OPSEC V24] REMOVED x-goog-api-client — canonical Go OAuth library does NOT send it on GET userinfo
    h.insert(HeaderName::from_static("connection"), HeaderValue::from_static("keep-alive")); // [OPSEC] Wektor O: keep-alive sync
    h
}
