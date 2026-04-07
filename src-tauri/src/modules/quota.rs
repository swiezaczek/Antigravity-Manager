use rquest;
use serde::{Deserialize, Serialize};
use serde_json::json;
use crate::models::QuotaData;
use crate::modules::config;

// Quota API endpoints (fallback order: Daily → Prod)
const QUOTA_API_ENDPOINTS: [&str; 2] = [
    "https://daily-cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels",
    "https://cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels",
];

/// Critical retry threshold: considered near recovery when quota reaches 95%
const NEAR_READY_THRESHOLD: i32 = 95;
const MAX_RETRIES: u32 = 3;
const RETRY_DELAY_SECS: u64 = 30;

#[derive(Debug, Serialize, Deserialize)]
struct QuotaResponse {
    models: std::collections::HashMap<String, ModelInfo>,
    #[serde(rename = "deprecatedModelIds")]
    deprecated_model_ids: Option<std::collections::HashMap<String, DeprecatedModelInfo>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DeprecatedModelInfo {
    #[serde(rename = "newModelId")]
    new_model_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ModelInfo {
    #[serde(rename = "quotaInfo")]
    quota_info: Option<QuotaInfo>,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(rename = "supportsImages")]
    supports_images: Option<bool>,
    #[serde(rename = "supportsThinking")]
    supports_thinking: Option<bool>,
    #[serde(rename = "thinkingBudget")]
    thinking_budget: Option<i32>,
    recommended: Option<bool>,
    #[serde(rename = "maxTokens")]
    max_tokens: Option<i32>,
    #[serde(rename = "maxOutputTokens")]
    max_output_tokens: Option<i32>,
    #[serde(rename = "supportedMimeTypes")]
    supported_mime_types: Option<std::collections::HashMap<String, bool>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct QuotaInfo {
    #[serde(rename = "remainingFraction")]
    remaining_fraction: Option<f64>,
    #[serde(rename = "resetTime")]
    reset_time: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoadProjectResponse {
    #[serde(rename = "cloudaicompanionProject")]
    project_id: Option<String>,
    #[serde(rename = "currentTier")]
    current_tier: Option<Tier>,
    #[serde(rename = "paidTier")]
    paid_tier: Option<Tier>,
    #[serde(rename = "allowedTiers")]
    allowed_tiers: Option<Vec<Tier>>,
    #[serde(rename = "ineligibleTiers")]
    ineligible_tiers: Option<Vec<IneligibleTier>>,
}

#[derive(Debug, Deserialize)]
struct IneligibleTier {
    #[allow(dead_code)]
    #[serde(rename = "reasonCode")]
    reason_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Tier {
    #[allow(dead_code)]
    is_default: Option<bool>,
    id: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "quotaTier")]
    quota_tier: Option<String>,
    name: Option<String>,
    #[allow(dead_code)]
    slug: Option<String>,
}

/// Get shared HTTP Client (15s timeout) for pure info fetching (No JA3)
async fn create_standard_client(account_id: Option<&str>) -> rquest::Client {
    if let Some(pool) = crate::proxy::proxy_pool::get_global_proxy_pool() {
        pool.get_effective_standard_client(account_id, 15).await
    } else {
        crate::utils::http::get_standard_client()
    }
}

/// Get shared HTTP Client (60s timeout) for pure info fetching (No JA3)
#[allow(dead_code)] // 预留给预热/后台任务调用
async fn create_long_standard_client(account_id: Option<&str>) -> rquest::Client {
    if let Some(pool) = crate::proxy::proxy_pool::get_global_proxy_pool() {
        pool.get_effective_standard_client(account_id, 60).await
    } else {
        crate::utils::http::get_long_standard_client()
    }
}

const CLOUD_CODE_BASE_URL: &str = "https://cloudcode-pa.googleapis.com"; // [OPSEC] Wektor U: prod zamiast staging




/// Fetch project ID and subscription tier, running the FULL MITM Warmup Flow
async fn fetch_project_id(access_token: &str, email: &str, account_id: Option<&str>) -> (Option<String>, Option<String>) {
    let client = create_standard_client(account_id).await;
    let meta = json!({"metadata": {"ideType": "ANTIGRAVITY"}}); // [OPSEC] Synchronized with Draculabo reference

    // 1. Krok pierwszy: PROD loadCodeAssist (wyciąganie struktury)
    let res = client
        .post(format!("{}/v1internal:loadCodeAssist", "https://cloudcode-pa.googleapis.com")) // W MITM pierwszy jest zawsze na PROD
        .headers(crate::utils::http::google_api_headers(access_token))
        .json(&meta)
        .send()
        .await;

    let mut project_id = None;
    let mut subscription_tier = None;
    let mut tier_id_for_onboard = "free-tier".to_string();

    match res {
        Ok(response) => {
            if response.status().is_success() {
                if let Ok(data) = response.json::<LoadProjectResponse>().await {
                    project_id = data.project_id.clone();
                    
                    let mut tier = data.paid_tier.as_ref().and_then(|t| t.name.clone())
                        .or_else(|| data.paid_tier.as_ref().and_then(|t| t.id.clone()));
                        
                    let is_ineligible = data.ineligible_tiers.is_some() && !data.ineligible_tiers.as_ref().unwrap().is_empty();
                    
                    if tier.is_none() {
                        if !is_ineligible {
                            tier = data.current_tier.as_ref().and_then(|t| t.name.clone())
                                .or_else(|| data.current_tier.as_ref().and_then(|t| t.id.clone()));
                        } else {
                            if let Some(mut allowed) = data.allowed_tiers {
                                if let Some(default_tier) = allowed.iter_mut().find(|t| t.is_default == Some(true)) {
                                    if let Some(name) = &default_tier.name {
                                        tier = Some(format!("{} (Restricted)", name));
                                    } else if let Some(id) = &default_tier.id {
                                        tier = Some(format!("{} (Restricted)", id));
                                    }
                                }
                            }
                        }
                    }
                    
                    if let Some(ref t) = tier {
                        crate::modules::logger::log_info(&format!(
                            "📊 [{}] Subscription identified successfully: {}", email, t
                        ));
                    }
                    
                    tier_id_for_onboard = data.paid_tier.as_ref().and_then(|t| t.id.clone())
                        .or_else(|| data.current_tier.as_ref().and_then(|t| t.id.clone()))
                        .unwrap_or_else(|| "free-tier".to_string());
                        
                    subscription_tier = tier;
                }
            } else {
                crate::modules::logger::log_warn(&format!("⚠️ [{}] PROD loadCodeAssist failed: {}", email, response.status()));
            }
        }
        Err(e) => crate::modules::logger::log_error(&format!("❌ [{}] PROD loadCodeAssist network error: {}", email, e)),
    }

    // Ustawiamy fallback project jeśli nie ma
    let safe_pid = project_id.clone().unwrap_or_else(|| "advance-fold-f0tq9".to_string());
    if project_id.is_some() {
        crate::modules::logger::log_info(&format!("🎯 [{}] Cloud project assigned: {}", email, safe_pid));
    }

    // Lightweight session init — matching Draculabo reference (no aggressive DAILY onboarding)
    crate::modules::logger::log_info(&format!("✅ [{}] Project resolved, session ready", email));

    (project_id, subscription_tier)
}

/// Unified entry point for fetching account quota
pub async fn fetch_quota(access_token: &str, email: &str, account_id: Option<&str>) -> crate::error::AppResult<(QuotaData, Option<String>)> {
    fetch_quota_with_cache(access_token, email, None, account_id).await
}

/// Fetch quota with cache support
pub async fn fetch_quota_with_cache(
    access_token: &str,
    email: &str,
    cached_project_id: Option<&str>,
    account_id: Option<&str>,
) -> crate::error::AppResult<(QuotaData, Option<String>)> {
    use crate::error::AppError;
    
    // Optimization: Skip loadCodeAssist call if project_id is cached to save API quota
    let (project_id, subscription_tier) = if let Some(pid) = cached_project_id {
        (Some(pid.to_string()), None)
    } else {
        let res = fetch_project_id(access_token, email, account_id).await;
        res
    };
    
    // We keep project_id to store in the DB, but we NO LONGER force inject it into payload if it's absent
    
    let client = create_standard_client(account_id).await;
    let payload = if let Some(ref pid) = project_id {
        json!({ "project": pid })
    } else {
        json!({}) // Empty payload fallback
    };


    let mut quota_data = QuotaData::new();
    quota_data.subscription_tier = subscription_tier.clone();
    let mut any_success = false;
    let mut last_error: Option<AppError> = None;

    for (ep_idx, ep_url) in QUOTA_API_ENDPOINTS.iter().enumerate() {
        let has_next = ep_idx + 1 < QUOTA_API_ENDPOINTS.len();

        match client
            .post(*ep_url)
            .headers(crate::utils::http::google_api_headers(access_token))
            .json(&payload)
            .send()
            .await
        {
            Ok(response) => {
                if let Err(_) = response.error_for_status_ref() {
                    let status = response.status();
                    let text = response.text().await.unwrap_or_else(|_| "No body".to_string());
                    
                    if status == rquest::StatusCode::FORBIDDEN {
                        crate::modules::logger::log_warn(&format!(
                            "Account unauthorized (403 Forbidden) on {}. DETAILS: {}", ep_url, text
                        ));
                        last_error = Some(AppError::Unknown(format!("HTTP {} - {}", status, text)));
                        continue;
                    }
                    
                    if has_next && (status == rquest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()) {
                         crate::modules::logger::log_warn(&format!("Quota API {} returned {}, retrying on next...", ep_url, status));
                         last_error = Some(AppError::Unknown(format!("HTTP {} - {}", status, text)));
                         tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                    continue;
                }

                any_success = true;

                if let Ok(quota_response) = response.json::<QuotaResponse>().await {
                    tracing::debug!("Quota API {} returned {} models", ep_url, quota_response.models.len());

                    for (name, info) in quota_response.models {
                        // Unikamy duplikatów modeli ze środowisk
                        if quota_data.models.iter().any(|m| m.name == name) {
                            continue;
                        }

                        if let Some(quota_info) = info.quota_info {
                            let percentage = quota_info.remaining_fraction
                                .map(|f| (f * 100.0) as i32)
                                .unwrap_or(0);
                            
                            let reset_time = quota_info.reset_time.clone().unwrap_or_default();
                            
                            // Zachowujemy tylko sensowne
                            if name.contains("gemini") || name.contains("claude") || name.contains("gpt") || name.contains("image") || name.contains("imagen") {
                                let model_quota = crate::models::quota::ModelQuota {
                                    name,
                                    percentage,
                                    reset_time,
                                    display_name: info.display_name,
                                    supports_images: info.supports_images,
                                    supports_thinking: info.supports_thinking,
                                    thinking_budget: info.thinking_budget,
                                    recommended: info.recommended,
                                    max_tokens: info.max_tokens,
                                    max_output_tokens: info.max_output_tokens,
                                    supported_mime_types: info.supported_mime_types,
                                };
                                quota_data.add_model(model_quota);
                            }
                        }
                    }
                    
                    if let Some(deprecated) = quota_response.deprecated_model_ids {
                        for (old_id, info) in deprecated {
                            quota_data.model_forwarding_rules.insert(old_id, info.new_model_id);
                        }
                    }
                }
            },
            Err(e) => {
                crate::modules::logger::log_warn(&format!("Quota API request failed at {}: {}", ep_url, e));
                last_error = Some(AppError::from(e));
                if has_next {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }
    
    if any_success {
        // Jeśli choć jeden endpoint odpowiedział modelami - udało się
        return Ok((quota_data, project_id.clone()));
    }

    if let Some(AppError::Unknown(msg)) = &last_error {
        if msg.contains("403") {
            quota_data.is_forbidden = true;
            return Ok((quota_data, project_id.clone()));
        }
    }

    Err(last_error.unwrap_or_else(|| AppError::Unknown("Quota fetch failed: no endpoint returned models".to_string())))
}

/// Internal fetch quota logic
#[allow(dead_code)]
pub async fn fetch_quota_inner(access_token: &str, email: &str) -> crate::error::AppResult<(QuotaData, Option<String>)> {
    fetch_quota_with_cache(access_token, email, None, None).await
}

/// Batch fetch all account quotas (backup functionality)
#[allow(dead_code)]
pub async fn fetch_all_quotas(accounts: Vec<(String, String, String)>) -> Vec<(String, crate::error::AppResult<QuotaData>)> {
    let mut results = Vec::new();
    for (id, email, access_token) in accounts {
        let res = fetch_quota(&access_token, &email, Some(&id)).await;
        results.push((email, res.map(|(q, _)| q)));
    }
    results
}

/// Get valid token (auto-refresh if expired)
pub async fn get_valid_token_for_warmup(account: &crate::models::account::Account) -> Result<(String, String), String> {
    let mut account = account.clone();
    
    // Check and auto-refresh token
    let new_token = crate::modules::oauth::ensure_fresh_token(&account.token, Some(&account.id)).await?;
    
    // If token changed (meant refreshed), save it
    if new_token.access_token != account.token.access_token {
        account.token = new_token;
        if let Err(e) = crate::modules::account::save_account(&account) {
            crate::modules::logger::log_warn(&format!("[Warmup] Failed to save refreshed token: {}", e));
        } else {
            crate::modules::logger::log_info(&format!("[Warmup] Successfully refreshed and saved new token for {}", account.email));
        }
    }
    
    // Fetch project_id
    let (project_id, _) = fetch_project_id(&account.token.access_token, &account.email, Some(&account.id)).await;
    let final_pid = project_id.unwrap_or_else(|| "bamboo-precept-lgxtn".to_string());
    
    Ok((account.token.access_token, final_pid))
}

/// Send warmup request via proxy internal API
pub async fn warmup_model_directly(
    access_token: &str,
    model_name: &str,
    project_id: &str,
    email: &str,
    percentage: i32,
    _account_id: Option<&str>,
) -> bool {
    // Get currently configured proxy port
    let port = config::load_app_config()
        .map(|c| c.proxy.port)
        .unwrap_or(8045);

    let warmup_url = format!("http://127.0.0.1:{}/internal/warmup", port);
    let body = json!({
        "email": email,
        "model": model_name,
        "access_token": access_token,
        "project_id": project_id
    });

    // Use a no-proxy client for local loopback requests
    // This prevents Docker environments from routing localhost through external proxies
    let client = rquest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .no_proxy()
        .build()
        .unwrap_or_else(|_| rquest::Client::builder().http1_only().build().expect("critical: warmup loopback client build failed"));
    let resp = client
        .post(&warmup_url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await;

    match resp {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                crate::modules::logger::log_info(&format!("[Warmup] ✓ Triggered {} for {} (was {}%)", model_name, email, percentage));
                true
            } else {
                let text = response.text().await.unwrap_or_default();
                crate::modules::logger::log_warn(&format!("[Warmup] ✗ {} for {} (was {}%): HTTP {} - {}", model_name, email, percentage, status, text));
                false
            }
        }
        Err(e) => {
            crate::modules::logger::log_warn(&format!("[Warmup] ✗ {} for {} (was {}%): {}", model_name, email, percentage, e));
            false
        }
    }
}

/// Smart warmup for all accounts
pub async fn warm_up_all_accounts() -> Result<String, String> {
    let mut retry_count = 0;

    loop {
        let all_accounts = crate::modules::account::list_accounts().unwrap_or_default();
        // [FIX] 过滤掉禁用反代的账号
        let target_accounts: Vec<_> = all_accounts
            .into_iter()
            .filter(|a| !a.disabled && !a.proxy_disabled)
            .collect();

        if target_accounts.is_empty() {
            return Ok("No accounts available".to_string());
        }

        crate::modules::logger::log_info(&format!("[Warmup] Screening models for {} accounts...", target_accounts.len()));

        let mut warmup_items = Vec::new();
        let mut has_near_ready_models = false;

        // [OPSEC] Sequential quota scanning — no parallel batching to avoid concurrent
        // API calls from the same IP that would betray automated tooling.
        for account in &target_accounts {
            let (token, pid) = match get_valid_token_for_warmup(account).await {
                Ok(t) => t,
                Err(_) => continue,
            };
            let quota = fetch_quota_with_cache(&token, &account.email, Some(&pid), Some(&account.id)).await.ok();

            if let Some((fresh_quota, _)) = quota {
                // [FIX] 预热阶段检测到 403 时，使用统一禁用逻辑
                if fresh_quota.is_forbidden {
                    crate::modules::logger::log_warn(&format!(
                        "[Warmup] Account {} returned 403 Forbidden during quota fetch, marking as forbidden",
                        account.email
                    ));
                    let _ = crate::modules::account::mark_account_forbidden(&account.id, "Warmup: 403 Forbidden - quota fetch denied");
                    continue;
                }
                let mut account_warmed_series = std::collections::HashSet::new();
                for m in fresh_quota.models {
                    if m.percentage >= 100 {
                        let model_to_ping = m.name.clone();

                        if !account_warmed_series.contains(&model_to_ping) {
                            warmup_items.push((account.id.clone(), account.email.clone(), model_to_ping.clone(), token.clone(), pid.clone(), m.percentage));
                            account_warmed_series.insert(model_to_ping);
                        }
                    } else if m.percentage >= NEAR_READY_THRESHOLD {
                        has_near_ready_models = true;
                    }
                }
            }

            // [OPSEC] Small jitter between sequential quota scans
            {
                use rand::Rng;
                let scan_delay = rand::thread_rng().gen_range(2..=8);
                tokio::time::sleep(tokio::time::Duration::from_secs(scan_delay)).await;
            }
        }

        if !warmup_items.is_empty() {
            let total_before = warmup_items.len();
            
            // Filter out models warmed up within 4 hours
            warmup_items.retain(|(_, email, model, _, _, _)| {
                let history_key = format!("{}:{}:100", email, model);
                !crate::modules::scheduler::check_cooldown(&history_key, 14400)
            });
            
            if warmup_items.is_empty() {
                let skipped = total_before;
                crate::modules::logger::log_info(&format!("[Warmup] Returning to frontend: All models in cooldown, skipped {}", skipped));
                return Ok(format!("All models are in cooldown, skipped {} items", skipped));
            }
            
            let total = warmup_items.len();
            let skipped = total_before - total;
            
            if skipped > 0 {
                crate::modules::logger::log_info(&format!(
                    "[Warmup] Skipped {} models in cooldown, preparing to warmup {}",
                    skipped, total
                ));
            }
            
            crate::modules::logger::log_info(&format!(
                "[Warmup] 🔥 Starting manual warmup for {} models",
                total
            ));
            
            let (min_j, max_j) = if let Ok(app_config) = crate::modules::config::load_app_config() {
                let min = std::cmp::max(1, app_config.scheduled_warmup.min_jitter_secs);
                let max = std::cmp::max(min, app_config.scheduled_warmup.max_jitter_secs);
                (min, max)
            } else {
                (30, 120)
            };

            tokio::spawn(async move {
                let mut success = 0;
                let now_ts = chrono::Utc::now().timestamp();
                
                for (task_idx, (id, email, model, token, pid, pct)) in warmup_items.into_iter().enumerate() {
                    crate::modules::logger::log_info(&format!(
                        "[Warmup {}/{}] {} @ {} ({}%)",
                        task_idx + 1, total, model, email, pct
                    ));
                    
                    let result = warmup_model_directly(&token, &model, &pid, &email, pct, Some(&id)).await;
                    
                    if result {
                        success += 1;
                        let history_key = format!("{}:{}:100", email, model);
                        crate::modules::scheduler::record_warmup_history(&history_key, now_ts);
                    }
                    
                    if task_idx < total - 1 {
                        use rand::Rng;
                        let delay = rand::thread_rng().gen_range(min_j..=max_j);
                        crate::modules::logger::log_info(&format!("[Warmup] Jitter delay: {}s before next request...", delay));
                        tokio::time::sleep(tokio::time::Duration::from_secs(delay)).await;
                    }
                }
                
                crate::modules::logger::log_info(&format!("[Warmup] Warmup task completed: success {}/{}", success, total));
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                let _ = crate::modules::account::refresh_all_quotas_logic().await;
            });
            crate::modules::logger::log_info(&format!("[Warmup] Returning to frontend: Warmup task triggered for {} models", total));
            return Ok(format!("Warmup task triggered for {} models", total));
        }

        if has_near_ready_models && retry_count < MAX_RETRIES {
            retry_count += 1;
            crate::modules::logger::log_info(&format!("[Warmup] Critical recovery model detected, waiting {}s to retry ({}/{})", RETRY_DELAY_SECS, retry_count, MAX_RETRIES));
            tokio::time::sleep(tokio::time::Duration::from_secs(RETRY_DELAY_SECS)).await;
            continue;
        }

        return Ok("No models need warmup".to_string());
    }
}

/// Warmup for single account
pub async fn warm_up_account(account_id: &str) -> Result<String, String> {
    let accounts = crate::modules::account::list_accounts().unwrap_or_default();
    let account_owned = accounts.iter().find(|a| a.id == account_id).cloned().ok_or_else(|| "Account not found".to_string())?;

    if account_owned.disabled || account_owned.proxy_disabled {
        return Err("Account is disabled".to_string());
    }
    
    let email = account_owned.email.clone();
    let (token, pid) = get_valid_token_for_warmup(&account_owned).await?;
    let (fresh_quota, _) = fetch_quota_with_cache(&token, &email, Some(&pid), Some(&account_owned.id)).await.map_err(|e| format!("Failed to fetch quota: {}", e))?;
    
    // [FIX] 预热阶段检测到 403 时，使用统一的 mark_account_forbidden 逻辑，
    // 确保账号文件和索引文件同时更新，且前端刷新后能感知到禁用状态
    if fresh_quota.is_forbidden {
        crate::modules::logger::log_warn(&format!(
            "[Warmup] Account {} returned 403 Forbidden during quota fetch, marking as forbidden",
            email
        ));
        let reason = "Warmup: 403 Forbidden - quota fetch denied";
        let _ = crate::modules::account::mark_account_forbidden(account_id, reason);
        return Err("Account is forbidden (403)".to_string());
    }

    let mut models_to_warm = Vec::new();
    let mut warmed_series = std::collections::HashSet::new();

    for m in fresh_quota.models {
        if m.percentage >= 100 {
            let model_name = m.name.clone();

            // Removed hardcoded whitelist - now warms up any model at 100%
            if !warmed_series.contains(&model_name) {
                models_to_warm.push((model_name.clone(), m.percentage));
                warmed_series.insert(model_name);
            }
        }
    }

    if models_to_warm.is_empty() {
        return Ok("No warmup needed".to_string());
    }

    let warmed_count = models_to_warm.len();
    let account_id_clone = account_id.to_string();
    
    tokio::spawn(async move {
        for (name, pct) in models_to_warm {
            if warmup_model_directly(&token, &name, &pid, &email, pct, Some(&account_id_clone)).await {
                let history_key = format!("{}:{}:100", email, name);
                let now_ts = chrono::Utc::now().timestamp();
                crate::modules::scheduler::record_warmup_history(&history_key, now_ts);
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
        let _ = crate::modules::account::refresh_all_quotas_logic().await;
    });

    Ok(format!("Successfully triggered warmup for {} model series", warmed_count))
}
