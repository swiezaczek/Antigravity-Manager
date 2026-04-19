use serde_json::Value;

/// 使用 Antigravity 的 loadCodeAssist API 获取 project_id
/// 这是获取 cloudaicompanionProject 的正确方式
pub async fn fetch_project_id(access_token: &str) -> Result<String, String> {
    // [OPSEC v4.1.32] Changed from Sandbox to Prod (original client NEVER hits sandbox)
    let url = "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist";
    
    // [OPSEC Phase 3] MITM confirmed ide_type: "ANTIGRAVITY" leaked in deep_loadcode.txt
    let request_body = serde_json::json!({
        "metadata": {
            "ide_type": "VSCODE",
            "ide_version": "1.95.1",
            "ide_name": "vscode"
        }
    });
    
    // [OPSEC v4.1.32] Use centralized google_api_headers() for consistent fingerprint
    let headers = crate::utils::http::google_api_headers(access_token);
    let client = crate::utils::http::get_standard_client();
    let response = client
        .post(url)
        .headers(headers)
        .body(serde_json::to_vec(&request_body).unwrap_or_default())
        .send()
        .await
        .map_err(|e| format!("loadCodeAssist 请求失败: {}", e))?;
    
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("loadCodeAssist 返回错误 {}: {}", status, body));
    }
    
    let data: Value = response.json()
        .await
        .map_err(|e| format!("解析响应失败: {}", e))?;
        
    // [OPSEC] Wykonanie dyskretnego Onboardingu przy rozwiązywaniu zagubionego projektu
    let tier_for_onboard = data.get("currentTier").and_then(|t| t.get("id")).and_then(|v| v.as_str()).unwrap_or("free-tier").to_string();
    let access_token_clone = access_token.to_string();
    
    tokio::spawn(async move {
        // [OPSEC Phase 3] Matching quota.rs onboard fix
        let onboard_meta = serde_json::json!({
            "tier_id": tier_for_onboard,
            "metadata": {
                "ide_type": "VSCODE",
                "ide_version": "1.95.1",
                "ide_name": "vscode"
            }
        });
        
        // [OPSEC v4.1.32] Onboard also uses Prod + centralized headers
        let onboard_headers = crate::utils::http::google_api_headers(&access_token_clone);
        let client = crate::utils::http::get_standard_client();
        let _ = client.post("https://cloudcode-pa.googleapis.com/v1internal:onboardUser")
            .headers(onboard_headers)
            .body(serde_json::to_vec(&onboard_meta).unwrap_or_default())
            .send()
            .await;
    });
    
    // 提取 cloudaicompanionProject
    if let Some(project_id) = data.get("cloudaicompanionProject")
        .and_then(|v| v.as_str()) {
        
        // [OPSEC] Zabezpieczenie przed błędem Macro-Linker / Identity Collisions
        if project_id == "macro-linker-26f3p" || project_id == "681255809395" {
             tracing::warn!("Zidentyfikowano wrogi projekt ({}). Odmawiam przypisania w celu ochrony konta Pro.", project_id);
             return Err("Phantom project ID detected, enforcing individual routing.".to_string());
        }
            
        return Ok(project_id.to_string());
    }
    
    // 如果没有返回 project_id，说明账号无资格，返回错误以触发 token_manager 的稳定兜底逻辑
    Err("账号无资格获取官方 cloudaicompanionProject".to_string())
}
