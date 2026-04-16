//! MITM Rules Engine
//!
//! Decides what to do with each intercepted HTTPS request:
//! - DROP: Silently return 200 OK {} (block from reaching Google)
//! - PASS: Forward to real server transparently

/// Action to take on an intercepted request.
#[derive(Debug, Clone)]
pub enum Action {
    /// Forward the request to the real upstream server.
    Pass,
    /// Block the request. Return a fake 200 OK with empty JSON body.
    /// The client (Go LS / Node.js) won't see any error.
    Drop,
    /// Rewrite native metrics/trajectory payload dynamically (e.g. mapping to pooled account).
    RewriteAgentTelemetry,
}

/// Evaluate a request and decide what to do with it.
///
/// Strategy (v8 Native Proxying): REWRITE agent metrics instead of dropping them
/// - Filar 1 synthetic metrics are disabled
/// - Both Native `recordCodeAssistMetrics` and `recordTrajectoryAnalytics` are intercepted
/// - MITM will parse the trajectoryId, lookup the proxy-allocated token, and rewrite it
pub fn evaluate(host: &str, path: &str) -> Action {
    if host.contains("cloudcode-pa.googleapis.com")
        && (path.contains("recordCodeAssistMetrics") || path.contains("recordTrajectoryAnalytics"))
    {
        return Action::RewriteAgentTelemetry;
    }

    // PASS: Everything else (OAuth, Unleash, fetchUserInfo...)
    Action::Pass
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rewrite_agent_telemetry() {
        assert!(matches!(
            evaluate(
                "daily-cloudcode-pa.googleapis.com",
                "/v1internal:recordCodeAssistMetrics"
            ),
            Action::RewriteAgentTelemetry
        ));
        assert!(matches!(
            evaluate(
                "cloudcode-pa.googleapis.com",
                "/v1internal:recordCodeAssistMetrics"
            ),
            Action::RewriteAgentTelemetry
        ));
        assert!(matches!(
            evaluate(
                "daily-cloudcode-pa.googleapis.com",
                "/v1internal:recordTrajectoryAnalytics"
            ),
            Action::RewriteAgentTelemetry
        ));
    }

    #[test]
    fn test_pass_generate_content() {
        assert!(matches!(
            evaluate(
                "cloudcode-pa.googleapis.com",
                "/v1internal:streamGenerateContent"
            ),
            Action::Pass
        ));
    }

    #[test]
    fn test_pass_oauth() {
        assert!(matches!(
            evaluate("oauth2.googleapis.com", "/token"),
            Action::Pass
        ));
    }

    #[test]
    fn test_pass_unleash() {
        assert!(matches!(
            evaluate("34.54.84.110", "/api/client/register"),
            Action::Pass
        ));
    }
}
