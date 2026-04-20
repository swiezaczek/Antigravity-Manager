// [NEW v4.1.24] Tools for deriving stable session identifiers

// [OPSEC V13] Rotate session IDs across application restarts
static APP_BOOT_SEED: std::sync::LazyLock<i64> = std::sync::LazyLock::new(|| {
    chrono::Utc::now().timestamp_millis()
});

/// From account ID string to a stable negative signed integer session ID
/// Implements FNV-1a hash which matches the official client behavior of sending
/// a large negative integer for `sessionId`.
pub fn derive_session_id(account_id: &str) -> String {
    let mut hash: i64 = -3750763034362895579_i64; // FNV offset basis
    for byte in account_id.bytes() {
        hash = hash.wrapping_mul(1099511628211_i64);
        hash ^= byte as i64;
    }
    hash ^= *APP_BOOT_SEED;
    hash.to_string()
}

use std::sync::{LazyLock, Mutex};
use std::collections::HashMap;

static VSCODE_SESSIONS: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(|| {
    Mutex::new(HashMap::new())
});

pub fn get_or_create_vscode_session_id(account_id: &str) -> String {
    let mut map = VSCODE_SESSIONS.lock().unwrap();
    if let Some(session) = map.get(account_id) {
        return session.clone();
    }
    
    // [OPSEC] Format: UUIDv4 + timestamp_ms (49 characters) to match native VSCode telemetry behavior
    let generated = format!("{}{}", uuid::Uuid::new_v4(), chrono::Utc::now().timestamp_millis());
    map.insert(account_id.to_string(), generated.clone());
    generated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_session_id() {
        let x = derive_session_id("my_account@gmail.com");
        let y = derive_session_id("my_account@gmail.com");
        assert_eq!(x, y);
    }

    #[test]
    fn test_sequence_number() {
        let a1 = next_sequence_number(Some("acc1"));
        let a2 = next_sequence_number(Some("acc1"));
        assert_eq!(a1 + 1, a2);
        
        let b1 = next_sequence_number(Some("acc2"));
        assert_ne!(a2, b1);
    }
}

// [OPSEC v4.1.32] Global sequence counters per account for requestId
static SEQUENCE_COUNTERS: LazyLock<Mutex<HashMap<String, u64>>> = LazyLock::new(|| {
    Mutex::new(HashMap::new())
});

/// Gets and increments the global sequence number for an account
/// This matches the original Go LS format agent/{timestamp}/{trajectory}/{seq_num}
/// sequence starts at a high semi-random number for realism
pub fn next_sequence_number(account_id: Option<&str>) -> u64 {
    let key = account_id.unwrap_or("default");
    let mut map = SEQUENCE_COUNTERS.lock().unwrap();
    
    // Seed initial sequence with a deterministic pseudo-random offset based on account ID
    let count = map.entry(key.to_string()).or_insert_with(|| {
        let mut hash: i64 = -3750763034362895579_i64;
        for byte in key.bytes() {
            hash = hash.wrapping_mul(1099511628211_i64);
            hash ^= byte as i64;
        }
        // Take absolute value mod 10000, then add a realistic starting offset (~3000-13000)
        (hash.abs() % 10000) as u64 + 3800
    });
    
    let current = *count;
    *count += 1;
    current
}
