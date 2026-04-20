// [NEW v4.1.24] Tools for deriving stable session identifiers

/// From account ID string to a stable negative signed integer session ID
/// Implements FNV-1a hash which matches the official client behavior of sending
/// a large negative integer for `sessionId`.
pub fn derive_session_id(account_id: &str) -> String {
    let mut hash: i64 = -3750763034362895579_i64; // FNV offset basis
    for byte in account_id.bytes() {
        hash = hash.wrapping_mul(1099511628211_i64);
        hash ^= byte as i64;
    }
    hash.to_string()
}

/// Generate a deterministic vscode-style session ID from an account ID.
/// This replaces the global SESSION_ID constant with per-account isolation,
/// preventing cross-account correlation via `x-vscode-sessionid` header.
/// Format matches the canonical UUID pattern used by VS Code/Cloud Code.
pub fn get_or_create_vscode_session_id(account_id: &str) -> String {
    // Deterministyczny UUID-like string z account_id (FNV-1a hash)
    let mut hash: u128 = 0x6c62272e07bb0142_u128.wrapping_mul(0x100000001b3);
    for &byte in account_id.as_bytes() {
        hash ^= byte as u128;
        hash = hash.wrapping_mul(0x01000000000000000000013b);
    }
    // Format jako UUID-style: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    let bytes = hash.to_be_bytes();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15]
    )
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
}
