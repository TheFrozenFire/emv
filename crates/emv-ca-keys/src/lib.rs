//! EMV CA Keys - Certificate Authority public key management
//!
//! This crate provides functionality to load and retrieve CA public keys
//! used for verifying EMV certificate chains.

use rsa::{BigUint, RsaPublicKey};

/// Get CA (Certificate Authority) public key by RID and index
///
/// Loads the public key from the embedded ca-public-keys.txt file,
/// which contains keys from all major payment schemes (Visa, Mastercard, etc.)
///
/// # Arguments
/// * `rid` - Registered Application Provider Identifier (5 bytes)
/// * `ca_index` - CA Public Key Index (1 byte)
///
/// # Returns
/// * `Some(RsaPublicKey)` - The CA public key if found
/// * `None` - If no matching key is found
///
/// # Example
/// ```
/// use emv_ca_keys::get_ca_public_key;
///
/// // Mastercard RID with CA index 05
/// let rid = &[0xA0, 0x00, 0x00, 0x00, 0x04];
/// let ca_index = 0x05;
///
/// if let Some(key) = get_ca_public_key(rid, ca_index) {
///     println!("Found CA public key");
/// }
/// ```
pub fn get_ca_public_key(rid: &[u8], ca_index: u8) -> Option<RsaPublicKey> {
    let ca_keys_data = include_str!("../../../ca-public-keys.txt");
    let rid_hex = hex::encode_upper(rid);

    for line in ca_keys_data.lines() {
        // Skip empty lines and comments
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 5 {
            continue;
        }

        // Format: Scheme, Exponent, Index, RID, Modulus, KeyLength, Hash
        let file_exponent = parts[1];
        let file_index_str = parts[2];
        let file_rid = parts[3];
        let file_modulus = parts[4];

        // Parse the index as hex
        let file_index = match u8::from_str_radix(file_index_str, 16) {
            Ok(idx) => idx,
            Err(_) => continue,
        };

        // Check if RID and index match
        if file_rid == rid_hex && file_index == ca_index {
            let modulus = BigUint::parse_bytes(file_modulus.as_bytes(), 16)?;
            let exponent = BigUint::parse_bytes(file_exponent.as_bytes(), 16)?;
            return RsaPublicKey::new(modulus, exponent).ok();
        }
    }

    None
}

/// Get all available CA public keys for a given RID
///
/// # Arguments
/// * `rid` - Registered Application Provider Identifier (5 bytes)
///
/// # Returns
/// Vector of tuples containing (ca_index, RsaPublicKey)
pub fn get_all_ca_keys_for_rid(rid: &[u8]) -> Vec<(u8, RsaPublicKey)> {
    let ca_keys_data = include_str!("../../../ca-public-keys.txt");
    let rid_hex = hex::encode_upper(rid);
    let mut keys = Vec::new();

    for line in ca_keys_data.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 5 {
            continue;
        }

        let file_exponent = parts[1];
        let file_index_str = parts[2];
        let file_rid = parts[3];
        let file_modulus = parts[4];

        if file_rid != rid_hex {
            continue;
        }

        let file_index = match u8::from_str_radix(file_index_str, 16) {
            Ok(idx) => idx,
            Err(_) => continue,
        };

        if let (Some(modulus), Some(exponent)) = (
            BigUint::parse_bytes(file_modulus.as_bytes(), 16),
            BigUint::parse_bytes(file_exponent.as_bytes(), 16),
        ) {
            if let Ok(key) = RsaPublicKey::new(modulus, exponent) {
                keys.push((file_index, key));
            }
        }
    }

    keys
}

/// Common RIDs for major payment schemes
pub mod rids {
    /// Visa RID
    pub const VISA: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x03];

    /// Mastercard RID
    pub const MASTERCARD: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x04];

    /// American Express RID
    pub const AMEX: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x02];

    /// Discover RID
    pub const DISCOVER: &[u8] = &[0xA0, 0x00, 0x00, 0x01, 0x52];

    /// JCB RID
    pub const JCB: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x65];

    /// UnionPay RID
    pub const UNIONPAY: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x33];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_ca_public_key_mastercard() {
        // Test with Mastercard RID and common CA index
        let key = get_ca_public_key(rids::MASTERCARD, 0x05);
        assert!(key.is_some(), "Should find Mastercard CA key index 05");
    }

    #[test]
    fn test_get_ca_public_key_not_found() {
        // Test with invalid index
        let key = get_ca_public_key(rids::MASTERCARD, 0xFF);
        assert!(key.is_none(), "Should not find non-existent CA key");
    }

    #[test]
    fn test_get_all_ca_keys_for_mastercard() {
        let keys = get_all_ca_keys_for_rid(rids::MASTERCARD);
        assert!(!keys.is_empty(), "Should find multiple Mastercard CA keys");
    }
}
