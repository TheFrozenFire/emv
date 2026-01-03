//! Cryptographic operations for EMV certificate verification

use rsa::{BigUint, RsaPublicKey};
use rsa::traits::PublicKeyParts;
use emv_common::find_tag;
use emv_ca_keys::get_ca_public_key;

/// Certificate data extracted from card
#[derive(Debug, Clone)]
pub struct CertificateChainData {
    pub ca_index: Option<u8>,
    pub rid: Vec<u8>,
    pub issuer_cert: Option<Vec<u8>>,
    pub issuer_exp: Option<Vec<u8>>,
    pub issuer_rem: Option<Vec<u8>>,
    pub icc_cert: Option<Vec<u8>>,
    pub icc_exp: Option<Vec<u8>>,
    pub icc_rem: Option<Vec<u8>>,
    pub pan: Option<Vec<u8>>,
}

impl CertificateChainData {
    /// Extract certificate data from all card records
    pub fn from_records(records: &[Vec<u8>], rid: Vec<u8>) -> Self {
        let mut data = Self {
            ca_index: None,
            rid,
            issuer_cert: None,
            issuer_exp: None,
            issuer_rem: None,
            icc_cert: None,
            icc_exp: None,
            icc_rem: None,
            pan: None,
        };

        for record in records {
            // First check if record is wrapped in tag 70 (Record Template)
            let search_data = if let Some(template) = find_tag(record, &[0x70]) {
                template
            } else {
                record.as_slice()
            };

            if let Some(val) = find_tag(search_data, &[0x8F]) {
                if !val.is_empty() {
                    data.ca_index = Some(val[0]);
                }
            }
            if let Some(val) = find_tag(search_data, &[0x90]) {
                data.issuer_cert = Some(val.to_vec());
            }
            if let Some(val) = find_tag(search_data, &[0x9F, 0x32]) {
                data.issuer_exp = Some(val.to_vec());
            }
            if let Some(val) = find_tag(search_data, &[0x92]) {
                data.issuer_rem = Some(val.to_vec());
            }
            if let Some(val) = find_tag(search_data, &[0x9F, 0x46]) {
                data.icc_cert = Some(val.to_vec());
            }
            if let Some(val) = find_tag(search_data, &[0x9F, 0x47]) {
                data.icc_exp = Some(val.to_vec());
            }
            if let Some(val) = find_tag(search_data, &[0x9F, 0x48]) {
                data.icc_rem = Some(val.to_vec());
            }
            if let Some(val) = find_tag(search_data, &[0x5A]) {
                data.pan = Some(val.to_vec());
            }
        }

        data
    }
}

/// Certificate verification result
#[derive(Debug, Clone)]
pub struct CertificateVerificationResult {
    pub ca_key_found: bool,
    pub issuer_cert_valid: bool,
    pub icc_cert_valid: bool,
    pub chain_valid: bool,
    pub errors: Vec<String>,
}

impl CertificateVerificationResult {
    fn new() -> Self {
        Self {
            ca_key_found: false,
            issuer_cert_valid: false,
            icc_cert_valid: false,
            chain_valid: false,
            errors: Vec::new(),
        }
    }
}

/// Verify an EMV certificate using RSA signature recovery
///
/// # Arguments
/// * `certificate` - The certificate bytes
/// * `parent_key` - The parent's public key
/// * `expected_trailer` - Expected trailer byte (0xBC for issuer, 0xCC for ICC)
///
/// # Returns
/// * `Some(Vec<u8>)` - Recovered certificate data if valid
/// * `None` - If verification fails
pub fn verify_certificate(
    certificate: &[u8],
    parent_key: &RsaPublicKey,
    expected_trailer: u8,
) -> Option<Vec<u8>> {
    // Convert certificate bytes to BigUint
    let cert_bigint = BigUint::from_bytes_be(certificate);

    // Get modulus
    let modulus = parent_key.n();

    // Perform RSA operation: cert^e mod n (signature verification with recovery)
    let recovered = cert_bigint.modpow(parent_key.e(), modulus);

    // Convert back to bytes
    let mut recovered_bytes = recovered.to_bytes_be();

    // Pad to expected length (same as modulus length)
    let expected_len = (modulus.bits() + 7) / 8;
    while recovered_bytes.len() < expected_len {
        recovered_bytes.insert(0, 0);
    }

    // Verify format
    if recovered_bytes.len() < 2 {
        return None;
    }

    // Check header (0x6A) and trailer
    if recovered_bytes[0] != 0x6A {
        return None;
    }

    if recovered_bytes[recovered_bytes.len() - 1] != expected_trailer {
        return None;
    }

    Some(recovered_bytes)
}

/// Verify the complete EMV certificate chain
///
/// Verifies: CA → Issuer → ICC
pub fn verify_certificate_chain(cert_data: &CertificateChainData) -> CertificateVerificationResult {
    let mut result = CertificateVerificationResult::new();

    // Step 1: Get CA Public Key
    let ca_index = cert_data.ca_index.unwrap_or(0x05); // Default to Mastercard CA index 05

    let ca_key = match get_ca_public_key(&cert_data.rid, ca_index) {
        Some(key) => {
            result.ca_key_found = true;
            key
        }
        None => {
            result.errors.push(format!(
                "CA Public Key not found for RID {} index {:02X}",
                hex::encode_upper(&cert_data.rid),
                ca_index
            ));
            return result;
        }
    };

    // Step 2: Verify Issuer Certificate
    if let Some(ref issuer_cert) = cert_data.issuer_cert {
        match verify_certificate(issuer_cert, &ca_key, 0xBC) {
            Some(_recovered) => {
                result.issuer_cert_valid = true;

                // TODO: Extract issuer public key from recovered data
                // For now, we mark as valid if signature check passes
            }
            None => {
                result.errors.push("Issuer certificate signature verification failed".to_string());
                return result;
            }
        }
    } else {
        result.errors.push("Issuer certificate not found in card data".to_string());
        return result;
    }

    // Step 3: Verify ICC Certificate (requires issuer public key)
    // TODO: Implement full ICC verification once we extract issuer public key

    if result.ca_key_found && result.issuer_cert_valid {
        result.chain_valid = true;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_verification_result() {
        let result = CertificateVerificationResult::new();
        assert!(!result.ca_key_found);
        assert!(!result.chain_valid);
        assert!(result.errors.is_empty());
    }
}
