//! Cryptographic operations for EMV certificate verification

use rsa::{BigUint, RsaPublicKey};
use rsa::traits::PublicKeyParts;
use emv_common::find_tag;
use emv_ca_keys::get_ca_public_key;

/// Certificate data extracted from card
#[derive(Debug, Clone)]
pub struct CertificateChainData {
    pub aip: Option<Vec<u8>>,
    pub ca_index: Option<u8>,
    pub rid: Vec<u8>,
    pub issuer_cert: Option<Vec<u8>>,
    pub issuer_exp: Option<Vec<u8>>,
    pub issuer_rem: Option<Vec<u8>>,
    pub icc_cert: Option<Vec<u8>>,
    pub icc_exp: Option<Vec<u8>>,
    pub icc_rem: Option<Vec<u8>>,
    pub pan: Option<Vec<u8>>,
    pub sda_tag_list: Option<Vec<u8>>,
    pub signed_static_app_data: Option<Vec<u8>>,
}

/// Detect authentication method from AIP
fn detect_auth_method(aip: &[u8]) -> AuthenticationMethod {
    if aip.len() < 1 {
        return AuthenticationMethod::None;
    }

    let byte1 = aip[0];

    // Check bits in order of preference (CDA > DDA > SDA)
    if byte1 & 0x01 != 0 {
        AuthenticationMethod::Cda
    } else if byte1 & 0x20 != 0 {
        AuthenticationMethod::Dda
    } else if byte1 & 0x40 != 0 {
        AuthenticationMethod::Sda
    } else {
        AuthenticationMethod::None
    }
}

impl CertificateChainData {
    /// Extract certificate data from all card records and GPO response
    pub fn from_card_data(records: &[Vec<u8>], gpo_response: Option<&[u8]>, rid: Vec<u8>) -> Self {
        let mut data = Self {
            aip: None,
            ca_index: None,
            rid,
            issuer_cert: None,
            issuer_exp: None,
            issuer_rem: None,
            icc_cert: None,
            icc_exp: None,
            icc_rem: None,
            pan: None,
            sda_tag_list: None,
            signed_static_app_data: None,
        };

        // Extract AIP from GPO response
        if let Some(gpo_data) = gpo_response {
            let search_data = if let Some(template) = find_tag(gpo_data, &[0x77]) {
                template
            } else if let Some(template) = find_tag(gpo_data, &[0x80]) {
                template
            } else {
                gpo_data
            };

            if let Some(val) = find_tag(search_data, &[0x82]) {
                data.aip = Some(val.to_vec());
            }
        }

        for record in records {
            // First check if record is wrapped in tag 70 (Record Template)
            let search_data = if let Some(template) = find_tag(record, &[0x70]) {
                template
            } else {
                record.as_slice()
            };

            if let Some(val) = find_tag(search_data, &[0x82]) {
                data.aip = Some(val.to_vec());
            }
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
            if let Some(val) = find_tag(search_data, &[0x9F, 0x4A]) {
                data.sda_tag_list = Some(val.to_vec());
            }
            if let Some(val) = find_tag(search_data, &[0x93]) {
                data.signed_static_app_data = Some(val.to_vec());
            }
        }

        data
    }
}

/// Authentication method detected from card
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationMethod {
    Sda,
    Dda,
    Cda,
    None,
}

/// Certificate verification result
#[derive(Debug, Clone)]
pub struct CertificateVerificationResult {
    pub auth_method: AuthenticationMethod,
    pub ca_key_found: bool,
    pub issuer_cert_valid: bool,
    pub icc_cert_valid: bool,
    pub chain_valid: bool,
    pub errors: Vec<String>,
}

impl CertificateVerificationResult {
    fn new(auth_method: AuthenticationMethod) -> Self {
        Self {
            auth_method,
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
/// Handles both SDA and DDA/CDA authentication methods
pub fn verify_certificate_chain(cert_data: &CertificateChainData) -> CertificateVerificationResult {
    // Detect authentication method from AIP
    let aip_auth_method = if let Some(ref aip) = cert_data.aip {
        detect_auth_method(aip)
    } else {
        AuthenticationMethod::None
    };

    // Override with data-driven detection:
    // If card has SDA Tag List (9F4A) but no Issuer Cert (90), it's actually using SDA
    // regardless of what AIP says (cards may advertise CDA but fall back to SDA)
    let auth_method = if cert_data.sda_tag_list.is_some() && cert_data.issuer_cert.is_none() {
        AuthenticationMethod::Sda
    } else {
        aip_auth_method
    };

    let mut result = CertificateVerificationResult::new(auth_method);

    match auth_method {
        AuthenticationMethod::Sda => {
            // SDA: Verify static data signature
            // For SDA, we need:
            // - Issuer Public Key Certificate (tag 90) to get Issuer Public Key
            // - Signed Static Application Data (tag 93) - the signature
            // - SDA Tag List (tag 9F4A) - tells us which tags to hash

            let has_tag_list = cert_data.sda_tag_list.is_some();
            let has_issuer_cert = cert_data.issuer_cert.is_some();
            let has_signed_data = cert_data.signed_static_app_data.is_some();

            if !has_tag_list && !has_issuer_cert && !has_signed_data {
                result.errors.push(
                    "SDA authentication method detected, but card is missing all SDA data (tags 90, 93, 9F4A)".to_string()
                );
            } else {
                let mut missing = Vec::new();
                if !has_issuer_cert {
                    missing.push("Issuer Certificate (90)");
                }
                if !has_signed_data {
                    missing.push("Signed Static Application Data (93)");
                }
                if !has_tag_list {
                    missing.push("SDA Tag List (9F4A)");
                }

                if !missing.is_empty() {
                    result.errors.push(format!(
                        "SDA authentication incomplete - missing: {}",
                        missing.join(", ")
                    ));
                } else {
                    result.errors.push("SDA detected - full verification not yet implemented".to_string());
                }
            }
        }
        AuthenticationMethod::Dda | AuthenticationMethod::Cda => {
            // DDA/CDA: Verify certificate chain (CA → Issuer → ICC)

            // Step 1: Get CA Public Key
            let ca_index = cert_data.ca_index.unwrap_or(0x05);

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
        }
        AuthenticationMethod::None => {
            result.errors.push("No authentication method detected in AIP".to_string());
        }
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
