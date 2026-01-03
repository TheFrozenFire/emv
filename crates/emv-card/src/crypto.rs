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

/// Extract public key from recovered certificate data
///
/// Returns (modulus_part, exponent_length, pk_length)
fn extract_public_key_from_certificate(recovered: &[u8]) -> Option<(Vec<u8>, usize, usize)> {
    // EMV certificate format (Issuer Public Key Certificate):
    // Byte 1: Header (0x6A)
    // Byte 2: Certificate Format
    // Bytes 3-12: Issuer Identifier (10 bytes - leftmost PAN digits + 'F' padding)
    // Bytes 13-14: Certificate Expiration Date (2 bytes)
    // Bytes 15-16: Certificate Serial Number (2 bytes)
    // Byte 17: Hash Algorithm Indicator
    // Byte 18: Issuer Public Key Algorithm Indicator
    // Byte 19: Issuer Public Key Length NI (in bytes)
    // Byte 20: Issuer Public Key Exponent Length NIE (in bytes)
    // Bytes 21+: Issuer Public Key or leftmost digits
    // Last 21 bytes: Hash Result
    // Last byte: Trailer (0xBC)

    if recovered.len() < 42 {
        return None;
    }

    println!("DEBUG: Recovered certificate {} bytes", recovered.len());
    println!("DEBUG: Last 25 bytes:");
    let start_idx = if recovered.len() > 25 { recovered.len() - 25 } else { 0 };
    for i in start_idx..recovered.len() {
        if (i - start_idx) % 16 == 0 {
            print!("  {:3}: ", i + 1);
        }
        print!("{:02X} ", recovered[i]);
        if ((i - start_idx + 1) % 16 == 0 || i == recovered.len() - 1) {
            println!();
        }
    }
    println!("DEBUG: Trailer (last byte): 0x{:02X} (expected 0xBC)", recovered[recovered.len() - 1]);

    println!("DEBUG: Bytes 1-35:");
    for i in 0..35.min(recovered.len()) {
        if i % 16 == 0 {
            print!("  {:3}: ", i + 1);
        }
        print!("{:02X} ", recovered[i]);
        if (i + 1) % 16 == 0 || i == 34 {
            println!();
        }
    }
    println!("DEBUG: Byte 18 (PK Algo): 0x{:02X}", recovered[17]);
    println!("DEBUG: Byte 19 (PK Length): 0x{:02X} = {} bytes", recovered[18], recovered[18]);
    println!("DEBUG: Byte 20 (Exp Length): 0x{:02X} = {} bytes", recovered[19], recovered[19]);

    let pk_length = recovered[18] as usize;
    let exp_length = recovered[19] as usize;

    // Extract public key portion from certificate
    // It starts at byte 21 (index 20) and goes until 22 bytes before the end (hash + trailer)
    let pk_start = 20;
    let pk_end = recovered.len() - 22;

    if pk_end <= pk_start {
        return None;
    }

    let pk_part = recovered[pk_start..pk_end].to_vec();

    Some((pk_part, exp_length, pk_length))
}

/// Build complete public key from certificate part and optional remainder
fn build_public_key(
    pk_cert_part: Vec<u8>,
    pk_remainder: Option<&[u8]>,
    exponent_bytes: &[u8],
    total_length: usize,
) -> Option<RsaPublicKey> {
    // Combine certificate part with remainder
    let mut modulus_bytes = pk_cert_part;

    if let Some(remainder) = pk_remainder {
        modulus_bytes.extend_from_slice(remainder);
    }

    // Pad or truncate to expected length
    if modulus_bytes.len() < total_length {
        // Need more bytes - this shouldn't happen if we have the right remainder
        return None;
    } else if modulus_bytes.len() > total_length {
        // Truncate to expected length
        modulus_bytes.truncate(total_length);
    }

    // Build modulus from bytes
    let modulus = BigUint::from_bytes_be(&modulus_bytes);

    // Build exponent from bytes
    let exponent = BigUint::from_bytes_be(exponent_bytes);

    // Create RSA public key
    RsaPublicKey::new(modulus, exponent).ok()
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
                    println!("CA Public Key loaded:");
                    println!("  RID: {}", hex::encode_upper(&cert_data.rid));
                    println!("  Index: {:02X}", ca_index);
                    println!("  Modulus bits: {}", key.n().bits());
                    println!("  Modulus bytes: {}", (key.n().bits() + 7) / 8);
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
            let issuer_key = if let Some(ref issuer_cert) = cert_data.issuer_cert {
                match verify_certificate(issuer_cert, &ca_key, 0xBC) {
                    Some(recovered) => {
                        result.issuer_cert_valid = true;

                        // Extract issuer public key from recovered certificate
                        match extract_public_key_from_certificate(&recovered) {
                            Some((pk_cert_part, _exp_len, pk_len)) => {
                                println!("Extracting Issuer Public Key:");
                                println!("  PK length from cert: {} bytes", pk_len);
                                println!("  PK cert part: {} bytes", pk_cert_part.len());
                                if let Some(ref rem) = cert_data.issuer_rem {
                                    println!("  PK remainder: {} bytes", rem.len());
                                } else {
                                    println!("  PK remainder: none");
                                }

                                // Get exponent from card data
                                if let Some(ref exp_bytes) = cert_data.issuer_exp {
                                    println!("  Exponent: {} bytes", exp_bytes.len());

                                    // Build complete public key
                                    match build_public_key(
                                        pk_cert_part,
                                        cert_data.issuer_rem.as_deref(),
                                        exp_bytes,
                                        pk_len,
                                    ) {
                                        Some(key) => Some(key),
                                        None => {
                                            result.errors.push("Failed to build Issuer Public Key from certificate data".to_string());
                                            None
                                        }
                                    }
                                } else {
                                    result.errors.push("Issuer Public Key Exponent (9F32) not found".to_string());
                                    None
                                }
                            }
                            None => {
                                result.errors.push("Failed to extract public key from Issuer certificate".to_string());
                                None
                            }
                        }
                    }
                    None => {
                        result.errors.push("Issuer certificate signature verification failed".to_string());
                        return result;
                    }
                }
            } else {
                result.errors.push("Issuer certificate not found in card data".to_string());
                return result;
            };

            // Step 3: Verify ICC Certificate (requires issuer public key)
            if let Some(issuer_pk) = issuer_key {
                println!("Issuer Public Key extracted successfully:");
                println!("  Modulus bits: {}", issuer_pk.n().bits());
                println!("  Exponent: {}", issuer_pk.e());

                if let Some(ref icc_cert) = cert_data.icc_cert {
                    println!("Attempting to verify ICC certificate ({} bytes)...", icc_cert.len());
                    println!("  ICC cert (first 16 bytes): {}", hex::encode_upper(&icc_cert[..16.min(icc_cert.len())]));

                    match verify_certificate(icc_cert, &issuer_pk, 0xCC) {
                        Some(recovered) => {
                            result.icc_cert_valid = true;
                            println!("✓ ICC certificate verified successfully");
                            println!("  Recovered data: {} bytes", recovered.len());

                            // Optionally: Extract ICC Public Key for DDA/CDA
                            // This would be used for INTERNAL AUTHENTICATE commands
                            // For now, we just verify the signature
                        }
                        None => {
                            println!("✗ ICC certificate verification failed");
                            println!("  Certificate length: {}", icc_cert.len());
                            println!("  Issuer key modulus length: {} bytes", (issuer_pk.n().bits() + 7) / 8);

                            // Try to see what we get back
                            let cert_bigint = rsa::BigUint::from_bytes_be(icc_cert);
                            let recovered = cert_bigint.modpow(issuer_pk.e(), issuer_pk.n());
                            let recovered_bytes = recovered.to_bytes_be();
                            println!("  Recovered (unpadded): {} bytes", recovered_bytes.len());
                            if recovered_bytes.len() >= 2 {
                                println!("  Header: 0x{:02X} (expected 0x6A)", recovered_bytes[0]);
                                println!("  Trailer: 0x{:02X} (expected 0xCC)", recovered_bytes[recovered_bytes.len() - 1]);
                            }

                            result.errors.push("ICC certificate signature verification failed".to_string());
                        }
                    }
                } else {
                    result.errors.push("ICC certificate not found in card data".to_string());
                }
            } else {
                result.errors.push("Cannot verify ICC certificate without Issuer Public Key".to_string());
            }

            // Mark chain as valid only if all certificates verified
            if result.ca_key_found && result.issuer_cert_valid && result.icc_cert_valid {
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
