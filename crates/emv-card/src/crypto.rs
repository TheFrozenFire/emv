//! Cryptographic operations for EMV certificate verification

use rsa::{BigUint, RsaPublicKey};
use rsa::traits::PublicKeyParts;
use emv_common::find_tag;
use emv_ca_keys::CaKeyStore;
use tracing::{debug, trace};

/// Errors that can occur during certificate verification
#[derive(Debug, thiserror::Error)]
pub enum CertVerificationError {
    #[error("Invalid certificate format: {0}")]
    InvalidFormat(String),

    #[error("Certificate signature verification failed")]
    SignatureInvalid,

    #[error("Invalid certificate header or trailer: expected {expected:#04X}, got {actual:#04X}")]
    InvalidHeaderTrailer { expected: u8, actual: u8 },

    #[error("Failed to build RSA public key: {0}")]
    KeyConstructionFailed(String),

    #[error("Certificate data too short: expected at least {expected} bytes, got {actual}")]
    InsufficientData { expected: usize, actual: usize },
}

/// Public key data extracted from a certificate
#[derive(Debug, Clone)]
pub struct ExtractedKeyData {
    pub modulus_part: Vec<u8>,
    pub exponent_length: usize,
    pub total_length: usize,
}

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

/// Low-level certificate verification operations
///
/// Handles RSA signature verification, certificate parsing, and public key extraction.
pub struct CertificateVerifier {
    // Stateless - no fields needed
}

impl CertificateVerifier {
    /// Create a new certificate verifier
    pub fn new() -> Self {
        Self {}
    }

    /// Verify an EMV certificate using RSA signature recovery
    ///
    /// # Arguments
    /// * `certificate` - The certificate bytes
    /// * `parent_key` - The parent's public key
    /// * `expected_trailer` - Expected trailer byte (0xBC for issuer, 0xCC for ICC)
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Recovered certificate data if valid
    /// * `Err(CertVerificationError)` - If verification fails
    pub fn verify_and_recover(
        &self,
        certificate: &[u8],
        parent_key: &RsaPublicKey,
        expected_trailer: u8,
    ) -> Result<Vec<u8>, CertVerificationError> {
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
            return Err(CertVerificationError::InsufficientData {
                expected: 2,
                actual: recovered_bytes.len(),
            });
        }

        // Check header (0x6A)
        if recovered_bytes[0] != 0x6A {
            return Err(CertVerificationError::InvalidHeaderTrailer {
                expected: 0x6A,
                actual: recovered_bytes[0],
            });
        }

        // Check trailer
        let trailer = recovered_bytes[recovered_bytes.len() - 1];
        if trailer != expected_trailer {
            return Err(CertVerificationError::InvalidHeaderTrailer {
                expected: expected_trailer,
                actual: trailer,
            });
        }

        Ok(recovered_bytes)
    }

    /// Extract public key data from recovered certificate
    ///
    /// # Returns
    /// * `Ok(ExtractedKeyData)` - Extracted key components
    /// * `Err(CertVerificationError)` - If extraction fails
    pub fn extract_public_key(
        &self,
        recovered: &[u8],
    ) -> Result<ExtractedKeyData, CertVerificationError> {
        // EMV certificate format:
        // Byte 1: Header (0x6A)
        // Byte 2: Certificate Format
        // Bytes 3-12: Issuer Identifier
        // Bytes 13-14: Certificate Expiration Date
        // Bytes 15-16: Certificate Serial Number
        // Byte 17: Hash Algorithm Indicator
        // Byte 18: Public Key Algorithm Indicator
        // Byte 19: Public Key Length (in bytes)
        // Byte 20: Public Key Exponent Length (in bytes)
        // Bytes 21+: Public Key or leftmost digits
        // Last 21 bytes: Hash Result
        // Last byte: Trailer (0xBC or 0xCC)

        if recovered.len() < 42 {
            return Err(CertVerificationError::InsufficientData {
                expected: 42,
                actual: recovered.len(),
            });
        }

        trace!(recovered_bytes = recovered.len(), "Extracting public key from certificate");
        trace!(last_bytes = %hex::encode_upper(&recovered[recovered.len().saturating_sub(25)..]), "Last 25 bytes");
        trace!(trailer = format!("0x{:02X}", recovered[recovered.len() - 1]), "Trailer");
        trace!(first_bytes = %hex::encode_upper(&recovered[..35.min(recovered.len())]), "First 35 bytes");
        trace!(pk_algo = format!("0x{:02X}", recovered[17]), "Byte 18: PK Algorithm");
        trace!(pk_length = format!("0x{:02X} = {} bytes", recovered[18], recovered[18]), "Byte 19: PK Length");
        trace!(exp_length = format!("0x{:02X} = {} bytes", recovered[19], recovered[19]), "Byte 20: Exp Length");

        let pk_length = recovered[18] as usize;
        let exp_length = recovered[19] as usize;

        // Extract public key portion from certificate
        // It starts at byte 21 (index 20) and goes until 22 bytes before the end (hash + trailer)
        let pk_start = 20;
        let pk_end = recovered.len() - 22;

        if pk_end <= pk_start {
            return Err(CertVerificationError::InvalidFormat(
                "Certificate too short to contain public key data".to_string(),
            ));
        }

        let modulus_part = recovered[pk_start..pk_end].to_vec();

        Ok(ExtractedKeyData {
            modulus_part,
            exponent_length: exp_length,
            total_length: pk_length,
        })
    }

    /// Build complete RSA public key from certificate parts
    ///
    /// # Arguments
    /// * `data` - Extracted key data from certificate
    /// * `remainder` - Optional remainder bytes (for keys longer than certificate can hold)
    /// * `exponent` - Public exponent bytes
    ///
    /// # Returns
    /// * `Ok(RsaPublicKey)` - Constructed public key
    /// * `Err(CertVerificationError)` - If key construction fails
    pub fn build_public_key(
        &self,
        data: &ExtractedKeyData,
        remainder: Option<&[u8]>,
        exponent: &[u8],
    ) -> Result<RsaPublicKey, CertVerificationError> {
        // Combine certificate part with remainder
        let mut modulus_bytes = data.modulus_part.clone();

        if let Some(remainder) = remainder {
            modulus_bytes.extend_from_slice(remainder);
        }

        // Pad or truncate to expected length
        if modulus_bytes.len() < data.total_length {
            return Err(CertVerificationError::InvalidFormat(format!(
                "Insufficient key data: need {} bytes, have {}",
                data.total_length,
                modulus_bytes.len()
            )));
        } else if modulus_bytes.len() > data.total_length {
            modulus_bytes.truncate(data.total_length);
        }

        // Build modulus from bytes
        let modulus = BigUint::from_bytes_be(&modulus_bytes);
        let exponent = BigUint::from_bytes_be(exponent);

        // Create RSA public key
        RsaPublicKey::new(modulus, exponent).map_err(|e| {
            CertVerificationError::KeyConstructionFailed(format!("RSA key creation failed: {}", e))
        })
    }
}

impl Default for CertificateVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// High-level certificate chain verification orchestrator
///
/// Handles the complete EMV certificate chain verification process,
/// orchestrating CA key loading, issuer certificate verification, and ICC certificate verification.
pub struct ChainVerifier {
    ca_store: CaKeyStore,
    cert_verifier: CertificateVerifier,
}

impl ChainVerifier {
    /// Create a new chain verifier with embedded CA keys
    pub fn new() -> Self {
        Self {
            ca_store: CaKeyStore::embedded(),
            cert_verifier: CertificateVerifier::new(),
        }
    }

    /// Create a chain verifier with a custom CA key store (useful for testing)
    pub fn with_ca_store(ca_store: CaKeyStore) -> Self {
        Self {
            ca_store,
            cert_verifier: CertificateVerifier::new(),
        }
    }

    /// Verify the complete EMV certificate chain
    ///
    /// Handles both SDA and DDA/CDA authentication methods
    pub fn verify_chain(&self, cert_data: &CertificateChainData) -> CertificateVerificationResult {
        // Detect authentication method from AIP
        let auth_method = self.detect_auth_method(cert_data);
        let mut result = CertificateVerificationResult::new(auth_method);

        match auth_method {
            AuthenticationMethod::Sda => self.verify_sda(cert_data, &mut result),
            AuthenticationMethod::Dda | AuthenticationMethod::Cda => {
                self.verify_dda_cda(cert_data, &mut result)
            }
            AuthenticationMethod::None => {
                result.errors.push("No authentication method detected in AIP".to_string());
            }
        }

        result
    }

    /// Detect authentication method from AIP and card data
    fn detect_auth_method(&self, cert_data: &CertificateChainData) -> AuthenticationMethod {
        let aip_auth_method = if let Some(ref aip) = cert_data.aip {
            detect_auth_method(aip)
        } else {
            AuthenticationMethod::None
        };

        // Override with data-driven detection:
        // If card has SDA Tag List (9F4A) but no Issuer Cert (90), it's actually using SDA
        // regardless of what AIP says (cards may advertise CDA but fall back to SDA)
        if cert_data.sda_tag_list.is_some() && cert_data.issuer_cert.is_none() {
            AuthenticationMethod::Sda
        } else {
            aip_auth_method
        }
    }

    /// Verify SDA (Static Data Authentication)
    fn verify_sda(&self, cert_data: &CertificateChainData, result: &mut CertificateVerificationResult) {
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

    /// Verify DDA/CDA (Dynamic Data Authentication / Combined Data Authentication)
    fn verify_dda_cda(&self, cert_data: &CertificateChainData, result: &mut CertificateVerificationResult) {
        // DDA/CDA: Verify certificate chain (CA → Issuer → ICC)

        // Step 1: Load CA Public Key
        let ca_key = match self.load_ca_key(cert_data, result) {
            Some(key) => key,
            None => return,
        };

        // Step 2: Verify Issuer Certificate
        let issuer_key = match self.verify_issuer_cert(cert_data, &ca_key, result) {
            Some(key) => key,
            None => return,
        };

        // Step 3: Verify ICC Certificate
        self.verify_icc_cert(cert_data, &issuer_key, result);

        // Mark chain as valid only if all certificates verified
        if result.ca_key_found && result.issuer_cert_valid && result.icc_cert_valid {
            result.chain_valid = true;
        }
    }

    /// Load CA Public Key from store
    fn load_ca_key(
        &self,
        cert_data: &CertificateChainData,
        result: &mut CertificateVerificationResult,
    ) -> Option<RsaPublicKey> {
        let ca_index = cert_data.ca_index.unwrap_or(0x05);

        match self.ca_store.get_key(&cert_data.rid, ca_index) {
            Some(key) => {
                result.ca_key_found = true;
                debug!(
                    rid = %hex::encode_upper(&cert_data.rid),
                    index = format!("{:02X}", ca_index),
                    modulus_bits = key.n().bits(),
                    "CA Public Key loaded"
                );
                Some(key)
            }
            None => {
                result.errors.push(format!(
                    "CA Public Key not found for RID {} index {:02X}",
                    hex::encode_upper(&cert_data.rid),
                    ca_index
                ));
                None
            }
        }
    }

    /// Verify Issuer Certificate and extract Issuer Public Key
    fn verify_issuer_cert(
        &self,
        cert_data: &CertificateChainData,
        ca_key: &RsaPublicKey,
        result: &mut CertificateVerificationResult,
    ) -> Option<RsaPublicKey> {
        let issuer_cert = match &cert_data.issuer_cert {
            Some(cert) => cert,
            None => {
                result.errors.push("Issuer certificate not found in card data".to_string());
                return None;
            }
        };

        let recovered = match self.cert_verifier.verify_and_recover(issuer_cert, ca_key, 0xBC) {
            Ok(data) => {
                result.issuer_cert_valid = true;
                data
            }
            Err(e) => {
                result.errors.push(format!("Issuer certificate signature verification failed: {}", e));
                return None;
            }
        };

        // Extract issuer public key from recovered certificate
        let extracted = match self.cert_verifier.extract_public_key(&recovered) {
            Ok(data) => data,
            Err(e) => {
                result.errors.push(format!("Failed to extract public key from Issuer certificate: {}", e));
                return None;
            }
        };

        debug!(
            pk_length = extracted.total_length,
            pk_cert_part_bytes = extracted.modulus_part.len(),
            pk_remainder_bytes = cert_data.issuer_rem.as_ref().map(|r| r.len()),
            "Extracting Issuer Public Key from certificate"
        );

        // Get exponent from card data
        let exp_bytes = match &cert_data.issuer_exp {
            Some(bytes) => {
                trace!(exponent_bytes = bytes.len(), "Issuer exponent present");
                bytes
            }
            None => {
                result.errors.push("Issuer Public Key Exponent (9F32) not found".to_string());
                return None;
            }
        };

        // Build complete public key
        match self.cert_verifier.build_public_key(
            &extracted,
            cert_data.issuer_rem.as_deref(),
            exp_bytes,
        ) {
            Ok(key) => Some(key),
            Err(e) => {
                result.errors.push(format!("Failed to build Issuer Public Key: {}", e));
                None
            }
        }
    }

    /// Verify ICC Certificate
    fn verify_icc_cert(
        &self,
        cert_data: &CertificateChainData,
        issuer_key: &RsaPublicKey,
        result: &mut CertificateVerificationResult,
    ) {
        debug!(
            modulus_bits = issuer_key.n().bits(),
            exponent = %issuer_key.e(),
            "Issuer Public Key extracted successfully"
        );

        let icc_cert = match &cert_data.icc_cert {
            Some(cert) => cert,
            None => {
                result.errors.push("ICC certificate not found in card data".to_string());
                return;
            }
        };

        debug!(cert_bytes = icc_cert.len(), "Attempting to verify ICC certificate");
        trace!(icc_cert_start = %hex::encode_upper(&icc_cert[..16.min(icc_cert.len())]), "ICC certificate start");

        match self.cert_verifier.verify_and_recover(icc_cert, issuer_key, 0xCC) {
            Ok(recovered) => {
                result.icc_cert_valid = true;
                debug!(recovered_bytes = recovered.len(), "ICC certificate verified successfully");

                // Optionally: Extract ICC Public Key for DDA/CDA
                // This would be used for INTERNAL AUTHENTICATE commands
                // For now, we just verify the signature
            }
            Err(e) => {
                debug!("ICC certificate verification failed: {}", e);
                trace!(
                    cert_length = icc_cert.len(),
                    issuer_key_modulus_bytes = (issuer_key.n().bits() + 7) / 8,
                    "ICC certificate details"
                );

                // Try to see what we get back for debugging
                let cert_bigint = BigUint::from_bytes_be(icc_cert);
                let recovered = cert_bigint.modpow(issuer_key.e(), issuer_key.n());
                let recovered_bytes = recovered.to_bytes_be();
                trace!(recovered_bytes = recovered_bytes.len(), "Recovered (unpadded)");
                if recovered_bytes.len() >= 2 {
                    trace!(
                        header = format!("0x{:02X}", recovered_bytes[0]),
                        trailer = format!("0x{:02X}", recovered_bytes[recovered_bytes.len() - 1]),
                        "Header (expected 0x6A) and Trailer (expected 0xCC)"
                    );
                }

                result.errors.push(format!("ICC certificate signature verification failed: {}", e));
            }
        }
    }
}

impl Default for ChainVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify an EMV certificate using RSA signature recovery
///
/// Backward-compatible wrapper around `CertificateVerifier::verify_and_recover`.
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
    CertificateVerifier::new()
        .verify_and_recover(certificate, parent_key, expected_trailer)
        .ok()
}

/// Verify the complete EMV certificate chain
///
/// Backward-compatible wrapper around `ChainVerifier::verify_chain`.
///
/// Handles both SDA and DDA/CDA authentication methods
pub fn verify_certificate_chain(cert_data: &CertificateChainData) -> CertificateVerificationResult {
    ChainVerifier::new().verify_chain(cert_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_verification_result() {
        let result = CertificateVerificationResult::new(AuthenticationMethod::None);
        assert!(!result.ca_key_found);
        assert!(!result.chain_valid);
        assert!(result.errors.is_empty());
        assert_eq!(result.auth_method, AuthenticationMethod::None);
    }
}
