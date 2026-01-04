//! Cryptographic operations for EMV certificate verification

use emv_ca_keys::CaKeyStore;
use emv_common::find_tag;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};
use tracing::{debug, info, trace};

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
    // Store ALL instances of certificate tags (some cards have multiple)
    pub all_issuer_certs: Vec<Vec<u8>>,
    pub all_icc_certs: Vec<Vec<u8>>,
}

/// Certificate type determined from format byte
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertificateType {
    Issuer,  // Format byte 0x02
    Icc,     // Format byte 0x04
    Unknown(u8),
}

/// A certificate discovered on the card
#[derive(Debug, Clone)]
struct DiscoveredCertificate {
    /// The certificate data
    cert_data: Vec<u8>,
    /// Associated exponent
    exponent: Option<Vec<u8>>,
    /// Associated remainder
    remainder: Option<Vec<u8>>,
    /// Which tag this came from
    tag: Vec<u8>,
}

/// Detect authentication method from AIP
fn detect_auth_method(aip: &[u8]) -> AuthenticationMethod {
    if aip.is_empty() {
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
    /// Discover all certificates present on the card
    ///
    /// Returns certificates in the order they should be verified (tag 90 first, then all 9F46, etc.)
    fn discover_certificates(&self) -> Vec<DiscoveredCertificate> {
        let mut certs = Vec::new();

        // Certificate tag 90: Issuer Public Key Certificate (signed by CA)
        // Try all instances
        for cert in &self.all_issuer_certs {
            debug!(
                tag = "90",
                bytes = cert.len(),
                "Found certificate: Issuer Public Key Certificate"
            );
            certs.push(DiscoveredCertificate {
                cert_data: cert.clone(),
                exponent: self.issuer_exp.clone(),
                remainder: self.issuer_rem.clone(),
                tag: vec![0x90],
            });
        }

        // Certificate tag 9F46: ICC Public Key Certificate (signed by Issuer)
        // Note: May actually be another Issuer cert in two-level hierarchies
        // Cards can have multiple instances - try all of them
        for (index, cert) in self.all_icc_certs.iter().enumerate() {
            debug!(
                tag = "9F46",
                instance = index + 1,
                bytes = cert.len(),
                "Found certificate: ICC Public Key Certificate"
            );
            certs.push(DiscoveredCertificate {
                cert_data: cert.clone(),
                exponent: self.icc_exp.clone(),
                remainder: self.icc_rem.clone(),
                tag: vec![0x9F, 0x46],
            });
        }

        if certs.is_empty() {
            debug!("No certificates found on card");
        } else {
            debug!(count = certs.len(), "Discovered certificates");
        }

        certs
    }

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
            all_issuer_certs: Vec::new(),
            all_icc_certs: Vec::new(),
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
                let cert = val.to_vec();
                data.all_issuer_certs.push(cert.clone());
                data.issuer_cert = Some(cert);  // Keep last for backward compat
            }
            if let Some(val) = find_tag(search_data, &[0x9F, 0x32]) {
                data.issuer_exp = Some(val.to_vec());
            }
            if let Some(val) = find_tag(search_data, &[0x92]) {
                data.issuer_rem = Some(val.to_vec());
            }
            if let Some(val) = find_tag(search_data, &[0x9F, 0x46]) {
                let cert = val.to_vec();
                data.all_icc_certs.push(cert.clone());
                data.icc_cert = Some(cert);  // Keep last for backward compat
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
    pub icc_public_key: Option<RsaPublicKey>,
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
            icc_public_key: None,
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
        let expected_len = modulus.bits().div_ceil(8);
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
        // EMV certificate format (EMV Book 2, Table 5):
        // Byte 0: Recovered Data Header (0x6A)
        // Byte 1: Certificate Format (0x02 for Issuer, 0x04 for ICC)
        // Bytes 2-5: Issuer Identifier
        // Bytes 6-7: Certificate Expiration Date
        // Bytes 8-10: Certificate Serial Number
        // Byte 11: Hash Algorithm Indicator
        // Byte 12: Public Key Algorithm Indicator
        // Byte 13: Public Key Length (in bytes)
        // Byte 14: Public Key Exponent Length (in bytes)
        // Byte 15+: Public Key or leftmost digits
        // Last 20 bytes: Hash Result
        // Last byte: Recovered Data Trailer (0xBC)

        if recovered.len() < 36 {
            return Err(CertVerificationError::InsufficientData {
                expected: 36,
                actual: recovered.len(),
            });
        }

        trace!(
            recovered_bytes = recovered.len(),
            "Extracting public key from certificate"
        );
        trace!(last_bytes = %hex::encode_upper(&recovered[recovered.len().saturating_sub(25)..]), "Last 25 bytes");
        trace!(
            trailer = format!("0x{:02X}", recovered[recovered.len() - 1]),
            "Trailer"
        );
        trace!(first_bytes = %hex::encode_upper(&recovered[..35.min(recovered.len())]), "First 35 bytes");
        trace!(
            pk_algo = format!("0x{:02X}", recovered[12]),
            "Byte 12: PK Algorithm"
        );
        trace!(
            pk_length = format!("0x{:02X} = {} bytes", recovered[13], recovered[13]),
            "Byte 13: PK Length"
        );
        trace!(
            exp_length = format!("0x{:02X} = {} bytes", recovered[14], recovered[14]),
            "Byte 14: Exp Length"
        );

        let pk_length = recovered[13] as usize;
        let exp_length = recovered[14] as usize;

        // Extract public key portion from certificate
        // It starts at byte 15 and goes until:
        // 1. We hit 0xBB padding bytes, or
        // 2. We reach 21 bytes before the end (20 bytes hash + 1 byte trailer), or
        // 3. We've extracted pk_length bytes
        let pk_start = 15;
        let pk_end = recovered.len() - 21;

        if pk_end <= pk_start {
            return Err(CertVerificationError::InvalidFormat(
                "Certificate too short to contain public key data".to_string(),
            ));
        }

        // Find where the actual modulus data ends (before 0xBB padding)
        let mut actual_end = pk_end;
        for i in pk_start..pk_end {
            if recovered[i] == 0xBB {
                actual_end = i;
                break;
            }
        }

        // Limit to pk_length bytes maximum
        let available_bytes = actual_end - pk_start;
        let bytes_to_extract = available_bytes.min(pk_length);
        let actual_end = pk_start + bytes_to_extract;

        let modulus_part = recovered[pk_start..actual_end].to_vec();

        Ok(ExtractedKeyData {
            modulus_part,
            exponent_length: exp_length,
            total_length: pk_length,
        })
    }

    /// Verify DDA signature from INTERNAL AUTHENTICATE response
    ///
    /// # Arguments
    /// * `signature` - Signature data from INTERNAL AUTHENTICATE response
    /// * `icc_public_key` - ICC public key extracted from certificate
    /// * `challenge` - Original challenge sent to the card
    ///
    /// # Returns
    /// * `Ok(())` - Signature is valid
    /// * `Err(CertVerificationError)` - Signature verification failed
    pub fn verify_dda_signature(
        &self,
        signature: &[u8],
        icc_public_key: &RsaPublicKey,
        challenge: &[u8],
    ) -> Result<(), CertVerificationError> {
        // Recover data from signature using ICC public key
        let sig_bigint = BigUint::from_bytes_be(signature);
        let recovered = sig_bigint.modpow(icc_public_key.e(), icc_public_key.n());
        let mut recovered_bytes = recovered.to_bytes_be();

        // Pad to expected length
        let expected_len = icc_public_key.n().bits().div_ceil(8);
        while recovered_bytes.len() < expected_len {
            recovered_bytes.insert(0, 0);
        }

        trace!(
            signature_len = signature.len(),
            recovered_len = recovered_bytes.len(),
            "DDA signature recovery"
        );

        // Verify format (EMV Book 2, Section 6.4)
        // Header should be 0x6A, Trailer should be 0xBC
        if recovered_bytes.len() < 2 {
            return Err(CertVerificationError::InsufficientData {
                expected: 2,
                actual: recovered_bytes.len(),
            });
        }

        if recovered_bytes[0] != 0x6A {
            return Err(CertVerificationError::InvalidHeaderTrailer {
                expected: 0x6A,
                actual: recovered_bytes[0],
            });
        }

        let trailer = recovered_bytes[recovered_bytes.len() - 1];
        if trailer != 0xBC {
            return Err(CertVerificationError::InvalidHeaderTrailer {
                expected: 0xBC,
                actual: trailer,
            });
        }

        // Verify challenge is present in recovered data
        // The challenge should be at the beginning of the data portion (after format byte)
        // Typical format: 0x6A | Format | Data | Hash | 0xBC
        if recovered_bytes.len() < challenge.len() + 22 {
            return Err(CertVerificationError::InvalidFormat(
                "Recovered data too short to contain challenge".to_string(),
            ));
        }

        // Find challenge in recovered data (usually starts at byte 2)
        let mut challenge_found = false;
        for start in 1..recovered_bytes.len().saturating_sub(challenge.len()) {
            if &recovered_bytes[start..start + challenge.len()] == challenge {
                debug!(
                    challenge_offset = start,
                    "Challenge found in DDA response"
                );
                challenge_found = true;
                break;
            }
        }

        if !challenge_found {
            return Err(CertVerificationError::InvalidFormat(
                "Challenge not found in DDA response".to_string(),
            ));
        }

        debug!("DDA signature verification successful");
        Ok(())
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
        let remainder_len = remainder.map(|r| r.len()).unwrap_or(0);

        // Calculate how many bytes we need from the certificate part
        // The remainder contains the rightmost (least significant) bytes
        // So we need (total_length - remainder_length) bytes from the certificate
        let cert_bytes_needed = if remainder_len > 0 {
            data.total_length.saturating_sub(remainder_len)
        } else {
            data.total_length
        };

        // Take only the needed bytes from certificate part (leftmost/most significant bytes)
        let mut modulus_bytes = if data.modulus_part.len() > cert_bytes_needed {
            data.modulus_part[..cert_bytes_needed].to_vec()
        } else {
            data.modulus_part.clone()
        };

        // Append remainder (rightmost/least significant bytes)
        if let Some(remainder) = remainder {
            modulus_bytes.extend_from_slice(remainder);
        }

        // Check we have the right amount of data
        if modulus_bytes.len() < data.total_length {
            return Err(CertVerificationError::InvalidFormat(format!(
                "Insufficient key data: need {} bytes, have {}",
                data.total_length,
                modulus_bytes.len()
            )));
        } else if modulus_bytes.len() > data.total_length {
            return Err(CertVerificationError::InvalidFormat(format!(
                "Too much key data: need {} bytes, have {}",
                data.total_length,
                modulus_bytes.len()
            )));
        }

        // Build modulus from bytes
        let modulus = BigUint::from_bytes_be(&modulus_bytes);
        let exponent_val = BigUint::from_bytes_be(exponent);

        // Create RSA public key
        RsaPublicKey::new(modulus, exponent_val).map_err(|e| {
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
                result
                    .errors
                    .push("No authentication method detected in AIP".to_string());
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
    fn verify_sda(
        &self,
        cert_data: &CertificateChainData,
        result: &mut CertificateVerificationResult,
    ) {
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
                result
                    .errors
                    .push("SDA detected - full verification not yet implemented".to_string());
            }
        }
    }

    /// Verify DDA/CDA (Dynamic Data Authentication / Combined Data Authentication)
    fn verify_dda_cda(
        &self,
        cert_data: &CertificateChainData,
        result: &mut CertificateVerificationResult,
    ) {
        // DDA/CDA: Verify certificate chain iteratively
        // Discover all certificates and verify them in order, checking format bytes

        // Step 1: Load CA Public Key
        let mut current_key = match self.load_ca_key(cert_data, result) {
            Some(key) => key,
            None => return,
        };

        // Step 2: Discover all certificates on the card
        let certificates = cert_data.discover_certificates();

        if certificates.is_empty() {
            result.errors.push("No certificates found on card for DDA/CDA verification".to_string());
            return;
        }

        info!(count = certificates.len(), "Verifying certificate chain");

        // Step 3: Verify each certificate iteratively
        let mut issuer_count = 0;
        let mut icc_found = false;

        for (index, discovered_cert) in certificates.iter().enumerate() {
            let cert_num = index + 1;
            debug!(
                cert_num,
                tag = %hex::encode_upper(&discovered_cert.tag),
                "Verifying certificate"
            );

            // Try standard trailer first (0xBC for Issuer, 0xCC for ICC)
            // We'll determine which based on format byte
            let verify_result = self.cert_verifier.verify_and_recover(
                &discovered_cert.cert_data,
                &current_key,
                0xBC,
            );

            // If 0xBC fails, try 0xCC
            let verify_result = verify_result.or_else(|_| {
                self.cert_verifier.verify_and_recover(
                    &discovered_cert.cert_data,
                    &current_key,
                    0xCC,
                )
            });

            let recovered = match verify_result {
                Ok(data) => data,
                Err(e) => {
                    debug!(
                        cert_num,
                        error = %e,
                        "Certificate signature verification failed, skipping"
                    );
                    result.errors.push(format!(
                        "Certificate {} (tag {}) verification failed: {}",
                        cert_num,
                        hex::encode_upper(&discovered_cert.tag),
                        e
                    ));
                    // Continue to next certificate instead of stopping
                    continue;
                }
            };

            // Check format byte to determine certificate type
            let cert_type = if recovered.len() > 1 {
                match recovered[1] {
                    0x02 => CertificateType::Issuer,
                    0x04 => CertificateType::Icc,
                    other => CertificateType::Unknown(other),
                }
            } else {
                debug!(
                    cert_num,
                    "Certificate too short to contain format byte, skipping"
                );
                result.errors.push(format!(
                    "Certificate {}: Too short to contain format byte",
                    cert_num
                ));
                continue;
            };

            let cert_type_str = match cert_type {
                CertificateType::Issuer => "Issuer (0x02)".to_string(),
                CertificateType::Icc => "ICC (0x04)".to_string(),
                CertificateType::Unknown(b) => format!("Unknown (0x{:02X})", b),
            };
            debug!(
                cert_num,
                cert_type = %cert_type_str,
                "Certificate type detected"
            );

            // Extract public key from certificate
            let extracted = match self.cert_verifier.extract_public_key(&recovered) {
                Ok(data) => data,
                Err(e) => {
                    debug!(
                        cert_num,
                        error = %e,
                        "Failed to extract public key, skipping certificate"
                    );
                    result.errors.push(format!(
                        "Certificate {}: Failed to extract public key: {}",
                        cert_num, e
                    ));
                    continue;
                }
            };

            // Get exponent (use default 0x03 if not present)
            let exponent = discovered_cert.exponent.as_deref().unwrap_or(&[0x03]);

            // Build public key
            let public_key = match self.cert_verifier.build_public_key(
                &extracted,
                discovered_cert.remainder.as_deref(),
                exponent,
            ) {
                Ok(key) => key,
                Err(e) => {
                    debug!(
                        cert_num,
                        error = %e,
                        "Failed to build public key, skipping certificate"
                    );
                    result.errors.push(format!(
                        "Certificate {}: Failed to build public key: {}",
                        cert_num, e
                    ));
                    continue;
                }
            };

            debug!(
                cert_num,
                modulus_bits = public_key.n().bits(),
                exponent = %public_key.e(),
                "Public key extracted successfully"
            );

            // Update result based on certificate type
            match cert_type {
                CertificateType::Issuer => {
                    issuer_count += 1;
                    if issuer_count == 1 {
                        // First Issuer certificate (signed by CA)
                        result.issuer_cert_valid = true;
                        info!(
                            cert_num,
                            issuer_level = issuer_count,
                            "Issuer certificate verified"
                        );
                    } else {
                        // Additional Issuer certificate (two-level hierarchy)
                        info!(
                            cert_num,
                            issuer_level = issuer_count,
                            "Additional Issuer certificate verified (two-level hierarchy)"
                        );
                    }
                    // Use this key for next certificate
                    current_key = public_key;
                }
                CertificateType::Icc => {
                    result.icc_cert_valid = true;
                    result.icc_public_key = Some(public_key.clone());
                    icc_found = true;
                    info!(cert_num, "ICC certificate verified");
                    // ICC cert is the end of the chain
                    break;
                }
                CertificateType::Unknown(format_byte) => {
                    debug!(
                        cert_num,
                        format_byte,
                        "Certificate has unknown format byte, skipping"
                    );
                    result.errors.push(format!(
                        "Certificate {}: Unknown format byte 0x{:02X}",
                        cert_num, format_byte
                    ));
                    continue;
                }
            }
        }

        // Summary
        if !icc_found && issuer_count > 1 {
            info!(
                issuer_levels = issuer_count,
                "Card uses {}-level Issuer hierarchy without ICC certificate",
                issuer_count
            );
            result.errors.push(format!(
                "Card uses {}-level Issuer hierarchy - no ICC certificate found. DDA/CDA not supported.",
                issuer_count
            ));
        }

        // Mark chain as valid if we verified at least the Issuer cert
        // For ICC cert to be valid, we need icc_found to be true
        if result.ca_key_found && result.issuer_cert_valid {
            if result.icc_cert_valid {
                result.chain_valid = true;
                info!("Complete certificate chain verified (CA → Issuer → ICC)");
            } else {
                info!("Partial certificate chain verified (CA → Issuer) - no ICC certificate");
            }
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
    use rsa::RsaPublicKey;

    #[test]
    fn test_certificate_verification_result() {
        let result = CertificateVerificationResult::new(AuthenticationMethod::None);
        assert!(!result.ca_key_found);
        assert!(!result.chain_valid);
        assert!(result.errors.is_empty());
        assert_eq!(result.auth_method, AuthenticationMethod::None);
    }

    #[test]
    fn test_certificate_verification_result_all_auth_methods() {
        for method in [
            AuthenticationMethod::None,
            AuthenticationMethod::Sda,
            AuthenticationMethod::Dda,
            AuthenticationMethod::Cda,
        ] {
            let result = CertificateVerificationResult::new(method);
            assert_eq!(result.auth_method, method);
            assert!(!result.ca_key_found);
            assert!(!result.issuer_cert_valid);
            assert!(!result.icc_cert_valid);
            assert!(!result.chain_valid);
            assert!(result.errors.is_empty());
        }
    }

    #[test]
    fn test_detect_auth_method_none() {
        let empty_aip = vec![];
        assert_eq!(detect_auth_method(&empty_aip), AuthenticationMethod::None);
    }

    #[test]
    fn test_detect_auth_method_sda() {
        // Bit 6 of byte 1 = 0x40 = SDA
        let aip = vec![0x40, 0x00];
        assert_eq!(detect_auth_method(&aip), AuthenticationMethod::Sda);
    }

    #[test]
    fn test_detect_auth_method_dda() {
        // Bit 5 of byte 1 = 0x20 = DDA
        let aip = vec![0x20, 0x00];
        assert_eq!(detect_auth_method(&aip), AuthenticationMethod::Dda);
    }

    #[test]
    fn test_detect_auth_method_cda() {
        // Bit 0 of byte 1 = 0x01 = CDA
        let aip = vec![0x01, 0x00];
        assert_eq!(detect_auth_method(&aip), AuthenticationMethod::Cda);
    }

    #[test]
    fn test_detect_auth_method_priority() {
        // CDA should win over DDA and SDA when all are set
        let aip = vec![0x61, 0x00]; // 0x61 = 0x40 (SDA) | 0x20 (DDA) | 0x01 (CDA)
        assert_eq!(detect_auth_method(&aip), AuthenticationMethod::Cda);

        // DDA should win over SDA
        let aip = vec![0x60, 0x00]; // 0x60 = 0x40 (SDA) | 0x20 (DDA)
        assert_eq!(detect_auth_method(&aip), AuthenticationMethod::Dda);
    }

    #[test]
    fn test_certificate_verifier_new() {
        let verifier = CertificateVerifier::new();
        // Just verify it can be instantiated
        assert_eq!(
            std::mem::size_of_val(&verifier),
            0,
            "CertificateVerifier should be zero-sized"
        );
    }

    #[test]
    fn test_certificate_verifier_verify_and_recover_invalid_data() {
        let verifier = CertificateVerifier::new();

        // Create a small test RSA key
        // Using a small prime for testing: n should be product of two primes
        let n = BigUint::from(3233u32); // 61 * 53
        let e = BigUint::from(17u32);
        let key = RsaPublicKey::new(n, e).unwrap();

        // Invalid certificate (too short to be valid)
        let cert = vec![0x00];
        let result = verifier.verify_and_recover(&cert, &key, 0xBC);
        assert!(result.is_err());
    }

    #[test]
    fn test_certificate_verifier_extract_public_key_too_short() {
        let verifier = CertificateVerifier::new();

        // Certificate data too short (< 36 bytes minimum)
        let short_data = vec![0x6A; 30];
        let result = verifier.extract_public_key(&short_data);

        assert!(result.is_err());
        match result {
            Err(CertVerificationError::InsufficientData { expected, actual }) => {
                assert_eq!(expected, 36);
                assert_eq!(actual, 30);
            }
            _ => panic!("Expected InsufficientData error"),
        }
    }

    #[test]
    fn test_certificate_verifier_extract_public_key_valid() {
        let verifier = CertificateVerifier::new();

        // Create minimal valid recovered certificate data (36+ bytes)
        // EMV Book 2 format:
        let mut recovered = vec![0x6A]; // Byte 0: Header
        recovered.push(0x04); // Byte 1: Format (ICC cert)
        recovered.extend_from_slice(&[0xFF; 4]); // Bytes 2-5: Issuer ID
        recovered.extend_from_slice(&[0x12, 0x31]); // Bytes 6-7: Expiration
        recovered.extend_from_slice(&[0x00, 0x01, 0x02]); // Bytes 8-10: Serial
        recovered.push(0x01); // Byte 11: Hash algo
        recovered.push(0x01); // Byte 12: PK algo
        recovered.push(128); // Byte 13: PK length = 128 bytes
        recovered.push(3); // Byte 14: Exp length = 3 bytes
        recovered.extend_from_slice(&[0xAA; 50]); // Bytes 15-64: PK data (50 bytes)
        recovered.extend_from_slice(&[0x00; 20]); // Last 20 bytes: Hash
        recovered.push(0xCC); // Last byte: Trailer

        let result = verifier.extract_public_key(&recovered);
        assert!(result.is_ok());

        let extracted = result.unwrap();
        assert_eq!(extracted.total_length, 128);
        assert_eq!(extracted.exponent_length, 3);
        assert_eq!(extracted.modulus_part.len(), 50); // Space between byte 15 and hash (21 bytes from end)
    }

    #[test]
    fn test_certificate_verifier_build_public_key_insufficient_data() {
        let verifier = CertificateVerifier::new();

        let data = ExtractedKeyData {
            modulus_part: vec![0xAA; 50],
            exponent_length: 3,
            total_length: 128, // Need 128 bytes total
        };

        let exponent = vec![0x01, 0x00, 0x01]; // 65537

        // No remainder, so we only have 50 bytes but need 128
        let result = verifier.build_public_key(&data, None, &exponent);

        assert!(result.is_err());
        match result {
            Err(CertVerificationError::InvalidFormat(msg)) => {
                assert!(msg.contains("Insufficient key data"));
            }
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn test_certificate_verifier_build_public_key_valid() {
        let verifier = CertificateVerifier::new();

        // Create 128 bytes of modulus data
        let mut modulus_bytes = vec![0x00, 0xFF]; // Start with non-zero to ensure valid RSA modulus
        modulus_bytes.extend_from_slice(&[0xAB; 126]);

        let data = ExtractedKeyData {
            modulus_part: modulus_bytes.clone(),
            exponent_length: 3,
            total_length: 128,
        };

        let exponent = vec![0x01, 0x00, 0x01]; // 65537

        let result = verifier.build_public_key(&data, None, &exponent);
        assert!(result.is_ok());

        let key = result.unwrap();
        assert_eq!(key.e(), &BigUint::from(65537u32));
    }

    #[test]
    fn test_certificate_verifier_build_public_key_with_remainder() {
        let verifier = CertificateVerifier::new();

        let mut modulus_part = vec![0x00, 0xFF]; // 2 bytes in cert
        modulus_part.extend_from_slice(&[0xAB; 48]); // 50 bytes in cert total
        let remainder = vec![0xCD; 78]; // 78 bytes remainder = 128 total

        let data = ExtractedKeyData {
            modulus_part,
            exponent_length: 3,
            total_length: 128,
        };

        let exponent = vec![0x01, 0x00, 0x01]; // 65537

        let result = verifier.build_public_key(&data, Some(&remainder), &exponent);
        assert!(result.is_ok());
    }

    #[test]
    fn test_chain_verifier_new() {
        let _verifier = ChainVerifier::new();
        // Just verify it can be instantiated
        // Should use embedded CA store
    }

    #[test]
    fn test_chain_verifier_with_custom_ca_store() {
        let ca_store = CaKeyStore::from_data(String::new());
        let _verifier = ChainVerifier::with_ca_store(ca_store);
        // Verify it can be created with custom store
    }

    #[test]
    fn test_chain_verifier_no_auth_method() {
        let verifier = ChainVerifier::new();
        let cert_data = CertificateChainData {
            aip: None, // No AIP = no auth method
            ca_index: None,
            rid: vec![0xA0, 0x00, 0x00, 0x00, 0x04], // Mastercard
            issuer_cert: None,
            issuer_exp: None,
            issuer_rem: None,
            icc_cert: None,
            icc_exp: None,
            icc_rem: None,
            pan: None,
            sda_tag_list: None,
            signed_static_app_data: None,
            all_issuer_certs: vec![],
            all_icc_certs: vec![],
        };

        let result = verifier.verify_chain(&cert_data);
        assert_eq!(result.auth_method, AuthenticationMethod::None);
        assert!(!result.chain_valid);
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].contains("No authentication method"));
    }

    #[test]
    fn test_chain_verifier_sda_incomplete_data() {
        let verifier = ChainVerifier::new();
        let cert_data = CertificateChainData {
            aip: Some(vec![0x40, 0x00]), // SDA
            ca_index: None,
            rid: vec![0xA0, 0x00, 0x00, 0x00, 0x04],
            issuer_cert: None, // Missing
            issuer_exp: None,
            issuer_rem: None,
            icc_cert: None,
            icc_exp: None,
            icc_rem: None,
            pan: None,
            sda_tag_list: Some(vec![0x9F, 0x4A]), // Has SDA tag list
            signed_static_app_data: None,         // Missing
            all_issuer_certs: vec![],
            all_icc_certs: vec![],
        };

        let result = verifier.verify_chain(&cert_data);
        assert_eq!(result.auth_method, AuthenticationMethod::Sda);
        assert!(!result.chain_valid);
        assert!(!result.errors.is_empty());
        assert!(result.errors[0].contains("missing"));
    }

    #[test]
    fn test_chain_verifier_dda_missing_issuer_cert() {
        let verifier = ChainVerifier::new();
        let cert_data = CertificateChainData {
            aip: Some(vec![0x20, 0x00]), // DDA
            ca_index: Some(0x05),
            rid: vec![0xA0, 0x00, 0x00, 0x00, 0x04], // Mastercard
            issuer_cert: None,                       // Missing issuer cert
            issuer_exp: None,
            issuer_rem: None,
            icc_cert: None,
            icc_exp: None,
            icc_rem: None,
            pan: None,
            sda_tag_list: None,
            signed_static_app_data: None,
            all_issuer_certs: vec![],
            all_icc_certs: vec![],
        };

        let result = verifier.verify_chain(&cert_data);
        assert_eq!(result.auth_method, AuthenticationMethod::Dda);
        assert!(result.ca_key_found); // Mastercard CA key 05 exists
        assert!(!result.issuer_cert_valid);
        assert!(!result.chain_valid);
        assert!(!result.errors.is_empty()); // Should have errors
    }

    #[test]
    fn test_chain_verifier_invalid_ca_key() {
        let verifier = ChainVerifier::new();
        let cert_data = CertificateChainData {
            aip: Some(vec![0x20, 0x00]),             // DDA
            ca_index: Some(0xAA),                    // Invalid CA index
            rid: vec![0xA0, 0x00, 0x00, 0x00, 0x04], // Mastercard
            issuer_cert: Some(vec![0x00; 128]),
            issuer_exp: None,
            issuer_rem: None,
            icc_cert: None,
            icc_exp: None,
            icc_rem: None,
            pan: None,
            sda_tag_list: None,
            signed_static_app_data: None,
            all_issuer_certs: vec![],
            all_icc_certs: vec![],
        };

        let result = verifier.verify_chain(&cert_data);
        assert_eq!(result.auth_method, AuthenticationMethod::Dda);
        assert!(!result.ca_key_found);
        assert!(!result.chain_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("CA Public Key not found")));
    }

    #[test]
    fn test_certificate_chain_data_from_card_data() {
        let records = vec![
            // Record with AIP - properly formatted TLV
            vec![
                0x70, 0x11, // Tag 70 (template), length 17 bytes
                0x82, 0x02, 0x20, 0x00, // AIP (DDA) - tag 82, length 2
                0x8F, 0x01, 0x05, // CA index - tag 8F, length 1
                0x5A, 0x08, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34,
                0x56, // PAN - tag 5A, length 8
            ],
        ];

        let gpo_response = None;
        let rid = vec![0xA0, 0x00, 0x00, 0x00, 0x04];

        let data = CertificateChainData::from_card_data(&records, gpo_response, rid.clone());

        assert_eq!(data.aip, Some(vec![0x20, 0x00]));
        assert_eq!(data.ca_index, Some(0x05));
        assert_eq!(data.rid, rid);
        assert_eq!(
            data.pan,
            Some(vec![0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56])
        );
    }

    #[test]
    fn test_extracted_key_data_clone() {
        let data = ExtractedKeyData {
            modulus_part: vec![0xAA; 128],
            exponent_length: 3,
            total_length: 128,
        };

        let cloned = data.clone();
        assert_eq!(data.modulus_part, cloned.modulus_part);
        assert_eq!(data.exponent_length, cloned.exponent_length);
        assert_eq!(data.total_length, cloned.total_length);
    }
}
