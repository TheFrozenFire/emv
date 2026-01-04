//! Data structures for card information

use emv_card::crypto::{AuthenticationMethod, CertificateVerificationResult};
use emv_card::protocol::ApplicationInfo;
use emv_card::CardData;

/// Complete card information collected during reading
#[derive(Debug, Clone)]
pub struct CardInfoData {
    pub reader_name: String,
    pub applications: Vec<ApplicationInfo>,
    pub card_data: CardData,
    pub verification_result: CertificateVerificationResult,
}

impl CardInfoData {
    /// Create certificate data summary
    pub fn certificate_summary(&self) -> CertificateSummary {
        let has_ca_index = self.has_tag(&[0x8F]);
        let has_issuer_cert = self.has_tag(&[0x90]);
        let has_icc_cert = self.has_tag(&[0x9F, 0x46]);

        CertificateSummary {
            has_ca_index,
            has_issuer_cert,
            has_icc_cert,
            auth_method: self.verification_result.auth_method,
            ca_key_found: self.verification_result.ca_key_found,
            issuer_cert_valid: self.verification_result.issuer_cert_valid,
            icc_cert_valid: self.verification_result.icc_cert_valid,
            chain_valid: self.verification_result.chain_valid,
            errors: self.verification_result.errors.clone(),
            result: self.verification_result.clone(),
        }
    }

    /// Check if any record contains a specific tag
    fn has_tag(&self, tag: &[u8]) -> bool {
        use emv_common::find_tag;

        self.card_data.records.iter().any(|r| {
            let search_data = if let Some(template) = find_tag(r, &[0x70]) {
                template
            } else {
                r.as_slice()
            };
            find_tag(search_data, tag).is_some()
        })
    }
}

/// Summary of certificate verification
#[derive(Debug, Clone)]
pub struct CertificateSummary {
    pub has_ca_index: bool,
    pub has_issuer_cert: bool,
    pub has_icc_cert: bool,
    pub auth_method: AuthenticationMethod,
    pub ca_key_found: bool,
    pub issuer_cert_valid: bool,
    pub icc_cert_valid: bool,
    pub chain_valid: bool,
    pub errors: Vec<String>,
    /// Full verification result for accessing detailed issues
    pub result: CertificateVerificationResult,
}
