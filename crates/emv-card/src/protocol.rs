//! EMV protocol implementation

use crate::apdu::{commands, ApduResponse};
use crate::crypto::{
    verify_certificate_chain, CertificateChainData, CertificateVerificationResult,
};
use emv_common::find_tag;
use pcsc::Card;
use tracing::{debug, info, trace};

/// Known EMV Application Identifiers (AIDs)
pub mod aids {
    /// PSE (Payment System Environment)
    pub const PSE: &[u8] = b"1PAY.SYS.DDF01";

    /// PPSE (Proximity Payment System Environment) for contactless
    pub const PPSE: &[u8] = b"2PAY.SYS.DDF01";

    /// Visa
    pub const VISA: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10];

    /// Mastercard
    pub const MASTERCARD: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10];

    /// American Express
    pub const AMEX: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x02, 0x50, 0x00];
}

/// Application information from card
#[derive(Debug, Clone)]
pub struct ApplicationInfo {
    pub aid: Vec<u8>,
    pub label: Option<String>,
    pub priority: Option<u8>,
    pub preferred_name: Option<String>,
}

/// Card data read from the EMV card
#[derive(Debug, Clone, Default)]
pub struct CardData {
    pub records: Vec<Vec<u8>>,
    pub select_response: Option<Vec<u8>>,
    pub gpo_response: Option<Vec<u8>>,
}

/// Certificate data extracted from card
pub use crate::crypto::CertificateChainData as CertificateData;

/// EMV card interface
pub struct EmvCard<'a> {
    card: &'a Card,
    rid: Option<Vec<u8>>,
}

impl<'a> EmvCard<'a> {
    /// Create a new EMV card interface
    pub fn new(card: &'a Card) -> Self {
        Self { card, rid: None }
    }

    /// Select an EMV application by AID
    pub fn select(&mut self, aid: &[u8]) -> Result<ApduResponse, pcsc::Error> {
        let response = commands::select(aid).send(self.card)?;

        if response.is_success() {
            // Extract RID from AID (first 5 bytes of AID)
            if aid.len() >= 5 {
                self.rid = Some(aid[..5].to_vec());
            }
        }

        Ok(response)
    }

    /// Parse PSE/PPSE response to extract available applications
    fn parse_pse_response(&self, pse_response: &[u8]) -> Vec<ApplicationInfo> {
        let mut apps = Vec::new();

        // PSE response is FCI with tag 6F (File Control Information Template)
        if let Some(fci) = find_tag(pse_response, &[0x6F]) {
            // Look for A5 (FCI Proprietary Template)
            if let Some(fci_prop) = find_tag(fci, &[0xA5]) {
                // Look for BF0C (FCI Issuer Discretionary Data)
                if let Some(issuer_data) = find_tag(fci_prop, &[0xBF, 0x0C]) {
                    // Parse 61 (Application Template) entries
                    let mut i = 0;
                    while i < issuer_data.len() {
                        if issuer_data[i] == 0x61 {
                            i += 1;
                            if i >= issuer_data.len() {
                                break;
                            }

                            let len = issuer_data[i] as usize;
                            i += 1;

                            if i + len > issuer_data.len() {
                                break;
                            }

                            let app_template = &issuer_data[i..i + len];

                            let mut app_info = ApplicationInfo {
                                aid: Vec::new(),
                                label: None,
                                priority: None,
                                preferred_name: None,
                            };

                            // Extract AID (tag 4F)
                            if let Some(aid) = find_tag(app_template, &[0x4F]) {
                                app_info.aid = aid.to_vec();
                            }

                            // Extract Application Label (tag 50)
                            if let Some(label) = find_tag(app_template, &[0x50]) {
                                app_info.label = String::from_utf8(label.to_vec()).ok();
                            }

                            // Extract Application Priority (tag 87)
                            if let Some(priority) = find_tag(app_template, &[0x87]) {
                                if !priority.is_empty() {
                                    app_info.priority = Some(priority[0]);
                                }
                            }

                            // Extract Application Preferred Name (tag 9F12)
                            if let Some(pref_name) = find_tag(app_template, &[0x9F, 0x12]) {
                                app_info.preferred_name =
                                    String::from_utf8(pref_name.to_vec()).ok();
                            }

                            if !app_info.aid.is_empty() {
                                apps.push(app_info);
                            }

                            i += len;
                        } else {
                            i += 1;
                        }
                    }
                }
            }
        }

        apps
    }

    /// List all available applications on the card
    pub fn list_applications(&mut self) -> Vec<ApplicationInfo> {
        let mut all_apps = Vec::new();

        // Try PPSE (contactless) first
        if let Ok(response) = self.select(aids::PPSE) {
            if response.is_success() {
                info!("Found PPSE (contactless payment system)");
                let apps = self.parse_pse_response(&response.data);
                all_apps.extend(apps);
            }
        }

        // Try PSE (contact)
        if let Ok(response) = self.select(aids::PSE) {
            if response.is_success() {
                info!("Found PSE (contact payment system)");
                let apps = self.parse_pse_response(&response.data);
                all_apps.extend(apps);
            }
        }

        all_apps
    }

    /// Try to select an EMV application (PSE first, then fallback to known AIDs)
    pub fn select_application(&mut self) -> Result<ApduResponse, pcsc::Error> {
        // Try PSE first
        if let Ok(response) = self.select(aids::PSE) {
            if response.is_success() {
                return Ok(response);
            }
        }

        // Try known AIDs
        for aid in &[aids::VISA, aids::MASTERCARD, aids::AMEX] {
            if let Ok(response) = self.select(aid) {
                if response.is_success() {
                    return Ok(response);
                }
            }
        }

        Err(pcsc::Error::UnknownReader)
    }

    /// Send GET PROCESSING OPTIONS command
    pub fn get_processing_options(
        &self,
        select_response: &[u8],
    ) -> Result<ApduResponse, pcsc::Error> {
        // Parse PDOL from SELECT response
        let pdol = find_tag(select_response, &[0x9F, 0x38]);

        // Build PDOL response data (simplified - using empty PDOL for now)
        let pdol_response_data = if let Some(_pdol_data) = pdol {
            // TODO: Parse PDOL and build proper response
            vec![0x83, 0x00]
        } else {
            vec![0x83, 0x00]
        };

        commands::get_processing_options(pdol_response_data).send(self.card)
    }

    /// Parse AFL (Application File Locator) from GPO response
    pub fn parse_afl(&self, gpo_data: &[u8]) -> Option<Vec<u8>> {
        // Check if response is wrapped in tag 77 (Response Message Template Format 2)
        let search_data = if let Some(template77) = find_tag(gpo_data, &[0x77]) {
            template77
        } else {
            gpo_data
        };

        // Try to find AFL (tag 94)
        if let Some(afl) = find_tag(search_data, &[0x94]) {
            return Some(afl.to_vec());
        }

        // Try Format 1 response (tag 80)
        if let Some(template) = find_tag(gpo_data, &[0x80]) {
            if template.len() >= 6 {
                // In Format 1, AFL starts after AIP (2 bytes)
                return Some(template[4..].to_vec());
            }
        }

        None
    }

    /// Read a single record from the card
    pub fn read_record(&self, record_number: u8, sfi: u8) -> Result<ApduResponse, pcsc::Error> {
        commands::read_record(record_number, sfi).send(self.card)
    }

    /// Read all records specified in AFL
    pub fn read_afl_records(&self, afl_data: &[u8]) -> Result<Vec<Vec<u8>>, pcsc::Error> {
        let mut records = Vec::new();

        // AFL format: groups of 4 bytes
        // Byte 1: SFI (upper 5 bits) + first record (lower 3 bits)
        // Byte 2: Last record number
        // Byte 3: Number of records involved in offline data auth
        // Byte 4: Number of records involved in online data auth
        //
        // Note: Record numbers in EMV are 1-based, not 0-based

        for chunk in afl_data.chunks(4) {
            if chunk.len() != 4 {
                continue;
            }

            let sfi = chunk[0] >> 3;
            let first_record = chunk[0] & 0x07;
            let last_record = chunk[1];

            // EMV records are numbered starting from 1
            // If first_record is 0, treat it as 1
            let start_record = if first_record == 0 { 1 } else { first_record };

            for record_num in start_record..=last_record {
                if let Ok(response) = self.read_record(record_num, sfi) {
                    if response.is_success() && !response.data.is_empty() {
                        records.push(response.data);
                    }
                }
            }
        }

        Ok(records)
    }

    /// Read all card data (application selection + records)
    pub fn read_card_data(&mut self) -> Result<CardData, pcsc::Error> {
        let mut card_data = CardData::default();

        // Step 1: Select application
        let select_response = self.select_application()?;
        card_data.select_response = Some(select_response.data.clone());

        // Log what we selected
        if let Some(ref rid) = self.rid {
            debug!(rid = %hex::encode_upper(rid), "Selected application");
        }

        // Show PDOL from SELECT response
        if let Some(pdol) = find_tag(&select_response.data, &[0x9F, 0x38]) {
            debug!(bytes = pdol.len(), "PDOL present");
            trace!(pdol = %hex::encode_upper(pdol), "PDOL raw data");
        } else {
            debug!("No PDOL in SELECT response");
        }

        // Show Application Label if present
        if let Some(label) = find_tag(&select_response.data, &[0x50]) {
            if let Ok(label_str) = String::from_utf8(label.to_vec()) {
                info!(label = %label_str, "Application selected");
            }
        }

        // Step 2: GET PROCESSING OPTIONS
        let gpo_response = self.get_processing_options(&select_response.data)?;
        card_data.gpo_response = Some(gpo_response.data.clone());

        // Step 3: Parse AFL and read records
        if let Some(afl_data) = self.parse_afl(&gpo_response.data) {
            card_data.records = self.read_afl_records(&afl_data)?;
        }

        // Step 4: Try GET DATA for missing certificate tags
        debug!("Attempting to retrieve certificate data via GET DATA");
        let cert_tags: Vec<(&str, &[u8])> = vec![
            ("CA Public Key Index (8F)", &[0x8F]),
            ("Issuer Public Key Certificate (90)", &[0x90]),
            ("Issuer Public Key Exponent (9F32)", &[0x9F, 0x32]),
            ("Issuer Public Key Remainder (92)", &[0x92]),
            ("Signed Static Application Data (93)", &[0x93]),
        ];

        for (name, tag) in &cert_tags {
            match commands::get_data(tag).send(self.card) {
                Ok(response) if response.is_success() && !response.data.is_empty() => {
                    debug!(
                        tag = name,
                        bytes = response.data.len(),
                        "Found certificate data via GET DATA"
                    );
                    // Add as a synthetic record
                    card_data.records.push(response.data);
                }
                Ok(response) => {
                    trace!(tag = name, status = %response.status_string(), "Certificate data not available via GET DATA");
                }
                Err(e) => {
                    trace!(tag = name, error = ?e, "GET DATA failed");
                }
            }
        }

        // Step 5: Try reading additional records beyond AFL
        debug!("Scanning for additional records beyond AFL");
        let initial_count = card_data.records.len();

        // Try SFIs 1-10, records 1-5 for each
        for sfi in 1..=10 {
            for record_num in 1..=5 {
                match self.read_record(record_num, sfi) {
                    Ok(response) if response.is_success() && !response.data.is_empty() => {
                        // Check if we already have this record
                        if !card_data.records.iter().any(|r| r == &response.data) {
                            debug!(sfi, record_num, "Found additional record beyond AFL");
                            card_data.records.push(response.data);
                        }
                    }
                    _ => {
                        // Stop trying higher record numbers for this SFI if we hit an error
                        break;
                    }
                }
            }
        }

        let new_records = card_data.records.len() - initial_count;
        if new_records > 0 {
            info!(count = new_records, "Found additional records beyond AFL");
        } else {
            debug!("No additional records found beyond AFL");
        }

        Ok(card_data)
    }

    /// Verify certificate chain from card data
    pub fn verify_certificates(&self, card_data: &CardData) -> CertificateVerificationResult {
        let rid = self
            .rid
            .clone()
            .unwrap_or_else(|| vec![0xA0, 0x00, 0x00, 0x00, 0x04]);
        let gpo_response = card_data.gpo_response.as_deref();
        let cert_data = CertificateChainData::from_card_data(&card_data.records, gpo_response, rid);
        verify_certificate_chain(&cert_data)
    }

    /// Perform INTERNAL AUTHENTICATE for Dynamic Data Authentication (DDA)
    ///
    /// Sends a challenge to the card and receives a signed response.
    /// The card signs the challenge with its ICC private key.
    ///
    /// # Arguments
    /// * `challenge` - Random challenge data (typically 4-8 bytes)
    ///
    /// # Returns
    /// * `Ok(ApduResponse)` - Response containing the signature
    /// * `Err(pcsc::Error)` - If communication fails
    pub fn internal_authenticate(&self, challenge: &[u8]) -> Result<ApduResponse, pcsc::Error> {
        debug!(
            challenge_len = challenge.len(),
            challenge = %hex::encode_upper(challenge),
            "Sending INTERNAL AUTHENTICATE"
        );

        commands::internal_authenticate(challenge.to_vec()).send(self.card)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aids() {
        assert_eq!(aids::VISA.len(), 7);
        assert_eq!(aids::MASTERCARD.len(), 7);
        assert_eq!(aids::PSE, b"1PAY.SYS.DDF01");
    }
}
