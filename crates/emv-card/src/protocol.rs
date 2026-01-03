//! EMV protocol implementation

use crate::apdu::{commands, ApduResponse};
use crate::crypto::{CertificateChainData, CertificateVerificationResult, verify_certificate_chain};
use emv_common::find_tag;
use pcsc::Card;

/// Known EMV Application Identifiers (AIDs)
pub mod aids {
    /// PSE (Payment System Environment)
    pub const PSE: &[u8] = b"1PAY.SYS.DDF01";

    /// Visa
    pub const VISA: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10];

    /// Mastercard
    pub const MASTERCARD: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10];

    /// American Express
    pub const AMEX: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x02, 0x50, 0x00];
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
    pub fn get_processing_options(&self, select_response: &[u8]) -> Result<ApduResponse, pcsc::Error> {
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

        for chunk in afl_data.chunks(4) {
            if chunk.len() != 4 {
                continue;
            }

            let sfi = chunk[0] >> 3;
            let first_record = chunk[0] & 0x07;
            let last_record = chunk[1];

            for record_num in first_record..=last_record {
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

        // Step 2: GET PROCESSING OPTIONS
        let gpo_response = self.get_processing_options(&select_response.data)?;
        card_data.gpo_response = Some(gpo_response.data.clone());

        // Step 3: Parse AFL and read records
        if let Some(afl_data) = self.parse_afl(&gpo_response.data) {
            card_data.records = self.read_afl_records(&afl_data)?;
        }

        Ok(card_data)
    }

    /// Verify certificate chain from card data
    pub fn verify_certificates(&self, card_data: &CardData) -> CertificateVerificationResult {
        let rid = self.rid.clone().unwrap_or_else(|| vec![0xA0, 0x00, 0x00, 0x00, 0x04]);
        let cert_data = CertificateChainData::from_records(&card_data.records, rid);
        verify_certificate_chain(&cert_data)
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
