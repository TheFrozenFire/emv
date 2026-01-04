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

/// Type of cryptogram requested from the card
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptogramType {
    /// Application Authentication Cryptogram (AAC) - transaction declined by card
    Aac,
    /// Transaction Certificate (TC) - transaction approved offline
    Tc,
    /// Authorization Request Cryptogram (ARQC) - request online authorization
    Arqc,
}

impl CryptogramType {
    /// Get the P1 byte value for this cryptogram type
    pub fn p1_value(&self) -> u8 {
        match self {
            CryptogramType::Aac => 0x00, // or 0x40
            CryptogramType::Tc => 0x40,  // or 0x80
            CryptogramType::Arqc => 0x80, // or 0x00
        }
    }
}

/// Request for GENERATE AC command
#[derive(Debug, Clone)]
pub struct GenerateAcRequest {
    pub cryptogram_type: CryptogramType,
    pub cdol_data: Vec<u8>,
}

/// Response from GENERATE AC command
#[derive(Debug, Clone)]
pub struct GenerateAcResponse {
    /// Application Cryptogram (tag 9F26)
    pub cryptogram: Option<Vec<u8>>,
    /// Application Transaction Counter (tag 9F36)
    pub atc: Option<u16>,
    /// Cryptogram Information Data (tag 9F27)
    pub cid: Option<u8>,
    /// Issuer Application Data (tag 9F10)
    pub iad: Option<Vec<u8>>,
    /// Signed Dynamic Application Data (tag 9F4B) - for CDA
    pub sdad: Option<Vec<u8>>,
    /// Full response data for additional processing
    pub raw_data: Vec<u8>,
}

/// Data Object List (DOL) entry - tag and expected length pair
#[derive(Debug, Clone)]
pub struct DolEntry {
    pub tag: Vec<u8>,
    pub length: usize,
}

/// Parse a DOL (Data Object List) into individual entries
/// DOL format: tag1 len1 tag2 len2 ... (concatenated tag-length pairs)
pub fn parse_dol(dol: &[u8]) -> Result<Vec<DolEntry>, pcsc::Error> {
    let mut entries = Vec::new();
    let mut i = 0;

    while i < dol.len() {
        // Parse tag (1-4 bytes)
        let tag_start = i;
        let tag_len = if dol[i] & 0x1F == 0x1F {
            // Multi-byte tag - keep reading while bit 8 is set
            let mut len = 1;
            while i + len < dol.len() && dol[i + len] & 0x80 != 0 {
                len += 1;
            }
            len + 1
        } else {
            1 // Single-byte tag
        };

        if i + tag_len > dol.len() {
            return Err(pcsc::Error::InvalidParameter);
        }

        let tag = dol[tag_start..tag_start + tag_len].to_vec();
        i += tag_len;

        // Parse length (1 byte)
        if i >= dol.len() {
            return Err(pcsc::Error::InvalidParameter);
        }

        let length = dol[i] as usize;
        i += 1;

        entries.push(DolEntry { tag, length });
    }

    Ok(entries)
}

/// Builder for constructing DOL data values
pub struct DolBuilder {
    values: std::collections::HashMap<Vec<u8>, Vec<u8>>,
}

impl DolBuilder {
    /// Create a new DOL builder
    pub fn new() -> Self {
        Self {
            values: std::collections::HashMap::new(),
        }
    }

    /// Set a raw tag value
    pub fn set(&mut self, tag: &[u8], value: Vec<u8>) -> &mut Self {
        self.values.insert(tag.to_vec(), value);
        self
    }

    /// Set amount authorized (tag 9F02) in smallest currency units
    pub fn set_amount(&mut self, amount: u64) -> &mut Self {
        // Amount is 6 bytes BCD (12 digits)
        self.set(&[0x9F, 0x02], encode_bcd(amount, 6))
    }

    /// Set transaction currency code (tag 5F2A)
    pub fn set_currency(&mut self, code: u16) -> &mut Self {
        self.set(&[0x5F, 0x2A], code.to_be_bytes().to_vec())
    }

    /// Set terminal country code (tag 9F1A)
    pub fn set_terminal_country(&mut self, code: u16) -> &mut Self {
        self.set(&[0x9F, 0x1A], code.to_be_bytes().to_vec())
    }

    /// Set transaction type (tag 9C)
    pub fn set_transaction_type(&mut self, trans_type: u8) -> &mut Self {
        self.set(&[0x9C], vec![trans_type])
    }

    /// Set terminal type (tag 9F35)
    pub fn set_terminal_type(&mut self, term_type: u8) -> &mut Self {
        self.set(&[0x9F, 0x35], vec![term_type])
    }

    /// Set unpredictable number (tag 9F37)
    pub fn set_unpredictable_number(&mut self, number: Vec<u8>) -> &mut Self {
        self.set(&[0x9F, 0x37], number)
    }

    /// Set amount other (tag 9F03) - secondary amount
    pub fn set_amount_other(&mut self, amount: u64) -> &mut Self {
        self.set(&[0x9F, 0x03], encode_bcd(amount, 6))
    }

    /// Set transaction date (tag 9A) - YYMMDD format
    pub fn set_transaction_date(&mut self, date: &[u8; 3]) -> &mut Self {
        self.set(&[0x9A], date.to_vec())
    }

    /// Set terminal verification results (tag 95)
    pub fn set_tvr(&mut self, tvr: Vec<u8>) -> &mut Self {
        self.set(&[0x95], tvr)
    }

    /// Set CVM results (tag 9F34)
    pub fn set_cvm_results(&mut self, results: Vec<u8>) -> &mut Self {
        self.set(&[0x9F, 0x34], results)
    }

    /// Set defaults for common EMV terminal values
    pub fn with_defaults(&mut self) -> &mut Self {
        // Set current date (YYMMDD)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let days_since_epoch = now / 86400;
        let years_since_epoch = days_since_epoch / 365;
        let year = (70 + years_since_epoch) as u8; // 1970 = 70 in YY format
        let year_day = days_since_epoch % 365;
        let month = (1 + year_day / 30) as u8;
        let day = (1 + year_day % 30) as u8;

        self.set_transaction_date(&[year, month.min(12), day.min(31)]);

        // Default TVR (5 bytes) - all zeros = no issues
        self.set_tvr(vec![0x00; 5]);

        // Default CVM Results (3 bytes)
        // Byte 1: CVM performed (0x3F = No CVM performed)
        // Byte 2: CVM condition (0x00)
        // Byte 3: CVM result (0x02 = Unknown)
        self.set_cvm_results(vec![0x3F, 0x00, 0x02]);

        self
    }

    /// Build the DOL data according to the template
    pub fn build(&self, dol: &[u8]) -> Result<Vec<u8>, pcsc::Error> {
        let entries = parse_dol(dol)?;
        let mut data = Vec::new();

        for entry in entries {
            let value = if let Some(v) = self.values.get(&entry.tag) {
                v.clone()
            } else {
                // Provide zero-filled value for missing tags (common for optional fields)
                debug!(
                    "DOL tag {} not set, using zeros (length: {})",
                    hex::encode(&entry.tag),
                    entry.length
                );
                vec![0x00; entry.length]
            };

            if value.len() != entry.length {
                debug!(
                    "DOL value length mismatch for tag {}: expected {}, got {}",
                    hex::encode(&entry.tag),
                    entry.length,
                    value.len()
                );
                return Err(pcsc::Error::InvalidParameter);
            }

            data.extend_from_slice(&value);
        }

        Ok(data)
    }
}

impl Default for DolBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode a value as BCD (Binary Coded Decimal)
fn encode_bcd(value: u64, length: usize) -> Vec<u8> {
    let s = format!("{:0width$}", value, width = length * 2);
    hex::decode(&s).unwrap_or_else(|_| vec![0; length])
}

/// Generate random bytes for unpredictable number
pub fn generate_random_bytes(count: usize) -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..count).map(|_| rng.gen()).collect()
}

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

        // Build PDOL response data
        let pdol_data = if let Some(pdol_template) = pdol {
            debug!("PDOL template: {}", hex::encode(pdol_template));

            // Build DOL data with default terminal values
            let data = DolBuilder::new()
                .set_amount(100) // 1.00 in smallest currency units
                .set_currency(840) // USD
                .set_terminal_country(840) // USA
                .set_transaction_type(0x00) // Purchase
                .set_terminal_type(0x22) // Smart card reader
                .set_unpredictable_number(generate_random_bytes(4))
                .build(pdol_template)?;

            debug!("Built PDOL data: {}", hex::encode(&data));
            data
        } else {
            debug!("No PDOL in SELECT response, using empty data");
            vec![]
        };

        // Wrap in tag 83 (Command Template)
        let mut pdol_response_data = vec![0x83, pdol_data.len() as u8];
        pdol_response_data.extend_from_slice(&pdol_data);

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

        // Step 4: Try GET DATA for all known EMV tags (comprehensive)
        debug!("Attempting to retrieve all known EMV tags via GET DATA");
        let all_tags: Vec<(&str, &[u8])> = vec![
            // Application metadata
            ("Application Identifier (4F)", &[0x4F]),
            ("Application Label (50)", &[0x50]),
            ("Application PAN (5A)", &[0x5A]),
            ("Application Expiration Date (5F24)", &[0x5F, 0x24]),
            ("Application Effective Date (5F25)", &[0x5F, 0x25]),
            ("Application PAN Sequence Number (5F34)", &[0x5F, 0x34]),
            ("Application Usage Control (9F07)", &[0x9F, 0x07]),
            ("Application Version Number (9F08)", &[0x9F, 0x08]),
            ("Application Currency Code (9F42)", &[0x9F, 0x42]),
            ("Application Preferred Name (9F12)", &[0x9F, 0x12]),

            // Cardholder data
            ("Cardholder Name (5F20)", &[0x5F, 0x20]),
            ("Track 1 Data (56)", &[0x56]),
            ("Track 2 Equivalent Data (57)", &[0x57]),
            ("Track 2 Data (9F6B)", &[0x9F, 0x6B]),

            // Issuer data
            ("Issuer Country Code (5F28)", &[0x5F, 0x28]),
            ("Language Preference (5F2D)", &[0x5F, 0x2D]),

            // Cryptography and certificates
            ("CA Public Key Index (8F)", &[0x8F]),
            ("Issuer Public Key Certificate (90)", &[0x90]),
            ("Issuer Public Key Exponent (9F32)", &[0x9F, 0x32]),
            ("Issuer Public Key Remainder (92)", &[0x92]),
            ("ICC Public Key Certificate (9F46)", &[0x9F, 0x46]),
            ("ICC Public Key Exponent (9F47)", &[0x9F, 0x47]),
            ("ICC Public Key Remainder (9F48)", &[0x9F, 0x48]),
            ("ICC PIN Encipherment Public Key Certificate (9F2D)", &[0x9F, 0x2D]),
            ("ICC PIN Encipherment Public Key Exponent (9F2E)", &[0x9F, 0x2E]),
            ("ICC PIN Encipherment Public Key Remainder (9F2F)", &[0x9F, 0x2F]),
            ("Static Data Authentication Tag List (9F4A)", &[0x9F, 0x4A]),
            ("Signed Static Application Data (93)", &[0x93]),
            ("Signed Dynamic Application Data (9F4B)", &[0x9F, 0x4B]),

            // Transaction-related
            ("AIP - Application Interchange Profile (82)", &[0x82]),
            ("AFL - Application File Locator (94)", &[0x94]),
            ("PDOL - Processing Options Data Object List (9F38)", &[0x9F, 0x38]),
            ("CDOL1 - Card Risk Management DOL (8C)", &[0x8C]),
            ("CDOL2 - Card Risk Management DOL 2 (8D)", &[0x8D]),

            // Additional data
            ("Application Cryptogram (9F26)", &[0x9F, 0x26]),
            ("Cryptogram Information Data (9F27)", &[0x9F, 0x27]),
            ("CVM List (8E)", &[0x8E]),
            ("Transaction Certificate Data Object List (97)", &[0x97]),
            ("Log Entry (9F4D)", &[0x9F, 0x4D]),
            ("Log Format (9F4F)", &[0x9F, 0x4F]),
        ];

        for (name, tag) in &all_tags {
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

    /// Send GET CHALLENGE command to card
    ///
    /// Requests the card to generate and return 8 bytes of random data.
    /// Used for secure messaging and enciphered PIN verification.
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - 8 bytes of random data
    /// * `Err(pcsc::Error)` - If communication fails
    pub fn get_challenge(&self) -> Result<Vec<u8>, pcsc::Error> {
        debug!("Sending GET CHALLENGE");

        let response = commands::get_challenge().send(self.card)?;

        if !response.is_success() {
            debug!(
                status = %response.status_string(),
                "GET CHALLENGE failed"
            );
        } else {
            debug!(
                random_bytes = %hex::encode_upper(&response.data),
                "GET CHALLENGE succeeded"
            );
        }

        Ok(response.data)
    }

    /// Send GENERATE AC command to card
    ///
    /// **WARNING**: This command increments the Application Transaction Counter (ATC) on the card!
    /// Each call will permanently increment this counter, which may affect card behavior.
    ///
    /// # Arguments
    /// * `request` - The GENERATE AC request with cryptogram type and CDOL data
    ///
    /// # Returns
    /// * `Ok(GenerateAcResponse)` - The response containing cryptogram and other data
    /// * `Err(pcsc::Error)` - If communication fails
    pub fn generate_ac(&self, request: &GenerateAcRequest) -> Result<GenerateAcResponse, pcsc::Error> {
        let p1 = request.cryptogram_type.p1_value();

        debug!(
            cryptogram_type = ?request.cryptogram_type,
            cdol_data_len = request.cdol_data.len(),
            cdol_data = %hex::encode_upper(&request.cdol_data),
            "Sending GENERATE AC"
        );

        let response = commands::generate_ac(p1, request.cdol_data.clone()).send(self.card)?;

        if !response.is_success() {
            debug!(
                status = %response.status_string(),
                "GENERATE AC failed"
            );
            // Return error with empty response
            return Ok(GenerateAcResponse {
                cryptogram: None,
                atc: None,
                cid: None,
                iad: None,
                sdad: None,
                raw_data: response.data,
            });
        }

        parse_generate_ac_response(&response.data)
    }
}

/// Parse GENERATE AC response data
fn parse_generate_ac_response(data: &[u8]) -> Result<GenerateAcResponse, pcsc::Error> {
    debug!(
        response_len = data.len(),
        response_data = %hex::encode_upper(data),
        "Parsing GENERATE AC response"
    );

    // Response can be in two formats:
    // Format 1 (primitive): Response data starts immediately with tags
    // Format 2 (template): Response wrapped in tag 77 or 80

    // Check for template wrappers
    let search_data = if let Some(template77) = find_tag(data, &[0x77]) {
        debug!("Found tag 77 (Response Message Template Format 2)");
        template77
    } else if let Some(template80) = find_tag(data, &[0x80]) {
        debug!("Found tag 80 (Response Message Template Format 1)");
        template80
    } else {
        // No template wrapper, use raw data
        data
    };

    // Extract individual tags
    let cryptogram = find_tag(search_data, &[0x9F, 0x26]).map(|v| v.to_vec());
    let atc = find_tag(search_data, &[0x9F, 0x36]).and_then(|v| {
        if v.len() >= 2 {
            Some(u16::from_be_bytes([v[0], v[1]]))
        } else {
            None
        }
    });
    let cid = find_tag(search_data, &[0x9F, 0x27]).and_then(|v| {
        if !v.is_empty() {
            Some(v[0])
        } else {
            None
        }
    });
    let iad = find_tag(search_data, &[0x9F, 0x10]).map(|v| v.to_vec());
    let sdad = find_tag(search_data, &[0x9F, 0x4B]).map(|v| v.to_vec());

    debug!(
        cryptogram = ?cryptogram.as_ref().map(hex::encode_upper),
        atc,
        cid,
        iad = ?iad.as_ref().map(hex::encode_upper),
        sdad = ?sdad.as_ref().map(hex::encode_upper),
        "Parsed GENERATE AC response"
    );

    Ok(GenerateAcResponse {
        cryptogram,
        atc,
        cid,
        iad,
        sdad,
        raw_data: data.to_vec(),
    })
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

    #[test]
    fn test_parse_dol_single_byte_tags() {
        // DOL with single-byte tags: 9F02 06 9F03 06 9C 01
        // Tag 9F02 (2 bytes), length 6
        // Tag 9F03 (2 bytes), length 6
        // Tag 9C (1 byte), length 1
        let dol = vec![0x9F, 0x02, 0x06, 0x9F, 0x03, 0x06, 0x9C, 0x01];
        let entries = parse_dol(&dol).unwrap();

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].tag, vec![0x9F, 0x02]);
        assert_eq!(entries[0].length, 6);
        assert_eq!(entries[1].tag, vec![0x9F, 0x03]);
        assert_eq!(entries[1].length, 6);
        assert_eq!(entries[2].tag, vec![0x9C]);
        assert_eq!(entries[2].length, 1);
    }

    #[test]
    fn test_parse_dol_empty() {
        let dol = vec![];
        let entries = parse_dol(&dol).unwrap();
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_dol_builder_basic() {
        // Simple DOL: 9C 01 (transaction type, 1 byte)
        let dol = vec![0x9C, 0x01];

        let data = DolBuilder::new()
            .set_transaction_type(0x00)
            .build(&dol)
            .unwrap();

        assert_eq!(data, vec![0x00]);
    }

    #[test]
    fn test_dol_builder_multiple_fields() {
        // DOL: 9F02 06 5F2A 02 9C 01
        // Amount (6 bytes) + Currency (2 bytes) + Transaction Type (1 byte)
        let dol = vec![0x9F, 0x02, 0x06, 0x5F, 0x2A, 0x02, 0x9C, 0x01];

        let data = DolBuilder::new()
            .set_amount(100) // 1.00 -> 000000000100 in BCD
            .set_currency(840) // USD -> 0x0348
            .set_transaction_type(0x00)
            .build(&dol)
            .unwrap();

        // Expected: 6 bytes amount (000000000100) + 2 bytes currency (0348) + 1 byte type (00)
        assert_eq!(data.len(), 9);
        assert_eq!(&data[0..6], &[0x00, 0x00, 0x00, 0x00, 0x01, 0x00]); // Amount in BCD
        assert_eq!(&data[6..8], &[0x03, 0x48]); // Currency code
        assert_eq!(data[8], 0x00); // Transaction type
    }

    #[test]
    fn test_encode_bcd() {
        assert_eq!(encode_bcd(0, 3), vec![0x00, 0x00, 0x00]);
        assert_eq!(encode_bcd(123, 3), vec![0x00, 0x01, 0x23]);
        assert_eq!(encode_bcd(100, 6), vec![0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);
    }
}
