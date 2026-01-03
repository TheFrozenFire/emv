//! EMV Common - Shared data structures and utilities for EMV processing

/// TLV (Tag-Length-Value) parser for EMV data
///
/// Searches for a specific tag in EMV-encoded data and returns its value.
/// Properly handles both single-byte and two-byte tags, as well as extended length encoding.
///
/// # Arguments
/// * `data` - The EMV-encoded data to search
/// * `tag` - The tag bytes to search for (1 or 2 bytes)
///
/// # Returns
/// * `Some(&[u8])` - The value bytes if tag is found
/// * `None` - If tag is not found or data is malformed
pub fn find_tag<'a>(data: &'a [u8], tag: &[u8]) -> Option<&'a [u8]> {
    let mut i = 0;
    while i < data.len() {
        // Parse current tag
        // Determine tag length (1 or 2 bytes for EMV tags)
        if i >= data.len() {
            break;
        }

        let current_tag_len = if data[i] & 0x1F == 0x1F && i + 1 < data.len() {
            2  // Two-byte tag (like 9F46)
        } else {
            1  // One-byte tag (like 8F, 5A)
        };

        if i + current_tag_len > data.len() {
            break;
        }

        let current_tag = &data[i..i + current_tag_len];
        i += current_tag_len;

        // Parse length
        if i >= data.len() {
            break;
        }

        let len = data[i] as usize;
        i += 1;

        // Handle extended length (if bit 8 is set)
        let actual_len = if len & 0x80 != 0 {
            let num_len_bytes = (len & 0x7F) as usize;
            if i + num_len_bytes > data.len() {
                break;
            }

            let mut actual = 0usize;
            for j in 0..num_len_bytes {
                actual = (actual << 8) | (data[i + j] as usize);
            }
            i += num_len_bytes;
            actual
        } else {
            len
        };

        // Check if this is the tag we're looking for
        if current_tag == tag {
            if i + actual_len <= data.len() {
                return Some(&data[i..i + actual_len]);
            }
            return None;
        }

        // Skip value and continue to next tag
        i += actual_len;
    }
    None
}

/// EMV Tag identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EmvTag(pub &'static [u8]);

/// Common EMV tags used in payment card processing
pub mod tags {
    use super::EmvTag;

    // Application metadata
    pub const APPLICATION_IDENTIFIER: EmvTag = EmvTag(&[0x4F]);
    pub const APPLICATION_LABEL: EmvTag = EmvTag(&[0x50]);
    pub const APPLICATION_PAN: EmvTag = EmvTag(&[0x5A]);
    pub const APPLICATION_EXPIRATION_DATE: EmvTag = EmvTag(&[0x5F, 0x24]);
    pub const APPLICATION_EFFECTIVE_DATE: EmvTag = EmvTag(&[0x5F, 0x25]);
    pub const APPLICATION_PAN_SEQUENCE_NUMBER: EmvTag = EmvTag(&[0x5F, 0x34]);
    pub const APPLICATION_USAGE_CONTROL: EmvTag = EmvTag(&[0x9F, 0x07]);
    pub const APPLICATION_VERSION_NUMBER: EmvTag = EmvTag(&[0x9F, 0x08]);
    pub const APPLICATION_CURRENCY_CODE: EmvTag = EmvTag(&[0x9F, 0x42]);
    pub const APPLICATION_CURRENCY_EXPONENT: EmvTag = EmvTag(&[0x9F, 0x44]);

    // Cardholder data
    pub const CARDHOLDER_NAME: EmvTag = EmvTag(&[0x5F, 0x20]);
    pub const TRACK_1_DATA: EmvTag = EmvTag(&[0x56]);
    pub const TRACK_2_EQUIVALENT_DATA: EmvTag = EmvTag(&[0x57]);
    pub const TRACK_2_DATA: EmvTag = EmvTag(&[0x9F, 0x6B]);

    // Issuer data
    pub const ISSUER_COUNTRY_CODE: EmvTag = EmvTag(&[0x5F, 0x28]);
    pub const LANGUAGE_PREFERENCE: EmvTag = EmvTag(&[0x5F, 0x2D]);

    // Cryptography and certificates
    pub const CA_PUBLIC_KEY_INDEX: EmvTag = EmvTag(&[0x8F]);
    pub const ISSUER_PUBLIC_KEY_CERTIFICATE: EmvTag = EmvTag(&[0x90]);
    pub const ISSUER_PUBLIC_KEY_EXPONENT: EmvTag = EmvTag(&[0x9F, 0x32]);
    pub const ISSUER_PUBLIC_KEY_REMAINDER: EmvTag = EmvTag(&[0x92]);
    pub const ICC_PUBLIC_KEY_CERTIFICATE: EmvTag = EmvTag(&[0x9F, 0x46]);
    pub const ICC_PUBLIC_KEY_EXPONENT: EmvTag = EmvTag(&[0x9F, 0x47]);
    pub const ICC_PUBLIC_KEY_REMAINDER: EmvTag = EmvTag(&[0x9F, 0x48]);
    pub const ICC_PIN_ENCIPHERMENT_PUBLIC_KEY_CERTIFICATE: EmvTag = EmvTag(&[0x9F, 0x2D]);
    pub const STATIC_DATA_AUTHENTICATION_TAG_LIST: EmvTag = EmvTag(&[0x9F, 0x4A]);

    // Transaction data
    pub const TRANSACTION_CURRENCY_CODE: EmvTag = EmvTag(&[0x5F, 0x2A]);
    pub const PDOL: EmvTag = EmvTag(&[0x9F, 0x38]);
    pub const AFL: EmvTag = EmvTag(&[0x94]);
    pub const AIP: EmvTag = EmvTag(&[0x82]);

    // Response templates
    pub const FCI_TEMPLATE: EmvTag = EmvTag(&[0x6F]);
    pub const RESPONSE_MESSAGE_TEMPLATE_FORMAT_1: EmvTag = EmvTag(&[0x80]);
    pub const RESPONSE_MESSAGE_TEMPLATE_FORMAT_2: EmvTag = EmvTag(&[0x77]);
    pub const RECORD_TEMPLATE: EmvTag = EmvTag(&[0x70]);
}

/// Get a human-readable name for an EMV tag
pub fn get_tag_name(tag: &[u8]) -> &'static str {
    match tag {
        [0x4F] => "Application Identifier (AID)",
        [0x50] => "Application Label",
        [0x56] => "Track 1 Data",
        [0x57] => "Track 2 Equivalent Data",
        [0x5A] => "Application PAN",
        [0x5F, 0x20] => "Cardholder Name",
        [0x5F, 0x24] => "Application Expiration Date",
        [0x5F, 0x25] => "Application Effective Date",
        [0x5F, 0x28] => "Issuer Country Code",
        [0x5F, 0x2A] => "Transaction Currency Code",
        [0x5F, 0x2D] => "Language Preference",
        [0x5F, 0x34] => "Application PAN Sequence Number",
        [0x8F] => "CA Public Key Index",
        [0x90] => "Issuer Public Key Certificate",
        [0x92] => "Issuer Public Key Remainder",
        [0x9F, 0x07] => "Application Usage Control",
        [0x9F, 0x08] => "Application Version Number (Card)",
        [0x9F, 0x32] => "Issuer Public Key Exponent",
        [0x9F, 0x42] => "Application Currency Code",
        [0x9F, 0x44] => "Application Currency Exponent",
        [0x9F, 0x46] => "ICC Public Key Certificate",
        [0x9F, 0x47] => "ICC Public Key Exponent",
        [0x9F, 0x48] => "ICC Public Key Remainder",
        [0x9F, 0x4A] => "Static Data Authentication Tag List",
        [0x9F, 0x2D] => "ICC PIN Encipherment Public Key Certificate",
        [0x9F, 0x6B] => "Track 2 Data",
        _ => "Unknown Tag",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_tag_simple() {
        // Simple TLV: Tag 8F, Length 1, Value 05
        let data = &[0x8F, 0x01, 0x05];
        let result = find_tag(data, &[0x8F]);
        assert_eq!(result, Some(&[0x05][..]));
    }

    #[test]
    fn test_find_tag_two_byte() {
        // Two-byte tag: 9F46, Length 2, Value ABCD
        let data = &[0x9F, 0x46, 0x02, 0xAB, 0xCD];
        let result = find_tag(data, &[0x9F, 0x46]);
        assert_eq!(result, Some(&[0xAB, 0xCD][..]));
    }

    #[test]
    fn test_find_tag_not_found() {
        let data = &[0x8F, 0x01, 0x05];
        let result = find_tag(data, &[0x90]);
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_tag_nested() {
        // Tag 70 contains Tag 8F
        let data = &[0x70, 0x04, 0x8F, 0x01, 0x05, 0xFF];
        let template = find_tag(data, &[0x70]).unwrap();
        let inner = find_tag(template, &[0x8F]);
        assert_eq!(inner, Some(&[0x05][..]));
    }
}
