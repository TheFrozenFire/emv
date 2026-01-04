pub mod authenticate;
pub mod card_info;
pub mod info;
pub mod info_formatter;

use emv_common::{find_tag, get_tag_name};

use crate::formatters::{self, FormatMode};

/// Display EMV tags from TLV data
pub(crate) fn display_tags(data: &[u8], mode: &FormatMode) {
    let tags: Vec<&[u8]> = vec![
        &[0x50],       // Application Label
        &[0x5A],       // Application PAN
        &[0x5F, 0x20], // Cardholder Name
        &[0x5F, 0x24], // Application Expiration Date
        &[0x5F, 0x25], // Application Effective Date
        &[0x5F, 0x28], // Issuer Country Code
        &[0x5F, 0x2A], // Transaction Currency Code
        &[0x5F, 0x34], // Application PAN Sequence Number
        &[0x57],       // Track 2 Equivalent Data
        &[0x82],       // Application Interchange Profile
        &[0x8F],       // CA Public Key Index
        &[0x90],       // Issuer Public Key Certificate
        &[0x92],       // Issuer Public Key Remainder
        &[0x93],       // Signed Static Application Data
        &[0x94],       // Application File Locator
        &[0x9F, 0x07], // Application Usage Control
        &[0x9F, 0x08], // Application Version Number
        &[0x9F, 0x32], // Issuer Public Key Exponent
        &[0x9F, 0x42], // Application Currency Code
        &[0x9F, 0x46], // ICC Public Key Certificate
        &[0x9F, 0x47], // ICC Public Key Exponent
        &[0x9F, 0x48], // ICC Public Key Remainder
        &[0x9F, 0x4A], // Static Data Authentication Tag List
        &[0x9F, 0x6B], // Track 2 Data
    ];

    for tag in &tags {
        if let Some(value) = find_tag(data, tag) {
            let tag_name = get_tag_name(tag);
            let formatted_value = formatters::format_value(tag, value, mode);

            println!(
                "  [{}] {}: {}",
                hex::encode_upper(tag),
                tag_name,
                formatted_value
            );
        }
    }
}
