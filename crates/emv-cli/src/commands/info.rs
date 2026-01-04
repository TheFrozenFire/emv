use emv_card::{CardReader, EmvCard};

use crate::formatters::FormatMode;

use super::card_info::CardInfoData;
use super::info_formatter::format_card_info;

pub fn cmd_info(format_mode: FormatMode) {
    // Step 1: Connect to card reader
    let reader = match CardReader::new() {
        Ok(r) => r,
        Err(err) => {
            eprintln!("Failed to establish PC/SC context: {}", err);
            return;
        }
    };

    let (card, reader_name) = match reader.connect_first() {
        Ok((c, name)) => (c, name),
        Err(err) => {
            eprintln!("Failed to connect to card: {}", err);
            eprintln!("Please ensure a card is present on the reader");
            return;
        }
    };

    // Step 2: Collect all card data
    let mut emv_card = EmvCard::new(&card);

    // List available applications
    let applications = emv_card.list_applications();

    // Read card data
    let card_data = match emv_card.read_card_data() {
        Ok(data) => data,
        Err(err) => {
            eprintln!("Failed to read card data: {}", err);
            return;
        }
    };

    // Verify certificates
    let verification_result = emv_card.verify_certificates(&card_data);

    // Collect all data into structure
    let card_info = CardInfoData {
        reader_name,
        applications,
        card_data,
        verification_result,
    };

    // Format and output
    format_card_info(&card_info, format_mode);
}
