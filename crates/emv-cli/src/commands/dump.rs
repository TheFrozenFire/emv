use emv_card::{CardReader, EmvCard};
use emv_common::find_tag;

use super::dump_all_tags::dump_all_tags;

pub fn cmd_dump() {
    println!("EMV Tag Dump - All TLV Tags\n");

    // Connect to card reader
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

    println!("Reader: {}", reader_name);
    println!("Card connected successfully\n");

    // Read card data
    let mut emv_card = EmvCard::new(&card);

    let card_data = match emv_card.read_card_data() {
        Ok(data) => data,
        Err(err) => {
            eprintln!("Failed to read card data: {}", err);
            return;
        }
    };

    println!("=== DUMPING ALL TLV TAGS FROM ALL RECORDS ===\n");
    println!("Total records: {}\n", card_data.records.len());

    for (i, record) in card_data.records.iter().enumerate() {
        println!("Record {}:", i + 1);

        let search_data = if let Some(template) = find_tag(record, &[0x70]) {
            println!("  (Wrapped in tag 70 - Record Template)");
            template
        } else {
            record.as_slice()
        };

        dump_all_tags(search_data, 1);
        println!();
    }

    println!("=== Dump Complete ===");
}
