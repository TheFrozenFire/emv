use emv_card::{CardReader, EmvCard};

pub fn cmd_get_challenge() {
    println!("EMV GET CHALLENGE - Request Random Number\n");

    // Connect to card reader
    let reader = match CardReader::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to connect to card reader: {}", e);
            return;
        }
    };

    let (card, reader_name) = match reader.connect_first() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to connect to card: {}", e);
            return;
        }
    };

    println!("Connected to reader: {}", reader_name);

    let mut emv_card = EmvCard::new(&card);

    // Read card data (this selects the application)
    println!("\n=== Selecting EMV Application ===\n");
    if let Err(e) = emv_card.read_card_data() {
        eprintln!("Failed to select EMV application: {}", e);
        return;
    }
    println!("Application selected");

    println!("\n=== Sending GET CHALLENGE ===\n");

    match emv_card.get_challenge() {
        Ok(random_bytes) => {
            println!(
                "Random bytes ({} bytes): {}",
                random_bytes.len(),
                hex::encode_upper(&random_bytes)
            );
            println!("\nGET CHALLENGE completed successfully!");
        }
        Err(e) => {
            eprintln!("GET CHALLENGE failed: {}", e);
        }
    }
}
