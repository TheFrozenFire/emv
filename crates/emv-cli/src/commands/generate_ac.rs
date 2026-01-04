use emv_card::{CardReader, EmvCard, CryptogramType, GenerateAcRequest, DolBuilder};
use emv_common::find_tag;

pub fn cmd_generate_ac() {
    println!("EMV GENERATE AC - Application Cryptogram Generation\n");

    // WARNING about ATC
    println!("⚠️  WARNING ⚠️");
    println!("This command will INCREMENT the Application Transaction Counter (ATC) on your card!");
    println!("This is a permanent change that cannot be undone.");
    println!("Press Ctrl+C now to cancel, or press Enter to continue...\n");

    // Wait for user confirmation
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();

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

    // Read card data to get application info
    println!("\n=== Reading Card Data ===\n");
    let card_data = match emv_card.read_card_data() {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to read card data: {}", e);
            return;
        }
    };

    println!("Card data read successfully");

    // Get CDOL1 from card data (typically in tag 8C or 8D)
    // Tag 8C: Card Risk Management Data Object List 1 (CDOL1)
    // Tag 8D: Card Risk Management Data Object List 2 (CDOL2)
    // Search through individual records (they may be wrapped in tag 70)
    let mut cdol1 = None;
    let mut cdol2 = None;

    for record in &card_data.records {
        // Check if wrapped in tag 70 (Record Template)
        let search_data = if let Some(template) = find_tag(record, &[0x70]) {
            template
        } else {
            record.as_slice()
        };

        if cdol1.is_none() {
            cdol1 = find_tag(search_data, &[0x8C]);
        }
        if cdol2.is_none() {
            cdol2 = find_tag(search_data, &[0x8D]);
        }

        if cdol1.is_some() && cdol2.is_some() {
            break;
        }
    }

    let cdol = if let Some(cdol1_data) = cdol1 {
        println!("Found CDOL1 ({} bytes): {}", cdol1_data.len(), hex::encode_upper(cdol1_data));
        cdol1_data
    } else if let Some(cdol2_data) = cdol2 {
        println!("Found CDOL2 ({} bytes): {}", cdol2_data.len(), hex::encode_upper(cdol2_data));
        cdol2_data
    } else {
        eprintln!("No CDOL found on card");
        eprintln!("Cannot proceed with GENERATE AC");
        return;
    };

    // Build CDOL data
    println!("\n=== Building Transaction Data ===\n");
    let cdol_data = match DolBuilder::new()
        .with_defaults() // Set date, TVR, CVM results
        .set_amount(100) // 1.00 in smallest currency units
        .set_amount_other(0) // No cashback
        .set_currency(840) // USD
        .set_terminal_country(840) // USA
        .set_transaction_type(0x00) // Purchase
        .set_terminal_type(0x22) // Smart card reader
        .set_unpredictable_number(emv_card::protocol::generate_random_bytes(4))
        .build(cdol)
    {
        Ok(data) => {
            println!("Transaction amount: $1.00 USD");
            println!("Transaction type: Purchase");
            println!("CDOL data ({} bytes): {}", data.len(), hex::encode_upper(&data));
            data
        }
        Err(e) => {
            eprintln!("Failed to build CDOL data: {}", e);
            return;
        }
    };

    // Create GENERATE AC request (using ARQC - Authorization Request Cryptogram)
    let request = GenerateAcRequest {
        cryptogram_type: CryptogramType::Arqc,
        cdol_data,
    };

    println!("\n=== Sending GENERATE AC ===\n");
    println!("Cryptogram Type: ARQC (Authorization Request - Online)");

    let response = match emv_card.generate_ac(&request) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("GENERATE AC error: {}", e);
            return;
        }
    };

    println!("\n=== GENERATE AC Response ===\n");

    if let Some(cryptogram) = &response.cryptogram {
        println!("✓ Cryptogram (9F26): {}", hex::encode_upper(cryptogram));
    } else {
        println!("✗ Cryptogram: Not found");
    }

    if let Some(atc) = response.atc {
        println!("✓ Application Transaction Counter (9F36): {}", atc);
    } else {
        println!("✗ ATC: Not found");
    }

    if let Some(cid) = response.cid {
        println!("✓ Cryptogram Information Data (9F27): {:02X}", cid);

        // Parse CID bits
        let cryptogram_type_bits = (cid >> 6) & 0x03;
        let cryptogram_type_str = match cryptogram_type_bits {
            0b00 => "AAC (declined)",
            0b01 => "TC (approved offline)",
            0b10 => "TC (approved offline)",
            0b11 => "ARQC (go online)",
            _ => "unknown",
        };
        println!("  Cryptogram Type: {}", cryptogram_type_str);
    } else {
        println!("✗ CID: Not found");
    }

    if let Some(iad) = &response.iad {
        println!("✓ Issuer Application Data (9F10): {} ({} bytes)", hex::encode_upper(iad), iad.len());
    }

    if let Some(sdad) = &response.sdad {
        println!("✓ Signed Dynamic Application Data (9F4B): {} bytes", sdad.len());
        println!("  (CDA signature - can be verified with ICC public key)");
    }

    println!("\nRaw response ({} bytes): {}",
        response.raw_data.len(),
        hex::encode_upper(&response.raw_data));

    println!("\n✓ GENERATE AC completed successfully!");
    println!("  The card generated a cryptogram for a simulated transaction.");
}
