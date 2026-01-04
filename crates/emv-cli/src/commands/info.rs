use emv_card::{CardReader, EmvCard};
use emv_common::find_tag;

use crate::formatters::FormatMode;

use super::display_tags;

pub fn cmd_info(format_mode: FormatMode) {
    println!(
        "EMV Certificate Reader - {} Mode\n",
        format_mode.description()
    );

    // Step 1: Connect to card reader
    let reader = match CardReader::new() {
        Ok(r) => r,
        Err(err) => {
            eprintln!("Failed to establish PC/SC context: {}", err);
            return;
        }
    };

    let (card, _reader_name) = match reader.connect_first() {
        Ok((c, name)) => {
            println!("Reader: {}", name);
            println!("Card connected successfully\n");
            (c, name)
        }
        Err(err) => {
            eprintln!("Failed to connect to card: {}", err);
            eprintln!("Please ensure a card is present on the reader");
            return;
        }
    };

    // Step 2: List available applications
    let mut emv_card = EmvCard::new(&card);

    println!("=== Discovering Available Applications ===\n");
    let applications = emv_card.list_applications();

    if applications.is_empty() {
        println!("No applications found via PSE/PPSE\n");
    } else {
        println!("Found {} application(s):\n", applications.len());
        for (i, app) in applications.iter().enumerate() {
            println!("Application {}:", i + 1);
            println!("  AID: {}", hex::encode_upper(&app.aid));
            if let Some(ref label) = app.label {
                println!("  Label: {}", label);
            }
            if let Some(ref pref_name) = app.preferred_name {
                println!("  Preferred Name: {}", pref_name);
            }
            if let Some(priority) = app.priority {
                println!("  Priority: {} (lower = higher priority)", priority & 0x0F);
            }
            println!();
        }
    }

    println!("=== Selecting EMV Application ===\n");

    match emv_card.read_card_data() {
        Ok(card_data) => {
            // Display SELECT response details
            if let Some(ref select_response) = card_data.select_response {
                println!("=== SELECT Response Details ===\n");
                if format_mode == FormatMode::Raw {
                    println!("Raw SELECT response ({} bytes):", select_response.len());
                    println!("{}\n", hex::encode_upper(select_response));
                } else {
                    // Parse FCI
                    if let Some(fci) = find_tag(select_response, &[0x6F]) {
                        display_tags(fci, &format_mode);
                        // Also check A5 (FCI Proprietary Template)
                        if let Some(a5) = find_tag(fci, &[0xA5]) {
                            println!("\nFCI Proprietary Template (A5):");
                            display_tags(a5, &format_mode);
                        }
                    }
                    println!();
                }
            }

            println!("Successfully read card data");

            // Display GPO response
            if let Some(ref gpo_data) = card_data.gpo_response {
                println!("\n=== GET PROCESSING OPTIONS Response ===\n");

                // Check if wrapped in tag 77 or tag 80
                let search_data = if let Some(template) = find_tag(gpo_data, &[0x77]) {
                    template
                } else if let Some(template) = find_tag(gpo_data, &[0x80]) {
                    template
                } else {
                    gpo_data.as_slice()
                };

                if format_mode == FormatMode::Raw {
                    println!(
                        "  Data ({} bytes): {}",
                        search_data.len(),
                        hex::encode_upper(search_data)
                    );
                } else {
                    display_tags(search_data, &format_mode);
                }
            }

            println!("\nRecords read: {}\n", card_data.records.len());

            // Display records
            println!("=== Card Data ===\n");
            for (i, record) in card_data.records.iter().enumerate() {
                println!("Record {}:", i + 1);

                // Check if record is wrapped in tag 70
                let search_data = if let Some(template) = find_tag(record, &[0x70]) {
                    template
                } else {
                    record.as_slice()
                };

                if format_mode == FormatMode::Raw {
                    println!(
                        "  Data ({} bytes): {}",
                        search_data.len(),
                        hex::encode_upper(search_data)
                    );
                } else {
                    // Parse and display tags
                    display_tags(search_data, &format_mode);
                }
                println!();
            }

            // Verify certificates
            println!("=== Certificate Chain Verification ===\n");

            // Debug: Show what certificate data we have
            println!("Certificate data found:");
            let has_ca_index = card_data.records.iter().any(|r| {
                let search_data = if let Some(template) = find_tag(r, &[0x70]) {
                    template
                } else {
                    r.as_slice()
                };
                find_tag(search_data, &[0x8F]).is_some()
            });
            let has_issuer_cert = card_data.records.iter().any(|r| {
                let search_data = if let Some(template) = find_tag(r, &[0x70]) {
                    template
                } else {
                    r.as_slice()
                };
                find_tag(search_data, &[0x90]).is_some()
            });
            let has_icc_cert = card_data.records.iter().any(|r| {
                let search_data = if let Some(template) = find_tag(r, &[0x70]) {
                    template
                } else {
                    r.as_slice()
                };
                find_tag(search_data, &[0x9F, 0x46]).is_some()
            });
            println!(
                "  - CA Public Key Index (8F): {}",
                if has_ca_index { "✓" } else { "✗" }
            );
            println!(
                "  - Issuer Certificate (90): {}",
                if has_issuer_cert { "✓" } else { "✗" }
            );
            println!(
                "  - ICC Certificate (9F46): {}",
                if has_icc_cert { "✓" } else { "✗" }
            );
            println!();

            let verification_result = emv_card.verify_certificates(&card_data);

            println!(
                "Authentication Method: {:?}",
                verification_result.auth_method
            );
            println!(
                "CA Key Found: {}",
                if verification_result.ca_key_found {
                    "✓"
                } else {
                    "✗"
                }
            );
            println!(
                "Issuer Certificate Valid: {}",
                if verification_result.issuer_cert_valid {
                    "✓"
                } else {
                    "✗"
                }
            );
            println!(
                "ICC Certificate Valid: {}",
                if verification_result.icc_cert_valid {
                    "✓"
                } else {
                    "✗"
                }
            );
            println!(
                "Chain Valid: {}",
                if verification_result.chain_valid {
                    "✓"
                } else {
                    "✗"
                }
            );

            if !verification_result.errors.is_empty() {
                println!("\nErrors:");
                for error in &verification_result.errors {
                    println!("  - {}", error);
                }
            }

            println!("\n=== Certificate Reading Complete ===");
        }
        Err(err) => {
            eprintln!("Failed to read card data: {}", err);
        }
    }
}
