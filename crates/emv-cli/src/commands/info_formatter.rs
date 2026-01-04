//! Formatter for card information output

use emv_common::find_tag;

use crate::formatters::FormatMode;

use super::card_info::CardInfoData;
use super::display_tags;

/// Format and output card information
pub fn format_card_info(info: &CardInfoData, format_mode: FormatMode) {
    println!(
        "EMV Certificate Reader - {} Mode\n",
        format_mode.description()
    );

    // Reader info
    println!("Reader: {}", info.reader_name);
    println!("Card connected successfully\n");

    // Applications
    print_applications(info, format_mode);

    // SELECT response
    print_select_response(info, format_mode);

    println!("Successfully read card data");

    // GPO response
    print_gpo_response(info, format_mode);

    // Records
    print_records(info, format_mode);

    // Certificate verification
    print_certificate_verification(info);

    println!("\n=== Certificate Reading Complete ===");
}

fn print_applications(info: &CardInfoData, _format_mode: FormatMode) {
    println!("=== Discovering Available Applications ===\n");

    if info.applications.is_empty() {
        println!("No applications found via PSE/PPSE\n");
    } else {
        println!("Found {} application(s):\n", info.applications.len());
        for (i, app) in info.applications.iter().enumerate() {
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
}

fn print_select_response(info: &CardInfoData, format_mode: FormatMode) {
    if let Some(ref select_response) = info.card_data.select_response {
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
}

fn print_gpo_response(info: &CardInfoData, format_mode: FormatMode) {
    if let Some(ref gpo_data) = info.card_data.gpo_response {
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
}

fn print_records(info: &CardInfoData, format_mode: FormatMode) {
    println!("\nRecords read: {}\n", info.card_data.records.len());

    println!("=== Card Data ===\n");
    for (i, record) in info.card_data.records.iter().enumerate() {
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
}

fn print_certificate_verification(info: &CardInfoData) {
    println!("=== Certificate Chain Verification ===\n");

    let summary = info.certificate_summary();

    println!("Certificate data found:");
    println!(
        "  - CA Public Key Index (8F): {}",
        if summary.has_ca_index { "✓" } else { "✗" }
    );
    println!(
        "  - Issuer Certificate (90): {}",
        if summary.has_issuer_cert { "✓" } else { "✗" }
    );
    println!(
        "  - ICC Certificate (9F46): {}",
        if summary.has_icc_cert { "✓" } else { "✗" }
    );
    println!();

    println!("Authentication Method: {:?}", summary.auth_method);
    println!(
        "CA Key Found: {}",
        if summary.ca_key_found { "✓" } else { "✗" }
    );
    println!(
        "Issuer Certificate Valid: {}",
        if summary.issuer_cert_valid { "✓" } else { "✗" }
    );
    println!(
        "ICC Certificate Valid: {}",
        if summary.icc_cert_valid { "✓" } else { "✗" }
    );
    println!(
        "Chain Valid: {}",
        if summary.chain_valid { "✓" } else { "✗" }
    );

    if !summary.errors.is_empty() {
        println!("\nErrors:");
        for error in &summary.errors {
            println!("  - {}", error);
        }
    }
}
