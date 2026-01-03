//! Hardware-dependent integration tests
//!
//! These tests require a physical EMV card in a card reader.
//! They are ignored by default and must be explicitly run with:
//!
//!     cargo test --package emv-card --test hardware_integration -- --ignored
//!
//! Or to run all tests including hardware tests:
//!
//!     cargo test --package emv-card --test hardware_integration -- --include-ignored

use emv_card::apdu::commands;
use emv_card::crypto::{CertificateChainData, ChainVerifier};
use emv_card::protocol::aids;
use emv_card::reader::CardReader;

/// Test that we can connect to a card reader
///
/// **Requires**: Card reader connected (card not required)
#[test]
#[ignore = "requires hardware: card reader"]
fn test_connect_to_reader() {
    let result = CardReader::new();
    assert!(
        result.is_ok(),
        "Failed to connect to card reader. Is a reader connected?"
    );
}

/// Test that we can detect an inserted card
///
/// **Requires**: Card reader with card inserted
#[test]
#[ignore = "requires hardware: card inserted in reader"]
fn test_card_present() {
    let reader = CardReader::new().expect("Failed to connect to reader");
    let (_card, reader_name) = reader.connect_first().expect("Failed to connect to card");

    println!("Connected to reader: {}", reader_name);
    // If we got here, a card is present and connected
    assert!(true, "Card successfully detected");
}

/// Test selecting a known EMV application
///
/// **Requires**: EMV card (credit/debit card) inserted
#[test]
#[ignore = "requires hardware: EMV card"]
fn test_select_emv_application() {
    let reader = CardReader::new().expect("Failed to connect to reader");
    let (card, _reader_name) = reader.connect_first().expect("Failed to connect to card");

    // Try each known AID until one works
    let known_aids = [
        ("Visa", aids::VISA),
        ("Mastercard", aids::MASTERCARD),
        ("AmEx", aids::AMEX),
    ];

    let mut selected = false;
    for (name, aid) in &known_aids {
        let cmd = commands::select(aid);
        if let Ok(response) = cmd.send(&card) {
            if response.is_success() {
                println!(
                    "Successfully selected {} ({})",
                    name,
                    hex::encode_upper(aid)
                );
                selected = true;
                break;
            }
        }
    }

    assert!(selected, "No EMV application could be selected");
}

/// Full end-to-end test: Read card and verify certificate chain
///
/// **Requires**: EMV card (credit/debit card) with DDA/CDA support
#[test]
#[ignore = "requires hardware: EMV card with DDA/CDA"]
fn test_full_certificate_verification() {
    let reader = CardReader::new().expect("Failed to connect to reader");
    let (card, _reader_name) = reader.connect_first().expect("Failed to connect to card");

    // Select application
    let known_aids = [
        ("Visa", aids::VISA),
        ("Mastercard", aids::MASTERCARD),
        ("AmEx", aids::AMEX),
    ];

    let mut selected_aid = None;
    let mut select_response = None;
    for (name, aid) in &known_aids {
        let cmd = commands::select(aid);
        if let Ok(response) = cmd.send(&card) {
            if response.is_success() {
                println!("Selected {}", name);
                selected_aid = Some(*aid);
                select_response = Some(response);
                break;
            }
        }
    }

    assert!(
        selected_aid.is_some(),
        "Failed to select any EMV application"
    );
    let aid = selected_aid.unwrap();
    let _select_resp = select_response.unwrap();

    // Extract RID from AID
    let rid = aid[0..5].to_vec();

    // Get processing options
    let gpo_cmd = commands::get_processing_options(vec![0x83, 0x00]);
    let gpo_response = gpo_cmd
        .send(&card)
        .expect("Failed to get processing options");

    assert!(
        gpo_response.is_success(),
        "GPO failed: {}",
        gpo_response.status_string()
    );

    // Read records (simplified - just try a few)
    let mut records = vec![];
    for sfi in 1..=5 {
        for record in 1..=10 {
            let cmd = commands::read_record(record, sfi);
            if let Ok(response) = cmd.send(&card) {
                if response.is_success() && !response.data.is_empty() {
                    println!("Read record {}.{}", sfi, record);
                    records.push(response.data);
                } else {
                    // No more records in this SFI
                    break;
                }
            }
        }
    }

    println!("Read {} records", records.len());
    assert!(!records.is_empty(), "No records could be read");

    // Extract certificate data
    let cert_data =
        CertificateChainData::from_card_data(&records, Some(&gpo_response.data), rid.clone());

    println!("Authentication method: {:?}", cert_data.aip);
    println!("CA index: {:?}", cert_data.ca_index);

    // Verify certificate chain
    let verifier = ChainVerifier::new();
    let result = verifier.verify_chain(&cert_data);

    println!("Verification result:");
    println!("  CA key found: {}", result.ca_key_found);
    println!("  Issuer cert valid: {}", result.issuer_cert_valid);
    println!("  ICC cert valid: {}", result.icc_cert_valid);
    println!("  Chain valid: {}", result.chain_valid);

    if !result.errors.is_empty() {
        println!("Errors:");
        for error in &result.errors {
            println!("  - {}", error);
        }
    }

    // For this test, we at least expect to find the CA key
    // Full chain verification may fail depending on the card
    assert!(
        result.ca_key_found,
        "CA public key should be found for RID {}",
        hex::encode_upper(&rid)
    );
}

/// Test GET DATA command for application data
///
/// **Requires**: EMV card inserted
#[test]
#[ignore = "requires hardware: EMV card"]
fn test_get_data_command() {
    let reader = CardReader::new().expect("Failed to connect to reader");
    let (card, _reader_name) = reader.connect_first().expect("Failed to connect to card");

    // Select application first
    let known_aids = [
        ("Visa", aids::VISA),
        ("Mastercard", aids::MASTERCARD),
        ("AmEx", aids::AMEX),
    ];

    for (name, aid) in &known_aids {
        let cmd = commands::select(aid);
        if let Ok(response) = cmd.send(&card) {
            if response.is_success() {
                println!("Selected {}", name);
                break;
            }
        }
    }

    // Try to get PIN Try Counter (tag 9F17)
    let cmd = commands::get_data(&[0x9F, 0x17]);
    if let Ok(response) = cmd.send(&card) {
        if response.is_success() {
            println!("PIN Try Counter: {:?}", response.data);
            assert!(!response.data.is_empty());
        } else {
            println!("GET DATA not supported or tag not available");
        }
    }
}
