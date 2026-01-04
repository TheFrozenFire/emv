use emv_card::{CardReader, EmvCard};
use rsa::traits::PublicKeyParts;

pub fn cmd_authenticate(challenge_hex: Option<String>) {
    println!("EMV Dynamic Data Authentication (DDA)\n");

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

    // Read card data first to get certificates
    println!("\n=== Reading Card Data ===\n");
    let card_data = match emv_card.read_card_data() {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to read card data: {}", e);
            return;
        }
    };

    println!("Card data read successfully");

    // Verify certificates to get ICC public key
    println!("\n=== Verifying Certificates ===\n");
    let verification_result = emv_card.verify_certificates(&card_data);

    println!(
        "Authentication Method: {:?}",
        verification_result.auth_method
    );
    println!(
        "Chain Valid: {}",
        if verification_result.chain_valid {
            "✓"
        } else {
            "✗"
        }
    );

    // Check if we have ICC public key for DDA
    let icc_key = match verification_result.icc_public_key {
        Some(key) => key,
        None => {
            eprintln!("\nError: No ICC Public Key available for DDA");
            eprintln!("Card may not support INTERNAL AUTHENTICATE");
            if !verification_result.errors.is_empty() {
                eprintln!("\nCertificate errors:");
                for error in &verification_result.errors {
                    eprintln!("  - {}", error);
                }
            }
            return;
        }
    };

    println!("ICC Public Key: {} bits", icc_key.n().bits());

    // Prepare challenge
    let challenge = if let Some(hex_str) = challenge_hex {
        match hex::decode(&hex_str) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("Invalid hex string for challenge: {}", e);
                return;
            }
        }
    } else {
        // Generate random challenge (4 bytes is typical)
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..4).map(|_| rng.gen()).collect()
    };

    println!("\n=== Sending INTERNAL AUTHENTICATE ===\n");
    println!("Challenge ({} bytes): {}", challenge.len(), hex::encode_upper(&challenge));

    // Send INTERNAL AUTHENTICATE
    let response = match emv_card.internal_authenticate(&challenge) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("INTERNAL AUTHENTICATE error: {}", e);
            return;
        }
    };

    if !response.is_success() {
        eprintln!(
            "INTERNAL AUTHENTICATE failed: SW1={:02X} SW2={:02X}",
            response.sw1, response.sw2
        );
        eprintln!("Status: {}", response.status_string());
        return;
    }

    println!(
        "Response ({} bytes): {}{}",
        response.data.len(),
        hex::encode_upper(&response.data[..20.min(response.data.len())]),
        if response.data.len() > 20 {
            "..."
        } else {
            ""
        }
    );

    // Verify the signature
    println!("\n=== Verifying DDA Signature ===\n");
    let verifier = emv_card::crypto::CertificateVerifier::new();
    match verifier.verify_dda_signature(&response.data, &icc_key, &challenge) {
        Ok(()) => {
            println!("DDA Signature Valid: ✓");
            println!("\n✓ Card successfully proved possession of ICC private key!");
            println!("  This card cannot be cloned without the private key.");
        }
        Err(e) => {
            println!("DDA Signature Valid: ✗");
            eprintln!("Error: {}", e);
        }
    }
}
