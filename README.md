# EMV Certificate Reader

A Rust library and CLI tool for reading and verifying EMV (Europay, Mastercard, Visa) certificates from payment cards.

## Features

- **EMV Certificate Chain Verification**: Verify the complete certificate chain (CA → Issuer → ICC) for DDA/CDA authentication
- **Authentication Method Detection**: Automatically detect SDA, DDA, or CDA from card's Application Interchange Profile (AIP)
- **PC/SC Card Reader Support**: Direct communication with EMV cards via PC/SC-compatible card readers
- **CA Public Key Database**: Embedded database of Certificate Authority public keys for major payment schemes (Visa, Mastercard, American Express, Discover, JCB, UnionPay)
- **TLV Parsing**: Parse EMV BER-TLV encoded data structures
- **Structured Logging**: Comprehensive tracing support for debugging card communication

## Architecture

The project is organized as a Rust workspace with the following crates:

- **emv-common**: TLV (Tag-Length-Value) parsing utilities
- **emv-ca-keys**: Certificate Authority public key management
- **emv-card**: Core EMV protocol implementation, APDU commands, and certificate verification
- **emv-cli**: Command-line interface for card reading

## Installation

### Prerequisites

- Rust 1.70 or later
- PC/SC smartcard library:
  - **Linux**: `libpcsclite-dev` (Debian/Ubuntu) or `pcsc-lite` (Fedora/RHEL)
  - **macOS**: Included by default
  - **Windows**: Included by default

### From Source

```bash
git clone https://github.com/TheFrozenFire/emv.git
cd emv
cargo build --release
```

The CLI binary will be available at `target/release/emv-signer`.

## Usage

### CLI Tool

Read an EMV card and verify its certificate chain:

```bash
# Run the CLI tool
cargo run --package emv-cli

# Or use the built binary
./target/release/emv-signer
```

The tool will:
1. Connect to the first available card reader
2. Select an EMV application (Visa, Mastercard, etc.)
3. Read certificate data from the card
4. Verify the certificate chain using embedded CA public keys
5. Display the verification results

### Library Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
emv-card = { path = "crates/emv-card" }
emv-ca-keys = { path = "crates/emv-ca-keys" }
```

Example:

```rust
use emv_card::reader::CardReader;
use emv_card::protocol::EmvCard;
use emv_card::crypto::{CertificateChainData, ChainVerifier};

// Connect to card reader
let reader = CardReader::new()?;
let (card, _reader_name) = reader.connect_first()?;

// Create EMV card interface
let mut emv = EmvCard::new(&card);

// Select application
emv.select(&[0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10])?;  // Mastercard

// Read certificate data
let cert_data = emv.read_certificate_data()?;

// Verify certificate chain
let verifier = ChainVerifier::new();
let result = verifier.verify_chain(&cert_data);

println!("Chain valid: {}", result.chain_valid);
```

## Testing

### Unit Tests

Run all unit tests (no hardware required):

```bash
cargo test
```

### Hardware Integration Tests

Tests requiring a physical EMV card are marked with `#[ignore]` and must be explicitly run:

```bash
# Run only hardware tests (requires card reader + card)
cargo test --package emv-card --test hardware_integration -- --ignored

# Run all tests including hardware tests
cargo test -- --include-ignored
```

## Certificate Verification

### Supported Authentication Methods

- **SDA (Static Data Authentication)**: Verify static data signature (partial implementation)
- **DDA (Dynamic Data Authentication)**: Verify certificate chain CA → Issuer → ICC
- **CDA (Combined Data Authentication)**: Verify certificate chain (same as DDA)

### Verification Process

1. **Detect authentication method** from card's AIP
2. **Load CA public key** from embedded database using RID and CA index
3. **Verify issuer certificate** using CA public key
4. **Extract issuer public key** from verified issuer certificate
5. **Verify ICC certificate** using issuer public key
6. **Report verification result** with detailed error messages

## Security Considerations

This tool is designed for:
- Educational purposes
- EMV implementation testing
- Card authentication debugging
- Security research

**Not designed for**:
- Payment processing
- Production financial applications
- Cloning or fraud

Always use responsibly and ethically.

## Project Status

This project is under active development. Features implemented:
- [x] PC/SC card reader support
- [x] EMV application selection
- [x] Certificate chain verification (DDA/CDA)
- [x] CA public key database (Visa, Mastercard, AmEx, Discover, JCB, UnionPay)
- [x] TLV parsing
- [x] Structured logging
- [ ] SDA verification
- [ ] INTERNAL AUTHENTICATE (DDA challenge)
- [ ] CDA signature verification

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Resources

- [EMV Book 2: Security and Key Management](https://www.emvco.com/specifications/)
- [EMV Book 3: Application Specification](https://www.emvco.com/specifications/)
- [PC/SC Specification](https://pcscworkgroup.com/)

## Acknowledgments

- EMV specification from EMVCo
- CA public keys sourced from EMVCo databases
- Built with the Rust `pcsc` and `rsa` crates
