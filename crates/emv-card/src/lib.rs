//! EMV Card - Smart card reading and EMV protocol implementation
//!
//! This crate provides functionality to communicate with EMV payment cards
//! via PC/SC readers and implements the EMV protocol for reading card data
//! and verifying certificate chains.

pub mod reader;
pub mod apdu;
pub mod protocol;
pub mod crypto;

pub use reader::CardReader;
pub use protocol::{EmvCard, CardData, CertificateData};
pub use crypto::{AuthenticationMethod, CertificateVerificationResult};

/// Re-export commonly used types
pub use pcsc::{Card, Context, Error as PcscError};
