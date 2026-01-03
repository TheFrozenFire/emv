//! PC/SC card reader management

use pcsc::{Card, Context, Protocols, Scope, ShareMode};

/// Card reader wrapper for managing PC/SC connections
pub struct CardReader {
    context: Context,
}

impl CardReader {
    /// Create a new CardReader by establishing a PC/SC context
    pub fn new() -> Result<Self, pcsc::Error> {
        let context = Context::establish(Scope::User)?;
        Ok(Self { context })
    }

    /// List all available card readers
    pub fn list_readers(&self) -> Result<Vec<String>, pcsc::Error> {
        let mut readers_buf = [0; 2048];
        let readers = self.context.list_readers(&mut readers_buf)?;

        Ok(readers
            .map(|r| r.to_str().unwrap_or("Unknown").to_string())
            .collect())
    }

    /// Connect to the first available reader
    pub fn connect_first(&self) -> Result<(Card, String), pcsc::Error> {
        let mut readers_buf = [0; 2048];
        let mut readers = self.context.list_readers(&mut readers_buf)?;

        if let Some(reader) = readers.next() {
            let reader_name = reader.to_str().unwrap_or("Unknown").to_string();
            let card = self.context.connect(reader, ShareMode::Shared, Protocols::ANY)?;
            Ok((card, reader_name))
        } else {
            Err(pcsc::Error::NoReadersAvailable)
        }
    }

    /// Connect to a specific reader by name (CStr)
    pub fn connect(&self, reader_name: &std::ffi::CStr) -> Result<Card, pcsc::Error> {
        self.context.connect(
            reader_name,
            ShareMode::Shared,
            Protocols::ANY,
        )
    }
}

impl Default for CardReader {
    fn default() -> Self {
        Self::new().expect("Failed to establish PC/SC context")
    }
}
