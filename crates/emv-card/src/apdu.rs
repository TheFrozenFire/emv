//! APDU (Application Protocol Data Unit) command handling

use pcsc::{Card, MAX_BUFFER_SIZE};

/// APDU response containing data and status word
#[derive(Debug, Clone)]
pub struct ApduResponse {
    /// Response data (without status word)
    pub data: Vec<u8>,
    /// Status word SW1
    pub sw1: u8,
    /// Status word SW2
    pub sw2: u8,
}

impl ApduResponse {
    /// Check if the response indicates success (9000)
    pub fn is_success(&self) -> bool {
        self.sw1 == 0x90 && self.sw2 == 0x00
    }

    /// Get the full status word as a 16-bit value
    pub fn status_word(&self) -> u16 {
        ((self.sw1 as u16) << 8) | (self.sw2 as u16)
    }

    /// Get status word as hex string (e.g., "9000")
    pub fn status_string(&self) -> String {
        format!("{:02X}{:02X}", self.sw1, self.sw2)
    }
}

/// Send an APDU command to the card and return the response
pub fn send_apdu(card: &Card, apdu: &[u8]) -> Result<ApduResponse, pcsc::Error> {
    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = card.transmit(apdu, &mut rapdu_buf)?;

    if rapdu.len() < 2 {
        return Err(pcsc::Error::InsufficientBuffer);
    }

    let sw1 = rapdu[rapdu.len() - 2];
    let sw2 = rapdu[rapdu.len() - 1];
    let data = rapdu[..rapdu.len() - 2].to_vec();

    Ok(ApduResponse { data, sw1, sw2 })
}

/// APDU command builder
pub struct ApduCommand {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: Vec<u8>,
    le: Option<u8>,
}

impl ApduCommand {
    /// Create a new APDU command
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data: Vec::new(),
            le: None,
        }
    }

    /// Set command data
    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    /// Set expected response length
    pub fn le(mut self, le: u8) -> Self {
        self.le = Some(le);
        self
    }

    /// Build the APDU command bytes
    pub fn build(&self) -> Vec<u8> {
        let mut apdu = vec![self.cla, self.ins, self.p1, self.p2];

        if !self.data.is_empty() {
            apdu.push(self.data.len() as u8);
            apdu.extend_from_slice(&self.data);
        }

        if let Some(le) = self.le {
            apdu.push(le);
        }

        apdu
    }

    /// Send this command to the card
    pub fn send(&self, card: &Card) -> Result<ApduResponse, pcsc::Error> {
        let apdu_bytes = self.build();
        send_apdu(card, &apdu_bytes)
    }
}

/// Common EMV APDU commands
pub mod commands {
    use super::ApduCommand;

    /// SELECT command (by name/AID)
    pub fn select(aid: &[u8]) -> ApduCommand {
        ApduCommand::new(0x00, 0xA4, 0x04, 0x00)
            .data(aid.to_vec())
            .le(0x00)
    }

    /// GET PROCESSING OPTIONS command
    pub fn get_processing_options(pdol_data: Vec<u8>) -> ApduCommand {
        ApduCommand::new(0x80, 0xA8, 0x00, 0x00)
            .data(pdol_data)
            .le(0x00)
    }

    /// READ RECORD command
    pub fn read_record(record_number: u8, sfi: u8) -> ApduCommand {
        let p2 = (sfi << 3) | 0x04;
        ApduCommand::new(0x00, 0xB2, record_number, p2).le(0x00)
    }

    /// INTERNAL AUTHENTICATE command (for DDA)
    pub fn internal_authenticate(data: Vec<u8>) -> ApduCommand {
        ApduCommand::new(0x00, 0x88, 0x00, 0x00).data(data).le(0x00)
    }

    /// GET DATA command - request specific data object from card
    pub fn get_data(tag: &[u8]) -> ApduCommand {
        if tag.len() == 1 {
            ApduCommand::new(0x80, 0xCA, 0x00, tag[0]).le(0x00)
        } else if tag.len() == 2 {
            ApduCommand::new(0x80, 0xCA, tag[0], tag[1]).le(0x00)
        } else {
            // For longer tags, use data field
            ApduCommand::new(0x80, 0xCA, 0x9F, 0x36)
                .data(tag.to_vec())
                .le(0x00)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apdu_response_is_success() {
        let success = ApduResponse {
            data: vec![],
            sw1: 0x90,
            sw2: 0x00,
        };
        assert!(success.is_success());

        let failure = ApduResponse {
            data: vec![],
            sw1: 0x6A,
            sw2: 0x82,
        };
        assert!(!failure.is_success());
    }

    #[test]
    fn test_apdu_response_status_word() {
        let response = ApduResponse {
            data: vec![],
            sw1: 0x90,
            sw2: 0x00,
        };
        assert_eq!(response.status_word(), 0x9000);

        let error = ApduResponse {
            data: vec![],
            sw1: 0x6A,
            sw2: 0x82,
        };
        assert_eq!(error.status_word(), 0x6A82);
    }

    #[test]
    fn test_apdu_response_status_string() {
        let response = ApduResponse {
            data: vec![0x01, 0x02],
            sw1: 0x90,
            sw2: 0x00,
        };
        assert_eq!(response.status_string(), "9000");

        let error = ApduResponse {
            data: vec![],
            sw1: 0x6A,
            sw2: 0x82,
        };
        assert_eq!(error.status_string(), "6A82");
    }

    #[test]
    fn test_apdu_response_clone() {
        let response = ApduResponse {
            data: vec![0x01, 0x02, 0x03],
            sw1: 0x90,
            sw2: 0x00,
        };

        let cloned = response.clone();
        assert_eq!(response.data, cloned.data);
        assert_eq!(response.sw1, cloned.sw1);
        assert_eq!(response.sw2, cloned.sw2);
    }

    #[test]
    fn test_apdu_command_new() {
        let cmd = ApduCommand::new(0x00, 0xA4, 0x04, 0x00);
        let bytes = cmd.build();

        assert_eq!(bytes, vec![0x00, 0xA4, 0x04, 0x00]);
    }

    #[test]
    fn test_apdu_command_with_data() {
        let cmd = ApduCommand::new(0x00, 0xA4, 0x04, 0x00).data(vec![0xA0, 0x00, 0x00, 0x00, 0x04]);

        let bytes = cmd.build();

        assert_eq!(
            bytes,
            vec![
                0x00, 0xA4, 0x04, 0x00, // Header
                0x05, // Lc = 5 bytes
                0xA0, 0x00, 0x00, 0x00, 0x04, // Data
            ]
        );
    }

    #[test]
    fn test_apdu_command_with_le() {
        let cmd = ApduCommand::new(0x00, 0xA4, 0x04, 0x00).le(0x00);

        let bytes = cmd.build();

        assert_eq!(
            bytes,
            vec![
                0x00, 0xA4, 0x04, 0x00, // Header
                0x00, // Le
            ]
        );
    }

    #[test]
    fn test_apdu_command_with_data_and_le() {
        let cmd = ApduCommand::new(0x00, 0xA4, 0x04, 0x00)
            .data(vec![0xA0, 0x00, 0x00, 0x00, 0x04])
            .le(0x00);

        let bytes = cmd.build();

        assert_eq!(
            bytes,
            vec![
                0x00, 0xA4, 0x04, 0x00, // Header
                0x05, // Lc = 5 bytes
                0xA0, 0x00, 0x00, 0x00, 0x04, // Data
                0x00, // Le
            ]
        );
    }

    #[test]
    fn test_commands_select() {
        let aid = vec![0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10];
        let cmd = commands::select(&aid);
        let bytes = cmd.build();

        assert_eq!(
            bytes,
            vec![
                0x00, 0xA4, 0x04, 0x00, // SELECT command
                0x07, // Lc = 7 bytes
                0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10, // AID
                0x00, // Le
            ]
        );
    }

    #[test]
    fn test_commands_get_processing_options() {
        let pdol_data = vec![0x83, 0x00];
        let cmd = commands::get_processing_options(pdol_data);
        let bytes = cmd.build();

        assert_eq!(
            bytes,
            vec![
                0x80, 0xA8, 0x00, 0x00, // GPO command
                0x02, // Lc = 2 bytes
                0x83, 0x00, // PDOL data
                0x00, // Le
            ]
        );
    }

    #[test]
    fn test_commands_read_record() {
        // Read record 1 from SFI 2
        let cmd = commands::read_record(1, 2);
        let bytes = cmd.build();

        // P2 = (SFI << 3) | 0x04 = (2 << 3) | 0x04 = 0x14
        assert_eq!(
            bytes,
            vec![
                0x00, 0xB2, 0x01, 0x14, // READ RECORD: record 1, SFI 2
                0x00, // Le
            ]
        );
    }

    #[test]
    fn test_commands_read_record_different_sfi() {
        // Read record 3 from SFI 5
        let cmd = commands::read_record(3, 5);
        let bytes = cmd.build();

        // P2 = (5 << 3) | 0x04 = 0x2C
        assert_eq!(
            bytes,
            vec![
                0x00, 0xB2, 0x03, 0x2C, // READ RECORD: record 3, SFI 5
                0x00, // Le
            ]
        );
    }

    #[test]
    fn test_commands_internal_authenticate() {
        let challenge = vec![0x01, 0x02, 0x03, 0x04];
        let cmd = commands::internal_authenticate(challenge);
        let bytes = cmd.build();

        assert_eq!(
            bytes,
            vec![
                0x00, 0x88, 0x00, 0x00, // INTERNAL AUTHENTICATE
                0x04, // Lc = 4 bytes
                0x01, 0x02, 0x03, 0x04, // Challenge data
                0x00, // Le
            ]
        );
    }

    #[test]
    fn test_commands_get_data_single_byte_tag() {
        let cmd = commands::get_data(&[0x9F]);
        let bytes = cmd.build();

        assert_eq!(
            bytes,
            vec![
                0x80, 0xCA, 0x00, 0x9F, // GET DATA with single-byte tag
                0x00, // Le
            ]
        );
    }

    #[test]
    fn test_commands_get_data_two_byte_tag() {
        let cmd = commands::get_data(&[0x9F, 0x36]);
        let bytes = cmd.build();

        assert_eq!(
            bytes,
            vec![
                0x80, 0xCA, 0x9F, 0x36, // GET DATA with two-byte tag
                0x00, // Le
            ]
        );
    }

    #[test]
    fn test_commands_get_data_long_tag() {
        let tag = vec![0x9F, 0x36, 0x01];
        let cmd = commands::get_data(&tag);
        let bytes = cmd.build();

        assert_eq!(
            bytes,
            vec![
                0x80, 0xCA, 0x9F, 0x36, // GET DATA command
                0x03, // Lc = 3 bytes
                0x9F, 0x36, 0x01, // Tag in data field
                0x00, // Le
            ]
        );
    }
}
