use super::Screen;
use crossterm::event::{KeyCode, KeyEvent};
use emv_card::{crypto::CertificateVerifier, EmvCard};
use pcsc::Card;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};
use rsa::traits::PublicKeyParts;

/// State of the authentication process
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
enum AuthState {
    Idle,
    Running,
    Success { response_bytes: usize },
    Failed { error: String },
}

/// Authenticate screen for Dynamic Data Authentication
pub struct AuthenticateScreen {
    state: AuthState,
    challenge: Vec<u8>,
    icc_key_bits: Option<usize>,
}

impl AuthenticateScreen {
    pub fn new() -> Self {
        Self {
            state: AuthState::Idle,
            challenge: Self::generate_challenge(),
            icc_key_bits: None,
        }
    }

    fn generate_challenge() -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..4).map(|_| rng.gen()).collect()
    }

    /// Perform authentication with the card
    #[allow(dead_code)]
    pub fn authenticate(&mut self, card: &Card) {
        self.state = AuthState::Running;

        let mut emv_card = EmvCard::new(card);

        // Read card data
        let card_data = match emv_card.read_card_data() {
            Ok(data) => data,
            Err(e) => {
                self.state = AuthState::Failed {
                    error: format!("Failed to read card: {}", e),
                };
                return;
            }
        };

        // Verify certificates to get ICC public key
        let verification = emv_card.verify_certificates(&card_data);

        let icc_key = match verification.icc_public_key {
            Some(key) => {
                self.icc_key_bits = Some(key.n().bits());
                key
            }
            None => {
                self.state = AuthState::Failed {
                    error: "No ICC Public Key available for DDA".to_string(),
                };
                return;
            }
        };

        // Send INTERNAL AUTHENTICATE
        let response = match emv_card.internal_authenticate(&self.challenge) {
            Ok(r) => r,
            Err(e) => {
                self.state = AuthState::Failed {
                    error: format!("INTERNAL AUTHENTICATE error: {}", e),
                };
                return;
            }
        };

        if !response.is_success() {
            self.state = AuthState::Failed {
                error: format!(
                    "INTERNAL AUTHENTICATE failed: SW1={:02X} SW2={:02X}",
                    response.sw1, response.sw2
                ),
            };
            return;
        }

        // Verify the signature
        let verifier = CertificateVerifier::new();
        match verifier.verify_dda_signature(&response.data, &icc_key, &self.challenge) {
            Ok(()) => {
                self.state = AuthState::Success {
                    response_bytes: response.data.len(),
                };
            }
            Err(e) => {
                self.state = AuthState::Failed {
                    error: format!("Signature verification failed: {}", e),
                };
            }
        }
    }

    /// Clear the authentication state
    pub fn clear(&mut self) {
        self.state = AuthState::Idle;
        self.challenge = Self::generate_challenge();
        self.icc_key_bits = None;
    }
}

impl Screen for AuthenticateScreen {
    fn handle_key(&mut self, key: KeyEvent) {
        if let KeyCode::Char('r') = key.code {
            // Regenerate challenge
            self.challenge = Self::generate_challenge();
            self.state = AuthState::Idle;
        }
    }

    fn update(&mut self) {
        // Periodic updates can be handled here if needed
    }

    fn render(&self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0)])
            .split(area);

        // Help text
        let help = Paragraph::new("r: Regenerate challenge | Tab: Switch screen | q: Quit")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::ALL).title("Controls"));
        frame.render_widget(help, chunks[0]);

        // Content area
        let mut items = Vec::new();

        items.push(ListItem::new(Line::from(vec![
            Span::styled("Challenge: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(hex::encode_upper(&self.challenge)),
        ])));

        if let Some(bits) = self.icc_key_bits {
            items.push(ListItem::new(Line::from(vec![
                Span::styled("ICC Key:   ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format!("{} bits", bits)),
            ])));
        }

        items.push(ListItem::new(""));

        match &self.state {
            AuthState::Idle => {
                items.push(ListItem::new(Span::styled(
                    "Status: Waiting for card...",
                    Style::default().fg(Color::Yellow),
                )));
            }
            AuthState::Running => {
                items.push(ListItem::new(Span::styled(
                    "Status: Authenticating...",
                    Style::default().fg(Color::Cyan),
                )));
            }
            AuthState::Success { response_bytes } => {
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("Status: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(
                        "✓ Authentication Successful",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                ])));
                items.push(ListItem::new(""));
                items.push(ListItem::new(Span::styled(
                    "Card successfully proved possession of ICC private key!",
                    Style::default().fg(Color::Green),
                )));
                items.push(ListItem::new(Span::styled(
                    "This card cannot be cloned without the private key.",
                    Style::default().fg(Color::Green),
                )));
                items.push(ListItem::new(""));
                items.push(ListItem::new(format!("Response: {} bytes", response_bytes)));
            }
            AuthState::Failed { error } => {
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("Status: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(
                        "✗ Authentication Failed",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                ])));
                items.push(ListItem::new(""));
                items.push(ListItem::new(Span::styled(
                    error,
                    Style::default().fg(Color::Red),
                )));
            }
        }

        let list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Dynamic Data Authentication (DDA)"),
        );

        frame.render_widget(list, chunks[1]);
    }

    fn title(&self) -> &str {
        "Authenticate"
    }
}
