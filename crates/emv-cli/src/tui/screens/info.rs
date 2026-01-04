use super::Screen;
use crossterm::event::{KeyCode, KeyEvent};
use emv_card::crypto::CertificateVerificationResult;
use emv_card::CardData;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

/// State of the info screen
#[derive(Debug, Clone, PartialEq)]
enum InfoState {
    Waiting,
    Loading,
    Loaded,
    Error(String),
}

/// Info screen showing card data and certificate verification
pub struct InfoScreen {
    card_data: Option<CardData>,
    verification: Option<CertificateVerificationResult>,
    state: InfoState,
    scroll_offset: u16,
}

impl InfoScreen {
    pub fn new() -> Self {
        Self {
            card_data: None,
            verification: None,
            state: InfoState::Waiting,
            scroll_offset: 0,
        }
    }

    /// Set the screen to loading state
    pub fn set_loading(&mut self) {
        self.state = InfoState::Loading;
    }

    /// Set card data (from background thread)
    pub fn set_data(&mut self, card_data: CardData, verification: CertificateVerificationResult) {
        self.card_data = Some(card_data);
        self.verification = Some(verification);
        self.state = InfoState::Loaded;
    }

    /// Set error state
    pub fn set_error(&mut self, error: String) {
        self.state = InfoState::Error(error);
        self.card_data = None;
        self.verification = None;
    }

    /// Clear card data
    pub fn clear(&mut self) {
        self.card_data = None;
        self.verification = None;
        self.state = InfoState::Waiting;
        self.scroll_offset = 0;
    }
}

impl Screen for InfoScreen {
    fn handle_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.scroll_offset = self.scroll_offset.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.scroll_offset = self.scroll_offset.saturating_add(1);
            }
            KeyCode::PageUp => {
                self.scroll_offset = self.scroll_offset.saturating_sub(10);
            }
            KeyCode::PageDown => {
                self.scroll_offset = self.scroll_offset.saturating_add(10);
            }
            KeyCode::Home => {
                self.scroll_offset = 0;
            }
            _ => {}
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
        let help = Paragraph::new("↑/↓ or j/k: Scroll | PgUp/PgDn: Fast scroll | Home: Top | Tab: Switch screen | q: Quit")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::ALL).title("Controls"));
        frame.render_widget(help, chunks[0]);

        // Content area - check state instead of data
        match &self.state {
            InfoState::Waiting => {
                let waiting = Paragraph::new("Waiting for card...")
                    .style(Style::default().fg(Color::Yellow))
                    .block(Block::default().borders(Borders::ALL).title("Status"));
                frame.render_widget(waiting, chunks[1]);
                return;
            }
            InfoState::Loading => {
                let loading = Paragraph::new("Reading card data...")
                    .style(Style::default().fg(Color::Cyan))
                    .block(Block::default().borders(Borders::ALL).title("Status"));
                frame.render_widget(loading, chunks[1]);
                return;
            }
            InfoState::Error(error) => {
                let error_widget = Paragraph::new(error.as_str())
                    .style(Style::default().fg(Color::Red))
                    .block(Block::default().borders(Borders::ALL).title("Error"));
                frame.render_widget(error_widget, chunks[1]);
                return;
            }
            InfoState::Loaded => {
                // Continue to render certificate data below
            }
        }

        // Display card data and verification results
        let mut items = Vec::new();

        if let Some(ref verification) = self.verification {
            items.push(ListItem::new(Line::from(vec![
                Span::styled(
                    "Authentication Method: ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("{:?}", verification.auth_method)),
            ])));
            items.push(ListItem::new(""));

            let check = |valid: bool| if valid { "✓" } else { "✗" };
            let color = |valid: bool| if valid { Color::Green } else { Color::Red };

            items.push(ListItem::new(Line::from(vec![
                Span::styled("CA Key Found:          ", Style::default()),
                Span::styled(
                    check(verification.ca_key_found),
                    Style::default().fg(color(verification.ca_key_found)),
                ),
            ])));

            items.push(ListItem::new(Line::from(vec![
                Span::styled("Issuer Certificate:    ", Style::default()),
                Span::styled(
                    check(verification.issuer_cert_valid),
                    Style::default().fg(color(verification.issuer_cert_valid)),
                ),
            ])));

            items.push(ListItem::new(Line::from(vec![
                Span::styled("ICC Certificate:       ", Style::default()),
                Span::styled(
                    check(verification.icc_cert_valid),
                    Style::default().fg(color(verification.icc_cert_valid)),
                ),
            ])));

            items.push(ListItem::new(Line::from(vec![
                Span::styled(
                    "Chain Valid:           ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    check(verification.chain_valid),
                    Style::default()
                        .fg(color(verification.chain_valid))
                        .add_modifier(Modifier::BOLD),
                ),
            ])));

            if !verification.errors.is_empty() {
                items.push(ListItem::new(""));
                items.push(ListItem::new(Span::styled(
                    "Errors:",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )));

                // Check if this is a two-level Issuer hierarchy
                let is_two_level_issuer = verification.errors.iter().any(|e| {
                    e.contains("Failed to build ICC Public Key")
                        && e.contains("Insufficient key data")
                });

                for error in &verification.errors {
                    items.push(ListItem::new(Span::styled(
                        format!("  • {}", error),
                        Style::default().fg(Color::Red),
                    )));
                }

                // Add helpful note for two-level Issuer hierarchy
                if is_two_level_issuer {
                    items.push(ListItem::new(""));
                    items.push(ListItem::new(Span::styled(
                        "Note:",
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    )));
                    items.push(ListItem::new(Span::styled(
                        "  This card uses a two-level Issuer hierarchy.",
                        Style::default().fg(Color::Yellow),
                    )));
                    items.push(ListItem::new(Span::styled(
                        "  DDA authentication is not supported.",
                        Style::default().fg(Color::Yellow),
                    )));
                }
            }
        }

        if let Some(ref card_data) = self.card_data {
            items.push(ListItem::new(""));
            items.push(ListItem::new(Span::styled(
                format!("Records: {}", card_data.records.len()),
                Style::default().add_modifier(Modifier::BOLD),
            )));
        }

        let list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Certificate Verification"),
        );

        frame.render_widget(list, chunks[1]);
    }

    fn title(&self) -> &str {
        "Card Info"
    }
}
