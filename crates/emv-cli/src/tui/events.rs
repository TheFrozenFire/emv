use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use std::time::Duration;

/// Events that can occur in the TUI
#[derive(Debug)]
pub enum TuiEvent {
    /// User pressed a key
    Key(KeyEvent),
    /// Tick event for periodic updates
    Tick,
}

/// Event handler for the TUI
pub struct EventHandler {
    tick_rate: Duration,
}

impl EventHandler {
    /// Create a new event handler with the given tick rate
    pub fn new(tick_rate: Duration) -> Self {
        Self { tick_rate }
    }

    /// Wait for the next event
    pub fn next(&self) -> std::io::Result<TuiEvent> {
        if event::poll(self.tick_rate)? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    // Handle Ctrl-C specially
                    if key.code == KeyCode::Char('c')
                        && key.modifiers.contains(event::KeyModifiers::CONTROL)
                    {
                        // Exit immediately on Ctrl-C
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "Interrupted by user (Ctrl-C)",
                        ));
                    }
                    Ok(TuiEvent::Key(key))
                }
                _ => Ok(TuiEvent::Tick),
            }
        } else {
            Ok(TuiEvent::Tick)
        }
    }
}

/// Check if the user wants to quit (pressed 'q')
pub fn is_quit_key(key: &KeyEvent) -> bool {
    matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
}
