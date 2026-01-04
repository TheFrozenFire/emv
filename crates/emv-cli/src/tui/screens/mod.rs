mod authenticate;
mod info;

pub use authenticate::AuthenticateScreen;
pub use info::InfoScreen;

use crossterm::event::KeyEvent;
use ratatui::{layout::Rect, Frame};

/// Trait for all TUI screens
pub trait Screen {
    /// Handle a key event
    fn handle_key(&mut self, key: KeyEvent);

    /// Update the screen (called on each tick)
    fn update(&mut self);

    /// Render the screen
    fn render(&self, frame: &mut Frame, area: Rect);

    /// Get the screen title
    fn title(&self) -> &str;
}
