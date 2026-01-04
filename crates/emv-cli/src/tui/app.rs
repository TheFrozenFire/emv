use std::io::{self, Stdout};
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

use crossterm::{
    event::KeyCode,
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use tracing::{debug, info, warn};

use super::{
    card_worker::{CardCommand, CardEvent, CardWorker},
    events::{is_quit_key, EventHandler, TuiEvent},
    screens::{AuthenticateScreen, InfoScreen, Screen},
    ui,
};

/// Main TUI application
pub struct App {
    /// Current screen index
    selected_screen: usize,
    /// Info screen
    info_screen: InfoScreen,
    /// Authenticate screen
    auth_screen: AuthenticateScreen,
    /// Whether a card is present
    card_present: bool,
    /// Error message if reader unavailable
    reader_error: Option<String>,
    /// Receiver for card events from background thread
    card_event_rx: Receiver<CardEvent>,
    /// Sender for commands to background thread
    card_command_tx: Sender<CardCommand>,
}

impl App {
    pub fn new() -> Self {
        // Spawn background worker for card operations
        let (card_event_rx, card_command_tx) = CardWorker::spawn();

        Self {
            selected_screen: 0,
            info_screen: InfoScreen::new(),
            auth_screen: AuthenticateScreen::new(),
            card_present: false,
            reader_error: None,
            card_event_rx,
            card_command_tx,
        }
    }

    /// Process card events from the background worker
    fn process_card_events(&mut self) {
        // Process all available events (non-blocking)
        while let Ok(event) = self.card_event_rx.try_recv() {
            debug!("Card event: {:?}", event);

            match event {
                CardEvent::CardDetected { reader_name } => {
                    info!(reader = %reader_name, "Card detected");
                    self.card_present = true;
                    self.reader_error = None;
                }
                CardEvent::CardRemoved => {
                    info!("Card removed");
                    self.card_present = false;
                    self.info_screen.clear();
                    self.auth_screen.clear();
                }
                CardEvent::ReadingStarted => {
                    debug!("Card reading started");
                    self.info_screen.set_loading();
                }
                CardEvent::DataReady {
                    card_data,
                    verification,
                } => {
                    debug!("Card data ready");
                    self.info_screen.set_data(card_data, verification);
                }
                CardEvent::Error { message } => {
                    warn!(error = %message, "Card error");
                    self.info_screen.set_error(message);
                }
                CardEvent::ReaderUnavailable { error } => {
                    warn!(error = %error, "Reader unavailable");
                    self.reader_error = Some(format!("Card reader unavailable: {}", error));
                }
                CardEvent::ReaderAvailable => {
                    info!("Reader available");
                    self.reader_error = None;
                }
            }
        }
    }

    /// Handle switching to the next screen
    fn next_screen(&mut self) {
        self.selected_screen = (self.selected_screen + 1) % 2;
    }

    /// Handle switching to the previous screen
    fn prev_screen(&mut self) {
        self.selected_screen = if self.selected_screen == 0 {
            1
        } else {
            self.selected_screen - 1
        };
    }

    /// Handle a key event
    fn handle_key(&mut self, key: crossterm::event::KeyEvent) {
        match key.code {
            KeyCode::Tab => self.next_screen(),
            KeyCode::BackTab => self.prev_screen(),
            KeyCode::Char('1') => self.selected_screen = 0,
            KeyCode::Char('2') => self.selected_screen = 1,
            _ => {
                // Pass key to current screen
                match self.selected_screen {
                    0 => self.info_screen.handle_key(key),
                    1 => self.auth_screen.handle_key(key),
                    _ => {}
                }
            }
        }
    }

    /// Update the application state
    fn update(&mut self) {
        // Process card events from background thread (non-blocking)
        self.process_card_events();

        // Update current screen
        match self.selected_screen {
            0 => self.info_screen.update(),
            1 => self.auth_screen.update(),
            _ => {}
        }
    }

    /// Render the application
    fn render(&self, terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> io::Result<()> {
        terminal.draw(|frame| {
            let screens: Vec<&dyn Screen> = vec![&self.info_screen, &self.auth_screen];
            ui::render(
                frame,
                &screens,
                self.selected_screen,
                self.card_present,
                self.reader_error.as_deref(),
            );
        })?;
        Ok(())
    }

    /// Run the main event loop
    pub fn run(&mut self, terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> io::Result<()> {
        let event_handler = EventHandler::new(Duration::from_millis(100));

        loop {
            // Check for events first, before potentially blocking operations
            match event_handler.next()? {
                TuiEvent::Key(key) => {
                    if is_quit_key(&key) {
                        info!("Quit requested");
                        // Stop the card worker thread
                        let _ = self.card_command_tx.send(CardCommand::Stop);
                        return Ok(());
                    }
                    self.handle_key(key);
                }
                TuiEvent::Tick => {
                    // Update on tick
                    self.update();
                }
            }

            // Always render after processing events
            self.render(terminal)?;
        }
    }
}

/// Initialize the terminal for TUI mode
fn init_terminal() -> io::Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
}

/// Restore the terminal to normal mode
fn restore_terminal(mut terminal: Terminal<CrosstermBackend<Stdout>>) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

/// Main entry point for the TUI
pub fn run_tui() -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting TUI");

    // Set up panic hook to restore terminal on panic
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // Attempt to restore terminal
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);

        // Call the original panic hook
        original_hook(panic_info);
    }));

    let mut terminal = init_terminal()?;
    let mut app = App::new();

    let result = app.run(&mut terminal);

    // Always restore terminal, even on error
    let restore_result = restore_terminal(terminal);

    // Restore original panic hook
    let _ = std::panic::take_hook();

    // Check results
    restore_result?;

    if let Err(e) = result {
        warn!(error = %e, "TUI error");
        return Err(Box::new(e));
    }

    info!("TUI stopped");
    Ok(())
}
