use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Tabs},
    Frame,
};

use super::screens::Screen;

/// Render the main UI with tabs and current screen
pub fn render(
    frame: &mut Frame,
    screens: &[&dyn Screen],
    selected_screen: usize,
    card_present: bool,
    reader_error: Option<&str>,
) {
    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header with card status
            Constraint::Length(3), // Tabs
            Constraint::Min(0),    // Screen content
        ])
        .split(frame.area());

    render_header(frame, chunks[0], card_present, reader_error);
    render_tabs(frame, chunks[1], screens, selected_screen);

    if let Some(screen) = screens.get(selected_screen) {
        screen.render(frame, chunks[2]);
    }
}

fn render_header(frame: &mut Frame, area: Rect, card_present: bool, reader_error: Option<&str>) {
    let (status_text, status_color) = if let Some(error) = reader_error {
        // Truncate long error messages
        let error_msg = if error.len() > 50 {
            format!("{}...", &error[..47])
        } else {
            error.to_string()
        };
        (format!("⚠ {}", error_msg), Color::Red)
    } else if card_present {
        ("● Card Present".to_string(), Color::Green)
    } else {
        ("○ No Card".to_string(), Color::Red)
    };

    // Calculate available width for title (accounting for borders and padding)
    let max_title_width = area.width.saturating_sub(4) as usize;
    let title_base = "EMV Signer - ";
    let available_for_status = max_title_width.saturating_sub(title_base.len());

    let truncated_status = if status_text.len() > available_for_status {
        format!(
            "{}...",
            &status_text[..available_for_status.saturating_sub(3)]
        )
    } else {
        status_text
    };

    let title = format!("{}{}", title_base, truncated_status);
    let block = Block::default().borders(Borders::ALL).title(Span::styled(
        title,
        Style::default()
            .fg(status_color)
            .add_modifier(Modifier::BOLD),
    ));

    frame.render_widget(block, area);
}

fn render_tabs(frame: &mut Frame, area: Rect, screens: &[&dyn Screen], selected: usize) {
    let titles: Vec<_> = screens.iter().map(|s| s.title()).collect();

    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title("Screens"))
        .select(selected)
        .style(Style::default())
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_widget(tabs, area);
}
