use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod commands;
mod formatters;
mod tui;

use commands::{
    authenticate::cmd_authenticate, dump::cmd_dump, generate_ac::cmd_generate_ac,
    get_challenge::cmd_get_challenge, info::cmd_info,
};
use formatters::FormatMode;

#[derive(Parser)]
#[command(name = "emv-signer")]
#[command(about = "EMV Certificate Reader - Read and authenticate EMV cards")]
#[command(version)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Read card information and verify certificate chain
    Info {
        /// Output format mode
        #[arg(short, long, value_enum, default_value_t = FormatMode::Raw)]
        format: FormatMode,
    },
    /// Perform INTERNAL AUTHENTICATE for Dynamic Data Authentication
    Authenticate {
        /// Challenge data as hex string (default: random 4 bytes)
        #[arg(short, long)]
        challenge: Option<String>,
    },
    /// Generate Application Cryptogram (increments ATC)
    GenerateAc,
    /// Request random bytes from card (for secure messaging)
    GetChallenge,
    /// Dump all TLV tags from card (including unknown tags)
    Dump,
    /// Run interactive TUI with live card detection
    Tui,
}

fn main() {
    let args = Args::parse();

    // Initialize tracing based on command
    match &args.command {
        Commands::Tui => {
            // For TUI, write logs to stderr to avoid interfering with the terminal UI
            tracing_subscriber::fmt()
                .with_env_filter(
                    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
                )
                .with_target(false)
                .with_writer(std::io::stderr)
                .init();
        }
        _ => {
            // For CLI commands, use standard output logging
            tracing_subscriber::fmt()
                .with_env_filter(
                    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
                )
                .with_target(false)
                .init();
        }
    }

    match args.command {
        Commands::Info { format } => cmd_info(format),
        Commands::Authenticate { challenge } => cmd_authenticate(challenge),
        Commands::GenerateAc => cmd_generate_ac(),
        Commands::GetChallenge => cmd_get_challenge(),
        Commands::Dump => cmd_dump(),
        Commands::Tui => {
            if let Err(e) = tui::run_tui() {
                eprintln!("TUI error: {}", e);
                std::process::exit(1);
            }
        }
    }
}
