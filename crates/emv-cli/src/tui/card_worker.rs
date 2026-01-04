use emv_card::{CardData, CardReader, EmvCard};
use emv_card::crypto::CertificateVerificationResult;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Messages sent from the card worker to the UI
#[derive(Debug, Clone)]
pub enum CardEvent {
    /// Card was detected
    CardDetected { reader_name: String },
    /// Card was removed
    CardRemoved,
    /// Card data reading started
    ReadingStarted,
    /// Card data was successfully read
    DataReady {
        card_data: CardData,
        verification: CertificateVerificationResult,
    },
    /// Error occurred
    Error { message: String },
    /// Reader is unavailable
    ReaderUnavailable { error: String },
    /// Reader became available
    ReaderAvailable,
}

/// Commands sent from the UI to the card worker
#[derive(Debug)]
pub enum CardCommand {
    /// Stop the worker thread
    Stop,
}

/// Background worker for card operations
pub struct CardWorker {
    event_tx: Sender<CardEvent>,
    command_rx: Receiver<CardCommand>,
}

impl CardWorker {
    /// Spawn a new card worker thread
    pub fn spawn() -> (Receiver<CardEvent>, Sender<CardCommand>) {
        let (event_tx, event_rx) = mpsc::channel();
        let (command_tx, command_rx) = mpsc::channel();

        thread::spawn(move || {
            let worker = CardWorker {
                event_tx,
                command_rx,
            };
            worker.run();
        });

        (event_rx, command_tx)
    }

    fn run(self) {
        info!("Card worker thread started");

        let mut reader: Option<CardReader> = None;
        let mut card_present = false;
        let mut last_reader_check = std::time::Instant::now();

        loop {
            // Check for stop command (non-blocking)
            if let Ok(CardCommand::Stop) = self.command_rx.try_recv() {
                info!("Card worker stopping");
                break;
            }

            // Try to get reader if we don't have one (check every 2 seconds)
            if reader.is_none() && last_reader_check.elapsed() > Duration::from_secs(2) {
                match CardReader::new() {
                    Ok(r) => {
                        info!("Card reader initialized");
                        reader = Some(r);
                        let _ = self.event_tx.send(CardEvent::ReaderAvailable);
                    }
                    Err(e) => {
                        debug!("Card reader unavailable: {}", e);
                        let _ = self.event_tx.send(CardEvent::ReaderUnavailable {
                            error: format!("{}", e),
                        });
                    }
                }
                last_reader_check = std::time::Instant::now();
            }

            // Check for card if we have a reader
            if let Some(ref r) = reader {
                match r.connect_first() {
                    Ok((card, reader_name)) => {
                        if !card_present {
                            info!(reader = %reader_name, "Card detected");
                            card_present = true;
                            let _ = self.event_tx.send(CardEvent::CardDetected {
                                reader_name: reader_name.clone(),
                            });

                            // Read card data in background
                            let _ = self.event_tx.send(CardEvent::ReadingStarted);

                            let mut emv_card = EmvCard::new(&card);
                            match emv_card.read_card_data() {
                                Ok(card_data) => {
                                    let verification = emv_card.verify_certificates(&card_data);
                                    let _ = self.event_tx.send(CardEvent::DataReady {
                                        card_data,
                                        verification,
                                    });
                                }
                                Err(e) => {
                                    warn!(error = %e, "Failed to read card data");
                                    let _ = self.event_tx.send(CardEvent::Error {
                                        message: format!("Failed to read card: {}", e),
                                    });
                                }
                            }
                        }
                        // Keep card connection alive but don't re-read
                        drop(card);
                    }
                    Err(_) => {
                        if card_present {
                            info!("Card removed");
                            card_present = false;
                            let _ = self.event_tx.send(CardEvent::CardRemoved);
                        }
                    }
                }
            }

            // Sleep briefly to avoid busy loop
            thread::sleep(Duration::from_millis(250));
        }

        info!("Card worker thread stopped");
    }
}
