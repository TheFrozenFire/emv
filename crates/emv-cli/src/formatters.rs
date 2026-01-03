//! Field formatters for human-readable output

use clap::ValueEnum;

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FormatMode {
    /// Raw hex output
    Raw,
    /// Human-readable formatted output
    Human,
}

impl FormatMode {
    pub fn description(&self) -> &'static str {
        match self {
            FormatMode::Raw => "Raw",
            FormatMode::Human => "Human-Readable",
        }
    }
}

/// Format a field value based on its tag type
pub fn format_value(tag: &[u8], value: &[u8], mode: &FormatMode) -> String {
    if *mode == FormatMode::Raw {
        return hex::encode_upper(value);
    }

    // Human-readable formatting
    match tag {
        // Application Label (ASCII text)
        [0x50] => String::from_utf8(value.to_vec())
            .unwrap_or_else(|_| hex::encode_upper(value)),

        // Cardholder Name (ASCII text)
        [0x5F, 0x20] => String::from_utf8(value.to_vec())
            .unwrap_or_else(|_| hex::encode_upper(value))
            .trim()
            .to_string(),

        // Application Expiration Date (YYMMDD)
        [0x5F, 0x24] => {
            if value.len() == 3 {
                format!("20{:02X}/{:02X} (Year/Month)", value[0], value[1])
            } else {
                hex::encode_upper(value)
            }
        }

        // Application Effective Date (YYMMDD)
        [0x5F, 0x25] => {
            if value.len() == 3 {
                format!(
                    "20{:02X}/{:02X}/{:02X} (YY/MM/DD)",
                    value[0], value[1], value[2]
                )
            } else {
                hex::encode_upper(value)
            }
        }

        // Issuer Country Code (ISO 3166-1 numeric)
        [0x5F, 0x28] => {
            if value.len() == 2 {
                let code = (value[0] as u16) << 8 | (value[1] as u16);
                if let Some(country) = get_country_name(code) {
                    format!("{} ({})", code, country)
                } else {
                    format!("{}", code)
                }
            } else {
                hex::encode_upper(value)
            }
        }

        // Currency Codes
        [0x5F, 0x2A] | [0x9F, 0x42] => {
            if value.len() == 2 {
                let code = (value[0] as u16) << 8 | (value[1] as u16);
                if let Some(currency) = get_currency_name(code) {
                    format!("{}", currency)
                } else {
                    format!("Currency Code {}", code)
                }
            } else {
                hex::encode_upper(value)
            }
        }

        // Application PAN Sequence Number
        [0x5F, 0x34] => {
            if value.len() == 1 {
                format!("{}", value[0])
            } else {
                hex::encode_upper(value)
            }
        }

        // CA Public Key Index
        [0x8F] => {
            if value.len() == 1 {
                format!("{:02X} (decimal: {})", value[0], value[0])
            } else {
                hex::encode_upper(value)
            }
        }

        // Exponents
        [0x9F, 0x32] | [0x9F, 0x47] => {
            if value.len() <= 3 {
                let mut exp = 0u32;
                for &byte in value {
                    exp = (exp << 8) | (byte as u32);
                }
                format!("{} (0x{})", exp, hex::encode_upper(value))
            } else {
                hex::encode_upper(value)
            }
        }

        // Large binary fields (certificates, etc.)
        [0x90] | [0x92] | [0x9F, 0x46] | [0x9F, 0x48] => {
            if value.len() > 32 {
                format!(
                    "{} ... ({} bytes total)",
                    hex::encode_upper(&value[..32]),
                    value.len()
                )
            } else {
                hex::encode_upper(value)
            }
        }

        // Track 2 Data
        [0x57] | [0x9F, 0x6B] => {
            let hex_str = hex::encode_upper(value);
            hex_str.replace("D", " | ")
        }

        // Default: hex for everything else
        _ => hex::encode_upper(value),
    }
}

/// ISO 3166-1 numeric country codes (subset)
fn get_country_name(code: u16) -> Option<&'static str> {
    match code {
        124 => Some("Canada"),
        840 => Some("United States"),
        826 => Some("United Kingdom"),
        276 => Some("Germany"),
        250 => Some("France"),
        380 => Some("Italy"),
        724 => Some("Spain"),
        528 => Some("Netherlands"),
        156 => Some("China"),
        392 => Some("Japan"),
        _ => None,
    }
}

/// ISO 4217 numeric currency codes (subset)
fn get_currency_name(code: u16) -> Option<&'static str> {
    match code {
        124 => Some("CAD (Canadian Dollar)"),
        840 => Some("USD (US Dollar)"),
        978 => Some("EUR (Euro)"),
        826 => Some("GBP (Pound Sterling)"),
        392 => Some("JPY (Japanese Yen)"),
        156 => Some("CNY (Chinese Yuan)"),
        _ => None,
    }
}
