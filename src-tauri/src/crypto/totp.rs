use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::error::{VaultError, VaultResult};

type HmacSha1 = Hmac<Sha1>;
const DEFAULT_STEP_SECS: u64 = 30;
const DEFAULT_DIGITS: u32 = 6;

#[derive(Debug, Serialize)]
pub struct TotpCodeDto {
    pub code: String,
    pub remaining_secs: u64,
}

pub fn generate_current_totp(input: &str, unix_secs: u64) -> VaultResult<TotpCodeDto> {
    let raw_secret = extract_secret_param(input.trim())?;
    let secret_bytes = decode_base32_rfc4648(&raw_secret)?;

    let counter = unix_secs / DEFAULT_STEP_SECS;
    let remaining_secs = DEFAULT_STEP_SECS - (unix_secs % DEFAULT_STEP_SECS);

    let mut mac = HmacSha1::new_from_slice(&secret_bytes)
        .map_err(|_| VaultError::validation("Secreto TOTP inválido."))?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    let offset = (digest[19] & 0x0f) as usize;
    let binary = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);

    let otp = binary % 10u32.pow(DEFAULT_DIGITS);
    Ok(TotpCodeDto {
        code: format!("{:0width$}", otp, width = DEFAULT_DIGITS as usize),
        remaining_secs,
    })
}

fn extract_secret_param(input: &str) -> VaultResult<Zeroizing<String>> {
    if let Some(rest) = input.strip_prefix("otpauth://") {
        let query = rest
            .split_once('?')
            .map(|(_, q)| q)
            .ok_or_else(|| VaultError::validation("URI otpauth sin parámetros."))?;

        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k.eq_ignore_ascii_case("secret") && !v.is_empty() {
                    return Ok(Zeroizing::new(v.to_string()));
                }
            }
        }
        Err(VaultError::validation(
            "URI otpauth no contiene parámetro secret.",
        ))
    } else if !input.is_empty() {
        Ok(Zeroizing::new(input.to_string()))
    } else {
        Err(VaultError::validation("Semilla TOTP vacía."))
    }
}

fn decode_base32_rfc4648(encoded: &str) -> VaultResult<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(encoded.len() * 5 / 8 + 1));
    let mut buffer: u32 = 0;
    let mut bits_left: u8 = 0;

    for ch in encoded.chars() {
        if ch == '=' || ch == ' ' || ch == '-' {
            continue;
        }
        let val: u32 = match ch.to_ascii_uppercase() {
            'A'..='Z' => (ch.to_ascii_uppercase() as u32) - ('A' as u32),
            '2'..='7' => (ch as u32) - ('2' as u32) + 26,
            _ => {
                return Err(VaultError::validation(
                    "El secreto TOTP contiene caracteres fuera de Base32.",
                ))
            }
        };

        buffer = (buffer << 5) | val;
        bits_left += 5;
        if bits_left >= 8 {
            bits_left -= 8;
            out.push(((buffer >> bits_left) & 0xff) as u8);
        }
    }

    if out.is_empty() {
        return Err(VaultError::validation("Secreto TOTP vacío tras decodificar."));
    }
    Ok(out)
}
