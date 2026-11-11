use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::error::{VaultError, VaultResult};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

const DEFAULT_STEP_SECS: u64 = 30;
const MIN_STEP_SECS: u64 = 5;
const MAX_STEP_SECS: u64 = 300;
const DEFAULT_DIGITS: u32 = 6;
const MIN_DIGITS: u32 = 6;
const MAX_DIGITS: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug)]
struct ParsedTotpSpec {
    secret: Zeroizing<Vec<u8>>,
    algorithm: TotpAlgorithm,
    digits: u32,
    period: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TotpCodeDto {
    pub code: String,
    pub remaining_secs: u64,
    pub digits: u32,
    pub period: u64,
}

/// Valida completamente una semilla Base32 o URI `otpauth://totp/...` (incluyendo percent-encoding,
/// `algorithm`, `digits` y `period`) antes de persistir un ítem.
pub fn validate_totp_input(input: &str) -> VaultResult<()> {
    let _ = parse_totp_spec(input.trim())?;
    Ok(())
}

pub fn generate_current_totp(input: &str, unix_secs: u64) -> VaultResult<TotpCodeDto> {
    let spec = parse_totp_spec(input.trim())?;

    let counter = unix_secs / spec.period;
    let remaining_secs = spec.period - (unix_secs % spec.period);
    let msg = counter.to_be_bytes();

    let digest: Zeroizing<Vec<u8>> = match spec.algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac = HmacSha1::new_from_slice(&spec.secret)
                .map_err(|_| VaultError::validation("Secreto TOTP inválido para HMAC-SHA1."))?;
            mac.update(&msg);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }
        TotpAlgorithm::Sha256 => {
            let mut mac = HmacSha256::new_from_slice(&spec.secret)
                .map_err(|_| VaultError::validation("Secreto TOTP inválido para HMAC-SHA256."))?;
            mac.update(&msg);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }
        TotpAlgorithm::Sha512 => {
            let mut mac = HmacSha512::new_from_slice(&spec.secret)
                .map_err(|_| VaultError::validation("Secreto TOTP inválido para HMAC-SHA512."))?;
            mac.update(&msg);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }
    };

    // RFC 6238 / RFC 4226 §5.4: el offset se toma del último byte del resumen HMAC
    let last_idx = digest.len() - 1;
    let offset = (digest[last_idx] & 0x0f) as usize;
    let binary = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);

    let modulus = 10u64.pow(spec.digits);
    let otp = u64::from(binary) % modulus;

    Ok(TotpCodeDto {
        code: format!("{:0width$}", otp, width = spec.digits as usize),
        remaining_secs,
        digits: spec.digits,
        period: spec.period,
    })
}

fn parse_totp_spec(input: &str) -> VaultResult<ParsedTotpSpec> {
    if input.is_empty() {
        return Err(VaultError::validation("Semilla TOTP vacía."));
    }

    if input.len() >= 10 && input[..10].eq_ignore_ascii_case("otpauth://") {
        let rest = &input[10..];
        let (authority_and_path, query) = rest
            .split_once('?')
            .ok_or_else(|| VaultError::validation("URI otpauth:// no contiene parámetros."))?;

        let otp_type = authority_and_path
            .split('/')
            .next()
            .unwrap_or("");
        if !otp_type.eq_ignore_ascii_case("totp") {
            return Err(VaultError::validation(format!(
                "Tipo otpauth no soportado ('{otp_type}'). Solo se admite otpauth://totp/."
            )));
        }

        let mut raw_secret: Option<Zeroizing<String>> = None;
        let mut algorithm = TotpAlgorithm::Sha1;
        let mut digits = DEFAULT_DIGITS;
        let mut period = DEFAULT_STEP_SECS;

        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (raw_k, raw_v) = pair
                .split_once('=')
                .ok_or_else(|| VaultError::validation("Parámetro malformado en URI otpauth://."))?;
            let key = percent_decode(raw_k)?;
            let val = percent_decode(raw_v)?;

            if key.eq_ignore_ascii_case("secret") {
                if !val.trim().is_empty() {
                    raw_secret = Some(val);
                }
            } else if key.eq_ignore_ascii_case("algorithm") {
                algorithm = match val.trim().to_ascii_uppercase().as_str() {
                    "SHA1" | "HMAC-SHA1" => TotpAlgorithm::Sha1,
                    "SHA256" | "HMAC-SHA256" => TotpAlgorithm::Sha256,
                    "SHA512" | "HMAC-SHA512" => TotpAlgorithm::Sha512,
                    other => {
                        return Err(VaultError::validation(format!(
                            "Algoritmo TOTP no soportado: '{other}' (usa SHA1, SHA256 o SHA512)."
                        )))
                    }
                };
            } else if key.eq_ignore_ascii_case("digits") {
                let parsed: u32 = val.trim().parse().map_err(|_| {
                    VaultError::validation("El parámetro digits de TOTP debe ser numérico.")
                })?;
                if !(MIN_DIGITS..=MAX_DIGITS).contains(&parsed) {
                    return Err(VaultError::validation(format!(
                        "El parámetro digits de TOTP debe estar entre {MIN_DIGITS} y {MAX_DIGITS}."
                    )));
                }
                digits = parsed;
            } else if key.eq_ignore_ascii_case("period") {
                let parsed: u64 = val.trim().parse().map_err(|_| {
                    VaultError::validation("El parámetro period de TOTP debe ser numérico.")
                })?;
                if !(MIN_STEP_SECS..=MAX_STEP_SECS).contains(&parsed) {
                    return Err(VaultError::validation(format!(
                        "El parámetro period de TOTP debe estar entre {MIN_STEP_SECS} y {MAX_STEP_SECS} segundos."
                    )));
                }
                period = parsed;
            }
        }

        let secret_str = raw_secret.ok_or_else(|| {
            VaultError::validation("URI otpauth:// no contiene un parámetro secret válido.")
        })?;
        let secret = decode_base32_rfc4648(&secret_str)?;

        Ok(ParsedTotpSpec {
            secret,
            algorithm,
            digits,
            period,
        })
    } else {
        let decoded_input = percent_decode(input)?;
        let secret = decode_base32_rfc4648(&decoded_input)?;
        Ok(ParsedTotpSpec {
            secret,
            algorithm: TotpAlgorithm::Sha1,
            digits: DEFAULT_DIGITS,
            period: DEFAULT_STEP_SECS,
        })
    }
}

fn percent_decode(raw: &str) -> VaultResult<Zeroizing<String>> {
    let bytes = raw.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(VaultError::validation(
                    "Codificación porcentual (%) incompleta en URI TOTP.",
                ));
            }
            let hi = hex_nibble(bytes[i + 1]).ok_or_else(|| {
                VaultError::validation("Carácter hexadecimal inválido en escape % de URI TOTP.")
            })?;
            let lo = hex_nibble(bytes[i + 2]).ok_or_else(|| {
                VaultError::validation("Carácter hexadecimal inválido en escape % de URI TOTP.")
            })?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }

    let s = std::str::from_utf8(&out)
        .map_err(|_| VaultError::validation("UTF-8 inválido tras decodificar URI TOTP."))?
        .to_string();
    Ok(Zeroizing::new(s))
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
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
