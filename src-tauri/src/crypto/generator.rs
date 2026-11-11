use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{VaultError, VaultResult};

const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?";
const AMBIGUOUS: &[u8] = b"0O1lI|";

#[derive(Debug, Clone, Deserialize)]
pub struct PasswordGenOptions {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

#[derive(Debug, Serialize)]
pub struct GeneratedPasswordDto {
    pub value: String,
    pub entropy_bits: f64,
}

/// Muestreo uniforme sin sesgo de módulo (rejection sampling) usando OsRng.
fn uniform_index(upper_bound: usize) -> usize {
    assert!(upper_bound > 0 && upper_bound <= u32::MAX as usize);
    let bound = upper_bound as u32;
    let zone = u32::MAX - (u32::MAX % bound);
    loop {
        let v = OsRng.next_u32();
        if v < zone {
            return (v % bound) as usize;
        }
    }
}

fn filter_charset(chars: &[u8], exclude_ambiguous: bool) -> Vec<u8> {
    chars
        .iter()
        .copied()
        .filter(|c| !exclude_ambiguous || !AMBIGUOUS.contains(c))
        .collect()
}

pub fn generate_password(opts: &PasswordGenOptions) -> VaultResult<GeneratedPasswordDto> {
    if !(8..=128).contains(&opts.length) {
        return Err(VaultError::validation(
            "La longitud debe estar entre 8 y 128 caracteres.",
        ));
    }

    let mut active_sets: Vec<Vec<u8>> = Vec::with_capacity(4);
    if opts.uppercase {
        active_sets.push(filter_charset(UPPER, opts.exclude_ambiguous));
    }
    if opts.lowercase {
        active_sets.push(filter_charset(LOWER, opts.exclude_ambiguous));
    }
    if opts.digits {
        active_sets.push(filter_charset(DIGITS, opts.exclude_ambiguous));
    }
    if opts.symbols {
        active_sets.push(filter_charset(SYMBOLS, opts.exclude_ambiguous));
    }

    active_sets.retain(|s| !s.is_empty());
    if active_sets.is_empty() {
        return Err(VaultError::validation(
            "Debes habilitar al menos un conjunto de caracteres.",
        ));
    }
    if opts.length < active_sets.len() {
        return Err(VaultError::validation(
            "La longitud es menor que la cantidad de conjuntos obligatorios.",
        ));
    }

    let mut pool = Vec::new();
    for set in &active_sets {
        pool.extend_from_slice(set);
    }

    let mut buf = Zeroizing::new(Vec::with_capacity(opts.length));

    // Garantiza al menos un carácter de cada conjunto habilitado
    for set in &active_sets {
        buf.push(set[uniform_index(set.len())]);
    }
    // Completa el resto desde el alfabeto combinado
    while buf.len() < opts.length {
        buf.push(pool[uniform_index(pool.len())]);
    }

    // Permutación criptográfica Fisher-Yates
    for i in (1..buf.len()).rev() {
        let j = uniform_index(i + 1);
        buf.swap(i, j);
    }

    let entropy_bits = (opts.length as f64) * (pool.len() as f64).log2();
    let value = String::from_utf8(buf.to_vec())
        .map_err(|_| VaultError::internal("Charset inválido en generador"))?;

    Ok(GeneratedPasswordDto {
        value,
        entropy_bits: (entropy_bits * 10.0).round() / 10.0,
    })
}
