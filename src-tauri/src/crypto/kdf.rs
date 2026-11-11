use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};
use zxcvbn::Score;

use crate::crypto::aad::hello_binding_aad;
use crate::crypto::memory::{ProtectedKey, KEY_LEN};
use crate::error::{ErrorCode, VaultError, VaultResult};

pub const DEFAULT_KDF_MEM_KIB: u32 = 65_536; // 64 MiB
pub const DEFAULT_KDF_ITERATIONS: u32 = 3;
pub const DEFAULT_KDF_PARALLELISM: u32 = 4;
pub const SALT_LEN: usize = 16;

pub const MIN_KDF_MEM_KIB: u32 = 8_192; // 8 MiB mínimo permitido
pub const MAX_KDF_MEM_KIB: u32 = 524_288; // 512 MiB tope defensivo anti-DoS
pub const MAX_KDF_ITERATIONS: u32 = 32;
pub const MAX_KDF_PARALLELISM: u32 = 16;

pub const MIN_PASSWORD_CHARS: usize = 12;
pub const MAX_PASSWORD_BYTES: usize = 1024;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    pub mem_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            mem_kib: DEFAULT_KDF_MEM_KIB,
            iterations: DEFAULT_KDF_ITERATIONS,
            parallelism: DEFAULT_KDF_PARALLELISM,
        }
    }
}

pub fn validate_kdf_params(params: KdfParams, error_code: ErrorCode) -> VaultResult<()> {
    if !(MIN_KDF_MEM_KIB..=MAX_KDF_MEM_KIB).contains(&params.mem_kib)
        || !(1..=MAX_KDF_ITERATIONS).contains(&params.iterations)
        || !(1..=MAX_KDF_PARALLELISM).contains(&params.parallelism)
    {
        return Err(VaultError::new(
            error_code,
            "Parámetros KDF Argon2id fuera de rango seguro permitido.",
        ));
    }
    Ok(())
}

/// Verifica longitud mínima (12 caracteres en NFC), tope defensivo anti-DoS
/// y entropía mínima offline (`zxcvbn` >= 3/4) para contraseñas maestras y de respaldo.
pub fn validate_password_strength(password: &str, label: &str) -> VaultResult<()> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(VaultError::validation(format!(
            "{label} excede el límite máximo de {MAX_PASSWORD_BYTES} bytes."
        )));
    }

    let normalized = Zeroizing::new(password.nfc().collect::<String>());
    if normalized.chars().count() < MIN_PASSWORD_CHARS {
        return Err(VaultError::validation(format!(
            "{label} debe tener al menos {MIN_PASSWORD_CHARS} caracteres."
        )));
    }

    let estimate = zxcvbn::zxcvbn(
        &normalized,
        &[
            "aegisvault",
            "aegis",
            "vault",
            "boveda",
            "contraseña",
            "contrasena",
            "master",
            "respaldo",
        ],
    );

    if estimate.score() < Score::Three {
        let score_num = u8::from(estimate.score());
        return Err(VaultError::validation(format!(
            "{label} tiene entropía insuficiente (nivel {score_num}/4; se requiere mínimo 3/4). Evita repeticiones, secuencias o palabras comunes."
        )));
    }

    Ok(())
}

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn generate_random_key() -> ProtectedKey {
    let mut raw = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut raw);
    ProtectedKey::from_mut_bytes(&mut raw)
}

/// Normaliza la contraseña maestra en Unicode NFC dentro de un buffer Zeroizing
/// y deriva 32 bytes mediante Argon2id tras validar cotas seguras de memoria/CPU.
pub fn derive_key_argon2id(
    password: &str,
    salt: &[u8],
    params: KdfParams,
) -> VaultResult<ProtectedKey> {
    if password.is_empty() {
        return Err(VaultError::validation(
            "La contraseña maestra no puede estar vacía.",
        ));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(VaultError::validation(
            "La contraseña excede la longitud máxima permitida.",
        ));
    }
    if salt.len() != SALT_LEN {
        return Err(VaultError::data_corrupted("Longitud de salt KDF inválida."));
    }
    validate_kdf_params(params, ErrorCode::DataCorrupted)?;

    let normalized = Zeroizing::new(password.nfc().collect::<String>());

    let argon_params = Params::new(
        params.mem_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| VaultError::internal(format!("Parámetros Argon2id inválidos: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = [0u8; KEY_LEN];
    argon2
        .hash_password_into(normalized.as_bytes(), salt, &mut out)
        .map_err(|e| {
            out.zeroize();
            VaultError::internal(format!("Fallo al ejecutar Argon2id: {e}"))
        })?;

    Ok(ProtectedKey::from_mut_bytes(&mut out))
}

pub struct DerivedVaultSubkeys {
    pub overview_key: ProtectedKey,
    pub secret_key: ProtectedKey,
    pub config_mac_key: ProtectedKey,
    pub keycheck_tag: [u8; KEY_LEN],
}

impl Drop for DerivedVaultSubkeys {
    fn drop(&mut self) {
        self.keycheck_tag.zeroize();
    }
}

/// Deriva subclaves separadas por propósito desde VaultKey mediante HKDF-SHA256.
pub fn expand_vault_subkeys(vault_key: &ProtectedKey) -> VaultResult<DerivedVaultSubkeys> {
    let hk = Hkdf::<Sha256>::new(None, vault_key.as_bytes());

    let mut overview_raw = [0u8; KEY_LEN];
    hk.expand(b"vault-v1-overview", &mut overview_raw)
        .map_err(|_| VaultError::internal("Fallo HKDF overview"))?;

    let mut secret_raw = [0u8; KEY_LEN];
    hk.expand(b"vault-v1-secret", &mut secret_raw)
        .map_err(|_| {
            overview_raw.zeroize();
            VaultError::internal("Fallo HKDF secret")
        })?;

    let mut mac_raw = [0u8; KEY_LEN];
    hk.expand(b"vault-v2-config-mac", &mut mac_raw)
        .map_err(|_| {
            overview_raw.zeroize();
            secret_raw.zeroize();
            VaultError::internal("Fallo HKDF config_mac")
        })?;

    let mut keycheck_tag = [0u8; KEY_LEN];
    hk.expand(b"vault-v1-keycheck", &mut keycheck_tag)
        .map_err(|_| {
            overview_raw.zeroize();
            secret_raw.zeroize();
            mac_raw.zeroize();
            VaultError::internal("Fallo HKDF keycheck")
        })?;

    Ok(DerivedVaultSubkeys {
        overview_key: ProtectedKey::from_mut_bytes(&mut overview_raw),
        secret_key: ProtectedKey::from_mut_bytes(&mut secret_raw),
        config_mac_key: ProtectedKey::from_mut_bytes(&mut mac_raw),
        keycheck_tag,
    })
}

pub fn compute_hello_mac(
    config_mac_key: &ProtectedKey,
    schema_version: u32,
    hello_enabled: bool,
    hello_key_name: Option<&str>,
    hello_wrapped_vk: Option<&[u8]>,
) -> VaultResult<[u8; KEY_LEN]> {
    let payload = hello_binding_aad(
        schema_version,
        hello_enabled,
        hello_key_name,
        hello_wrapped_vk,
    );
    let mut mac = HmacSha256::new_from_slice(config_mac_key.as_bytes())
        .map_err(|_| VaultError::internal("Clave HMAC inválida para configuración Hello."))?;
    mac.update(&payload);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn verify_hello_mac(
    config_mac_key: &ProtectedKey,
    schema_version: u32,
    hello_enabled: bool,
    hello_key_name: Option<&str>,
    hello_wrapped_vk: Option<&[u8]>,
    expected_mac: &[u8],
) -> bool {
    if expected_mac.len() != KEY_LEN {
        return false;
    }
    let Ok(computed) = compute_hello_mac(
        config_mac_key,
        schema_version,
        hello_enabled,
        hello_key_name,
        hello_wrapped_vk,
    ) else {
        return false;
    };
    computed.ct_eq(expected_mac).into()
}
