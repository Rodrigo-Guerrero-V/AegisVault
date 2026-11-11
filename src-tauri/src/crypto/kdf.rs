use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::memory::{ProtectedKey, KEY_LEN};
use crate::error::{VaultError, VaultResult};

pub const DEFAULT_KDF_MEM_KIB: u32 = 65_536; // 64 MiB
pub const DEFAULT_KDF_ITERATIONS: u32 = 3;
pub const DEFAULT_KDF_PARALLELISM: u32 = 4;
pub const SALT_LEN: usize = 16;

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
/// y deriva 32 bytes mediante Argon2id.
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
    if salt.len() != SALT_LEN {
        return Err(VaultError::internal("Longitud de salt KDF inválida."));
    }

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

    Ok(DerivedVaultSubkeys {
        overview_key: ProtectedKey::from_mut_bytes(&mut overview_raw),
        secret_key: ProtectedKey::from_mut_bytes(&mut secret_raw),
    })
}
