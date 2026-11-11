use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

use crate::crypto::memory::{ProtectedKey, KEY_LEN};
use crate::error::{VaultError, VaultResult};

pub const NONCE_LEN: usize = 12;

pub struct SealedBlob {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

pub fn encrypt_with_aad(
    key: &ProtectedKey,
    plaintext: &[u8],
    aad: &[u8],
) -> VaultResult<SealedBlob> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|_| VaultError::internal("Clave AES-256 inválida"))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VaultError::internal("Fallo al cifrar con AES-256-GCM"))?;

    Ok(SealedBlob {
        nonce: nonce_bytes,
        ciphertext,
    })
}

pub fn decrypt_with_aad(
    key: &ProtectedKey,
    nonce_bytes: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> VaultResult<Zeroizing<Vec<u8>>> {
    if nonce_bytes.len() != NONCE_LEN {
        return Err(VaultError::internal("Longitud de nonce AES-GCM inválida."));
    }

    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|_| VaultError::internal("Clave AES-256 inválida"))?;

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| VaultError::invalid_credentials())?;

    Ok(Zeroizing::new(plaintext))
}

pub fn wrap_vault_key(
    wrapping_key: &ProtectedKey,
    vault_key: &ProtectedKey,
    aad: &[u8],
) -> VaultResult<SealedBlob> {
    encrypt_with_aad(wrapping_key, vault_key.as_bytes(), aad)
}

pub fn unwrap_vault_key(
    wrapping_key: &ProtectedKey,
    nonce_bytes: &[u8],
    wrapped_vk: &[u8],
    aad: &[u8],
) -> VaultResult<ProtectedKey> {
    let plain = decrypt_with_aad(wrapping_key, nonce_bytes, wrapped_vk, aad)?;
    if plain.len() != KEY_LEN {
        return Err(VaultError::internal(
            "Longitud de VaultKey desenvuelta inválida.",
        ));
    }

    let mut raw = [0u8; KEY_LEN];
    raw.copy_from_slice(&plain);
    Ok(ProtectedKey::from_mut_bytes(&mut raw))
}
