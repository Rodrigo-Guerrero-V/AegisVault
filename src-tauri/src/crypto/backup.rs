use zeroize::{Zeroize, Zeroizing};

use crate::commands::vault::{OverviewPayload, SecretPayload};
use crate::crypto::{
    aad::backup_aad,
    aead::{decrypt_with_aad, encrypt_with_aad, NONCE_LEN},
    kdf::{derive_key_argon2id, generate_salt, validate_kdf_params, KdfParams, SALT_LEN},
};
use crate::error::{ErrorCode, VaultError, VaultResult};
use serde::{Deserialize, Serialize};

pub const BACKUP_MAGIC: &[u8; 8] = b"AEGISBAK";
pub const BACKUP_FORMAT_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 8 + 1 + 8 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN; // 57 bytes
const GCM_TAG_LEN: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupFolderRecord {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupItemRecord {
    pub id: String,
    pub folder_id: Option<String>,
    pub item_type: String,
    pub favorite: bool,
    pub overview: OverviewPayload,
    pub secret: SecretPayload,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Zeroize for BackupItemRecord {
    fn zeroize(&mut self) {
        self.id.zeroize();
        if let Some(ref mut fid) = self.folder_id {
            fid.zeroize();
        }
        self.folder_id = None;
        self.item_type.zeroize();
        self.favorite = false;
        self.overview.zeroize();
        self.secret.zeroize();
        self.created_at = 0;
        self.updated_at = 0;
    }
}

impl Drop for BackupItemRecord {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupSnapshot {
    pub schema_version: u32,
    pub exported_at: i64,
    pub folders: Vec<BackupFolderRecord>,
    pub items: Vec<BackupItemRecord>,
}

impl Zeroize for BackupSnapshot {
    fn zeroize(&mut self) {
        for f in &mut self.folders {
            f.id.zeroize();
            f.name.zeroize();
            f.created_at = 0;
            f.updated_at = 0;
        }
        self.folders.clear();
        for it in &mut self.items {
            it.zeroize();
        }
        self.items.clear();
    }
}

impl Drop for BackupSnapshot {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub fn seal_backup_bytes(
    snapshot: &BackupSnapshot,
    backup_password: &str,
    params: KdfParams,
    created_at: i64,
) -> VaultResult<Vec<u8>> {
    validate_kdf_params(params, ErrorCode::ValidationError)?;
    let salt = generate_salt();
    let backup_key = derive_key_argon2id(backup_password, &salt, params)?;

    let aad = backup_aad(
        BACKUP_FORMAT_VERSION,
        created_at,
        &salt,
        params.mem_kib,
        params.iterations,
        params.parallelism,
    );

    let json_bytes = Zeroizing::new(
        serde_json::to_vec(snapshot)
            .map_err(|_| VaultError::internal("No se pudo serializar la instantánea de respaldo."))?,
    );

    let sealed = encrypt_with_aad(&backup_key, &json_bytes, &aad)?;

    let mut out = Vec::with_capacity(HEADER_LEN + sealed.ciphertext.len());
    out.extend_from_slice(BACKUP_MAGIC);
    out.push(BACKUP_FORMAT_VERSION);
    out.extend_from_slice(&created_at.to_le_bytes());
    out.extend_from_slice(&params.mem_kib.to_le_bytes());
    out.extend_from_slice(&params.iterations.to_le_bytes());
    out.extend_from_slice(&params.parallelism.to_le_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&sealed.nonce);
    out.extend_from_slice(&sealed.ciphertext);

    Ok(out)
}

pub fn open_backup_bytes(raw: &[u8], backup_password: &str) -> VaultResult<BackupSnapshot> {
    if raw.len() < HEADER_LEN + GCM_TAG_LEN || &raw[0..8] != BACKUP_MAGIC {
        return Err(VaultError::new(
            ErrorCode::BackupCorrupted,
            "El archivo no es un respaldo .aegisvault válido.",
        ));
    }

    let format_ver = raw[8];
    if format_ver != BACKUP_FORMAT_VERSION {
        return Err(VaultError::new(
            ErrorCode::BackupCorrupted,
            format!("Versión de formato .aegisvault no soportada: {format_ver}."),
        ));
    }

    let created_at = i64::from_le_bytes(raw[9..17].try_into().unwrap());
    let mem_kib = u32::from_le_bytes(raw[17..21].try_into().unwrap());
    let iterations = u32::from_le_bytes(raw[21..25].try_into().unwrap());
    let parallelism = u32::from_le_bytes(raw[25..29].try_into().unwrap());

    let params = KdfParams {
        mem_kib,
        iterations,
        parallelism,
    };
    validate_kdf_params(params, ErrorCode::BackupCorrupted)?;

    let salt = &raw[29..45];
    let nonce = &raw[45..57];
    let ciphertext = &raw[57..];

    let backup_key = derive_key_argon2id(backup_password, salt, params)?;
    let aad = backup_aad(
        format_ver,
        created_at,
        salt,
        mem_kib,
        iterations,
        parallelism,
    );

    let plain = decrypt_with_aad(&backup_key, nonce, ciphertext, &aad).map_err(|_| {
        VaultError::new(
            ErrorCode::InvalidCredentials,
            "Contraseña de respaldo incorrecta o archivo .aegisvault alterado.",
        )
    })?;

    serde_json::from_slice(&plain).map_err(|_| {
        VaultError::new(
            ErrorCode::BackupCorrupted,
            "Contenido interno del respaldo dañado.",
        )
    })
}
