use std::collections::HashMap;
use std::path::PathBuf;

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use tauri::State;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::commands::{
    auth::{VaultSessionInfo, MIN_MASTER_PASSWORD_CHARS},
    vault::{decrypt_item_secret, hydrate_session_index, OverviewPayload},
};
use crate::crypto::{
    aad::{folder_aad, item_overview_aad, item_secret_aad, mk_wrap_aad},
    aead::{decrypt_with_aad, encrypt_with_aad, unwrap_vault_key, wrap_vault_key},
    backup::{
        open_backup_bytes, seal_backup_bytes, BackupFolderRecord, BackupItemRecord, BackupSnapshot,
    },
    kdf::{
        derive_key_argon2id, expand_vault_subkeys, generate_random_key, generate_salt,
        DerivedVaultSubkeys, KdfParams, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEM_KIB,
        DEFAULT_KDF_PARALLELISM,
    },
};
use crate::db::{
    repo::{
        folder_exists, insert_initial_config, item_exists, list_all_raw_items_full,
        list_raw_folders, load_vault_config, NewVaultConfig,
    },
    schema::CURRENT_SCHEMA_VERSION,
};
use crate::error::{ErrorCode, VaultError, VaultResult};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ExportBackupInput {
    pub master_password: String,
    pub backup_password: String,
    pub dest_path: String,
}

#[derive(Debug, Deserialize)]
pub struct RestoreBackupInput {
    pub source_path: String,
    pub backup_password: String,
    pub new_master_password: String,
    pub ack_no_recovery: bool,
}

#[derive(Debug, Deserialize)]
pub struct ImportBackupInput {
    pub source_path: String,
    pub backup_password: String,
}

#[derive(Debug, Serialize)]
pub struct ImportBackupStatsDto {
    pub folders_imported: usize,
    pub items_imported: usize,
}

pub fn persist_snapshot_in_tx(
    tx: &rusqlite::Transaction<'_>,
    snapshot: &BackupSnapshot,
    subkeys: &DerivedVaultSubkeys,
) -> VaultResult<ImportBackupStatsDto> {
    let mut folder_id_map: HashMap<String, String> = HashMap::with_capacity(snapshot.folders.len());

    for folder in &snapshot.folders {
        let candidate_id = if Uuid::parse_str(&folder.id).is_ok() && !folder_exists(tx, &folder.id)? {
            folder.id.clone()
        } else {
            Uuid::new_v4().to_string()
        };

        let aad = folder_aad(CURRENT_SCHEMA_VERSION, &candidate_id);
        let sealed = encrypt_with_aad(&subkeys.overview_key, folder.name.as_bytes(), &aad)?;

        tx.execute(
            "INSERT INTO vault_folders (id, name_nonce, name_ciphertext, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                candidate_id,
                sealed.nonce,
                sealed.ciphertext,
                folder.created_at,
                folder.updated_at,
            ],
        )?;

        folder_id_map.insert(folder.id.clone(), candidate_id);
    }

    let mut items_imported = 0usize;
    for item in &snapshot.items {
        if item.item_type != item.secret.expected_item_type() {
            return Err(VaultError::new(
                ErrorCode::BackupCorrupted,
                "Inconsistencia de item_type detectada durante importación.",
            ));
        }

        let final_item_id = if Uuid::parse_str(&item.id).is_ok() && !item_exists(tx, &item.id)? {
            item.id.clone()
        } else {
            Uuid::new_v4().to_string()
        };

        let remapped_folder_id: Option<String> = match &item.folder_id {
            Some(old_fid) => folder_id_map.get(old_fid).cloned(),
            None => None,
        };

        let ov_bytes = Zeroizing::new(
            serde_json::to_vec(&item.overview)
                .map_err(|_| VaultError::internal("Error serializando overview en respaldo."))?,
        );
        let sec_bytes = Zeroizing::new(
            serde_json::to_vec(&item.secret)
                .map_err(|_| VaultError::internal("Error serializando secret en respaldo."))?,
        );

        let ov_aad = item_overview_aad(CURRENT_SCHEMA_VERSION, &final_item_id, &item.item_type);
        let sec_aad = item_secret_aad(CURRENT_SCHEMA_VERSION, &final_item_id, &item.item_type);

        let sealed_ov = encrypt_with_aad(&subkeys.overview_key, &ov_bytes, &ov_aad)?;
        let sealed_sec = encrypt_with_aad(&subkeys.secret_key, &sec_bytes, &sec_aad)?;

        tx.execute(
            "INSERT INTO vault_items (
                id, folder_id, item_type, favorite,
                overview_nonce, overview_ciphertext,
                secret_nonce, secret_ciphertext,
                created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                final_item_id,
                remapped_folder_id,
                item.item_type,
                i64::from(item.favorite),
                sealed_ov.nonce,
                sealed_ov.ciphertext,
                sealed_sec.nonce,
                sealed_sec.ciphertext,
                item.created_at,
                item.updated_at,
            ],
        )?;
        items_imported += 1;
    }

    Ok(ImportBackupStatsDto {
        folders_imported: folder_id_map.len(),
        items_imported,
    })
}

pub fn persist_snapshot_with_remap(
    conn: &mut Connection,
    snapshot: &BackupSnapshot,
    subkeys: &DerivedVaultSubkeys,
) -> VaultResult<ImportBackupStatsDto> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let stats = persist_snapshot_in_tx(&tx, snapshot, subkeys)?;
    tx.commit()?;
    Ok(stats)
}

#[tauri::command]
pub async fn export_encrypted_backup(
    state: State<'_, AppState>,
    input: ExportBackupInput,
) -> VaultResult<()> {
    let mp = Zeroizing::new(input.master_password);
    let bp = Zeroizing::new(input.backup_password);

    if bp.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err(VaultError::validation(format!(
            "La contraseña del archivo de respaldo debe tener al menos {MIN_MASTER_PASSWORD_CHARS} caracteres."
        )));
    }
    if state.is_locked() {
        return Err(VaultError::locked());
    }

    let cfg = state
        .db
        .with_conn(|conn| Ok(load_vault_config(conn)?))?
        .ok_or_else(|| VaultError::internal("Configuración ausente."))?;

    let salt = cfg.kdf_salt.clone();
    let nonce = cfg.mk_wrap_nonce.clone();
    let wrapped_vk = cfg.mk_wrapped_vk.clone();
    let schema_ver = cfg.schema_version;
    let kdf_params = KdfParams {
        mem_kib: cfg.kdf_mem_kib,
        iterations: cfg.kdf_iterations,
        parallelism: cfg.kdf_parallelism,
    };

    // Reautenticación criptográfica obligatoria de la Contraseña Maestra
    let verified_vk = tokio::task::spawn_blocking(move || -> VaultResult<_> {
        let mk = derive_key_argon2id(&mp, &salt, kdf_params)?;
        let aad = mk_wrap_aad(
            schema_ver,
            &salt,
            kdf_params.mem_kib,
            kdf_params.iterations,
            kdf_params.parallelism,
        );
        unwrap_vault_key(&mk, &nonce, &wrapped_vk, &aad)
    })
    .await
    .map_err(|_| VaultError::internal("Hilo KDF interrumpido al exportar."))??;

    let now = AppState::now_unix();
    let snapshot = state.with_unlocked(|session| {
        if !session.vault_key.ct_eq(&verified_vk) {
            return Err(VaultError::invalid_credentials());
        }

        let (raw_folders, raw_items) = state.db.with_conn(|conn| {
            Ok((list_raw_folders(conn)?, list_all_raw_items_full(conn)?))
        })?;

        let mut folders = Vec::with_capacity(raw_folders.len());
        for rf in raw_folders {
            let aad = folder_aad(CURRENT_SCHEMA_VERSION, &rf.id);
            let plain = decrypt_with_aad(
                &session.subkeys.overview_key,
                &rf.name_nonce,
                &rf.name_ciphertext,
                &aad,
            )?;
            let name = String::from_utf8(plain.to_vec())
                .map_err(|_| VaultError::internal("Carpeta UTF-8 inválida."))?;
            folders.push(BackupFolderRecord {
                id: rf.id,
                name,
                created_at: rf.created_at,
                updated_at: rf.updated_at,
            });
        }

        let mut items = Vec::with_capacity(raw_items.len());
        for ri in raw_items {
            let ov_aad = item_overview_aad(CURRENT_SCHEMA_VERSION, &ri.id, &ri.item_type);
            let ov_plain = decrypt_with_aad(
                &session.subkeys.overview_key,
                &ri.overview_nonce,
                &ri.overview_ciphertext,
                &ov_aad,
            )?;
            let overview: OverviewPayload = serde_json::from_slice(&ov_plain)
                .map_err(|_| VaultError::internal("Overview inválido al exportar."))?;

            let secret = decrypt_item_secret(
                &session.subkeys.secret_key,
                &ri.id,
                &ri.item_type,
                &ri.secret_nonce,
                &ri.secret_ciphertext,
            )?;

            items.push(BackupItemRecord {
                id: ri.id,
                folder_id: ri.folder_id,
                item_type: ri.item_type,
                favorite: ri.favorite,
                overview,
                secret,
                created_at: ri.created_at,
                updated_at: ri.updated_at,
            });
        }

        Ok(BackupSnapshot {
            schema_version: CURRENT_SCHEMA_VERSION,
            exported_at: now,
            folders,
            items,
        })
    })?;

    let dest = PathBuf::from(&input.dest_path);
    tokio::task::spawn_blocking(move || -> VaultResult<()> {
        let bytes = seal_backup_bytes(&snapshot, &bp, KdfParams::default(), now)?;
        let tmp_dest = dest.with_extension("aegisvault.tmp");
        std::fs::write(&tmp_dest, &bytes)
            .map_err(|e| VaultError::internal(format!("No se pudo escribir respaldo temporal: {e}")))?;
        std::fs::rename(&tmp_dest, &dest)
            .map_err(|e| VaultError::internal(format!("No se pudo finalizar el archivo de respaldo: {e}")))?;
        Ok(())
    })
    .await
    .map_err(|_| VaultError::internal("Hilo de exportación interrumpido."))??;

    Ok(())
}

#[tauri::command]
pub async fn restore_encrypted_backup(
    state: State<'_, AppState>,
    input: RestoreBackupInput,
) -> VaultResult<VaultSessionInfo> {
    let bp = Zeroizing::new(input.backup_password);
    let new_mp = Zeroizing::new(input.new_master_password);

    if !input.ack_no_recovery {
        return Err(VaultError::new(
            ErrorCode::ConsentRequired,
            "Debes confirmar que no existe recuperación de la nueva contraseña maestra.",
        ));
    }
    if new_mp.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err(VaultError::validation(format!(
            "La nueva contraseña maestra debe tener al menos {MIN_MASTER_PASSWORD_CHARS} caracteres."
        )));
    }

    let already_exists = state
        .db
        .with_conn(|conn| Ok(load_vault_config(conn)?.is_some()))?;
    if already_exists {
        return Err(VaultError::new(
            ErrorCode::VaultAlreadyInitialized,
            "Ya existe una bóveda inicializada; usa la opción de importar respaldo desde Ajustes.",
        ));
    }

    let source_path = PathBuf::from(&input.source_path);
    let kdf_params = KdfParams::default();
    let new_salt = generate_salt();

    let (snapshot, vault_key, subkeys, sealed_vk) =
        tokio::task::spawn_blocking(move || -> VaultResult<_> {
            let raw = std::fs::read(&source_path).map_err(|e| {
                VaultError::internal(format!("No se pudo leer el archivo .aegisvault: {e}"))
            })?;
            let snap = open_backup_bytes(&raw, &bp)?;

            let mk = derive_key_argon2id(&new_mp, &new_salt, kdf_params)?;
            let vk = generate_random_key();
            let derived = expand_vault_subkeys(&vk)?;
            let aad = mk_wrap_aad(
                CURRENT_SCHEMA_VERSION,
                &new_salt,
                kdf_params.mem_kib,
                kdf_params.iterations,
                kdf_params.parallelism,
            );
            let wrapped = wrap_vault_key(&mk, &vk, &aad)?;
            Ok((snap, vk, derived, wrapped))
        })
        .await
        .map_err(|_| VaultError::internal("Hilo de restauración interrumpido."))??;

let now = AppState::now_unix();
    state.db.with_conn(|conn| {
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        insert_initial_config(
            &tx,
            &NewVaultConfig {
                schema_version: CURRENT_SCHEMA_VERSION,
                kdf_salt: &new_salt,
                kdf_mem_kib: DEFAULT_KDF_MEM_KIB,
                kdf_iterations: DEFAULT_KDF_ITERATIONS,
                kdf_parallelism: DEFAULT_KDF_PARALLELISM,
                mk_wrapped_vk: &sealed_vk.ciphertext,
                mk_wrap_nonce: &sealed_vk.nonce,
                now,
            },
        )?;
        persist_snapshot_in_tx(&tx, &snapshot, &subkeys)?;
        tx.commit()?;
        Ok(())
    })?;

    state.install_unlocked_key(vault_key, 300, 25)?;
    state.with_unlocked_mut(|session| hydrate_session_index(&state.db, session))?;

    Ok(VaultSessionInfo {
        lock_timeout_secs: 300,
        clipboard_ttl_secs: 25,
        hello_enabled: false,
    })
}

#[tauri::command]
pub async fn import_encrypted_backup(
    state: State<'_, AppState>,
    input: ImportBackupInput,
) -> VaultResult<ImportBackupStatsDto> {
    if state.is_locked() {
        return Err(VaultError::locked());
    }

    let bp = Zeroizing::new(input.backup_password);
    let source_path = PathBuf::from(&input.source_path);

    let snapshot = tokio::task::spawn_blocking(move || -> VaultResult<BackupSnapshot> {
        let raw = std::fs::read(&source_path).map_err(|e| {
            VaultError::internal(format!("No se pudo leer el archivo .aegisvault: {e}"))
        })?;
        open_backup_bytes(&raw, &bp)
    })
    .await
    .map_err(|_| VaultError::internal("Hilo de importación interrumpido."))??;

    state.with_unlocked_mut(|session| {
        let stats = state.db.with_conn(|conn| {
            persist_snapshot_with_remap(conn, &snapshot, &session.subkeys)
        })?;
        hydrate_session_index(&state.db, session)?;
        Ok(stats)
    })
}
