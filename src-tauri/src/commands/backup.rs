use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::commands::{
    auth::{seal_security_prefs, EncryptedSecurityPrefs, VaultSessionInfo},
    vault::{
        decrypt_item_secret, hydrate_session_index, validate_totp_or_skip, OverviewPayload,
        SecretPayload,
    },
};
use crate::crypto::{
    aad::{folder_aad, item_overview_aad, item_secret_aad, mk_wrap_aad},
    aead::{decrypt_with_aad, encrypt_with_aad, unwrap_vault_key, wrap_vault_key},
    backup::{
        open_backup_bytes, seal_backup_bytes, BackupFolderRecord, BackupItemRecord, BackupSnapshot,
    },
    kdf::{
        compute_hello_mac, derive_key_argon2id, expand_vault_subkeys, generate_random_key,
        generate_salt, validate_kdf_params, validate_password_strength, DerivedVaultSubkeys,
        KdfParams, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEM_KIB, DEFAULT_KDF_PARALLELISM,
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
use crate::platform::window_privacy::apply_window_capture_protection;
use crate::state::AppState;

/// Límite máximo de lectura en disco para archivos `.aegisvault` (64 MiB anti-OOM/DoS).
pub const MAX_BACKUP_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct ExportBackupInput {
    pub master_password: String,
    pub backup_password: String,
    #[serde(default)]
    pub skip_corrupted: bool,
}

#[derive(Debug, Serialize)]
pub struct ExportBackupOutput {
    pub skipped_corrupted: usize,
}

#[derive(Debug, Deserialize)]
pub struct RestoreBackupInput {
    pub backup_password: String,
    pub new_master_password: String,
    pub ack_no_recovery: bool,
}

#[derive(Debug, Deserialize)]
pub struct ImportBackupInput {
    pub backup_password: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportBackupStatsDto {
    pub folders_imported: usize,
    pub items_imported: usize,
    pub folders_skipped: usize,
    pub items_skipped: usize,
}

#[derive(Debug, Serialize)]
pub struct SelectedBackupFileDto {
    pub file_name: String,
    pub size_bytes: u64,
}

pub fn ensure_aegisvault_extension(path: &Path) -> VaultResult<()> {
    let valid_ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("aegisvault"))
        .unwrap_or(false);
    if !valid_ext {
        return Err(VaultError::validation(
            "El archivo debe tener obligatoriamente la extensión .aegisvault.",
        ));
    }
    Ok(())
}

pub fn read_bounded_backup_file(path: &Path) -> VaultResult<Vec<u8>> {
    ensure_aegisvault_extension(path)?;

    let file = std::fs::File::open(path).map_err(|e| {
        VaultError::validation(format!("No se pudo abrir el archivo .aegisvault: {e}"))
    })?;
    let meta = file.metadata().map_err(|e| {
        VaultError::validation(format!("No se pudieron leer los metadatos del respaldo: {e}"))
    })?;
    if !meta.is_file() {
        return Err(VaultError::validation(
            "La ruta seleccionada no corresponde a un archivo regular.",
        ));
    }
    if meta.len() > MAX_BACKUP_FILE_BYTES {
        return Err(VaultError::validation(
            "El archivo .aegisvault excede el tamaño máximo permitido de 64 MiB.",
        ));
    }

    let mut buf = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_BACKUP_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| VaultError::internal(format!("Error leyendo el archivo .aegisvault: {e}")))?;

    if buf.len() as u64 > MAX_BACKUP_FILE_BYTES {
        return Err(VaultError::validation(
            "El archivo .aegisvault excede el tamaño máximo permitido de 64 MiB.",
        ));
    }

    Ok(buf)
}

pub fn write_backup_file_safely(dest: &Path, bytes: &[u8]) -> VaultResult<()> {
    let final_dest = if dest
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("aegisvault"))
        .unwrap_or(false)
    {
        dest.to_path_buf()
    } else {
        dest.with_extension("aegisvault")
    };
    ensure_aegisvault_extension(&final_dest)?;

    let parent = final_dest.parent().ok_or_else(|| {
        VaultError::validation("Ruta de destino inválida para exportar el respaldo.")
    })?;

    let tmp_name = format!(".aegisvault.{}.tmp", Uuid::new_v4());
    let tmp_dest = parent.join(tmp_name);

    {
        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_dest)
            .map_err(|e| {
                VaultError::internal(format!("No se pudo crear archivo temporal seguro: {e}"))
            })?;
        if let Err(e) = tmp_file.write_all(bytes).and_then(|_| tmp_file.sync_all()) {
            let _ = std::fs::remove_file(&tmp_dest);
            return Err(VaultError::internal(format!(
                "No se pudo escribir el respaldo temporal: {e}"
            )));
        }
    }

    if let Err(e) = std::fs::rename(&tmp_dest, &final_dest) {
        let _ = std::fs::remove_file(&tmp_dest);
        return Err(VaultError::internal(format!(
            "No se pudo finalizar el archivo de respaldo: {e}"
        )));
    }

    Ok(())
}

struct ExistingDecryptedItem {
    id: String,
    folder_id: Option<String>,
    item_type: String,
    overview: OverviewPayload,
    secret: SecretPayload,
}

pub fn persist_snapshot_in_tx(
    tx: &rusqlite::Transaction<'_>,
    snapshot: &BackupSnapshot,
    subkeys: &DerivedVaultSubkeys,
) -> VaultResult<ImportBackupStatsDto> {
    let mut existing_folders: HashMap<String, String> = HashMap::new();
    for rf in list_raw_folders(tx)? {
        let aad = folder_aad(CURRENT_SCHEMA_VERSION, &rf.id);
        if let Ok(plain) = decrypt_with_aad(
            &subkeys.overview_key,
            &rf.name_nonce,
            &rf.name_ciphertext,
            &aad,
        ) {
            if let Ok(name) = String::from_utf8(plain.to_vec()) {
                existing_folders.insert(rf.id, name);
            }
        }
    }

    let mut folder_id_map: HashMap<String, String> = HashMap::with_capacity(snapshot.folders.len());
    let mut folders_imported = 0usize;
    let mut folders_skipped = 0usize;

    for folder in &snapshot.folders {
        // Deduplicación: si el mismo UUID ya existe con el mismo nombre descifrado, reutilizar sin duplicar
        if existing_folders.get(&folder.id) == Some(&folder.name) {
            folder_id_map.insert(folder.id.clone(), folder.id.clone());
            folders_skipped += 1;
            continue;
        }

        // Si el UUID colisionaba con otra carpeta pero ya existe una carpeta con idéntico nombre, reutilizarla
        if folder_exists(tx, &folder.id)? {
            if let Some((matched_id, _)) =
                existing_folders.iter().find(|(_, n)| *n == &folder.name)
            {
                folder_id_map.insert(folder.id.clone(), matched_id.clone());
                folders_skipped += 1;
                continue;
            }
        }

        let candidate_id = if Uuid::parse_str(&folder.id).is_ok() && !folder_exists(tx, &folder.id)?
        {
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

        existing_folders.insert(candidate_id.clone(), folder.name.clone());
        folder_id_map.insert(folder.id.clone(), candidate_id);
        folders_imported += 1;
    }

    let mut existing_items: Vec<ExistingDecryptedItem> = Vec::new();
    for ri in list_all_raw_items_full(tx)? {
        let ov_aad = item_overview_aad(CURRENT_SCHEMA_VERSION, &ri.id, &ri.item_type);
        let Ok(ov_plain) = decrypt_with_aad(
            &subkeys.overview_key,
            &ri.overview_nonce,
            &ri.overview_ciphertext,
            &ov_aad,
        ) else {
            continue;
        };
        let Ok(overview) = serde_json::from_slice::<OverviewPayload>(&ov_plain) else {
            continue;
        };
        let Ok(secret) = decrypt_item_secret(
            &subkeys.secret_key,
            CURRENT_SCHEMA_VERSION,
            &ri.id,
            &ri.item_type,
            &ri.secret_nonce,
            &ri.secret_ciphertext,
        ) else {
            continue;
        };
        existing_items.push(ExistingDecryptedItem {
            id: ri.id,
            folder_id: ri.folder_id,
            item_type: ri.item_type,
            overview,
            secret,
        });
    }

    let mut items_imported = 0usize;
    let mut items_skipped = 0usize;

    for item in &snapshot.items {
        if item.item_type != item.secret.expected_item_type() {
            return Err(VaultError::new(
                ErrorCode::BackupCorrupted,
                "Inconsistencia de item_type detectada durante importación.",
            ));
        }

        let remapped_folder_id: Option<String> = match &item.folder_id {
            Some(old_fid) => folder_id_map.get(old_fid).cloned(),
            None => None,
        };

        let is_duplicate = existing_items.iter().any(|ex| {
            let same_payload = ex.item_type == item.item_type
                && ex.overview == item.overview
                && ex.secret.content_eq(&item.secret);
            same_payload && (ex.id == item.id || ex.folder_id == remapped_folder_id)
        });

        if is_duplicate {
            items_skipped += 1;
            continue;
        }

        let final_item_id = if Uuid::parse_str(&item.id).is_ok() && !item_exists(tx, &item.id)? {
            item.id.clone()
        } else {
            Uuid::new_v4().to_string()
        };

        // Sanitiza URI TOTP malformada solo en log informativo sin abortar respaldos antiguos
        validate_totp_or_skip(&item.secret);

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

        existing_items.push(ExistingDecryptedItem {
            id: final_item_id,
            folder_id: remapped_folder_id,
            item_type: item.item_type.clone(),
            overview: item.overview.clone(),
            secret: item.secret.clone(),
        });
        items_imported += 1;
    }

    Ok(ImportBackupStatsDto {
        folders_imported,
        items_imported,
        folders_skipped,
        items_skipped,
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

pub fn collect_export_snapshot(
    db: &crate::db::VaultDb,
    subkeys: &DerivedVaultSubkeys,
    now: i64,
    skip_corrupted: bool,
) -> VaultResult<(BackupSnapshot, usize)> {
    let (raw_folders, raw_items) = db.with_conn(|conn| {
        Ok((list_raw_folders(conn)?, list_all_raw_items_full(conn)?))
    })?;

    let mut folders = Vec::with_capacity(raw_folders.len());
    let mut corrupted = 0usize;

    for rf in raw_folders {
        let aad = folder_aad(CURRENT_SCHEMA_VERSION, &rf.id);
        let decoded = decrypt_with_aad(
            &subkeys.overview_key,
            &rf.name_nonce,
            &rf.name_ciphertext,
            &aad,
        )
        .map_err(|_| VaultError::data_corrupted("Carpeta con etiqueta AEAD inválida."))
        .and_then(|plain| {
            String::from_utf8(plain.to_vec())
                .map_err(|_| VaultError::data_corrupted("Carpeta UTF-8 inválida."))
        });

        match decoded {
            Ok(name) => folders.push(BackupFolderRecord {
                id: rf.id,
                name,
                created_at: rf.created_at,
                updated_at: rf.updated_at,
            }),
            Err(_) => {
                corrupted += 1;
            }
        }
    }

    let mut items = Vec::with_capacity(raw_items.len());
    for ri in raw_items {
        let ov_aad = item_overview_aad(CURRENT_SCHEMA_VERSION, &ri.id, &ri.item_type);
        let ov_res = decrypt_with_aad(
            &subkeys.overview_key,
            &ri.overview_nonce,
            &ri.overview_ciphertext,
            &ov_aad,
        )
        .map_err(|_| VaultError::data_corrupted("Overview de ítem con etiqueta AEAD inválida."))
        .and_then(|ov_plain| {
            serde_json::from_slice::<OverviewPayload>(&ov_plain)
                .map_err(|_| VaultError::data_corrupted("Overview inválido al exportar."))
        });

        let sec_res = decrypt_item_secret(
            &subkeys.secret_key,
            CURRENT_SCHEMA_VERSION,
            &ri.id,
            &ri.item_type,
            &ri.secret_nonce,
            &ri.secret_ciphertext,
        );

        match (ov_res, sec_res) {
            (Ok(overview), Ok(secret)) => items.push(BackupItemRecord {
                id: ri.id,
                folder_id: ri.folder_id,
                item_type: ri.item_type,
                favorite: ri.favorite,
                overview,
                secret,
                created_at: ri.created_at,
                updated_at: ri.updated_at,
            }),
            _ => {
                corrupted += 1;
            }
        }
    }

    if corrupted > 0 && !skip_corrupted {
        return Err(VaultError::data_corrupted(format!(
            "Se detectaron {corrupted} registro(s) con fallo de integridad AEAD en vault.db. Puedes exportar únicamente los {} registro(s) intactos usando la opción de recuperación.",
            items.len()
        )));
    }

    Ok((
        BackupSnapshot {
            schema_version: CURRENT_SCHEMA_VERSION,
            exported_at: now,
            folders,
            items,
        },
        corrupted,
    ))
}

#[tauri::command]
pub async fn select_restore_backup_file(
    app: AppHandle,
    state: State<'_, AppState>,
) -> VaultResult<SelectedBackupFileDto> {
    let picked = tokio::task::spawn_blocking(move || {
        app.dialog()
            .file()
            .add_filter("Respaldo AegisVault", &["aegisvault"])
            .blocking_pick_file()
    })
    .await
    .map_err(|_| VaultError::internal("Diálogo de selección interrumpido."))?;

    let Some(file_path) = picked else {
        return Err(VaultError::dialog_cancelled());
    };

    let path = file_path
        .into_path()
        .map_err(|_| VaultError::validation("Ruta de archivo de respaldo no válida."))?;

    ensure_aegisvault_extension(&path)?;
    let meta = std::fs::metadata(&path).map_err(|e| {
        VaultError::validation(format!("No se pudo inspeccionar el archivo seleccionado: {e}"))
    })?;
    if !meta.is_file() {
        return Err(VaultError::validation(
            "La selección no corresponde a un archivo regular.",
        ));
    }
    if meta.len() > MAX_BACKUP_FILE_BYTES {
        return Err(VaultError::validation(
            "El archivo .aegisvault excede el límite máximo permitido de 64 MiB.",
        ));
    }

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("respaldo.aegisvault")
        .to_string();

    state.set_approved_restore_path(Some(path))?;

    Ok(SelectedBackupFileDto {
        file_name,
        size_bytes: meta.len(),
    })
}

#[tauri::command]
pub async fn export_encrypted_backup(
    app: AppHandle,
    state: State<'_, AppState>,
    input: ExportBackupInput,
) -> VaultResult<ExportBackupOutput> {
    let mp = Zeroizing::new(input.master_password);
    let bp = Zeroizing::new(input.backup_password);

    if state.is_locked() {
        return Err(VaultError::locked());
    }
    state.check_unlock_backoff()?;
    validate_password_strength(&bp, "La contraseña del archivo de respaldo")?;

    let cfg = state
        .db
        .with_conn(|conn| Ok(load_vault_config(conn)?))?
        .ok_or_else(|| VaultError::internal("Configuración ausente."))?;

    let kdf_params = KdfParams {
        mem_kib: cfg.kdf_mem_kib,
        iterations: cfg.kdf_iterations,
        parallelism: cfg.kdf_parallelism,
    };
    validate_kdf_params(kdf_params, ErrorCode::DataCorrupted)?;

    // Reautenticación criptográfica obligatoria de la Contraseña Maestra bajo semáforo KDF
    let verified_vk = {
        let _kdf_permit = state
            .kdf_semaphore
            .acquire()
            .await
            .map_err(|_| VaultError::internal("Semáforo KDF cerrado."))?;

        let salt = cfg.kdf_salt.clone();
        let nonce = cfg.mk_wrap_nonce.clone();
        let wrapped_vk = cfg.mk_wrapped_vk.clone();
        let schema_ver = cfg.schema_version;

        let res = tokio::task::spawn_blocking(move || -> VaultResult<_> {
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
        .map_err(|_| VaultError::internal("Hilo KDF interrumpido al exportar."))?;

        match res {
            Ok(vk) => vk,
            Err(err) => {
                if err.code == ErrorCode::InvalidCredentials {
                    state.record_unlock_failure();
                }
                return Err(err);
            }
        }
    };

    let now = AppState::now_unix();
    let (snapshot, skipped_corrupted) = state.with_unlocked(|session| {
        if !session.vault_key.ct_eq(&verified_vk) {
            return Err(VaultError::invalid_credentials());
        }
        collect_export_snapshot(&state.db, &session.subkeys, now, input.skip_corrupted)
    })?;
    state.reset_unlock_backoff();

    // Diálogo nativo ejecutado desde Rust: WebView jamás elige rutas de escritura arbitrarias
    let default_filename = format!("respaldo-{now}.aegisvault");
    let app_for_dialog = app.clone();
    let picked_dest = tokio::task::spawn_blocking(move || {
        app_for_dialog
            .dialog()
            .file()
            .add_filter("Respaldo AegisVault", &["aegisvault"])
            .set_file_name(&default_filename)
            .blocking_save_file()
    })
    .await
    .map_err(|_| VaultError::internal("Diálogo de guardado interrumpido."))?;

    let Some(dest_fp) = picked_dest else {
        return Err(VaultError::dialog_cancelled());
    };
    let dest_path = dest_fp
        .into_path()
        .map_err(|_| VaultError::validation("Ruta de destino seleccionada no válida."))?;

    let _kdf_permit = state
        .kdf_semaphore
        .acquire()
        .await
        .map_err(|_| VaultError::internal("Semáforo KDF cerrado."))?;

    tokio::task::spawn_blocking(move || -> VaultResult<()> {
        let bytes = seal_backup_bytes(&snapshot, &bp, KdfParams::default(), now)?;
        write_backup_file_safely(&dest_path, &bytes)
    })
    .await
    .map_err(|_| VaultError::internal("Hilo de exportación interrumpido."))??;

    Ok(ExportBackupOutput { skipped_corrupted })
}

#[tauri::command]
pub async fn restore_encrypted_backup(
    app: AppHandle,
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
    validate_password_strength(&new_mp, "La nueva contraseña maestra")?;

    let already_exists = state
        .db
        .with_conn(|conn| Ok(load_vault_config(conn)?.is_some()))?;
    if already_exists {
        return Err(VaultError::new(
            ErrorCode::VaultAlreadyInitialized,
            "Ya existe una bóveda inicializada; usa la opción de importar respaldo desde Ajustes.",
        ));
    }

    let source_path = match state.take_approved_restore_path()? {
        Some(p) => p,
        None => {
            let app_for_dialog = app.clone();
            let picked = tokio::task::spawn_blocking(move || {
                app_for_dialog
                    .dialog()
                    .file()
                    .add_filter("Respaldo AegisVault", &["aegisvault"])
                    .blocking_pick_file()
            })
            .await
            .map_err(|_| VaultError::internal("Diálogo de apertura interrumpido."))?;

            let Some(fp) = picked else {
                return Err(VaultError::dialog_cancelled());
            };
            fp.into_path()
                .map_err(|_| VaultError::validation("Ruta de archivo no válida."))?
        }
    };

    let _kdf_permit = state
        .kdf_semaphore
        .acquire()
        .await
        .map_err(|_| VaultError::internal("Semáforo KDF cerrado."))?;

    let kdf_params = KdfParams::default();
    let new_salt = generate_salt();
    let default_prefs = EncryptedSecurityPrefs::default();
    let prefs_worker = default_prefs.clone();
    let source_for_worker = source_path.clone();

    let worker_res = tokio::task::spawn_blocking(move || -> VaultResult<_> {
        let raw = read_bounded_backup_file(&source_for_worker)?;
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
        let sealed_prefs =
            seal_security_prefs(&derived.overview_key, CURRENT_SCHEMA_VERSION, &prefs_worker)?;
        let hello_mac = compute_hello_mac(
            &derived.config_mac_key,
            CURRENT_SCHEMA_VERSION,
            false,
            None,
            None,
        )?;
        Ok((snap, vk, derived, wrapped, sealed_prefs, hello_mac))
    })
    .await
    .map_err(|_| VaultError::internal("Hilo de restauración interrumpido."))?;

    let (snapshot, vault_key, subkeys, sealed_vk, sealed_prefs, hello_mac) = match worker_res {
        Ok(res) => res,
        Err(err) => {
            // Conserva el archivo seleccionado para reintentar si la contraseña del respaldo fue errónea
            let _ = state.set_approved_restore_path(Some(source_path));
            return Err(err);
        }
    };

    let now = AppState::now_unix();
    let keycheck = subkeys.keycheck_tag;
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
                lock_timeout_secs: default_prefs.lock_timeout_secs,
                clipboard_ttl_secs: default_prefs.clipboard_ttl_secs,
                prefs_nonce: &sealed_prefs.nonce,
                prefs_ciphertext: &sealed_prefs.ciphertext,
                vk_keycheck: &keycheck,
                hello_mac: &hello_mac,
                now,
            },
        )?;
        persist_snapshot_in_tx(&tx, &snapshot, &subkeys)?;
        tx.commit()?;
        Ok(())
    })?;

    state.install_unlocked_key(
        vault_key,
        default_prefs.lock_timeout_secs,
        default_prefs.clipboard_ttl_secs,
        default_prefs.capture_protection_enabled,
    )?;
    apply_window_capture_protection(&app, default_prefs.capture_protection_enabled);
    state.with_unlocked_mut(|session| hydrate_session_index(&state.db, session))?;

    Ok(VaultSessionInfo {
        lock_timeout_secs: default_prefs.lock_timeout_secs,
        clipboard_ttl_secs: default_prefs.clipboard_ttl_secs,
        hello_enabled: false,
        capture_protection_enabled: default_prefs.capture_protection_enabled,
    })
}

#[tauri::command]
pub async fn import_encrypted_backup(
    app: AppHandle,
    state: State<'_, AppState>,
    input: ImportBackupInput,
) -> VaultResult<ImportBackupStatsDto> {
    if state.is_locked() {
        return Err(VaultError::locked());
    }

    let bp = Zeroizing::new(input.backup_password);
    if bp.is_empty() {
        return Err(VaultError::validation(
            "Ingresa la contraseña del archivo .aegisvault antes de importar.",
        ));
    }

    let picked = tokio::task::spawn_blocking(move || {
        app.dialog()
            .file()
            .add_filter("Respaldo AegisVault", &["aegisvault"])
            .blocking_pick_file()
    })
    .await
    .map_err(|_| VaultError::internal("Diálogo de importación interrumpido."))?;

    let Some(file_path) = picked else {
        return Err(VaultError::dialog_cancelled());
    };
    let source_path = file_path
        .into_path()
        .map_err(|_| VaultError::validation("Ruta de archivo no válida."))?;

    let _kdf_permit = state
        .kdf_semaphore
        .acquire()
        .await
        .map_err(|_| VaultError::internal("Semáforo KDF cerrado."))?;

    let snapshot = tokio::task::spawn_blocking(move || -> VaultResult<BackupSnapshot> {
        let raw = read_bounded_backup_file(&source_path)?;
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
