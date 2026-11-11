use rusqlite::params;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tauri::{AppHandle, Manager, State};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::commands::vault::{decrypt_item_secret, hydrate_session_index, OverviewPayload};
use crate::crypto::{
    aad::{config_prefs_aad, folder_aad, item_overview_aad, item_secret_aad, mk_wrap_aad},
    aead::{decrypt_with_aad, encrypt_with_aad, unwrap_vault_key, wrap_vault_key, SealedBlob},
    kdf::{
        compute_hello_mac, derive_key_argon2id, expand_vault_subkeys, generate_random_key,
        generate_salt, validate_kdf_params, validate_password_strength, verify_hello_mac,
        DerivedVaultSubkeys, KdfParams, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEM_KIB,
        DEFAULT_KDF_PARALLELISM, MIN_PASSWORD_CHARS,
    },
    memory::{ProtectedKey, KEY_LEN},
};
use crate::db::{
    repo::{
        clear_hello_enrollment_row, insert_initial_config, list_all_raw_items_full,
        list_raw_folders, load_vault_config, rotate_master_key_tx, set_hello_enrollment_row,
        update_security_prefs_row, NewVaultConfig, VaultConfigRow,
    },
    schema::{CURRENT_SCHEMA_VERSION, LEGACY_SCHEMA_VERSION},
};
use crate::error::{ErrorCode, VaultError, VaultResult};
use crate::platform::{
    window_privacy::apply_window_capture_protection,
    windows_hello::{
        delete_persisted_hello_key, enroll_and_wrap_vault_key, is_hello_available,
        is_valid_hello_key_name, unwrap_vault_key_with_hello,
    },
};
use crate::state::{
    clamp_security_timers, AppState, LockReason, DEFAULT_CLIPBOARD_TTL_SECS,
    DEFAULT_LOCK_TIMEOUT_SECS, MAX_CLIPBOARD_TTL_SECS, MAX_LOCK_TIMEOUT_SECS,
    MIN_CLIPBOARD_TTL_SECS, MIN_LOCK_TIMEOUT_SECS,
};

pub const MIN_MASTER_PASSWORD_CHARS: usize = MIN_PASSWORD_CHARS;
const RSA_2048_OAEP_CIPHERTEXT_LEN: usize = 256;

fn default_capture_protection() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSecurityPrefs {
    pub lock_timeout_secs: u64,
    pub clipboard_ttl_secs: u64,
    #[serde(default = "default_capture_protection")]
    pub capture_protection_enabled: bool,
}

impl Default for EncryptedSecurityPrefs {
    fn default() -> Self {
        Self {
            lock_timeout_secs: DEFAULT_LOCK_TIMEOUT_SECS,
            clipboard_ttl_secs: DEFAULT_CLIPBOARD_TTL_SECS,
            capture_protection_enabled: true,
        }
    }
}

pub fn seal_security_prefs(
    overview_key: &ProtectedKey,
    schema_version: u32,
    prefs: &EncryptedSecurityPrefs,
) -> VaultResult<SealedBlob> {
    let aad = config_prefs_aad(schema_version);
    let plain = Zeroizing::new(
        serde_json::to_vec(prefs)
            .map_err(|_| VaultError::internal("No se pudieron serializar las preferencias."))?,
    );
    encrypt_with_aad(overview_key, &plain, &aad)
}

pub fn open_security_prefs(
    overview_key: &ProtectedKey,
    schema_version: u32,
    nonce: Option<&[u8]>,
    ciphertext: Option<&[u8]>,
) -> VaultResult<EncryptedSecurityPrefs> {
    let (Some(n), Some(ct)) = (nonce, ciphertext) else {
        return Err(VaultError::data_corrupted(
            "Faltan las preferencias autenticadas en vault_config (posible alteración local).",
        ));
    };

    let aad = config_prefs_aad(schema_version);
    let plain = decrypt_with_aad(overview_key, n, ct, &aad).map_err(|_| {
        VaultError::data_corrupted(
            "Las preferencias de seguridad en vault_config fueron alteradas o están dañadas.",
        )
    })?;

    let prefs: EncryptedSecurityPrefs = serde_json::from_slice(&plain).map_err(|_| {
        VaultError::data_corrupted("Formato interno inválido en preferencias autenticadas.")
    })?;

    if !(MIN_LOCK_TIMEOUT_SECS..=MAX_LOCK_TIMEOUT_SECS).contains(&prefs.lock_timeout_secs)
        || !(MIN_CLIPBOARD_TTL_SECS..=MAX_CLIPBOARD_TTL_SECS).contains(&prefs.clipboard_ttl_secs)
    {
        return Err(VaultError::data_corrupted(
            "Los tiempos de autoprotección desencriptados están fuera del rango seguro.",
        ));
    }

    Ok(prefs)
}

#[derive(Debug, Serialize)]
pub struct VaultStatusDto {
    pub initialized: bool,
    pub locked: bool,
    pub hello_enabled: bool,
    pub hello_available: bool,
}

#[derive(Debug, Serialize)]
pub struct VaultSessionInfo {
    pub lock_timeout_secs: u64,
    pub clipboard_ttl_secs: u64,
    pub hello_enabled: bool,
    pub capture_protection_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct SecurityPrefsDto {
    pub lock_timeout_secs: u64,
    pub clipboard_ttl_secs: u64,
    pub hello_enabled: bool,
    pub hello_available: bool,
    pub capture_protection_enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateVaultInput {
    pub master_password: String,
    pub ack_no_recovery: bool,
}

#[derive(Debug, Deserialize)]
pub struct UnlockPasswordInput {
    pub master_password: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangeMasterPasswordInput {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct ChangeMasterPasswordOutput {
    pub hello_was_reset: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSecurityPrefsInput {
    pub lock_timeout_secs: u64,
    pub clipboard_ttl_secs: u64,
    #[serde(default = "default_capture_protection")]
    pub capture_protection_enabled: bool,
}

/// Migra de forma transparente y atómica una bóveda `v0.1.0` (`schema_version = 1`)
/// hacia `schema_version = 2` tras verificar criptográficamente la Contraseña Maestra.
pub fn migrate_v1_to_v2(
    conn: &mut rusqlite::Connection,
    mk: &ProtectedKey,
    vk: &ProtectedKey,
    subkeys: &DerivedVaultSubkeys,
    cfg: &VaultConfigRow,
    now: i64,
) -> VaultResult<(EncryptedSecurityPrefs, bool)> {
    let (clamped_lock, clamped_clip) =
        clamp_security_timers(cfg.lock_timeout_secs, cfg.clipboard_ttl_secs);
    let prefs = EncryptedSecurityPrefs {
        lock_timeout_secs: clamped_lock,
        clipboard_ttl_secs: clamped_clip,
        capture_protection_enabled: true,
    };
    let sealed_prefs = seal_security_prefs(&subkeys.overview_key, CURRENT_SCHEMA_VERSION, &prefs)?;

    let new_aad = mk_wrap_aad(
        CURRENT_SCHEMA_VERSION,
        &cfg.kdf_salt,
        cfg.kdf_mem_kib,
        cfg.kdf_iterations,
        cfg.kdf_parallelism,
    );
    let rewrapped_vk = wrap_vault_key(mk, vk, &new_aad)?;

    let preserve_hello = cfg.hello_enabled
        && cfg
            .hello_key_name
            .as_deref()
            .map(is_valid_hello_key_name)
            .unwrap_or(false)
        && cfg
            .hello_wrapped_vk
            .as_ref()
            .map(|b| b.len() == RSA_2048_OAEP_CIPHERTEXT_LEN)
            .unwrap_or(false);

    let (final_hello_enabled, final_key_name, final_wrapped_vk) = if preserve_hello {
        (
            true,
            cfg.hello_key_name.clone(),
            cfg.hello_wrapped_vk.clone(),
        )
    } else {
        (false, None, None)
    };

    let hello_mac = compute_hello_mac(
        &subkeys.config_mac_key,
        CURRENT_SCHEMA_VERSION,
        final_hello_enabled,
        final_key_name.as_deref(),
        final_wrapped_vk.as_deref(),
    )?;

    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

    let raw_folders = list_raw_folders(&tx)?;
    for f in raw_folders {
        let old_aad = folder_aad(LEGACY_SCHEMA_VERSION, &f.id);
        if let Ok(plain) = decrypt_with_aad(
            &subkeys.overview_key,
            &f.name_nonce,
            &f.name_ciphertext,
            &old_aad,
        ) {
            let new_f_aad = folder_aad(CURRENT_SCHEMA_VERSION, &f.id);
            let resealed = encrypt_with_aad(&subkeys.overview_key, &plain, &new_f_aad)?;
            tx.execute(
                "UPDATE vault_folders SET name_nonce = ?2, name_ciphertext = ?3 WHERE id = ?1",
                params![f.id, resealed.nonce, resealed.ciphertext],
            )?;
        }
    }

    let raw_items = list_all_raw_items_full(&tx)?;
    for item in raw_items {
        let old_ov_aad = item_overview_aad(LEGACY_SCHEMA_VERSION, &item.id, &item.item_type);
        let ov_res = decrypt_with_aad(
            &subkeys.overview_key,
            &item.overview_nonce,
            &item.overview_ciphertext,
            &old_ov_aad,
        )
        .and_then(|p| {
            serde_json::from_slice::<OverviewPayload>(&p)
                .map(|_| p)
                .map_err(|_| VaultError::data_corrupted("Overview JSON corrupto en migración v1"))
        });

        let sec_res = decrypt_item_secret(
            &subkeys.secret_key,
            LEGACY_SCHEMA_VERSION,
            &item.id,
            &item.item_type,
            &item.secret_nonce,
            &item.secret_ciphertext,
        );

        if let (Ok(ov_plain), Ok(sec_payload)) = (ov_res, sec_res) {
            let sec_plain = Zeroizing::new(
                serde_json::to_vec(&sec_payload)
                    .map_err(|_| VaultError::internal("Error re-serializando secreto en migración v1"))?,
            );
            let new_ov_aad = item_overview_aad(CURRENT_SCHEMA_VERSION, &item.id, &item.item_type);
            let new_sec_aad = item_secret_aad(CURRENT_SCHEMA_VERSION, &item.id, &item.item_type);
            let resealed_ov = encrypt_with_aad(&subkeys.overview_key, &ov_plain, &new_ov_aad)?;
            let resealed_sec = encrypt_with_aad(&subkeys.secret_key, &sec_plain, &new_sec_aad)?;

            tx.execute(
                "UPDATE vault_items
                 SET overview_nonce = ?2, overview_ciphertext = ?3,
                     secret_nonce = ?4, secret_ciphertext = ?5
                 WHERE id = ?1",
                params![
                    item.id,
                    resealed_ov.nonce,
                    resealed_ov.ciphertext,
                    resealed_sec.nonce,
                    resealed_sec.ciphertext
                ],
            )?;
        }
    }

    tx.execute(
        "UPDATE vault_config
         SET schema_version = ?1,
             mk_wrapped_vk = ?2,
             mk_wrap_nonce = ?3,
             hello_enabled = ?4,
             hello_key_name = ?5,
             hello_wrapped_vk = ?6,
             lock_timeout_secs = ?7,
             clipboard_ttl_secs = ?8,
             prefs_nonce = ?9,
             prefs_ciphertext = ?10,
             vk_keycheck = ?11,
             hello_mac = ?12,
             updated_at = ?13
         WHERE id = 1",
        params![
            CURRENT_SCHEMA_VERSION,
            rewrapped_vk.ciphertext,
            rewrapped_vk.nonce,
            i64::from(final_hello_enabled),
            final_key_name,
            final_wrapped_vk,
            prefs.lock_timeout_secs,
            prefs.clipboard_ttl_secs,
            sealed_prefs.nonce,
            sealed_prefs.ciphertext,
            subkeys.keycheck_tag,
            hello_mac,
            now,
        ],
    )?;

    tx.commit()?;
    Ok((prefs, final_hello_enabled))
}

#[tauri::command]
pub fn get_vault_status(state: State<'_, AppState>) -> VaultResult<VaultStatusDto> {
    let cfg = state.db.with_conn(|conn| Ok(load_vault_config(conn)?))?;
    let hello_well_formed = cfg
        .as_ref()
        .map(|c| {
            c.hello_enabled
                && c.schema_version == CURRENT_SCHEMA_VERSION
                && c.hello_key_name
                    .as_deref()
                    .map(is_valid_hello_key_name)
                    .unwrap_or(false)
                && c.hello_wrapped_vk.is_some()
                && c.hello_mac.is_some()
                && c.vk_keycheck.is_some()
        })
        .unwrap_or(false);

    Ok(VaultStatusDto {
        initialized: cfg.is_some(),
        locked: state.is_locked(),
        hello_enabled: hello_well_formed,
        hello_available: is_hello_available(),
    })
}

#[tauri::command]
pub async fn create_vault(
    app: AppHandle,
    state: State<'_, AppState>,
    input: CreateVaultInput,
) -> VaultResult<VaultSessionInfo> {
    let mp = Zeroizing::new(input.master_password);

    if !input.ack_no_recovery {
        return Err(VaultError::new(
            ErrorCode::ConsentRequired,
            "Debes confirmar que comprendes que no existe recuperación de la contraseña maestra.",
        ));
    }
    validate_password_strength(&mp, "La contraseña maestra")?;

    let already_exists = state
        .db
        .with_conn(|conn| Ok(load_vault_config(conn)?.is_some()))?;
    if already_exists {
        return Err(VaultError::new(
            ErrorCode::VaultAlreadyInitialized,
            "Ya existe una bóveda inicializada en este equipo.",
        ));
    }

    let _kdf_permit = state
        .kdf_semaphore
        .acquire()
        .await
        .map_err(|_| VaultError::internal("Semáforo KDF cerrado."))?;

    let kdf_params = KdfParams::default();
    let salt = generate_salt();
    let default_prefs = EncryptedSecurityPrefs::default();
    let prefs_for_worker = default_prefs.clone();

    let (vault_key, sealed_vk, sealed_prefs, keycheck_tag, hello_mac) =
        tokio::task::spawn_blocking(move || -> VaultResult<_> {
            let mk = derive_key_argon2id(&mp, &salt, kdf_params)?;
            let vk = generate_random_key();
            let subkeys = expand_vault_subkeys(&vk)?;
            let aad = mk_wrap_aad(
                CURRENT_SCHEMA_VERSION,
                &salt,
                kdf_params.mem_kib,
                kdf_params.iterations,
                kdf_params.parallelism,
            );
            let wrapped = wrap_vault_key(&mk, &vk, &aad)?;
            let enc_prefs =
                seal_security_prefs(&subkeys.overview_key, CURRENT_SCHEMA_VERSION, &prefs_for_worker)?;
            let mac = compute_hello_mac(
                &subkeys.config_mac_key,
                CURRENT_SCHEMA_VERSION,
                false,
                None,
                None,
            )?;
            Ok((vk, wrapped, enc_prefs, subkeys.keycheck_tag, mac))
        })
        .await
        .map_err(|_| VaultError::internal("Hilo KDF interrumpido al crear bóveda."))??;

    let now = AppState::now_unix();
    state.db.with_conn(|conn| {
        insert_initial_config(
            conn,
            &NewVaultConfig {
                schema_version: CURRENT_SCHEMA_VERSION,
                kdf_salt: &salt,
                kdf_mem_kib: DEFAULT_KDF_MEM_KIB,
                kdf_iterations: DEFAULT_KDF_ITERATIONS,
                kdf_parallelism: DEFAULT_KDF_PARALLELISM,
                mk_wrapped_vk: &sealed_vk.ciphertext,
                mk_wrap_nonce: &sealed_vk.nonce,
                lock_timeout_secs: default_prefs.lock_timeout_secs,
                clipboard_ttl_secs: default_prefs.clipboard_ttl_secs,
                prefs_nonce: &sealed_prefs.nonce,
                prefs_ciphertext: &sealed_prefs.ciphertext,
                vk_keycheck: &keycheck_tag,
                hello_mac: &hello_mac,
                now,
            },
        )?;
        Ok(())
    })?;

    state.install_unlocked_key(
        vault_key,
        default_prefs.lock_timeout_secs,
        default_prefs.clipboard_ttl_secs,
        default_prefs.capture_protection_enabled,
    )?;
    apply_window_capture_protection(&app, default_prefs.capture_protection_enabled);

    Ok(VaultSessionInfo {
        lock_timeout_secs: default_prefs.lock_timeout_secs,
        clipboard_ttl_secs: default_prefs.clipboard_ttl_secs,
        hello_enabled: false,
        capture_protection_enabled: default_prefs.capture_protection_enabled,
    })
}

#[tauri::command]
pub async fn unlock_with_password(
    app: AppHandle,
    state: State<'_, AppState>,
    input: UnlockPasswordInput,
) -> VaultResult<VaultSessionInfo> {
    let mp = Zeroizing::new(input.master_password);
    state.check_unlock_backoff()?;

    let cfg = state
        .db
        .with_conn(|conn| Ok(load_vault_config(conn)?))?
        .ok_or_else(|| {
            VaultError::new(
                ErrorCode::VaultNotInitialized,
                "Aún no se ha creado una bóveda local.",
            )
        })?;

    if cfg.schema_version != LEGACY_SCHEMA_VERSION && cfg.schema_version != CURRENT_SCHEMA_VERSION {
        return Err(VaultError::data_corrupted(format!(
            "Versión de esquema de bóveda no soportada: {}.",
            cfg.schema_version
        )));
    }

    let params = KdfParams {
        mem_kib: cfg.kdf_mem_kib,
        iterations: cfg.kdf_iterations,
        parallelism: cfg.kdf_parallelism,
    };
    validate_kdf_params(params, ErrorCode::DataCorrupted)?;

    let _kdf_permit = state
        .kdf_semaphore
        .acquire()
        .await
        .map_err(|_| VaultError::internal("Semáforo KDF cerrado."))?;

    let salt = cfg.kdf_salt.clone();
    let nonce = cfg.mk_wrap_nonce.clone();
    let wrapped_vk = cfg.mk_wrapped_vk.clone();
    let schema_ver = cfg.schema_version;

    let kdf_outcome = tokio::task::spawn_blocking(move || -> VaultResult<_> {
        let mk = derive_key_argon2id(&mp, &salt, params)?;
        let aad = mk_wrap_aad(
            schema_ver,
            &salt,
            params.mem_kib,
            params.iterations,
            params.parallelism,
        );
        let vk = unwrap_vault_key(&mk, &nonce, &wrapped_vk, &aad)?;
        let subkeys = expand_vault_subkeys(&vk)?;
        Ok((mk, vk, subkeys))
    })
    .await
    .map_err(|_| VaultError::internal("Hilo KDF interrumpido al desbloquear."))?;

    let (mk, vault_key, subkeys) = match kdf_outcome {
        Ok(triple) => triple,
        Err(err) => {
            if err.code == ErrorCode::InvalidCredentials {
                state.record_unlock_failure();
            }
            return Err(err);
        }
    };

    let now = AppState::now_unix();
    let (prefs, effective_hello_enabled) = if cfg.schema_version == LEGACY_SCHEMA_VERSION {
        let migrated = state.db.with_conn(|conn| {
            migrate_v1_to_v2(conn, &mk, &vault_key, &subkeys, &cfg, now)
        })?;
        state.db.mark_dirty_deletes();
        migrated
    } else {
        // Verifica compromiso de VaultKey en v2
        let Some(ref expected_kc) = cfg.vk_keycheck else {
            return Err(VaultError::data_corrupted(
                "Falta la etiqueta de compromiso vk_keycheck en vault_config.",
            ));
        };
        if expected_kc.len() != KEY_LEN
            || !bool::from(subkeys.keycheck_tag.ct_eq(expected_kc.as_slice()))
        {
            return Err(VaultError::data_corrupted(
                "Discrepancia criptográfica entre VaultKey y vk_keycheck.",
            ));
        }

        let verified_prefs = open_security_prefs(
            &subkeys.overview_key,
            CURRENT_SCHEMA_VERSION,
            cfg.prefs_nonce.as_deref(),
            cfg.prefs_ciphertext.as_deref(),
        )?;

        // Verifica autenticidad de las columnas hello_* mediante HMAC-SHA256
        let hello_valid = if cfg.hello_enabled {
            let key_ok = cfg
                .hello_key_name
                .as_deref()
                .map(is_valid_hello_key_name)
                .unwrap_or(false);
            let mac_ok = cfg
                .hello_mac
                .as_deref()
                .map(|m| {
                    verify_hello_mac(
                        &subkeys.config_mac_key,
                        CURRENT_SCHEMA_VERSION,
                        true,
                        cfg.hello_key_name.as_deref(),
                        cfg.hello_wrapped_vk.as_deref(),
                        m,
                    )
                })
                .unwrap_or(false);
            if key_ok && mac_ok {
                true
            } else {
                tracing::warn!(
                    " Columnas hello_* inválidas o alteradas detectadas al desbloquear; revocando Hello."
                );
                let fresh_disabled_mac = compute_hello_mac(
                    &subkeys.config_mac_key,
                    CURRENT_SCHEMA_VERSION,
                    false,
                    None,
                    None,
                )?;
                let _ = state.db.with_conn(|conn| {
                    Ok(clear_hello_enrollment_row(
                        conn,
                        Some(&fresh_disabled_mac),
                        now,
                    )?)
                });
                state.db.mark_dirty_deletes();
                false
            }
        } else {
            // Si hello_mac quedó en NULL tras una invalidación previa de TPM estando bloqueado,
            // o si alguien dejó residuos en hello_key_name/hello_wrapped_vk, saneamos y firmamos estado limpio.
            let mac_matches_clean = cfg.hello_key_name.is_none()
                && cfg.hello_wrapped_vk.is_none()
                && cfg
                    .hello_mac
                    .as_deref()
                    .map(|m| {
                        verify_hello_mac(
                            &subkeys.config_mac_key,
                            CURRENT_SCHEMA_VERSION,
                            false,
                            None,
                            None,
                            m,
                        )
                    })
                    .unwrap_or(false);
            if !mac_matches_clean {
                let fresh_disabled_mac = compute_hello_mac(
                    &subkeys.config_mac_key,
                    CURRENT_SCHEMA_VERSION,
                    false,
                    None,
                    None,
                )?;
                let _ = state.db.with_conn(|conn| {
                    Ok(clear_hello_enrollment_row(
                        conn,
                        Some(&fresh_disabled_mac),
                        now,
                    )?)
                });
            }
            false
        };

        (verified_prefs, hello_valid)
    };
    drop(mk);

    state.install_unlocked_key(
        vault_key,
        prefs.lock_timeout_secs,
        prefs.clipboard_ttl_secs,
        prefs.capture_protection_enabled,
    )?;
    apply_window_capture_protection(&app, prefs.capture_protection_enabled);

    state.with_unlocked_mut(|session| hydrate_session_index(&state.db, session))?;

    Ok(VaultSessionInfo {
        lock_timeout_secs: prefs.lock_timeout_secs,
        clipboard_ttl_secs: prefs.clipboard_ttl_secs,
        hello_enabled: effective_hello_enabled,
        capture_protection_enabled: prefs.capture_protection_enabled,
    })
}

#[tauri::command]
pub fn lock_vault(app: AppHandle, state: State<'_, AppState>) -> VaultResult<()> {
    state.lock_now(Some(&app), LockReason::Manual)?;
    Ok(())
}

#[tauri::command]
pub fn record_user_activity(state: State<'_, AppState>) -> VaultResult<()> {
    if !state.is_locked() {
        state.touch_activity();
    }
    Ok(())
}

#[tauri::command]
pub fn get_security_prefs(state: State<'_, AppState>) -> VaultResult<SecurityPrefsDto> {
    state.with_unlocked(|session| {
        let cfg = state
            .db
            .with_conn(|conn| Ok(load_vault_config(conn)?))?
            .ok_or_else(|| VaultError::internal("Configuración de bóveda ausente."))?;
        let (lock_secs, clip_secs) = state.security_prefs();
        let hello_ok = cfg.hello_enabled
            && cfg
                .hello_mac
                .as_deref()
                .map(|m| {
                    verify_hello_mac(
                        &session.subkeys.config_mac_key,
                        CURRENT_SCHEMA_VERSION,
                        true,
                        cfg.hello_key_name.as_deref(),
                        cfg.hello_wrapped_vk.as_deref(),
                        m,
                    )
                })
                .unwrap_or(false);

        Ok(SecurityPrefsDto {
            lock_timeout_secs: lock_secs,
            clipboard_ttl_secs: clip_secs,
            hello_enabled: hello_ok,
            hello_available: is_hello_available(),
            capture_protection_enabled: state.capture_protection_enabled(),
        })
    })
}

#[tauri::command]
pub fn update_security_prefs(
    app: AppHandle,
    state: State<'_, AppState>,
    input: UpdateSecurityPrefsInput,
) -> VaultResult<()> {
    if !(MIN_LOCK_TIMEOUT_SECS..=MAX_LOCK_TIMEOUT_SECS).contains(&input.lock_timeout_secs) {
        return Err(VaultError::validation(
            "El tiempo de bloqueo automático debe estar entre 15 y 3600 segundos.",
        ));
    }
    if !(MIN_CLIPBOARD_TTL_SECS..=MAX_CLIPBOARD_TTL_SECS).contains(&input.clipboard_ttl_secs) {
        return Err(VaultError::validation(
            "El tiempo de limpieza del portapapeles debe estar entre 5 y 300 segundos.",
        ));
    }

    state.with_unlocked(|session| {
        let prefs = EncryptedSecurityPrefs {
            lock_timeout_secs: input.lock_timeout_secs,
            clipboard_ttl_secs: input.clipboard_ttl_secs,
            capture_protection_enabled: input.capture_protection_enabled,
        };
        let sealed = seal_security_prefs(
            &session.subkeys.overview_key,
            CURRENT_SCHEMA_VERSION,
            &prefs,
        )?;
        let now = AppState::now_unix();
        state.db.with_conn(|conn| {
            update_security_prefs_row(
                conn,
                prefs.lock_timeout_secs,
                prefs.clipboard_ttl_secs,
                &sealed.nonce,
                &sealed.ciphertext,
                now,
            )?;
            Ok(())
        })?;
        state.db.mark_dirty_deletes();
        state.set_security_prefs(prefs.lock_timeout_secs, prefs.clipboard_ttl_secs);
        state.set_capture_protection(prefs.capture_protection_enabled);
        apply_window_capture_protection(&app, prefs.capture_protection_enabled);
        Ok(())
    })
}

#[tauri::command]
pub async fn change_master_password(
    state: State<'_, AppState>,
    input: ChangeMasterPasswordInput,
) -> VaultResult<ChangeMasterPasswordOutput> {
    let current_mp = Zeroizing::new(input.current_password);
    let new_mp = Zeroizing::new(input.new_password);

    if state.is_locked() {
        return Err(VaultError::locked());
    }
    state.check_unlock_backoff()?;
    validate_password_strength(&new_mp, "La nueva contraseña maestra")?;

    let cfg = state
        .db
        .with_conn(|conn| Ok(load_vault_config(conn)?))?
        .ok_or_else(|| VaultError::internal("Configuración de bóveda no encontrada."))?;

    let old_params = KdfParams {
        mem_kib: cfg.kdf_mem_kib,
        iterations: cfg.kdf_iterations,
        parallelism: cfg.kdf_parallelism,
    };
    validate_kdf_params(old_params, ErrorCode::DataCorrupted)?;

    let _kdf_permit = state
        .kdf_semaphore
        .acquire()
        .await
        .map_err(|_| VaultError::internal("Semáforo KDF cerrado."))?;

    let new_params = KdfParams::default();
    let new_salt = generate_salt();
    let old_salt = cfg.kdf_salt.clone();
    let old_nonce = cfg.mk_wrap_nonce.clone();
    let old_wrapped = cfg.mk_wrapped_vk.clone();
    let schema_ver = cfg.schema_version;

    // Re-autenticación criptográfica + re-envoltura de VK fuera del hilo principal
    let kdf_res = tokio::task::spawn_blocking(move || -> VaultResult<_> {
        let mk_old = derive_key_argon2id(&current_mp, &old_salt, old_params)?;
        let old_aad = mk_wrap_aad(
            schema_ver,
            &old_salt,
            old_params.mem_kib,
            old_params.iterations,
            old_params.parallelism,
        );
        let vk_from_disk = unwrap_vault_key(&mk_old, &old_nonce, &old_wrapped, &old_aad)?;

        let mk_new = derive_key_argon2id(&new_mp, &new_salt, new_params)?;
        let new_aad = mk_wrap_aad(
            CURRENT_SCHEMA_VERSION,
            &new_salt,
            new_params.mem_kib,
            new_params.iterations,
            new_params.parallelism,
        );
        let sealed_new = wrap_vault_key(&mk_new, &vk_from_disk, &new_aad)?;
        Ok((vk_from_disk, sealed_new))
    })
    .await
    .map_err(|_| VaultError::internal("Hilo KDF interrumpido al rotar contraseña maestra."))?;

    let (unwrapped_old_vk, new_sealed_vk) = match kdf_res {
        Ok(pair) => pair,
        Err(err) => {
            if err.code == ErrorCode::InvalidCredentials {
                state.record_unlock_failure();
            }
            return Err(err);
        }
    };

    // Verifica en tiempo constante que la VK desenvuelta coincida con la sesión activa
    let (keycheck_tag, disabled_hello_mac) = state.with_unlocked(|session| {
        if !session.vault_key.ct_eq(&unwrapped_old_vk) {
            return Err(VaultError::internal(
                "Discrepancia crítica de VaultKey en sesión activa.",
            ));
        }
        let mac = compute_hello_mac(
            &session.subkeys.config_mac_key,
            CURRENT_SCHEMA_VERSION,
            false,
            None,
            None,
        )?;
        Ok((session.subkeys.keycheck_tag, mac))
    })?;
    state.reset_unlock_backoff();

    let now = AppState::now_unix();
    let prev_hello_key = state.db.with_conn(|conn| {
        Ok(rotate_master_key_tx(
            conn,
            &new_salt,
            new_params.mem_kib,
            new_params.iterations,
            new_params.parallelism,
            &new_sealed_vk.ciphertext,
            &new_sealed_vk.nonce,
            &keycheck_tag,
            &disabled_hello_mac,
            now,
        )?)
    })?;

    state.db.mark_dirty_deletes();

    if let Some(ref old_key_name) = prev_hello_key {
        delete_persisted_hello_key(old_key_name);
    }

    Ok(ChangeMasterPasswordOutput {
        hello_was_reset: prev_hello_key.is_some() || cfg.hello_enabled,
    })
}

#[derive(Debug, Deserialize)]
pub struct EnableHelloInput {
    pub master_password: String,
}

fn main_window_hwnd(app: &AppHandle) -> Option<isize> {
    #[cfg(windows)]
    {
        app.get_webview_window("main")
            .and_then(|w| w.hwnd().ok())
            .map(|h| h.0 as isize)
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        None
    }
}

#[tauri::command]
pub async fn enable_windows_hello(
    app: AppHandle,
    state: State<'_, AppState>,
    input: EnableHelloInput,
) -> VaultResult<()> {
    let mp = Zeroizing::new(input.master_password);

    if state.is_locked() {
        return Err(VaultError::locked());
    }
    state.check_unlock_backoff()?;
    if !is_hello_available() {
        return Err(VaultError::validation(
            "Windows Hello no está configurado o disponible en este equipo.",
        ));
    }

    let cfg = state
        .db
        .with_conn(|conn| Ok(load_vault_config(conn)?))?
        .ok_or_else(|| VaultError::internal("Configuración de bóveda ausente."))?;

    let params = KdfParams {
        mem_kib: cfg.kdf_mem_kib,
        iterations: cfg.kdf_iterations,
        parallelism: cfg.kdf_parallelism,
    };
    validate_kdf_params(params, ErrorCode::DataCorrupted)?;

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
            let mk = derive_key_argon2id(&mp, &salt, params)?;
            let aad = mk_wrap_aad(
                schema_ver,
                &salt,
                params.mem_kib,
                params.iterations,
                params.parallelism,
            );
            unwrap_vault_key(&mk, &nonce, &wrapped_vk, &aad)
        })
        .await
        .map_err(|_| VaultError::internal("Hilo KDF interrumpido al habilitar Hello."))?;

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

    // Comprobación en tiempo constante contra la sesión activa
    state.with_unlocked(|session| {
        if !session.vault_key.ct_eq(&verified_vk) {
            return Err(VaultError::invalid_credentials());
        }
        Ok(())
    })?;
    state.reset_unlock_backoff();

    let parent_hwnd = main_window_hwnd(&app);
    let key_name = format!("AegisVault.VK.{}", Uuid::new_v4());
    let key_name_for_worker = key_name.clone();
    let prev_key_to_clean = cfg.hello_key_name.clone();

    // Enrolamiento en TPM/NGC en hilo bloqueante para no congelar el bucle de ventana
    let hello_wrapped_vk = tokio::task::spawn_blocking(move || {
        enroll_and_wrap_vault_key(&key_name_for_worker, &verified_vk, parent_hwnd)
    })
    .await
    .map_err(|_| VaultError::internal("Hilo NCrypt interrumpido al enrolar Hello."))??;

    let hello_mac = state.with_unlocked(|session| {
        compute_hello_mac(
            &session.subkeys.config_mac_key,
            CURRENT_SCHEMA_VERSION,
            true,
            Some(&key_name),
            Some(&hello_wrapped_vk),
        )
    })?;

    let now = AppState::now_unix();
    state.db.with_conn(|conn| {
        set_hello_enrollment_row(conn, &key_name, &hello_wrapped_vk, &hello_mac, now)?;
        Ok(())
    })?;
    state.db.mark_dirty_deletes();

    if let Some(old_name) = prev_key_to_clean {
        if old_name != key_name {
            delete_persisted_hello_key(&old_name);
        }
    }

    Ok(())
}

#[tauri::command]
pub async fn disable_windows_hello(state: State<'_, AppState>) -> VaultResult<()> {
    let disabled_mac = state.with_unlocked(|session| {
        compute_hello_mac(
            &session.subkeys.config_mac_key,
            CURRENT_SCHEMA_VERSION,
            false,
            None,
            None,
        )
    })?;

    let now = AppState::now_unix();
    let prev_key = state.db.with_conn(|conn| {
        Ok(clear_hello_enrollment_row(
            conn,
            Some(&disabled_mac),
            now,
        )?)
    })?;
    state.db.mark_dirty_deletes();

    if let Some(key_name) = prev_key {
        let _ = tokio::task::spawn_blocking(move || {
            delete_persisted_hello_key(&key_name);
        })
        .await;
    }
    Ok(())
}

#[tauri::command]
pub async fn unlock_with_hello(
    app: AppHandle,
    state: State<'_, AppState>,
) -> VaultResult<VaultSessionInfo> {
    let cfg = state
        .db
        .with_conn(|conn| Ok(load_vault_config(conn)?))?
        .ok_or_else(|| {
            VaultError::new(
                ErrorCode::VaultNotInitialized,
                "Aún no existe una bóveda inicializada.",
            )
        })?;

    if cfg.schema_version != CURRENT_SCHEMA_VERSION {
        return Err(VaultError::new(
            ErrorCode::HelloInvalidated,
            "Desbloquea primero con tu Contraseña Maestra para completar la actualización criptográfica v2.",
        ));
    }

    let (Some(key_name), Some(hello_wrapped), Some(expected_keycheck), Some(expected_mac)) = (
        cfg.hello_key_name.clone(),
        cfg.hello_wrapped_vk.clone(),
        cfg.vk_keycheck.clone(),
        cfg.hello_mac.clone(),
    ) else {
        return Err(VaultError::new(
            ErrorCode::HelloInvalidated,
            "Windows Hello no está configurado o sus metadatos de integridad están incompletos.",
        ));
    };

    if !cfg.hello_enabled
        || !is_valid_hello_key_name(&key_name)
        || hello_wrapped.len() != RSA_2048_OAEP_CIPHERTEXT_LEN
        || expected_keycheck.len() != KEY_LEN
        || expected_mac.len() != KEY_LEN
    {
        return Err(VaultError::new(
            ErrorCode::HelloInvalidated,
            "El registro de Windows Hello es inválido o se encuentra deshabilitado.",
        ));
    }

    let parent_hwnd = main_window_hwnd(&app);
    let key_name_worker = key_name.clone();
    let wrapped_for_worker = hello_wrapped.clone();

    let unwrap_result = tokio::task::spawn_blocking(move || {
        unwrap_vault_key_with_hello(&key_name_worker, &wrapped_for_worker, parent_hwnd)
    })
    .await
    .map_err(|_| VaultError::internal("Hilo NCrypt interrumpido al desbloquear."))?;

    let vault_key = match unwrap_result {
        Ok(vk) => vk,
        Err(err) if err.code == ErrorCode::HelloInvalidated => {
            // Limpieza resiliente: solo borra la clave NGC si el nombre cumple ^AegisVault\.VK\.[0-9a-f-]{36}$
            let now = AppState::now_unix();
            let _ = state
                .db
                .with_conn(|conn| Ok(clear_hello_enrollment_row(conn, None, now)?));
            state.db.mark_dirty_deletes();
            delete_persisted_hello_key(&key_name);
            return Err(err);
        }
        Err(err) => return Err(err),
    };

    // Verifica que la VaultKey desenvuelta por TPM corresponda exactamente a esta bóveda
    // y que las columnas hello_* no hayan sido sustituidas fuera de línea.
    let subkeys = expand_vault_subkeys(&vault_key)?;
    if !bool::from(
        subkeys
            .keycheck_tag
            .ct_eq(expected_keycheck.as_slice()),
    ) {
        return Err(VaultError::new(
            ErrorCode::HelloInvalidated,
            "La clave desenvuelta por Windows Hello no coincide con el compromiso criptográfico de esta bóveda. Usa tu Contraseña Maestra.",
        ));
    }

    if !verify_hello_mac(
        &subkeys.config_mac_key,
        CURRENT_SCHEMA_VERSION,
        true,
        Some(&key_name),
        Some(&hello_wrapped),
        &expected_mac,
    ) {
        return Err(VaultError::data_corrupted(
            "Se detectó alteración en el vínculo de Windows Hello en vault_config. Desbloquea con tu Contraseña Maestra.",
        ));
    }

    let prefs = open_security_prefs(
        &subkeys.overview_key,
        CURRENT_SCHEMA_VERSION,
        cfg.prefs_nonce.as_deref(),
        cfg.prefs_ciphertext.as_deref(),
    )?;
    drop(subkeys);

    state.install_unlocked_key(
        vault_key,
        prefs.lock_timeout_secs,
        prefs.clipboard_ttl_secs,
        prefs.capture_protection_enabled,
    )?;
    apply_window_capture_protection(&app, prefs.capture_protection_enabled);

    state.with_unlocked_mut(|session| hydrate_session_index(&state.db, session))?;

    Ok(VaultSessionInfo {
        lock_timeout_secs: prefs.lock_timeout_secs,
        clipboard_ttl_secs: prefs.clipboard_ttl_secs,
        hello_enabled: true,
        capture_protection_enabled: prefs.capture_protection_enabled,
    })
}
