use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
use zeroize::Zeroizing;

use tauri::Manager;
use uuid::Uuid;
use crate::db::repo::{clear_hello_enrollment_row, set_hello_enrollment_row};
use crate::platform::windows_hello::{
    delete_persisted_hello_key, enroll_and_wrap_vault_key, is_hello_available,
    unwrap_vault_key_with_hello,
};

use crate::crypto::{
    aad::mk_wrap_aad,
    aead::{unwrap_vault_key, wrap_vault_key},
    kdf::{
        derive_key_argon2id, generate_random_key, generate_salt, KdfParams,
        DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEM_KIB, DEFAULT_KDF_PARALLELISM,
    },
};
use crate::db::{
    repo::{
        insert_initial_config, load_vault_config, rotate_master_key_tx, update_security_prefs_row,
        NewVaultConfig,
    },
    schema::CURRENT_SCHEMA_VERSION,
};
use crate::error::{ErrorCode, VaultError, VaultResult};
use crate::state::{AppState, LockReason};

pub const MIN_MASTER_PASSWORD_CHARS: usize = 12;

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
}

#[derive(Debug, Serialize)]
pub struct SecurityPrefsDto {
    pub lock_timeout_secs: u64,
    pub clipboard_ttl_secs: u64,
    pub hello_enabled: bool,
    pub hello_available: bool,
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
}

#[tauri::command]
pub fn get_vault_status(state: State<'_, AppState>) -> VaultResult<VaultStatusDto> {
    let cfg = state.db.with_conn(|conn| Ok(load_vault_config(conn)?))?;
    Ok(VaultStatusDto {
        initialized: cfg.is_some(),
        locked: state.is_locked(),
        hello_enabled: cfg.as_ref().map(|c| c.hello_enabled).unwrap_or(false),
        hello_available: is_hello_available(),
    })
}

#[tauri::command]
pub async fn create_vault(
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
    if mp.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err(VaultError::validation(format!(
            "La contraseña maestra debe tener al menos {MIN_MASTER_PASSWORD_CHARS} caracteres."
        )));
    }

    let already_exists = state
        .db
        .with_conn(|conn| Ok(load_vault_config(conn)?.is_some()))?;
    if already_exists {
        return Err(VaultError::new(
            ErrorCode::VaultAlreadyInitialized,
            "Ya existe una bóveda inicializada en este equipo.",
        ));
    }

    let kdf_params = KdfParams::default();
    let salt = generate_salt();
    let (vault_key, sealed_vk) = tokio::task::spawn_blocking(move || -> VaultResult<_> {
        let mk = derive_key_argon2id(&mp, &salt, kdf_params)?;
        let vk = generate_random_key();
        let aad = mk_wrap_aad(
            CURRENT_SCHEMA_VERSION,
            &salt,
            kdf_params.mem_kib,
            kdf_params.iterations,
            kdf_params.parallelism,
        );
        let wrapped = wrap_vault_key(&mk, &vk, &aad)?;
        Ok((vk, wrapped))
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
                now,
            },
        )?;
        Ok(())
    })?;

    state.install_unlocked_key(vault_key, 300, 25)?;

    Ok(VaultSessionInfo {
        lock_timeout_secs: 300,
        clipboard_ttl_secs: 25,
        hello_enabled: false,
    })
}

#[tauri::command]
pub async fn unlock_with_password(
    state: State<'_, AppState>,
    input: UnlockPasswordInput,
) -> VaultResult<VaultSessionInfo> {
    let mp = Zeroizing::new(input.master_password);

    let cfg = state
        .db
        .with_conn(|conn| Ok(load_vault_config(conn)?))?
        .ok_or_else(|| {
            VaultError::new(
                ErrorCode::VaultNotInitialized,
                "Aún no se ha creado una bóveda local.",
            )
        })?;

    let salt = cfg.kdf_salt.clone();
    let nonce = cfg.mk_wrap_nonce.clone();
    let wrapped_vk = cfg.mk_wrapped_vk.clone();
    let schema_ver = cfg.schema_version;
    let params = KdfParams {
        mem_kib: cfg.kdf_mem_kib,
        iterations: cfg.kdf_iterations,
        parallelism: cfg.kdf_parallelism,
    };

    let vault_key = tokio::task::spawn_blocking(move || -> VaultResult<_> {
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
    .map_err(|_| VaultError::internal("Hilo KDF interrumpido al desbloquear."))??;

    state.install_unlocked_key(vault_key, cfg.lock_timeout_secs, cfg.clipboard_ttl_secs)?;

    state.with_unlocked_mut(|session| {
        crate::commands::vault::hydrate_session_index(&state.db, session)
    })?;

    Ok(VaultSessionInfo {
        lock_timeout_secs: cfg.lock_timeout_secs,
        clipboard_ttl_secs: cfg.clipboard_ttl_secs,
        hello_enabled: cfg.hello_enabled,
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
    state.with_unlocked(|_| {
        let cfg = state
            .db
            .with_conn(|conn| Ok(load_vault_config(conn)?))?
            .ok_or_else(|| VaultError::internal("Configuración de bóveda ausente."))?;
        Ok(SecurityPrefsDto {
            lock_timeout_secs: cfg.lock_timeout_secs,
            clipboard_ttl_secs: cfg.clipboard_ttl_secs,
            hello_enabled: cfg.hello_enabled,
            hello_available: is_hello_available(),
        })
    })
}

#[tauri::command]
pub fn update_security_prefs(
    state: State<'_, AppState>,
    input: UpdateSecurityPrefsInput,
) -> VaultResult<()> {
    if !(15..=3600).contains(&input.lock_timeout_secs) {
        return Err(VaultError::validation(
            "El tiempo de bloqueo automático debe estar entre 15 y 3600 segundos.",
        ));
    }
    if !(5..=300).contains(&input.clipboard_ttl_secs) {
        return Err(VaultError::validation(
            "El tiempo de limpieza del portapapeles debe estar entre 5 y 300 segundos.",
        ));
    }

    state.with_unlocked(|_| {
        let now = AppState::now_unix();
        state.db.with_conn(|conn| {
            update_security_prefs_row(
                conn,
                input.lock_timeout_secs,
                input.clipboard_ttl_secs,
                now,
            )?;
            Ok(())
        })?;
        state.set_security_prefs(input.lock_timeout_secs, input.clipboard_ttl_secs);
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

    if new_mp.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err(VaultError::validation(format!(
            "La nueva contraseña maestra debe tener al menos {MIN_MASTER_PASSWORD_CHARS} caracteres."
        )));
    }

    if state.is_locked() {
        return Err(VaultError::locked());
    }

    let cfg = state
        .db
        .with_conn(|conn| Ok(load_vault_config(conn)?))?
        .ok_or_else(|| VaultError::internal("Configuración de bóveda no encontrada."))?;

    let new_params = KdfParams::default();
    let new_salt = generate_salt();

    let old_params = KdfParams {
        mem_kib: cfg.kdf_mem_kib,
        iterations: cfg.kdf_iterations,
        parallelism: cfg.kdf_parallelism,
    };
    let old_salt = cfg.kdf_salt.clone();
    let old_nonce = cfg.mk_wrap_nonce.clone();
    let old_wrapped = cfg.mk_wrapped_vk.clone();
    let schema_ver = cfg.schema_version;

    // Re-autenticación criptográfica + re-envoltura de VK fuera del hilo principal
    let (unwrapped_old_vk, new_sealed_vk) =
        tokio::task::spawn_blocking(move || -> VaultResult<_> {
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
                schema_ver,
                &new_salt,
                new_params.mem_kib,
                new_params.iterations,
                new_params.parallelism,
            );
            let sealed_new = wrap_vault_key(&mk_new, &vk_from_disk, &new_aad)?;
            Ok((vk_from_disk, sealed_new))
        })
        .await
        .map_err(|_| VaultError::internal("Hilo KDF interrumpido al rotar contraseña maestra."))??;

    // Verifica en tiempo constante que la VK desenvuelta coincida con la sesión activa
    state.with_unlocked(|session| {
        if !session.vault_key.ct_eq(&unwrapped_old_vk) {
            return Err(VaultError::internal(
                "Discrepancia crítica de VaultKey en sesión activa.",
            ));
        }
        Ok(())
    })?;

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
    if !is_hello_available() {
        return Err(VaultError::validation(
            "Windows Hello no está configurado o disponible en este equipo.",
        ));
    }

    let cfg = state
        .db
        .with_conn(|conn| Ok(load_vault_config(conn)?))?
        .ok_or_else(|| VaultError::internal("Configuración de bóveda ausente."))?;

    let salt = cfg.kdf_salt.clone();
    let nonce = cfg.mk_wrap_nonce.clone();
    let wrapped_vk = cfg.mk_wrapped_vk.clone();
    let schema_ver = cfg.schema_version;
    let params = KdfParams {
        mem_kib: cfg.kdf_mem_kib,
        iterations: cfg.kdf_iterations,
        parallelism: cfg.kdf_parallelism,
    };

    let parent_hwnd = main_window_hwnd(&app);
    let key_name = format!("AegisVault.VK.{}", Uuid::new_v4());
    let key_name_for_worker = key_name.clone();
    let prev_key_to_clean = cfg.hello_key_name.clone();

    // 1. Reautenticación criptográfica de MP -> obtiene copia verificada de VK
    let verified_vk = tokio::task::spawn_blocking(move || -> VaultResult<_> {
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
    .map_err(|_| VaultError::internal("Hilo KDF interrumpido al habilitar Hello."))??;

    // 2. Comprobación en tiempo constante contra la sesión activa
    state.with_unlocked(|session| {
        if !session.vault_key.ct_eq(&verified_vk) {
            return Err(VaultError::invalid_credentials());
        }
        Ok(())
    })?;

    // 3. Enrolamiento en TPM/NGC en hilo bloqueante para no congelar el bucle de ventana
    let hello_wrapped_vk = tokio::task::spawn_blocking(move || {
        enroll_and_wrap_vault_key(&key_name_for_worker, &verified_vk, parent_hwnd)
    })
    .await
    .map_err(|_| VaultError::internal("Hilo NCrypt interrumpido al enrolar Hello."))??;

    let now = AppState::now_unix();
    state.db.with_conn(|conn| {
        set_hello_enrollment_row(conn, &key_name, &hello_wrapped_vk, now)?;
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
    if state.is_locked() {
        return Err(VaultError::locked());
    }

    let now = AppState::now_unix();
    let prev_key = state
        .db
        .with_conn(|conn| Ok(clear_hello_enrollment_row(conn, now)?))?;
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

    let (Some(key_name), Some(hello_wrapped)) =
        (cfg.hello_key_name.clone(), cfg.hello_wrapped_vk.clone())
    else {
        return Err(VaultError::new(
            ErrorCode::HelloInvalidated,
            "Windows Hello no está configurado para esta bóveda.",
        ));
    };

    if !cfg.hello_enabled {
        return Err(VaultError::new(
            ErrorCode::HelloInvalidated,
            "El desbloqueo con Windows Hello se encuentra deshabilitado.",
        ));
    }

    let parent_hwnd = main_window_hwnd(&app);
    let key_name_worker = key_name.clone();

    let unwrap_result = tokio::task::spawn_blocking(move || {
        unwrap_vault_key_with_hello(&key_name_worker, &hello_wrapped, parent_hwnd)
    })
    .await
    .map_err(|_| VaultError::internal("Hilo NCrypt interrumpido al desbloquear."))?;

    let vault_key = match unwrap_result {
        Ok(vk) => vk,
        Err(err) if err.code == ErrorCode::HelloInvalidated => {
            // Limpieza resiliente: si el PIN de Windows fue restablecido, desactivamos Hello
            // y dejamos intacta mk_wrapped_vk para entrar con Contraseña Maestra.
            let now = AppState::now_unix();
            let _ = state
                .db
                .with_conn(|conn| Ok(clear_hello_enrollment_row(conn, now)?));
            state.db.mark_dirty_deletes();
            delete_persisted_hello_key(&key_name);
            return Err(err);
        }
        Err(err) => return Err(err),
    };

    state.install_unlocked_key(vault_key, cfg.lock_timeout_secs, cfg.clipboard_ttl_secs)?;
    state.with_unlocked_mut(|session| {
        crate::commands::vault::hydrate_session_index(&state.db, session)
    })?;

    Ok(VaultSessionInfo {
        lock_timeout_secs: cfg.lock_timeout_secs,
        clipboard_ttl_secs: cfg.clipboard_ttl_secs,
        hello_enabled: true,
    })
}
