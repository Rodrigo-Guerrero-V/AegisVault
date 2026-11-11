// src-tauri/src/lib.rs
pub mod commands;
pub mod crypto;
pub mod db;
pub mod error;
pub mod platform;
pub mod state;

use std::time::Duration;
use tauri::{Manager, RunEvent};

use crate::db::{repo::load_vault_config, VaultDb};
use crate::state::{AppState, LockReason};

pub fn run() {
    let db = VaultDb::open_default().expect("Fallo crítico inicializando AegisVault SQLite");
    let (initial_timeout, initial_clip_ttl) = db
        .with_conn(|conn| Ok(load_vault_config(conn)?))
        .ok()
        .flatten()
        .map(|c| (c.lock_timeout_secs, c.clipboard_ttl_secs))
        .unwrap_or((300, 25));

    let app_state = AppState::new(db, initial_timeout, initial_clip_ttl);

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(app_state)
        .setup(|app| {
            let handle = app.handle().clone();
            platform::power_session::spawn_os_lock_watcher(handle.clone());

            tauri::async_runtime::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                loop {
                    interval.tick().await;
                    let state = handle.state::<AppState>();
                    state.check_inactivity_and_lock(&handle);
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::auth::get_vault_status,
            commands::auth::create_vault,
            commands::auth::unlock_with_password,
            commands::auth::unlock_with_hello,
            commands::auth::enable_windows_hello,
            commands::auth::disable_windows_hello,
            commands::auth::lock_vault,
            commands::auth::record_user_activity,
            commands::auth::get_security_prefs,
            commands::auth::update_security_prefs,
            commands::auth::change_master_password,
            commands::vault::list_vault_index,
            commands::vault::get_item_detail,
            commands::vault::save_item,
            commands::vault::delete_item,
            commands::vault::save_folder,
            commands::vault::delete_folder,
            commands::tools::generate_password,
            commands::tools::copy_item_field,
            commands::tools::copy_text_protected,
            commands::tools::clear_clipboard_now,
            commands::backup::export_encrypted_backup,
            commands::backup::restore_encrypted_backup,
            commands::backup::import_encrypted_backup,
        ])
        .build(tauri::generate_context!())
        .expect("Error construyendo instancia Tauri de AegisVault");

    app.run(|app_handle, event| {
        if let RunEvent::Exit = event {
            let state = app_handle.state::<AppState>();
            let _ = state.lock_now(None, LockReason::Manual);
        }
    });
}

#[cfg(test)]
mod phase1_tests {
    use crate::crypto::{
        aad::{encode_aad, mk_wrap_aad},
        aead::{unwrap_vault_key, wrap_vault_key},
        generator::{generate_password, PasswordGenOptions},
        kdf::{derive_key_argon2id, expand_vault_subkeys, generate_random_key, generate_salt, KdfParams},
        totp::generate_current_totp,
    };

    #[test]
    fn aad_length_prefix_prevents_boundary_collision() {
        let a = encode_aad(&[b"ab", b"c"]);
        let b = encode_aad(&[b"a", b"bc"]);
        assert_ne!(a, b);
    }

    #[test]
    fn nfc_normalization_and_wrong_password_rejection() {
        let params = KdfParams {
            mem_kib: 8192, // ligero solo para test unitario rápido
            iterations: 1,
            parallelism: 1,
        };
        let salt = generate_salt();

        // "ñ" precompuesta (U+00F1) vs descompuesta "n" + U+0303
        let composed = "Contrase\u{00f1}aSegura2026!";
        let decomposed = "Contrasen\u{0303}aSegura2026!";

        let mk1 = derive_key_argon2id(composed, &salt, params).unwrap();
        let mk2 = derive_key_argon2id(decomposed, &salt, params).unwrap();
        assert!(mk1.ct_eq(&mk2));

        let vk = generate_random_key();
        let aad = mk_wrap_aad(1, &salt, params.mem_kib, params.iterations, params.parallelism);
        let sealed = wrap_vault_key(&mk1, &vk, &aad).unwrap();

        // Desenvoltura exitosa con contraseña equivalente en NFC
        let unwrapped = unwrap_vault_key(&mk2, &sealed.nonce, &sealed.ciphertext, &aad).unwrap();
        assert!(vk.ct_eq(&unwrapped));

        // Alterar AAD (ej. alguien modifica iterations en vault_config) debe invalidar GCM
        let tampered_aad = mk_wrap_aad(1, &salt, params.mem_kib, 99, params.parallelism);
        assert!(unwrap_vault_key(&mk1, &sealed.nonce, &sealed.ciphertext, &tampered_aad).is_err());

        // Subclaves overview y secret deben ser criptográficamente distintas
        let sub = expand_vault_subkeys(&vk).unwrap();
        assert!(!sub.overview_key.ct_eq(&sub.secret_key));
    }

    #[test]
    fn generator_enforces_charsets_and_excludes_ambiguous() {
        let out = generate_password(&PasswordGenOptions {
            length: 24,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: true,
        })
        .unwrap();

        assert_eq!(out.value.len(), 24);
        assert!(!out.value.chars().any(|c| "0O1lI|".contains(c)));
        assert!(out.entropy_bits > 120.0);
    }

    #[test]
    fn totp_rfc6238_sha1_vector() {
        // Semilla RFC "12345678901234567890" en Base32 = GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        let dto = generate_current_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59).unwrap();
        assert_eq!(dto.code, "287082");
        assert_eq!(dto.remaining_secs, 1);
    }
}

#[cfg(test)]
mod phase2_tests {
    use rusqlite::Connection;
    use uuid::Uuid;

    use crate::commands::{
        backup::persist_snapshot_with_remap,
        vault::{decrypt_item_secret, OverviewPayload, SecretPayload},
    };
    use crate::crypto::{
        backup::{
            open_backup_bytes, seal_backup_bytes, BackupFolderRecord, BackupItemRecord,
            BackupSnapshot,
        },
        kdf::{expand_vault_subkeys, generate_random_key, KdfParams},
        memory::{ProtectedKey, KEY_LEN},
    };
    use crate::db::{
        repo::{get_raw_item_full, list_raw_folders, upsert_folder_row},
        schema::apply_pragmas_and_schema,
    };

    #[test]
    fn from_mut_bytes_zeroizes_caller_stack_buffer() {
        let mut caller_stack = [0xAAu8; KEY_LEN];
        let key = ProtectedKey::from_mut_bytes(&mut caller_stack);
        assert_eq!(caller_stack, [0u8; KEY_LEN]);
        assert_eq!(key.as_bytes(), &[0xAAu8; KEY_LEN]);
    }

    #[test]
    fn backup_roundtrip_and_header_tamper_detection() {
        let fast_kdf = KdfParams {
            mem_kib: 8_192,
            iterations: 1,
            parallelism: 1,
        };
        let folder_id = Uuid::new_v4().to_string();
        let item_id = Uuid::new_v4().to_string();

        let snap = BackupSnapshot {
            schema_version: 1,
            exported_at: 1_762_800_000,
            folders: vec![BackupFolderRecord {
                id: folder_id.clone(),
                name: "Infraestructura".into(),
                created_at: 100,
                updated_at: 100,
            }],
            items: vec![BackupItemRecord {
                id: item_id,
                folder_id: Some(folder_id),
                item_type: "login".into(),
                favorite: true,
                overview: OverviewPayload {
                    title: "PostgreSQL Prod".into(),
                    subtitle: "admin".into(),
                    urls: vec!["https://db.interno".into()],
                    tags: vec!["prod".into()],
                },
                secret: SecretPayload::Login {
                    username: "admin".into(),
                    password: "ClaveUltraSecreta#99".into(),
                    totp_uri: None,
                    notes: Some("Puerto 5432".into()),
                    password_history: vec![],
                },
                created_at: 100,
                updated_at: 100,
            }],
        };

        let mut blob = seal_backup_bytes(&snap, "RespaldoMaestro2026!", fast_kdf, 1_762_800_000).unwrap();
        let restored = open_backup_bytes(&blob, "RespaldoMaestro2026!").unwrap();
        assert_eq!(restored.folders.len(), 1);
        assert_eq!(restored.items.len(), 1);

        // Alterar un byte de CreatedAt en la cabecera en claro debe invalidar el AAD del GCM
        blob[10] ^= 0x01;
        assert!(open_backup_bytes(&blob, "RespaldoMaestro2026!").is_err());
    }

    #[test]
    fn import_remaps_colliding_folder_uuid_without_orphaning_items() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_pragmas_and_schema(&conn).unwrap();

        let vk = generate_random_key();
        let subkeys = expand_vault_subkeys(&vk).unwrap();

        // Insertamos una carpeta preexistente cuyo UUID colisionará con el del respaldo
        let colliding_folder_id = Uuid::new_v4().to_string();
        upsert_folder_row(&conn, &colliding_folder_id, &[1u8; 12], &[2u8; 32], 100).unwrap();

        let original_item_id = Uuid::new_v4().to_string();
        let snap = BackupSnapshot {
            schema_version: 1,
            exported_at: 200,
            folders: vec![BackupFolderRecord {
                id: colliding_folder_id.clone(),
                name: "Trabajo Importado".into(),
                created_at: 200,
                updated_at: 200,
            }],
            items: vec![BackupItemRecord {
                id: original_item_id.clone(),
                folder_id: Some(colliding_folder_id.clone()),
                item_type: "note".into(),
                favorite: false,
                overview: OverviewPayload {
                    title: "Llaves SSH".into(),
                    subtitle: "Ed25519".into(),
                    urls: vec![],
                    tags: vec![],
                },
                secret: SecretPayload::Note {
                    body: "ssh-ed25519 AAAA...".into(),
                },
                created_at: 200,
                updated_at: 200,
            }],
        };

        let stats = persist_snapshot_with_remap(&mut conn, &snap, &subkeys).unwrap();
        assert_eq!(stats.folders_imported, 1);
        assert_eq!(stats.items_imported, 1);

        let all_folders = list_raw_folders(&conn).unwrap();
        assert_eq!(all_folders.len(), 2);

        let new_folder_id = all_folders
            .iter()
            .map(|f| f.id.clone())
            .find(|id| id != &colliding_folder_id)
            .expect("Debe existir el nuevo UUID remapeado");

        let imported_item = get_raw_item_full(&conn, &original_item_id).unwrap().unwrap();
        assert_eq!(imported_item.folder_id.as_deref(), Some(new_folder_id.as_str()));

        let sec = decrypt_item_secret(
            &subkeys.secret_key,
            &imported_item.id,
            &imported_item.item_type,
            &imported_item.secret_nonce,
            &imported_item.secret_ciphertext,
        )
        .unwrap();
        assert!(matches!(sec, SecretPayload::Note { ref body } if body.starts_with("ssh-ed25519")));
    }
}
