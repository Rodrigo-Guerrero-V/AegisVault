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
use crate::state::{
    clamp_security_timers, AppState, LockReason, DEFAULT_CLIPBOARD_TTL_SECS,
    DEFAULT_LOCK_TIMEOUT_SECS,
};

pub fn run() {
    let db = VaultDb::open_default().unwrap_or_else(|err| {
        panic!("Fallo crítico inicializando AegisVault SQLite: {err}");
    });

    let (initial_timeout, initial_clip_ttl) = db
        .with_conn(|conn| Ok(load_vault_config(conn)?))
        .ok()
        .flatten()
        .map(|c| clamp_security_timers(c.lock_timeout_secs, c.clipboard_ttl_secs))
        .unwrap_or((DEFAULT_LOCK_TIMEOUT_SECS, DEFAULT_CLIPBOARD_TTL_SECS));

    let app_state = AppState::new(db, initial_timeout, initial_clip_ttl);

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(app_state)
        .setup(|app| {
            let handle = app.handle().clone();
            // Activa protección anticaptura (WDA_EXCLUDEFROMCAPTURE) desde el primer fotograma
            platform::window_privacy::apply_window_capture_protection(&handle, true);
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
            commands::backup::select_restore_backup_file,
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
        kdf::{
            derive_key_argon2id, expand_vault_subkeys, generate_random_key, generate_salt,
            KdfParams,
        },
        totp::{generate_current_totp, validate_totp_input},
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
            mem_kib: 8192,
            iterations: 1,
            parallelism: 1,
        };
        let salt = generate_salt();

        let composed = "Contrase\u{00f1}aSegura2026!";
        let decomposed = "Contrasen\u{0303}aSegura2026!";

        let mk1 = derive_key_argon2id(composed, &salt, params).unwrap();
        let mk2 = derive_key_argon2id(decomposed, &salt, params).unwrap();
        assert!(mk1.ct_eq(&mk2));

        let vk = generate_random_key();
        let aad = mk_wrap_aad(2, &salt, params.mem_kib, params.iterations, params.parallelism);
        let sealed = wrap_vault_key(&mk1, &vk, &aad).unwrap();

        let unwrapped = unwrap_vault_key(&mk2, &sealed.nonce, &sealed.ciphertext, &aad).unwrap();
        assert!(vk.ct_eq(&unwrapped));

        let tampered_aad = mk_wrap_aad(2, &salt, params.mem_kib, 99, params.parallelism);
        assert!(unwrap_vault_key(&mk1, &sealed.nonce, &sealed.ciphertext, &tampered_aad).is_err());

        let sub = expand_vault_subkeys(&vk).unwrap();
        assert!(!sub.overview_key.ct_eq(&sub.secret_key));
        assert!(!sub.overview_key.ct_eq(&sub.config_mac_key));
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
        let dto = generate_current_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59).unwrap();
        assert_eq!(dto.code, "287082");
        assert_eq!(dto.remaining_secs, 1);
    }

    #[test]
    fn totp_rfc6238_sha256_sha512_8digits_and_percent_encoded_uri() {
        // RFC 6238 Apéndice B — SHA256 (32B ASCII "12345678901234567890123456789012") con padding %3D
        let uri_sha256 = "otpauth://totp/ACME:alice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA%3D%3D%3D%3D&algorithm=SHA256&digits=8&period=30";
        let dto256 = generate_current_totp(uri_sha256, 59).unwrap();
        assert_eq!(dto256.code, "46119246");
        assert_eq!(dto256.digits, 8);

        // RFC 6238 Apéndice B — SHA512 (64B ASCII) con period=60 en t=119 -> T=1
        let uri_sha512 = "otpauth://totp/Root?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA%3D&algorithm=SHA512&digits=8&period=60";
        let dto512 = generate_current_totp(uri_sha512, 119).unwrap();
        assert_eq!(dto512.code, "90693936");
        assert_eq!(dto512.remaining_secs, 1);

        // Rechaza HOTP, dígitos fuera de rango y codificación % truncada
        assert!(validate_totp_input("otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(validate_totp_input("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=5").is_err());
        assert!(validate_totp_input("otpauth://totp/Test?secret=JBSWY3DP%3").is_err());
    }

    #[test]
    fn totp_multibyte_char_at_byte_boundary_does_not_panic() {
        // 9 bytes ASCII + 'é' (2 bytes UTF-8 en índices 9..11) + '…': antes provocaba panic en `input[..10]`
        let multibyte_at_9 = "123456789é…";
        assert!(validate_totp_input(multibyte_at_9).is_err());
        assert!(generate_current_totp(multibyte_at_9, 59).is_err());

        // Variantes adicionales con secuencias UTF-8 de 2, 3 y 4 bytes cruzando el byte 10
        for sample in ["123456789ñX", "12345678€abc", "1234567🔐test", "otpauth:/é?secret=JBSWY3DPEHPK3PXP"] {
            assert!(validate_totp_input(sample).is_err());
            assert!(generate_current_totp(sample, 59).is_err());
        }
    }
}

#[cfg(test)]
mod phase2_tests {
    use rusqlite::{params, Connection};
    use uuid::Uuid;

    use crate::commands::{
        auth::{migrate_v1_to_v2, open_security_prefs},
        backup::{
            collect_export_snapshot, ensure_aegisvault_extension, persist_snapshot_with_remap,
            read_bounded_backup_file, write_backup_file_safely,
        },
        vault::{decrypt_item_secret, hydrate_session_index, OverviewPayload, SecretPayload},
    };
    use crate::crypto::{
        aad::{folder_aad, item_overview_aad, item_secret_aad, mk_wrap_aad},
        aead::{encrypt_with_aad, wrap_vault_key},
        backup::{
            open_backup_bytes, seal_backup_bytes, BackupFolderRecord, BackupItemRecord,
            BackupSnapshot,
        },
        kdf::{
            derive_key_argon2id, expand_vault_subkeys, generate_random_key, generate_salt,
            validate_kdf_params, validate_password_strength, verify_hello_mac, KdfParams,
        },
        memory::{ProtectedKey, KEY_LEN, PROTECTED_PAGE_SIZE},
    };
    use crate::db::{
        repo::{
            get_raw_item_full, insert_item_row, list_raw_folders, load_vault_config,
            upsert_folder_row, UpsertItemRow,
        },
        schema::{apply_pragmas_and_schema, CURRENT_SCHEMA_VERSION, LEGACY_SCHEMA_VERSION},
        VaultDb,
    };
    use crate::error::ErrorCode;
    use crate::platform::windows_hello::is_valid_hello_key_name;
    use crate::state::AppState;

    #[test]
    fn from_mut_bytes_zeroizes_caller_stack_buffer() {
        let mut caller_stack = [0xAAu8; KEY_LEN];
        let key = ProtectedKey::from_mut_bytes(&mut caller_stack);
        assert_eq!(caller_stack, [0u8; KEY_LEN]);
        assert_eq!(key.as_bytes(), &[0xAAu8; KEY_LEN]);
    }

    #[test]
    fn protected_key_virtual_alloc_pages_are_isolated() {
        let mut raw_mk = [0x11u8; KEY_LEN];
        let mut raw_vk = [0x22u8; KEY_LEN];
        let mk = ProtectedKey::from_mut_bytes(&mut raw_mk);
        let vk = ProtectedKey::from_mut_bytes(&mut raw_vk);

        #[cfg(windows)]
        {
            assert_ne!(
                mk.page_addr() / PROTECTED_PAGE_SIZE,
                vk.page_addr() / PROTECTED_PAGE_SIZE,
                "MasterKey y VaultKey deben residir en páginas físicas/virtuales distintas"
            );
            assert!(vk.is_page_locked());
        }

        // Destruir `mk` ejecuta VirtualUnlock sobre su propia página sin desbloquear ni alterar `vk`
        drop(mk);
        assert_eq!(vk.as_bytes(), &[0x22u8; KEY_LEN]);
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
            schema_version: CURRENT_SCHEMA_VERSION,
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

        let mut blob =
            seal_backup_bytes(&snap, "RespaldoMaestro2026!", fast_kdf, 1_762_800_000).unwrap();
        let restored = open_backup_bytes(&blob, "RespaldoMaestro2026!").unwrap();
        assert_eq!(restored.folders.len(), 1);
        assert_eq!(restored.items.len(), 1);

        blob[10] ^= 0x01;
        assert!(open_backup_bytes(&blob, "RespaldoMaestro2026!").is_err());
    }

    #[test]
    fn import_remaps_colliding_folder_uuid_without_orphaning_items_and_deduplicates_repeat_import() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_pragmas_and_schema(&conn).unwrap();

        let vk = generate_random_key();
        let subkeys = expand_vault_subkeys(&vk).unwrap();

        let colliding_folder_id = Uuid::new_v4().to_string();
        upsert_folder_row(&conn, &colliding_folder_id, &[1u8; 12], &[2u8; 32], 100).unwrap();

        let original_item_id = Uuid::new_v4().to_string();
        let snap = BackupSnapshot {
            schema_version: CURRENT_SCHEMA_VERSION,
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
        assert_eq!(stats.folders_skipped, 0);
        assert_eq!(stats.items_skipped, 0);

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
            CURRENT_SCHEMA_VERSION,
            &imported_item.id,
            &imported_item.item_type,
            &imported_item.secret_nonce,
            &imported_item.secret_ciphertext,
        )
        .unwrap();
        assert!(matches!(sec, SecretPayload::Note { ref body } if body.starts_with("ssh-ed25519")));

        // Reimportar la misma instantánea no debe duplicar carpetas ni ítems
        let second_stats = persist_snapshot_with_remap(&mut conn, &snap, &subkeys).unwrap();
        assert_eq!(second_stats.folders_imported, 0);
        assert_eq!(second_stats.items_imported, 0);
        assert_eq!(second_stats.folders_skipped, 1);
        assert_eq!(second_stats.items_skipped, 1);
        assert_eq!(list_raw_folders(&conn).unwrap().len(), 2);
    }

    #[test]
    fn password_entropy_policy_rejects_weak_and_accepts_strong() {
        for weak in [
            "corto123!",
            "aaaaaaaaaaaa",
            "123456789012",
            "password12345",
            "qwertyuiop123",
            "aegisvault2026",
        ] {
            assert!(
                validate_password_strength(weak, "La contraseña maestra").is_err(),
                "Debió rechazar contraseña débil: {weak}"
            );
        }

        assert!(validate_password_strength("Tr0ub4dor&CaballoAzul#91", "La contraseña maestra").is_ok());
        assert!(validate_password_strength("umbra-farol-nexo-74-plomo", "La contraseña maestra").is_ok());
    }

    #[test]
    fn kdf_bounds_reject_dos_parameters_on_config_and_backup() {
        assert!(validate_kdf_params(
            KdfParams {
                mem_kib: 1024,
                iterations: 3,
                parallelism: 4
            },
            ErrorCode::DataCorrupted
        )
        .is_err());

        assert!(validate_kdf_params(
            KdfParams {
                mem_kib: 2_097_152, // 2 GiB -> rechazado
                iterations: 3,
                parallelism: 4
            },
            ErrorCode::DataCorrupted
        )
        .is_err());

        assert!(validate_kdf_params(
            KdfParams {
                mem_kib: 65_536,
                iterations: 99,
                parallelism: 4
            },
            ErrorCode::DataCorrupted
        )
        .is_err());
    }

    #[test]
    fn hello_key_name_validator_blocks_injection_and_foreign_keys() {
        let valid = format!("AegisVault.VK.{}", Uuid::new_v4());
        assert!(is_valid_hello_key_name(&valid));

        for invalid in [
            "",
            "AegisVault.VK.",
            "AegisVault.VK.not-a-uuid-at-all-1234567890123456",
            "AegisVault.VK.550E8400-E29B-41D4-A716-446655440000", // mayúsculas no permitidas
            "MicrosoftPassportKey",
            "../AegisVault.VK.550e8400-e29b-41d4-a716-446655440000",
            "AegisVault.VK.550e8400-e29b-41d4-a716-446655440000/extra",
        ] {
            assert!(
                !is_valid_hello_key_name(invalid),
                "Debió rechazar nombre NGC inválido: {invalid}"
            );
        }
    }

    #[test]
    fn v1_to_v2_migration_clamps_timers_binds_keys_and_detects_tampering() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_pragmas_and_schema(&conn).unwrap();

        let params = KdfParams {
            mem_kib: 8_192,
            iterations: 1,
            parallelism: 1,
        };
        let salt = generate_salt();
        let mk = derive_key_argon2id("ClaveMigracionSegura#2026", &salt, params).unwrap();
        let vk = generate_random_key();
        let subkeys = expand_vault_subkeys(&vk).unwrap();

        // Simula una bóveda v1 con lock_timeout_secs=0 (ataque offline) y un ítem cifrado con AAD v1
        let aad_v1 = mk_wrap_aad(LEGACY_SCHEMA_VERSION, &salt, 8_192, 1, 1);
        let wrapped_v1 = wrap_vault_key(&mk, &vk, &aad_v1).unwrap();
        conn.execute(
            "INSERT INTO vault_config (
                id, schema_version, kdf_salt, kdf_mem_kib, kdf_iterations, kdf_parallelism,
                mk_wrapped_vk, mk_wrap_nonce, hello_enabled, lock_timeout_secs, clipboard_ttl_secs,
                created_at, updated_at
            ) VALUES (1, 1, ?1, 8192, 1, 1, ?2, ?3, 0, 0, 99999, 100, 100)",
            params![salt, wrapped_v1.ciphertext, wrapped_v1.nonce],
        )
        .unwrap();

        let folder_id = Uuid::new_v4().to_string();
        let f_sealed = encrypt_with_aad(
            &subkeys.overview_key,
            b"Personal",
            &folder_aad(LEGACY_SCHEMA_VERSION, &folder_id),
        )
        .unwrap();
        upsert_folder_row(&conn, &folder_id, &f_sealed.nonce, &f_sealed.ciphertext, 100).unwrap();

        let item_id = Uuid::new_v4().to_string();
        let ov_json = serde_json::to_vec(&OverviewPayload {
            title: "Correo".into(),
            subtitle: "user@test.cl".into(),
            urls: vec![],
            tags: vec![],
        })
        .unwrap();
        let sec_json = serde_json::to_vec(&SecretPayload::Note {
            body: "secreto-v1".into(),
        })
        .unwrap();
        let ov_v1 = encrypt_with_aad(
            &subkeys.overview_key,
            &ov_json,
            &item_overview_aad(LEGACY_SCHEMA_VERSION, &item_id, "note"),
        )
        .unwrap();
        let sec_v1 = encrypt_with_aad(
            &subkeys.secret_key,
            &sec_json,
            &item_secret_aad(LEGACY_SCHEMA_VERSION, &item_id, "note"),
        )
        .unwrap();
        insert_item_row(
            &conn,
            &UpsertItemRow {
                id: &item_id,
                folder_id: Some(&folder_id),
                item_type: "note",
                favorite: false,
                overview_nonce: &ov_v1.nonce,
                overview_ciphertext: &ov_v1.ciphertext,
                secret_nonce: &sec_v1.nonce,
                secret_ciphertext: &sec_v1.ciphertext,
                now: 100,
            },
        )
        .unwrap();

        let cfg_v1 = load_vault_config(&conn).unwrap().unwrap();
        let (migrated_prefs, hello_after) =
            migrate_v1_to_v2(&mut conn, &mk, &vk, &subkeys, &cfg_v1, 200).unwrap();
        assert!(!hello_after);
        assert_eq!(migrated_prefs.lock_timeout_secs, 15);
        assert_eq!(migrated_prefs.clipboard_ttl_secs, 300);

        let cfg_v2 = load_vault_config(&conn).unwrap().unwrap();
        assert_eq!(cfg_v2.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(
            cfg_v2.vk_keycheck.as_deref(),
            Some(subkeys.keycheck_tag.as_slice())
        );
        assert!(verify_hello_mac(
            &subkeys.config_mac_key,
            CURRENT_SCHEMA_VERSION,
            false,
            None,
            None,
            cfg_v2.hello_mac.as_deref().unwrap()
        ));

        // El ítem migrado se descifra con AAD v2
        let raw_after = get_raw_item_full(&conn, &item_id).unwrap().unwrap();
        let dec = decrypt_item_secret(
            &subkeys.secret_key,
            CURRENT_SCHEMA_VERSION,
            &item_id,
            "note",
            &raw_after.secret_nonce,
            &raw_after.secret_ciphertext,
        )
        .unwrap();
        assert_eq!(
            dec,
            SecretPayload::Note {
                body: "secreto-v1".into()
            }
        );

        // Alterar un byte de prefs_ciphertext dispara ErrorCode::DataCorrupted
        let mut tampered_ct = cfg_v2.prefs_ciphertext.unwrap();
        tampered_ct[0] ^= 0xFF;
        let err = open_security_prefs(
            &subkeys.overview_key,
            CURRENT_SCHEMA_VERSION,
            cfg_v2.prefs_nonce.as_deref(),
            Some(&tampered_ct),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::DataCorrupted);
    }

    #[test]
    fn corrupted_row_surfaces_count_and_allows_recovery_export() {
        let temp_db_path =
            std::env::temp_dir().join(format!("aegis_corrupt_test_{}.db", Uuid::new_v4()));
        let db = VaultDb::open_at(&temp_db_path).unwrap();
        let state = AppState::new(db, 0, 0);
        // AppState::new(db, 0, 0) debe acotar automáticamente a (15, 5)
        assert_eq!(state.security_prefs(), (15, 5));

        let vk = generate_random_key();
        state.install_unlocked_key(vk, 300, 25, true).unwrap();

        let good_id = Uuid::new_v4().to_string();
        let bad_id = Uuid::new_v4().to_string();

        state
            .with_unlocked(|session| {
                let ov = serde_json::to_vec(&OverviewPayload {
                    title: "Intacto".into(),
                    subtitle: "ok".into(),
                    urls: vec![],
                    tags: vec![],
                })
                .unwrap();
                let sec = serde_json::to_vec(&SecretPayload::Note {
                    body: "dato sano".into(),
                })
                .unwrap();
                let s_ov = encrypt_with_aad(
                    &session.subkeys.overview_key,
                    &ov,
                    &item_overview_aad(CURRENT_SCHEMA_VERSION, &good_id, "note"),
                )
                .unwrap();
                let s_sec = encrypt_with_aad(
                    &session.subkeys.secret_key,
                    &sec,
                    &item_secret_aad(CURRENT_SCHEMA_VERSION, &good_id, "note"),
                )
                .unwrap();

                state.db.with_conn(|conn| {
                    insert_item_row(
                        conn,
                        &UpsertItemRow {
                            id: &good_id,
                            folder_id: None,
                            item_type: "note",
                            favorite: false,
                            overview_nonce: &s_ov.nonce,
                            overview_ciphertext: &s_ov.ciphertext,
                            secret_nonce: &s_sec.nonce,
                            secret_ciphertext: &s_sec.ciphertext,
                            now: 100,
                        },
                    )?;
                    // Ítem corrupto con ciphertext inválido
                    insert_item_row(
                        conn,
                        &UpsertItemRow {
                            id: &bad_id,
                            folder_id: None,
                            item_type: "note",
                            favorite: false,
                            overview_nonce: &[9u8; 12],
                            overview_ciphertext: &[7u8; 32],
                            secret_nonce: &[8u8; 12],
                            secret_ciphertext: &[6u8; 32],
                            now: 100,
                        },
                    )?;
                    Ok(())
                })
            })
            .unwrap();

        state
            .with_unlocked_mut(|session| {
                hydrate_session_index(&state.db, session)?;
                assert_eq!(session.corrupted_count, 1);
                assert_eq!(session.items_cache.len(), 1);

                // Exportación normal separa DATA_CORRUPTED de INVALID_CREDENTIALS
                let err = collect_export_snapshot(&state.db, &session.subkeys, 200, false)
                    .unwrap_err();
                assert_eq!(err.code, ErrorCode::DataCorrupted);

                // Exportación con skip_corrupted=true rescata el ítem sano
                let (snap, skipped) =
                    collect_export_snapshot(&state.db, &session.subkeys, 200, true).unwrap();
                assert_eq!(skipped, 1);
                assert_eq!(snap.items.len(), 1);
                assert_eq!(snap.items[0].id, good_id);
                Ok(())
            })
            .unwrap();

        // Verifica backoff tras intento fallido
        assert!(state.check_unlock_backoff().is_ok());
        let delay = state.record_unlock_failure();
        assert!(delay >= 1);
        assert_eq!(
            state.check_unlock_backoff().unwrap_err().code,
            ErrorCode::RateLimited
        );
        state.reset_unlock_backoff();
        assert!(state.check_unlock_backoff().is_ok());

        drop(state);
        let _ = std::fs::remove_file(&temp_db_path);
    }

    #[test]
    fn backup_file_io_enforces_extension_and_bounded_read() {
        assert!(ensure_aegisvault_extension(std::path::Path::new("malicioso.exe")).is_err());
        assert!(ensure_aegisvault_extension(std::path::Path::new("notas.txt")).is_err());
        assert!(ensure_aegisvault_extension(std::path::Path::new("copia.AEGISVAULT")).is_ok());

        let tmp_path =
            std::env::temp_dir().join(format!("aegis_io_test_{}.aegisvault", Uuid::new_v4()));
        write_backup_file_safely(&tmp_path, b"AEGISBAK_TEST_PAYLOAD").unwrap();
        let read_back = read_bounded_backup_file(&tmp_path).unwrap();
        assert_eq!(read_back, b"AEGISBAK_TEST_PAYLOAD");
        let _ = std::fs::remove_file(&tmp_path);
    }
}
