# AegisVault v1.0 — Spec v1.2 consolidada

Documento de referencia del proyecto. Recoge lo especificado y lo verificado en las
revisiones de las Fases 1–4 (ver `REVISIONES.md`). Si algo aquí contradice código
existente, el código manda solo si pasó `cargo test`; en caso contrario, esto manda.

## 1. Identidad y plataforma

- **Nombre:** AegisVault. **Paquete:** `com.aegisvault.desktop`.
- **Stack:** Tauri v2 (Rust + React + TypeScript), aplicación de escritorio **Windows**.
  Misma base compilable a Linux/Mac después; no es extensión ni página web.
  WebView2 solo dibuja la UI; el cerebro es Rust nativo.
- **Ventana:** 1120×740 (`tauri.conf.json`).
- **Modelo:** Zero-Knowledge / Local-First. Sin servidor, sin cuenta, sin recuperación:
  si se pierde la Contraseña Maestra y no hay respaldo `.aegisvault`, la bóveda es
  irrecuperable (el onboarding lo exige con checkbox `ack_no_recovery`).
- **Base de datos:** `%LOCALAPPDATA%\AegisVault\vault.db` (SQLite), con DACL que solo
  permite SYSTEM + SID del usuario.
- **Fuera de alcance declarado:** malware activo con la bóveda abierta.

## 2. Criptografía

- **Contraseña Maestra:** mínimo 12 caracteres, normalizada a NFC.
- **KDF:** Argon2id 64 MiB, t=3, p=4. La clave maestra (MK) envuelve la clave de bóveda
  (VK) de 32 bytes (envelope encryption).
- **Subclaves:** HKDF-SHA256 deriva OverviewKey y SecretKey desde la VK.
- **Cifrado:** AES-256-GCM con AAD canónico `encode_aad` (prefijo `"AEGIS-AAD-V1"`,
  conteo u8, largos u32 LE).
- **Claves en memoria:** `ProtectedKey` en heap (`Box`), VirtualLock tolerante
  (flag `page_locked`), `zeroize` al soltar. `ProtectedKey::from_mut_bytes(&mut [u8; 32])`
  limpia el buffer del llamador por contrato: ningún constructor copia claves por valor
  dejando residuos en el stack.
- **TOTP:** RFC 6238, calculado en Rust (`crypto/totp.rs`). Vector verificado: T=59 → 287082.
- **Generador de contraseñas:** CSPRNG con rejection sampling + Fisher-Yates
  (~153 bits a 24 caracteres).
- **Historial de contraseñas:** tope de 20 entradas por ítem.
- **SQLite:** `PRAGMA journal_mode = WAL`, `synchronous = FULL`, `foreign_keys = ON`,
  `secure_delete = ON`, `temp_store = MEMORY`. Al bloquear: `VACUUM` +
  `wal_checkpoint(TRUNCATE)` para purgar el WAL.

## 3. Windows Hello (Fase 4)

- Proveedor `MS_PASSPORT_KEY_STORAGE_PROVIDER` (Microsoft Passport KSP / NGC / TPM).
- Clave **RSA-2048** (longitud fijada explícita con `NCRYPT_LENGTH_PROPERTY`).
- La VK se envuelve con **RSA-OAEP-SHA256** usando la clave pública exportada
  (`BCRYPT_RSAPUBLIC_BLOB`); el envoltorio no pide gesto. Al desbloquear,
  `NCryptDecrypt` con `NCRYPT_PAD_OAEP_FLAG` y el HWND de la ventana principal
  (`NCRYPT_WINDOW_HANDLE_PROPERTY`) muestra el diálogo nativo de Windows Seguridad.
- Política de UI `NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG`: si no se puede aplicar,
  el enrolamiento aborta (nunca se persiste una clave degradada).
- Errores: cancelación del usuario → `HELLO_CANCELLED`; clave invalidada o
  `TPM_E_KEY_NOT_LOADED` (0x8029040F) → `HELLO_INVALIDATED` con limpieza de las
  columnas `hello_*` y vuelta suave a Contraseña Maestra. Nunca validación booleana.
- Rotación de Contraseña Maestra: verifica la actual por unwrap + comparación en
  tiempo constante, re-envuelve la misma VK, invalida Hello en la misma transacción
  y destruye la clave TPM (`NCryptDeleteKey`).

## 4. Portapapeles seguro (Fase 2, usado también por el generador)

- Copiado solo por el camino Win32 (`ClipboardGuard::copy_protected`), nunca por
  `navigator.clipboard` (el WebView no tiene banderas de exclusión).
- Tres formatos de exclusión: `ExcludeClipboardContentFromMonitorProcessing`,
  `CanIncludeInClipboardHistory`, `CanUploadToCloudClipboard` (DWORD 0).
- Digest BLAKE3 con clave de sesión + generación monotónica; la purga por TTL verifica
  el digest antes de vaciar, con reintentos (4×400 ms) y sin borrar el registro si el
  portapapeles está bloqueado (`PurgeStatus`: Cleared / ReplacedOrEmpty / LockedBusy).
- El comando `copy_text_protected` (tools.rs) es el único camino del generador.

## 5. Respaldo `.aegisvault`

- Contraseña de respaldo + salt fresco → Argon2id → BackupKey.
- Cabecera de 57 bytes en claro, autenticada por AAD: magic `"AEGISBAK"` (8 B),
  FormatVer u8, CreatedAt i64 LE, parámetros u32 LE (memoria, iteraciones, paralelismo),
  salt 16 B, nonce 12 B. Límites anti-DoS en lectura.
- Restauración: crea bóveda nueva o importa regenerando UUIDs y remapeando `folder_id`
  (sin huérfanos). La restauración es atómica (config + snapshot en una sola
  transacción Immediate).

## 6. Bloqueo

- Por inactividad (timeout configurable), por `lock_vault` explícito, y por eventos del
  SO escuchados en una ventana oculta Win32 en hilo dedicado (sin subclassing del
  WndProc de Tauri): `WM_WTSSESSION_CHANGE` (Win+L, logoff, desconexión de consola o
  remota) y `WM_POWERBROADCAST` / `PBT_APMSUSPEND` (suspensión/hibernación), con
  `zeroize` de claves y purga del WAL antes de dormir.

## 7. Contrato IPC (24 comandos)

Top-level en camelCase, campos de struct en snake_case, `SecretPayload` con tag `kind`.

- Auth: `get_vault_status`, `create_vault`, `unlock_with_password`, `unlock_with_hello`,
  `enable_windows_hello`, `disable_windows_hello`, `lock_vault`, `record_user_activity`,
  `get_security_prefs`, `update_security_prefs`, `change_master_password`
  (devuelve `hello_was_reset`).
- Bóveda: `list_vault_index`, `get_item_detail`, `save_item`, `delete_item`,
  `save_folder`, `delete_folder`.
- Herramientas: `generate_password` (valor + `entropy_bits`), `copy_item_field`
  (password/username/card_number/cvv/pin/totp/note_body), `copy_text_protected`,
  `clear_clipboard_now`.
- Respaldo: `export_encrypted_backup`, `restore_encrypted_backup`,
  `import_encrypted_backup`.

Eventos: `vault://locked` (con reason), `vault://clipboard-armed`,
`vault://clipboard-cleared`.

Errores: `INVALID_CREDENTIALS`, `VAULT_LOCKED`, `VAULT_ALREADY_INITIALIZED`,
`VAULT_NOT_INITIALIZED`, `HELLO_CANCELLED`, `HELLO_INVALIDATED`, `CONSENT_REQUIRED`,
`VALIDATION_ERROR`, `BACKUP_CORRUPTED`, `INTERNAL_ERROR`.

Reglas de UI verificadas: un login no se guarda con contraseña vacía; el TOTP se
recarga una sola vez en vuelo; los borrados y `refreshPrefs` tienen manejo de errores
con feedback; los mensajes de éxito usan la clase verde `alert-ok`.

## 8. Frontend (Fase 3)

- React + TypeScript, Tauri v2. `capabilities/default.json`, `types.ts`, `commands.ts`,
  `events.ts`, hooks, `theme.css`.
- Componentes: `PasswordGeneratorModal`, `PasswordHistoryPopover`, `ItemEditorDrawer`,
  `OnboardingView`, `UnlockView`, `SettingsSecurityView`, `VaultView` (3 columnas),
  `App.tsx`.
- Estilo: oscuro petróleo-esmeralda. La referencia visual exacta es
  `aegisvault-mockup.html` + `estilos-mockup-para-gemini.md` (tokens y medidas).
- Íconos lucide: usar `PenLine`, `TriangleAlert`, `WandSparkles`
  (`Edit3` / `AlertTriangle` / `Wand2` son alias deprecados, se eliminan en v1.0).

## 9. Tests y verificación

- 10 tests unitarios en Rust: 4 de Fase 1 (`phase1_tests`), 3 de Fase 2
  (`phase2_tests`), 3 de Fase 4 (`phase4_hello_tests`, incluido el envoltorio real
  BCrypt RSA-2048 OAEP-SHA256 de 256 bytes).
- Comandos (en Windows):
  - `npm install`
  - `cd src-tauri` → `cargo test -- --nocapture` (10 en verde)
  - `npm run tauri dev` (desarrollo con recarga en caliente)
  - `npm run tauri build` (instalador .msi / .exe NSIS)
- Entorno: si la carpeta se armó a mano sin `create-tauri-app`, se requiere
  `src-tauri/build.rs` con `fn main() { tauri_build::build() }` y al menos
  `src-tauri/icons/icon.ico` (o `npx tauri icon ruta/logo.png`).
