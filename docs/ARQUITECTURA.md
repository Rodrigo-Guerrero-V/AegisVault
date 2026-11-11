# AegisVault — Arquitectura

## 1. Vista general

Tauri v2. El frontend React + TypeScript dibuja la UI (WebView2) y el backend Rust
hace todo lo sensible: criptografía, base de datos, portapapeles y Windows Hello.
El frontend nunca ve claves: recibe índices y detalles ya descifrados por Rust, y
el copiado de secretos no pasa por JavaScript (ver §5).

```
┌──────────────────────────── React (src/) ────────────────────────────┐
│ Onboarding · Unlock · VaultView (3 col.) · ItemEditor · Generator   │
│ Settings · PasswordHistory · toasts · clip-pill (banner portapapeles)│
└────────────── Tauri IPC: invoke (comandos) / eventos ────────────────┘
┌──────────────────────────── Rust (src-tauri/src/) ───────────────────┐
│ commands/  auth · vault · tools · backup                             │
│ state.rs   AppState: sesión, prefs, clipboard guard                  │
│ crypto/    memory · kdf · aead · totp                                │
│ db/        schema · repo                                              │
│ platform/  acl · clipboard · windows_hello · power_session            │
│ error.rs   VaultError / ErrorCode                                     │
└──────────────────────────────────────────────────────────────────────┘
```

## 2. Mapa de módulos Rust

| Módulo | Responsabilidad |
|---|---|
| `lib.rs` | Entry: `setup` (levanta el watcher de sesión + el loop de inactividad cada 1 s), `manage(AppState)`, `invoke_handler` con los 24 comandos. |
| `error.rs` | `VaultError { code: ErrorCode, message: String }`, `VaultResult<T>`. Ver códigos en `IPC_REFERENCE.md`. |
| `crypto/memory.rs` | `ProtectedKey`: clave de 32 bytes en heap (`Box`), VirtualLock tolerante (flag `page_locked`), `zeroize` al soltar. `from_mut_bytes` limpia el buffer del llamador por contrato. |
| `crypto/kdf.rs` | Argon2id (64 MiB, t=3, p=4, contraseña NFC), `generate_random_key`, `expand_vault_subkeys` (HKDF-SHA256 → OverviewKey + SecretKey). |
| `crypto/aead.rs` | Envoltura de VK (AES-256-GCM), `encode_aad` canónico (`"AEGIS-AAD-V1"`, conteo u8, largos u32 LE). |
| `crypto/totp.rs` | TOTP RFC 6238. |
| `db/schema.rs` | Pragmas + esquema. `journal_mode = WAL`, `synchronous = FULL`, `foreign_keys = ON`, `secure_delete = ON`, `temp_store = MEMORY`. |
| `db/repo.rs` | Operaciones de config e ítems: carga de `vault_config`, `rotate_master_key_tx`, filas `hello_*`, CRUD. |
| `state.rs` | `AppState`: DB, sesión desbloqueada (VK + índice en memoria), prefs de seguridad, `ClipboardGuard`. `install_unlocked_key`, `lock_now`, `check_inactivity_and_lock`, `with_unlocked`. |
| `commands/auth.rs` | Estado, creación, desbloqueo (contraseña/Hello), bloqueo, prefs, rotación de Contraseña Maestra, enable/disable Hello. |
| `commands/vault.rs` | Índice, detalle, guardado/borrado de ítems y carpetas, hidratación resiliente por registro. |
| `commands/tools.rs` | Generador, `copy_item_field`, `copy_text_protected`, `clear_clipboard_now`. |
| `commands/backup.rs` | Export / restore / import `.aegisvault`. |
| `platform/acl.rs` | DACL de la DB: solo SYSTEM + SID del usuario. |
| `platform/clipboard.rs` | `ClipboardGuard`: copiado Win32 con exclusión, digest BLAKE3, TTL y purga con reintentos. |
| `platform/windows_hello.rs` | FFI NCrypt/TPM: enrolamiento, unwrap, borrado, disponibilidad, mapeo de errores. |
| `platform/power_session.rs` | Ventana oculta Win32 en hilo dedicado: Win+L / logoff / desconexión y suspensión. |

Tabla `vault_config` (id = 1): `kdf_salt`, `mk_wrap_nonce`, `mk_wrapped_vk`,
`schema_version`, `kdf_mem_kib`, `kdf_iterations`, `kdf_parallelism`,
`lock_timeout_secs`, `clipboard_ttl_secs`, `hello_enabled`, `hello_key_name`,
`hello_wrapped_vk`, `updated_at`.

## 3. Flujos principales

### 3.1 Crear bóveda
Contraseña Maestra (≥12, NFC) → Argon2id → MK → genera VK aleatoria → MK envuelve VK
(AES-256-GCM) → se guarda config + VK envuelta. Sin recuperación: el onboarding exige
el checkbox `ack_no_recovery`.

### 3.2 Desbloquear con contraseña
Argon2id (MK) → unwrap de VK → comparación en tiempo constante contra la sesión →
`install_unlocked_key` → hidratación del índice (resiliente: un ítem corrupto no
aborta el desbloqueo) → sesión activa con timeout de inactividad y TTL de portapapeles.

### 3.3 Desbloquear con Hello
`NCryptDecrypt` (TPM, RSA-OAEP-SHA256, con HWND para el diálogo modal) → VK directa
a `ProtectedKey` → misma instalación de sesión. Si Hello está invalidado, se limpian
las columnas `hello_*` y se cae a Contraseña Maestra.

### 3.4 Guardar un ítem
El frontend envía `SecretPayload` (tag `kind`: login / tarjeta / nota, con TOTP
opcional). Rust valida (título no vacío; login exige contraseña no vacía), cifra los
campos con SecretKey + AAD, guarda, y actualiza el historial (tope 20).

### 3.5 Copiar un secreto
El frontend NUNCA copia: invoca `copy_item_field` o `copy_text_protected`. Rust
escribe en el portapapeles Win32 con las 3 banderas de exclusión, arma el digest
BLAKE3 y emite `vault://clipboard-armed` (el banner con cuenta atrás). Al expirar el
TTL (o con `clear_clipboard_now` / al bloquear), verifica el digest y vacía solo si
el contenido sigue siendo el secreto. Ver `SPEC_v1.2_CONSOLIDADO.md` §4.

### 3.6 Respaldo y restauración
Export: contraseña de respaldo + salt fresco → Argon2id → BackupKey → cabecera de
57 bytes en claro (autenticada por AAD) + cuerpo cifrado. Restore/import: verifica
cabecera y AAD, regenera UUIDs y remapea `folder_id`, todo en una transacción atómica.

### 3.7 Rotación de Contraseña Maestra
Verifica la actual (unwrap + comparación en tiempo constante) → re-envuelve la MISMA
VK con la nueva MK → invalida Hello en la misma transacción → destruye la clave TPM
(`NCryptDeleteKey`). La VK no cambia: no hay que re-cifrar los ítems.

## 4. Ciclo de vida de la sesión

```
BLOQUEADA ──unlock (contraseña/Hello)──▶ DESBLOQUEADA
    ▲                                        │  inactividad
    │                                        │  lock_vault
    └──────── lock_now ◀── Win+L / logoff /──┘  suspensión
              (zeroize VK + purga WAL + evento vault://locked)
```

Al bloquear: la VK se sobrescribe con ceros, se emite `vault://locked` (con `reason`),
se purga el portapapeles si hay un secreto activo y se ejecuta `VACUUM` +
`wal_checkpoint(TRUNCATE)`.

## 5. Modelo de amenazas

**Protege contra:**
- Robo del archivo `vault.db` o del respaldo `.aegisvault` sin la contraseña
  (Argon2id + AES-256-GCM; el respaldo lleva sus propios parámetros KDF en cabecera).
- Historial de portapapeles de Windows (Win+V) y sincronización en la nube
  (formatos de exclusión + purga por TTL con verificación de digest).
- Miradas y sesiones olvidadas: bloqueo por inactividad, Win+L y suspensión.
- PIN de Windows cambiado o TPM reseteado: caída limpia a Contraseña Maestra,
  sin pérdida de la bóveda (la MK envuelta sigue intacta).
- Lectura de la DB por otros usuarios del equipo (DACL SYSTEM + usuario).

**Fuera de alcance (declarado):**
- Malware activo con la bóveda abierta (puede leer la memoria del proceso).
- Acceso físico con la sesión desbloqueada.
- Pérdida de la Contraseña Maestra sin respaldo: irrecuperable por diseño.

## 6. Frontend (src/)

- `types.ts`, `commands.ts` (24 comandos), `events.ts`, hooks.
- Vistas: `OnboardingView`, `UnlockView`, `VaultView` (sidebar 212 px / lista 308 px /
  detalle flexible), `SettingsSecurityView`.
- Componentes: `PasswordGeneratorModal`, `PasswordHistoryPopover`, `ItemEditorDrawer`.
- `theme.css`: tema oscuro petróleo-esmeralda. Referencia visual exacta:
  `aegisvault-mockup.html` + `estilos-mockup-para-gemini.md`.
