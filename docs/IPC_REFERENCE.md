# AegisVault — Referencia IPC

Contrato entre el frontend React y el backend Rust (Tauri v2).

## Convenciones

- El string de `invoke` es el nombre Rust de la función (snake_case, ej.
  `"copy_text_protected"`); las funciones envoltorio de `commands.ts` son camelCase
  (ej. `copyTextProtected`). Los campos de struct van en snake_case.
- Las formas exactas de TypeScript viven en `src/types.ts`; si una forma de esta
  referencia contradice `types.ts`, manda `types.ts`.
- `SecretPayload` lleva tag `kind` (`login` / `card` / `note`, con TOTP opcional).
- Todos los comandos que operan sobre secretos exigen bóveda desbloqueada
  (si no, `VAULT_LOCKED`), salvo los de estado/creación/desbloqueo.
- Los errores llegan al frontend como `VaultError { code, message }`.

## Comandos de autenticación y estado

| Comando | Entrada | Salida / efecto | Errores típicos |
|---|---|---|---|
| `get_vault_status` | — | `{ initialized, locked, hello_available, hello_enabled }` | — |
| `create_vault` | `{ master_password }` | Crea la bóveda (MK + VK envuelta). Exige contraseña ≥12 y confirmación. | `VAULT_ALREADY_INITIALIZED`, `VALIDATION_ERROR` |
| `unlock_with_password` | `{ master_password }` | Instala la sesión; devuelve `VaultSessionInfo { lock_timeout_secs, clipboard_ttl_secs, hello_enabled }` | `INVALID_CREDENTIALS`, `VAULT_NOT_INITIALIZED` |
| `unlock_with_hello` | — | Desenvuelve la VK en TPM y abre la sesión (misma salida que arriba). Si Hello se invalidó, limpia el enrolamiento. | `HELLO_CANCELLED`, `HELLO_INVALIDATED`, `VAULT_NOT_INITIALIZED` |
| `enable_windows_hello` | `{ master_password }` | Reautentica la Maestra (unwrap + comparación en tiempo constante), enrola la clave RSA-2048 en TPM y guarda `hello_wrapped_vk`. | `INVALID_CREDENTIALS`, `HELLO_CANCELLED`, `VALIDATION_ERROR` (Hello no disponible) |
| `disable_windows_hello` | — | Limpia las columnas `hello_*` y destruye la clave TPM. | `VAULT_LOCKED` |
| `lock_vault` | — | Bloquea ahora: zeroize, purga WAL y portapapeles, evento `vault://locked`. | — |
| `record_user_activity` | — | Reinicia el temporizador de inactividad. | — |
| `get_security_prefs` | — | `{ lock_timeout_secs, clipboard_ttl_secs, hello_available, hello_enabled }` | — |
| `update_security_prefs` | `{ lock_timeout_secs?, clipboard_ttl_secs? }` | Persiste las preferencias. | `VALIDATION_ERROR` |
| `change_master_password` | `{ current_password, new_password }` | Re-envuelve la misma VK; invalida Hello; devuelve `{ hello_was_reset }`. | `INVALID_CREDENTIALS`, `VALIDATION_ERROR` |

## Comandos de bóveda

| Comando | Entrada | Salida / efecto | Errores típicos |
|---|---|---|---|
| `list_vault_index` | — | Índice de ítems y carpetas (títulos y metadatos, sin secretos). | `VAULT_LOCKED` |
| `get_item_detail` | `{ id }` | Ítem completo descifrado + TOTP vigente (`current_totp { code?, remaining_secs }`). | `VAULT_LOCKED` |
| `save_item` | `{ id?, title, folder_id?, favorite?, secret: SecretPayload }` | Crea o actualiza; valida título y contraseña no vacía en login; actualiza historial (tope 20). | `VALIDATION_ERROR`, `VAULT_LOCKED` |
| `delete_item` | `{ id }` | Borra el ítem y su historial. | `VAULT_LOCKED` |
| `save_folder` | `{ id?, name }` | Crea o renombra carpeta. | `VALIDATION_ERROR`, `VAULT_LOCKED` |
| `delete_folder` | `{ id }` | Borra la carpeta (los ítems quedan sin carpeta / según regla del repo). | `VAULT_LOCKED` |

## Comandos de herramientas

| Comando | Entrada | Salida / efecto | Errores típicos |
|---|---|---|---|
| `generate_password` | `{ length?, uppercase?, lowercase?, digits?, symbols? }` | `{ value, entropy_bits }` (CSPRNG, rejection sampling + Fisher-Yates). | `VALIDATION_ERROR` |
| `copy_item_field` | `{ id, field }` | Copia por el camino Win32 protegido; `field` ∈ `password, username, card_number, cvv, pin, totp, note_body`. Devuelve `{ expires_in_secs }`. | `VAULT_LOCKED`, `VALIDATION_ERROR` |
| `copy_text_protected` | `{ input: { text, field? } }` | Como el anterior, para texto libre (el generador usa `field: "generated_password"`). Rechaza texto vacío. Emite `vault://clipboard-armed`. | `VALIDATION_ERROR`, `VAULT_LOCKED` |
| `clear_clipboard_now` | — | Vacía el portapapeles si contiene el secreto activo (verifica digest). | — |

## Comandos de respaldo

| Comando | Entrada | Salida / efecto | Errores típicos |
|---|---|---|---|
| `export_encrypted_backup` | `{ backup_password, path? }` | Escribe el archivo `.aegisvault` (cabecera 57 bytes + cuerpo cifrado). | `VALIDATION_ERROR`, `VAULT_LOCKED` |
| `restore_encrypted_backup` | `{ backup_password, path }` | Restaura como bóveda nueva (atómico). | `BACKUP_CORRUPTED`, `VALIDATION_ERROR` |
| `import_encrypted_backup` | `{ backup_password, path }` | Importa en la bóveda actual regenerando UUIDs y remapeando `folder_id`. | `BACKUP_CORRUPTED`, `VALIDATION_ERROR` |

## Eventos (Rust → frontend)

| Evento | Payload | Cuándo |
|---|---|---|
| `vault://locked` | `{ reason }` (`reason`: manual / inactividad / `OsSessionLock` / `OsSuspend`) | Cada vez que la bóveda se bloquea. El frontend vuelve a la pantalla de desbloqueo. |
| `vault://clipboard-armed` | `{ expires_in_secs, label? }` | Tras un copiado protegido. El frontend muestra la píldora con cuenta atrás. |
| `vault://clipboard-cleared` | `{}` | Cuando la purga vació el portapapeles. El frontend oculta la píldora. |

## Códigos de error

| Código | Significado | Acción del frontend |
|---|---|---|
| `INVALID_CREDENTIALS` | Contraseña Maestra incorrecta. | Mostrar error en desbloqueo / cambio de contraseña; no revelar nada más. |
| `VAULT_LOCKED` | La bóveda está bloqueada. | Volver a la pantalla de desbloqueo. |
| `VAULT_ALREADY_INITIALIZED` | Ya existe una bóveda. | Ofrecer desbloqueo en vez de creación. |
| `VAULT_NOT_INITIALIZED` | Aún no hay bóveda. | Ir al onboarding. |
| `HELLO_CANCELLED` | El usuario canceló el gesto de Hello. | Mensaje neutro; quedarse en desbloqueo. |
| `HELLO_INVALIDATED` | La credencial Hello cambió o no carga (PIN reseteado, TPM). | Informar y ofrecer Contraseña Maestra (la bóveda sigue intacta). |
| `CONSENT_REQUIRED` | Falta una confirmación obligatoria (ej. `ack_no_recovery`). | Mostrar el consentimiento. |
| `VALIDATION_ERROR` | Entrada inválida (título vacío, contraseña de login vacía, etc.). | Mostrar el mensaje junto al campo. |
| `BACKUP_CORRUPTED` | Respaldo inválido o contraseña de respaldo incorrecta. | Pedir revisar archivo/contraseña. |
| `INTERNAL_ERROR` | Error interno inesperado. | Mensaje genérico + log. Nunca exponer detalles internos al usuario. |

## Notas de implementación (frontend)

- `commands.ts` centraliza los 24 `invoke`; `events.ts` centraliza los 3 listeners.
- El TOTP se recarga con un solo intento en vuelo (guard con ref); al llegar
  `remaining_secs` a 1 se pide el detalle nuevo una sola vez.
- Los borrados (`deleteItem`, `deleteFolder`) y `refreshPrefs` van con try/catch y
  feedback en UI; la navegación solo cambia si el borrado tuvo éxito.
- El generador copia SOLO con `copy_text_protected`. `navigator.clipboard` está
  prohibido en toda la app: no tiene banderas de exclusión ni purga.
