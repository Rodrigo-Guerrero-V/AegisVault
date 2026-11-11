<!-- NOTA DE PROCEDENCIA (no forma parte del texto original) -->
<!-- Este archivo reune los dos unicos textos de especificacion pegados por Rodrigo en el chat principal: -->
<!--  (a) el Spec v1.0 integro, mensaje de usuario 2026-11-10 23:37:47 -03 (message_id 03b2a72d-744c-4122-88a2-db7123b55756); -->
<!--  (b) el cierre del Spec v1.2 (tres micro-ajustes), seccion 1 del mensaje de usuario 2026-11-10 23:50:18 -03 -->
<!--      (message_id b493fefb-70b0-4e14-85cd-395b45b3d089), que tambien contiene la Fase 1. -->
<!-- No existe en el historial un paste independiente con el texto completo del Spec v1.2; -->
<!-- el v1.2 es el v1.0 mas estos tres micro-ajustes. Ambos bloques se reproducen verbatim, sin editar. -->

Esta especificación técnica (**Spec v1.0**) establece la arquitectura de seguridad, criptografía, persistencia y ciclo de vida en memoria para la aplicación de escritorio en **Tauri v2 (Rust + React)** sobre Windows, bajo un modelo estricto *Zero-Knowledge* y *Local-First*.

---

## 1. Modelo de Amenazas y Frontera de Confianza

El diseño divide la aplicación en dos zonas con distinto nivel de privilegio: el **Core en Rust** (única zona de confianza donde residen claves criptográficas, el generador CSPRNG, SQLite y la integración con APIs Win32/TPM) y el **WebView en React** (tratado como cliente no confiable de solo presentación, sin acceso a claves ni secretos crudos salvo solicitud puntual del usuario).

| Vector de amenaza | Estado en v1 | Mitigación de arquitectura |
| --- | --- | --- |
| **Robo en frío del disco o copia de la base de datos** | **Mitigado** | Todo registro (incluyendo títulos, usuarios y URLs) se almacena cifrado con `AES-256-GCM`; SQLite opera con `secure_delete = ON` para sobrescribir páginas borradas. |
| **Fuerza bruta offline (GPU/ASIC) contra la Contraseña Maestra** | **Mitigado** | Derivación con `Argon2id` de alto costo en memoria y verificación implícita mediante el tag de autenticación AEAD, sin guardar hashes de validación. |
| **Bypass en memoria de Windows Hello** | **Mitigado** | No se usa una validación booleana (`UserConsentVerifier`); la clave se envuelve criptográficamente en el TPM mediante `NCrypt` (`Microsoft Passport Key Storage Provider`), exigiendo el gesto biométrico/PIN en hardware para descifrar los bytes. |
| **Fuga en Historial del Portapapeles (`Win + V`) o Cloud Sync** | **Mitigado** | Inyección de banderas nativas Win32 que excluyen el secreto del monitoreo del historial de Windows y de la sincronización en la nube, sumado a purga temporizada. |
| **Volcado de claves a disco por paginación o hibernación** | **Mitigado** | Las claves activas en RAM se alojan en buffers protegidos con `VirtualLock` y se sobrescriben con ceros (`zeroize`) al bloquear o cerrar el proceso. |
| **XSS o inspección accidental del DOM en React** | **Mitigado** | CSP estricta sin conexiones externas (`connect-src 'none'`), aislamiento de claves en Rust y descifrado perezoso (*lazy decryption*): las contraseñas nunca viajan en el listado inicial hacia React. |
| **Malware activo ejecutándose como el mismo usuario con bóveda abierta** | **Fuera de alcance** | Un proceso malicioso local con permisos de depuración (`ReadProcessMemory` o keylogger de sesión) mientras la bóveda está desbloqueada compromete cualquier app de usuario en Windows; se reduce la ventana de exposición con bloqueo agresivo. |

---

## 2. Diseño Criptográfico y Jerarquía de Claves

Para permitir que la Contraseña Maestra (`MP`) sea siempre la raíz soberana y que Windows Hello actúe únicamente como un atajo opcional revocable sin almacenar jamás la `MP`, se utiliza **Envelope Encryption (Envoltura de Claves)**:

```text
[Contraseña Maestra (UTF-8 NFC)]                [Gesto / PIN Windows Hello]
               │                                             │
     Argon2id (salt 16B)                         TPM / Microsoft Passport KSP
   (m=64 MiB, t=3, p=4)                            (RSA-2048 OAEP-SHA256)
               ▼                                             ▼
      MasterKey (MK, 32B)                           Desencriptado en TPM
               │                                             │
    AES-256-GCM Unwrap                             Unwrap hello_wrapped_vk
               └──────────────────────┬──────────────────────┘
                                      ▼
                             VaultKey (VK, 32B)  ◄── En RAM bloqueada (VirtualLock + Zeroize)
                                      │
                                HKDF-SHA256
                                      ├──► OverviewKey (32B) ──► Cifra metadatos (título, URL, usuario)
                                      └──► SecretKey   (32B) ──► Cifra secretos (password, TOTP, notas)

```

### Primitivas y Parámetros Innegociables

* **Normalización y Cero Almacenamiento de `MP`:** Antes de pasar por el KDF, la Contraseña Maestra se normaliza en **Unicode NFC** para evitar discrepancias de teclado y su buffer en Rust se limpia inmediatamente tras derivar `MK`. No existe tabla ni campo `password_hash`: saber si la `MP` es correcta depende exclusivamente de que el tag de 16 bytes de `AES-256-GCM` valide con éxito al desenvolver la `VaultKey` (`VK`).
* **Derivación KDF (`Argon2id`):** Implementada con el crate auditado `argon2` usando `salt` CSPRNG de 16 bytes, memoria `m = 65536 KiB` (64 MiB), iteraciones `t = 3`, paralelismo `p = 4` y salida de 32 bytes. Estos parámetros se guardan en los metadatos de la bóveda para permitir subir la dureza en versiones futuras sin romper compatibilidad.
* **Subclaves por Propósito (`HKDF-SHA256`):** La `VK` (32 bytes generados al crear la bóveda con `OsRng`) nunca cifra registros directamente; de ella se derivan en memoria dos subclaves independientes mediante `HKDF-SHA256`:
* `OverviewKey` (`info = "vault-v1-overview"`): descifra nombres de sitios, usuarios y carpetas al desbloquear para permitir búsqueda instantánea en memoria en Rust.
* `SecretKey` (`info = "vault-v1-secret"`): descifra contraseñas, semillas TOTP, notas e historial **únicamente en el instante** en que se solicita copiar o visualizar un ítem específico.


* **Cifrado Autenticado (`AES-256-GCM`) con `AAD` Contextual:** Cada escritura genera un `nonce` fresco de 12 bytes (96 bits) mediante `OsRng` (`BCryptGenRandom`). Todo cifrado vincula **Associated Authenticated Data (`AAD`)** canónico (`item_id || item_type || payload_kind || schema_version`), impidiendo que alguien con acceso al archivo SQLite pueda trasplantar el `ciphertext` de una fila a otra sin invalidar la etiqueta GCM.
* **Generador de Contraseñas (CSPRNG sin sesgo):** Basado exclusivamente en `OsRng` con muestreo uniforme por rechazo (*rejection sampling*, evitando `rand % len` para no introducir sesgo de módulo). Soporta longitud configurable (ej. 8 a 128 caracteres), conjuntos independientes (mayúsculas, minúsculas, dígitos, símbolos personalizados y exclusión de caracteres ambiguos como `0O1lI`), garantiza al menos un carácter por cada conjunto activo y aplica una permutación final *Fisher-Yates* criptográficamente aleatoria.

---

## 3. Esquema de Base de Datos y Payloads (SQLite)

El archivo se aloja en `%LOCALAPPDATA%\AppIdentifier\vault.db` con permisos ACL restringidos al usuario actual de Windows y pragmas obligatorios al abrir la conexión: `PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA secure_delete = ON;`.

```sql
-- Configuración global de la bóveda y envoltorios criptográficos (fila única: id = 1)
CREATE TABLE vault_config (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version      INTEGER NOT NULL DEFAULT 1,
    kdf_salt            BLOB NOT NULL,          -- 16 bytes CSPRNG
    kdf_mem_kib         INTEGER NOT NULL,       -- 65536 (64 MiB)
    kdf_iterations      INTEGER NOT NULL,       -- 3
    kdf_parallelism     INTEGER NOT NULL,       -- 4
    mk_wrapped_vk       BLOB NOT NULL,          -- VK cifrada con MK (AES-256-GCM: ciphertext + 16B tag)
    mk_wrap_nonce       BLOB NOT NULL,          -- 12 bytes
    hello_enabled        INTEGER NOT NULL DEFAULT 0 CHECK (hello_enabled IN (0, 1)),
    hello_key_name      TEXT,                   -- Identificador de clave en Microsoft Passport KSP
    hello_wrapped_vk    BLOB,                   -- VK cifrada con RSA-OAEP-SHA256 del TPM (NULL si inactivo)
    lock_timeout_secs   INTEGER NOT NULL DEFAULT 300,
    clipboard_ttl_secs  INTEGER NOT NULL DEFAULT 25,
    created_at          INTEGER NOT NULL,       -- Unix epoch (segundos)
    updated_at          INTEGER NOT NULL
);

-- Carpetas / Colecciones (el nombre vive cifrado con OverviewKey)
CREATE TABLE vault_folders (
    id                  TEXT PRIMARY KEY,       -- UUID v4
    name_nonce          BLOB NOT NULL,          -- 12 bytes
    name_ciphertext     BLOB NOT NULL,          -- UTF-8 cifrado con OverviewKey + AAD(id || "folder")
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
);

-- Registros de la bóveda con separación física entre vista previa y secreto
CREATE TABLE vault_items (
    id                  TEXT PRIMARY KEY,       -- UUID v4
    folder_id           TEXT REFERENCES vault_folders(id) ON DELETE SET NULL,
    item_type           TEXT NOT NULL CHECK (item_type IN ('login', 'note', 'card')),
    favorite            INTEGER NOT NULL DEFAULT 0 CHECK (favorite IN (0, 1)),
    overview_nonce      BLOB NOT NULL,          -- 12 bytes
    overview_ciphertext BLOB NOT NULL,          -- JSON cifrado con OverviewKey + AAD
    secret_nonce        BLOB NOT NULL,          -- 12 bytes
    secret_ciphertext   BLOB NOT NULL,          -- JSON cifrado con SecretKey + AAD
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
);

```

### Estructura JSON Interna antes de Cifrar

Separar cada registro en dos blobs cifrados evita cargar contraseñas en memoria cuando el usuario solo navega o filtra su lista:

```json
// 1. Payload de overview_ciphertext (se descifra al abrir la bóveda para búsqueda local en Rust)
{
  "title": "GitHub Personal",
  "subtitle": "dev@ejemplo.cl",
  "urls": ["https://github.com"],
  "tags": ["trabajo", "codigo"]
}

// 2. Payload de secret_ciphertext (permanece cifrado en SQLite; solo se abre al copiar/editar/ver)
{
  "password": "c9#Lp2!vQ8...secreto",
  "totp_uri": null,
  "notes": "Cuenta principal de repositorios",
  "password_history": [
    { "password": "clave_anterior_1", "changed_at": 1762001200 }
  ]
}

```

---

## 4. Flujos de Desbloqueo, Portapapeles y Bloqueo

### A. Creación de Bóveda y Activación Opcional de Windows Hello

1. **Onboarding:** El usuario define su Contraseña Maestra. Rust genera `kdf_salt` (16B) y `VK` (32B) con `OsRng`, deriva `MK` vía `Argon2id`, envuelve `VK` en `mk_wrapped_vk` (`AAD = "vault-v1-mk-wrap"`) e inicializa `vault.db`.
2. **Enrolamiento en Windows Hello (Desde Ajustes):**
* Exige reautenticar con la Contraseña Maestra para confirmar posesión de la raíz criptográfica.
* Rust invoca `NCryptOpenStorageProvider(MS_PASSPORT_KEY_STORAGE_PROVIDER)` y `NCryptCreatePersistedKey` para crear una clave `RSA-2048` vinculada al usuario actual y protegida por gesto biométrico/PIN de Windows.
* Rust exporta la clave pública RSA del contenedor, cifra una copia de `VK` con `RSA-OAEP-SHA256`, guarda `hello_wrapped_vk` en `vault_config` y marca `hello_enabled = 1`.



### B. Desbloqueo Normal y Fallback Resiliente

1. Al iniciar la app, el estado en Rust es `Locked`. React solo recibe `{ exists: true, hello_enabled: true }`.
2. **Ruta Windows Hello:** Si `hello_enabled = 1`, Rust invoca `NCryptDecrypt` sobre `hello_wrapped_vk`. Windows despliega el diálogo nativo de seguridad del sistema (rostro, huella o PIN).
* **Éxito:** El TPM devuelve los 32 bytes de `VK` directamente a un buffer `Zeroizing` bloqueado con `VirtualLock` en Rust; se derivan `OverviewKey` y `SecretKey` y la sesión pasa a `Unlocked`.
* **Cancelación o invalidación del TPM** (ej. el usuario restableció su PIN de Windows y el contenedor NGC quedó inválido): Si `NCryptDecrypt` devuelve `NTE_BAD_KEYSET` o `NTE_PERM`, la app limpia `hello_enabled = 0` y cae de forma transparente al formulario de **Contraseña Maestra**, sin riesgo alguno de pérdida de datos porque `mk_wrapped_vk` sigue intacto.


3. **Ruta Contraseña Maestra:** Siempre disponible en la pantalla de bloqueo mediante el botón *"Usar contraseña maestra"*. Rust ejecuta `Argon2id` en un hilo dedicado (`tokio::task::spawn_blocking`) para no congelar la interfaz y valida el tag GCM de `mk_wrapped_vk`.

### C. Copiado Seguro y Autolimpieza del Portapapeles

1. Cuando el usuario pulsa *"Copiar contraseña"* en un `item_id`, React llama al comando Tauri `copy_item_secret(item_id)` **sin que la contraseña viaje de vuelta al frontend**.
2. Rust lee `secret_ciphertext` de SQLite, lo descifra en un buffer efímero con `SecretKey`, abre el portapapeles Win32 (`OpenClipboard`) y escribe el texto `CF_UNICODETEXT` junto con dos formatos registrados del sistema:
* `ExcludeClipboardContentFromMonitorProcessing`
* `CanIncludeInHistory` con valor `DWORD = 0` y `CanUploadToCloudClipboard` con valor `DWORD = 0`


3. Rust calcula un digest `BLAKE3` (con clave efímera aleatoria de sesión) del texto copiado, aplica `zeroize` inmediato al secreto en texto plano e inicia un temporizador asíncrono (`clipboard_ttl_secs`, por defecto 25 s).
4. Al expirar el temporizador (o al cerrarse/bloquearse la app), Rust lee el portapapeles actual, calcula su digest `BLAKE3` y **solo vacía el portapapeles (`EmptyClipboard`) si el hash coincide**, evitando borrar texto legítimo que el usuario haya copiado segundos después en otro programa.

### D. Bloqueo Automático por Inactividad y Eventos del Sistema

1. **Reloj de actividad en Rust:** Cada comando IPC legítimo o pulso de actividad del usuario actualiza un `AtomicU64` con el instante monotónico de última interacción (con *throttle* de 2 segundos desde el frontend). Un vigilante en segundo plano en Rust comprueba cada segundo si el tiempo transcurrido supera `lock_timeout_secs`.
2. **Hooks del Sistema Operativo:** La ventana nativa de Tauri escucha `WM_WTSSESSION_CHANGE` (`WTS_SESSION_LOCK` cuando el usuario presiona `Win + L`) y `WM_POWERBROADCAST` (`PBT_APMSUSPEND` al suspender/hibernar el equipo), disparando el bloqueo de forma instantánea sin esperar el timeout.
3. **Secuencia de purga al bloquear:** Rust purga el portapapeles si el hash activo coincide, ejecuta `zeroize` y `VirtualUnlock` sobre `VK`, `OverviewKey`, `SecretKey` y el índice de búsqueda en memoria, cambia el estado a `Locked` y emite el evento `vault:locked` para que React desmonte toda vista privada y redirija a la pantalla de desbloqueo.

---

¿Estás conforme con este diseño (en particular los parámetros de **Argon2id a 64 MiB**, la separación `overview` vs. `secret` en SQLite y el alcance de tipos de ítem `'login' | 'note' | 'card'` para la v1), o quieres ajustar algún punto antes de definir los comandos IPC de Tauri y armar el esqueleto del proyecto?

---

## 1. Cierre de Micro-ajustes (Spec v1.2)

1. **Lectura de preferencias de seguridad (`get_security_prefs` + `VaultSessionInfo`):**
* `get_vault_status` se mantiene minimalista en pantalla de bloqueo (`{ initialized, locked, hello_enabled, hello_available }`) para no exponer configuración interna sin autenticar.
* Al desbloquear/crear la bóveda, `VaultSessionInfo` devuelve `{ lock_timeout_secs, clipboard_ttl_secs, hello_enabled }`, y se añade el comando explícito `get_security_prefs` (requiere sesión desbloqueada) que lee `SecurityPrefsDto` en tiempo real para poblar `SettingsSecurityView.tsx`.


2. **Remapeo relacional de `folder_id` al importar respaldos:**
* Durante la importación sobre una bóveda existente, Rust procesa primero el arreglo `folders` construyendo un `HashMap<String, String>` (`old_folder_id -> final_folder_id`). Si un `folder.id` colisiona con uno existente en `vault_folders`, se genera un `Uuid::new_v4()` y se registra en el mapa; luego, al insertar cada ítem, su `folder_id` se traduce mediante `folder_id_map.get(&old_id)` antes de cifrar y persistir, garantizando cero ítems huérfanos.


3. **Módulo explícito para TOTP (`src-tauri/src/crypto/totp.rs`):**
* El cálculo RFC 6238 vive exclusivamente en `crypto/totp.rs` (usando los crates `hmac` + `sha1` + decodificador Base32 RFC 4648 sin padding obligatorio, paso por defecto de `30 s` y `6 dígitos`, parseando URIs `otpauth://totp/...` o secretos Base32 directos). Tanto `copy_item_field(item_id, "totp")` como la vista puntual de detalle invocan `crypto::totp::generate_current_totp(&totp_secret, now_unix)`, devolviendo `{ code, remaining_secs }` y limpiando con `zeroize` la clave decodificada tras el HMAC.



---
