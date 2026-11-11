# AegisVault — Registro de decisiones (ADR)

Decisiones de arquitectura y diseño con su motivo. Si una decisión se revisa en el
futuro, se agrega una entrada nueva que la reemplace, no se borra el historial.

## ADR-01 — Tauri v2 (Rust + React) como plataforma

**Decisión:** aplicación de escritorio Windows con Tauri v2: backend Rust, UI React
en WebView2.
**Descartado:** WinUI 3 (solo Windows, curva de UI nativa mayor) y PWA + WebAuthn
(la app debe ser un programa instalable, no una página; WebAuthn solo devuelve un
booleano, ver ADR-06).
**Motivo:** binario pequeño, UI web ágil, criptografía nativa en Rust, y el mismo
código compila a Linux/Mac después.

## ADR-02 — Zero-Knowledge / Local-First, sin recuperación

**Decisión:** sin servidor, sin cuenta, sin recuperación de Contraseña Maestra.
**Motivo:** el modelo de amenazas es el robo del archivo, no el olvido; cualquier
vía de recuperación sería una vía de ataque. El onboarding lo deja explícito con
el checkbox obligatorio `ack_no_recovery`.

## ADR-03 — Argon2id 64 MiB / t=3 / p=4, contraseña en NFC

**Decisión:** KDF memory-hard con esos parámetros; la Contraseña Maestra se
normaliza a NFC antes de derivar.
**Motivo:** parámetros alineados con las recomendaciones actuales para KDF
(64 MiB resiste GPU/ASIC mejor que PBKDF2); NFC evita que la misma contraseña
escrita con distinta composición Unicode derive claves distintas.

## ADR-04 — Envelope encryption: MK envuelve VK; HKDF para subclaves

**Decisión:** la VK (32 bytes aleatorios) cifra los datos; la MK solo envuelve la VK.
HKDF-SHA256 deriva OverviewKey (índice) y SecretKey (secretos).
**Motivo:** rotar la Contraseña Maestra re-envuelve solo la VK, sin re-cifrar
todos los ítems; separar subclaves limita el impacto si una se expone.

## ADR-05 — AES-256-GCM con AAD canónico

**Decisión:** AAD `encode_aad` con prefijo `"AEGIS-AAD-V1"`, conteo u8 y largos u32 LE.
**Motivo:** el cifrado queda atado a su contexto (qué campo, de qué ítem): mover un
texto cifrado a otro lugar no descifra válido.

## ADR-06 — Windows Hello por NCrypt/TPM, nunca por booleano

**Decisión:** la VK se envuelve con RSA-2048 (TPM) y RSA-OAEP-SHA256; el gesto de
Hello es lo que permite desenvolverla.
**Descartado:** `UserConsentVerifier` / APIs que devuelven un booleano "autenticado".
**Motivo:** un booleano en memoria es falsificable por quien controle el proceso;
con NCrypt la clave nunca sale del TPM sin el gesto.

## ADR-07 — Portapapeles solo por Win32 protegido

**Decisión:** todo copiado pasa por `ClipboardGuard::copy_protected` (3 formatos de
exclusión, digest BLAKE3, purga por TTL). Prohibido `navigator.clipboard` en el
frontend.
**Motivo:** el portapapeles del WebView no admite banderas de exclusión: el secreto
caería en el historial Win+V y en la nube. La Fase 3 tuvo este fallo real en el
generador y se corrigió en Fase 4 con `copy_text_protected`.

## ADR-08 — Ventana oculta Win32 para bloqueo por SO, sin subclassing

**Decisión:** hilo dedicado con ventana invisible que escucha `WM_WTSSESSION_CHANGE`
y `WM_POWERBROADCAST`; nunca subclassing del WndProc de Tauri/WebView2.
**Motivo:** tocar el WndProc de tao/Chromium puede colisionar con su despacho
interno; la ventana propia es aislada y recibe los broadcasts que una ventana
message-only no recibiría.

## ADR-09 — SQLite WAL + synchronous FULL + purga al bloquear

**Decisión:** `synchronous = FULL` (no NORMAL) aunque cueste rendimiento;
`secure_delete = ON`; al bloquear, `VACUUM` + `wal_checkpoint(TRUNCATE)`.
**Motivo:** durabilidad ante cortes de energía y que no queden restos de secretos
en el WAL tras el bloqueo.

## ADR-10 — Respaldo `.aegisvault` con cabecera autenticada

**Decisión:** formato propio: cabecera de 57 bytes en claro (magic, versión, fecha,
parámetros KDF, salt, nonce) autenticada por el AAD, cuerpo cifrado.
**Motivo:** el respaldo es autocontenido: la restauración conoce los parámetros KDF
sin necesitar la bóveda original. La restauración es atómica y regenera UUIDs con
remapeo de `folder_id` para no dejar huérfanos.

## ADR-11 — Contraseña Maestra mínima de 12 caracteres

**Decisión:** mínimo 12 (era 10 en el primer borrador).
**Motivo:** paridad con Bitwarden (12 desde su release 2023.3.0) y con la práctica
actual para gestores; el costo de memorizar 2 caracteres más es menor que el
margen de seguridad que se gana.

## ADR-12 — Historial de contraseñas con tope de 20

**Decisión:** cada ítem guarda hasta 20 contraseñas anteriores.
**Motivo:** permite recuperar una contraseña cambiada por error sin que la base de
datos crezca sin control.

## ADR-13 — El mockup es la referencia visual; el frontend la implementa

**Decisión:** el mockup interactivo aprobado es el plano; `theme.css` debe reproducir
sus tokens exactos (ver `estilos-mockup-para-gemini.md`).
**Motivo:** validar flujos y estados antes de codear evita rehacer UI; la revisión
visual es contra el mockup, no contra el gusto del momento.

## ADR-14 — Tests por fase como puerta de aceptación

**Decisión:** cada fase trae sus tests (10 en total: 4 + 3 + 3); nada se da por
cerrado sin `cargo test` en verde.
**Motivo:** la Fase 4 llegó con un error de compilación (E0599) que solo el build
detecta; la revisión estática no basta.
