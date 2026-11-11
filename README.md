# AegisVault

Gestor de contraseñas de escritorio para Windows. **Local-first y zero-knowledge**: tus datos viven solo en tu equipo, cifrados, sin servidor, sin cuenta y sin recuperación de contraseña maestra.

## Autor

**Rodrigo Andrés Guerrero Vargas** — [GitHub](https://github.com/Rodrigo-Guerrero-V)

## Características

- Bóveda local cifrada con **AES-256-GCM** y derivación de clave **Argon2id (64 MiB, t=3, p=4)** + HKDF-SHA256
- Claves aisladas en páginas dedicadas `VirtualAlloc` + `VirtualLock` con borrado explícito (`Zeroize`) al bloquear
- Configuración autenticada (`schema_version = 2`): preferencias selladas bajo AEAD, etiqueta `vk_keycheck` y enlace `HMAC-SHA256` (`hello_mac`) sobre Windows Hello
- Credenciales, notas seguras y tarjetas (con PIN y notas), organizadas en carpetas
- Generador de contraseñas CSPRNG (24 caracteres por defecto) y política de entropía `zxcvbn >= 3/4`
- TOTP (RFC 6238: `SHA1` / `SHA256` / `SHA512`, 6–8 dígitos y periodo configurable) para segundo factor
- Desbloqueo con **Windows Hello** (TPM, RSA-2048 OAEP-SHA256)
- Respaldo cifrado **`.aegisvault`** mediante diálogos nativos en Rust (exportar / importar con deduplicación / recuperación ante filas corruptas)
- Portapapeles protegido: exclusión del historial de Windows y de sincronización en la nube
- Protección contra captura de pantalla (`SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`) activa por defecto
- Bloqueo automático por inactividad (15–3600 s) y bloqueo manual
- Temas claro y oscuro
- Base de datos SQLite en `%LOCALAPPDATA%\AegisVault\vault.db`, con ACL explícita para el SID del `TokenUser` actual y `SYSTEM`

## Stack

- **Tauri v2** (Rust + React + TypeScript)
- SQLite (rusqlite)
- WebView2 (Windows, CSP estricta)

## Instalación y verificación de integridad

Descarga el instalador y `SHA256SUMS.txt` desde [Releases](../../releases): `AegisVault_0.1.1_x64-setup.exe` (NSIS) o `AegisVault_0.1.1_x64_en-US.msi` (WiX).

> **Importante:** Nunca omitas advertencias de Windows SmartScreen a ciegas sin verificar antes el hash SHA-256 y la atestación criptográfica de procedencia SLSA generada por GitHub Actions:

1. **Verificar hash SHA-256 (`SHA256SUMS.txt`):**
   ```powershell
   Get-FileHash -Algorithm SHA256 .\AegisVault_0.1.1_x64-setup.exe
   Get-Content .\SHA256SUMS.txt
   ```
2. **Verificar procedencia de compilación SLSA ([GitHub CLI `gh`](https://cli.github.com/)):**
   ```powershell
   gh attestation verify .\AegisVault_0.1.1_x64-setup.exe --repo Rodrigo-Guerrero-V/AegisVault
   gh attestation verify .\AegisVault_0.1.1_x64_en-US.msi --repo Rodrigo-Guerrero-V/AegisVault
   ```
3. **Verificar firma Authenticode (cuando el certificado de código esté activo en CI):**
   ```powershell
   Get-AuthenticodeSignature .\AegisVault_0.1.1_x64-setup.exe | Format-List Status, SignerCertificate
   ```

> **Mantenimiento de Releases:** se recomienda activar *Immutable Releases* en GitHub (*Settings → General → Releases → Enable release immutability*) y configurar los secretos `WINDOWS_CERTIFICATE` (PFX en Base64) y `WINDOWS_CERTIFICATE_PASSWORD` para el firmado Authenticode automático en `.github/workflows/release.yml`.

## Compilar desde el código

Requisitos: Node.js 18+, Rust estable y **VS 2022 Build Tools con el workload de C++** (Rust necesita `link.exe`).

```bash
npm install
npm run tauri dev      # desarrollo
npm run tauri build    # instaladores en src-tauri/target/release/bundle/
```

Chequeos y tests:

```bash
npx tsc --noEmit
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml -- --nocapture
```

## Primer uso

1. Crea la bóveda con una **contraseña maestra** (mínimo 12 caracteres y entropía `zxcvbn >= 3/4`). **No hay recuperación**: si se pierde y no tienes un respaldo `.aegisvault`, los datos son irrecuperables.
2. Agrega tus primeras credenciales.
3. Exporta un respaldo `.aegisvault` desde **Seguridad y Respaldo** y guárdalo fuera del equipo.

## Seguridad

> AegisVault es un proyecto personal en desarrollo continuo. Para el uso crítico empresarial o diario a gran escala, evalúa siempre tus requisitos frente a gestores con múltiples auditorías externas independientes.

## Licencia

MIT — ver [LICENSE](LICENSE).
