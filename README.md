# AegisVault

Gestor de contraseñas de escritorio para Windows. **Local-first y zero-knowledge**: tus datos viven solo en tu equipo, cifrados, sin servidor, sin cuenta y sin recuperación de contraseña maestra.

## Autor

**Rodrigo Andrés Guerrero Vargas** — [GitHub](https://github.com/Rodrigo-Guerrero-V)

## Características

- Bóveda local cifrada con **AES-256-GCM** y derivación de clave **Argon2id (64 MiB, t=3, p=4)** + HKDF-SHA256
- Credenciales, notas seguras y tarjetas, organizadas en carpetas
- Generador de contraseñas CSPRNG (24 caracteres por defecto)
- TOTP (RFC 6238) para códigos de segundo factor
- Desbloqueo con **Windows Hello** (TPM, RSA-2048 OAEP-SHA256)
- Respaldo cifrado **`.aegisvault`** (exportar / importar / fusionar)
- Portapapeles protegido: exclusión del historial de Windows
- Bloqueo automático por inactividad y bloqueo manual
- Temas claro y oscuro
- Base de datos SQLite en `%LOCALAPPDATA%\AegisVault\vault.db`, con ACL solo para el usuario y SYSTEM

## Stack

- **Tauri v2** (Rust + React + TypeScript)
- SQLite (rusqlite)
- WebView2 (Windows)

## Instalación

Descarga el instalador desde [Releases](../../releases): `AegisVault_0.1.0_x64-setup.exe` (NSIS) o `AegisVault_0.1.0_x64_en-US.msi` (WiX).

Como el instalador no está firmado, Windows SmartScreen puede mostrar una advertencia: haz clic en **Más información → Ejecutar de todas formas**.

## Compilar desde el código

Requisitos: Node.js 18+, Rust estable y **VS 2022 Build Tools con el workload de C++** (Rust necesita `link.exe`).

```bash
npm install
npm run tauri dev      # desarrollo
npm run tauri build    # instaladores en src-tauri/target/release/bundle/
```

Los tests de Rust:

```bash
cargo test
```

## Primer uso

1. Crea la bóveda con una **contraseña maestra** (mínimo 12 caracteres). **No hay recuperación**: si se pierde y no tienes un respaldo `.aegisvault`, los datos son irrecuperables.
2. Agrega tus primeras credenciales.
3. Exporta un respaldo `.aegisvault` desde **Seguridad y Respaldo** y guárdalo fuera del equipo.

## Seguridad

> AegisVault es un proyecto personal en versión 1.0, **sin auditoría de seguridad externa**. Para el uso diario con credenciales reales, un gestor auditado como Bitwarden sigue siendo la opción más segura.

## Licencia

MIT — ver [LICENSE](LICENSE).
