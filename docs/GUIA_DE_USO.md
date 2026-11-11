# AegisVault — Guía de uso

## 1. Requisitos

- Windows 10 u 11 (64 bits).
- Windows Hello configurado (PIN, huella o rostro) solo si se quiere desbloquear
  con Hello; sin él la app funciona igual con Contraseña Maestra.
- Para compilar: Rust (cargo, vía rustup) y Node.js + npm.
- TPM 2.0 recomendado para Hello (la clave RSA-2048 vive en el TPM/NGC).

## 2. Compilar y probar (desarrollador)

```powershell
npm install
cd src-tauri
cargo test -- --nocapture   # 10 tests en verde: 4 Fase 1 + 3 Fase 2 + 3 Fase 4
cd ..
npm run tauri dev            # app en desarrollo, con recarga en caliente
npm run tauri build          # instalador .msi / .exe NSIS
```

Si la carpeta se armó a mano sin `create-tauri-app`, verificar que existan
`src-tauri/build.rs` con `fn main() { tauri_build::build() }` y
`src-tauri/icons/icon.ico` (o generarlos con `npx tauri icon ruta/logo.png`).

## 3. Primer uso

1. **Crear bóveda:** elige una Contraseña Maestra de 12 caracteres o más y confirma
   que entiendes que no hay recuperación (checkbox obligatorio).
2. **Crear ítems:** login, tarjeta o nota, en carpetas o en "Todos". El generador
   crea contraseñas seguras; el botón "Copiar" usa el portapapeles protegido.
3. **Activar Windows Hello (opcional):** en Ajustes → Seguridad, con la bóveda
   desbloqueada. Te pedirá la Contraseña Maestra y luego el gesto de Hello.
4. **Respaldo:** en Ajustes, exporta un `.aegisvault` con una contraseña de respaldo
   distinta y guárdalo fuera del equipo (USB, nube personal). Sin ese archivo y sin
   la Contraseña Maestra, no hay forma de recuperar la bóveda.

## 4. Uso diario

- **Desbloqueo:** Contraseña Maestra o Hello. Si Hello falla (PIN cambiado, TPM
  reseteado), usa la Contraseña Maestra: la bóveda sigue intacta.
- **Copiar:** cada secreto copiado se purga solo al expirar el TTL (configurable
  en Ajustes). El banner inferior muestra la cuenta atrás; "Limpiar ahora" lo
  vacía de inmediato. El portapapeles no guarda el secreto en el historial Win+V
  ni lo sincroniza a la nube.
- **TOTP:** los códigos se muestran en el detalle del ítem y se recalculan solos.
- **Bloqueo:** la bóveda se bloquea sola por inactividad, con Win+L o al suspender
  el equipo. También puedes bloquearla a mano.
- **Cambio de Contraseña Maestra:** en Ajustes. Requiere la actual; invalida Hello
  (hay que volver a enrolarlo después).

## 5. Problemas frecuentes

| Síntoma | Qué hacer |
|---|---|
| `cargo` no se reconoce | Instalar Rust desde rustup.rs, cerrar y reabrir la terminal. |
| `cargo test` falla en un test | Pegar el error completo a Gemini; no reescribir módulos enteros. |
| `tauri dev` no levanta / falta `build.rs` o ícono | Ver §2 (scaffold manual). |
| Hello dice que no está disponible | Configurar Windows Hello en Configuración → Cuentas → Opciones de inicio de sesión. |
| Hello pide Contraseña Maestra tras cambiar el PIN | Esperado: el PIN nuevo invalida la clave anterior; desbloquea con la Maestra y vuelve a enrolar Hello en Ajustes. |
| La app no se ve como el mockup | Aplicar `estilos-mockup-para-gemini.md` a `src/styles/theme.css` y comparar con `aegisvault-mockup.html`. |
| Olvidé la Contraseña Maestra | Sin respaldo `.aegisvault` no hay recuperación. Con respaldo: restaurar con su contraseña y crear bóveda nueva. |
