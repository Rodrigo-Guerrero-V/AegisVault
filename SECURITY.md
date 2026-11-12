# Política de seguridad — AegisVault

AegisVault es un gestor de contraseñas local-first y de conocimiento cero:
no hay servidores, no hay cuentas en la nube y la bóveda nunca sale del
equipo del usuario. Por eso mismo, cualquier fallo que exponga la bóveda,
la contraseña maestra o las credenciales guardadas es crítico para nosotros.
Si encuentras uno, gracias por reportarlo de forma responsable.

> **No abras un issue público para reportar una vulnerabilidad.**
> Usa el reporte privado de GitHub (ver abajo) para que podamos corregirla
> antes de que se haga pública.

## Versiones con soporte

| Versión | Soporte de seguridad |
| ------- | -------------------- |
| 0.1.1   | ✅ Sí                |
| < 0.1.1 | ❌ No — actualiza a la última versión |

Solo la última versión publicada recibe correcciones de seguridad. Si usas
una versión anterior, actualiza primero y verifica si el problema persiste.

## Cómo reportar una vulnerabilidad

Usa el **reporte privado de vulnerabilidades de GitHub** del repositorio
(pestaña *Security* → *Report a vulnerability*). Es el canal habilitado
para este proyecto y mantiene el reporte visible solo para el mantenedor
hasta que se resuelva.

Incluye, en lo posible:

- Versión de AegisVault y versión de Windows donde lo reprodujiste.
- Descripción del problema y su impacto (qué podría obtener un atacante).
- Pasos para reproducirlo, y una prueba de concepto si la tienes.
- Si el fallo requiere una condición especial (bóveda desbloqueada,
  acceso físico, otra app instalada, etc.), indícalo.

Si no puedes usar el reporte privado de GitHub, abre un issue describiendo
el problema **sin detalles que permitan explotarlo** y pide un canal
privado para compartirlos.

## Alcance

Nos interesa especialmente todo lo que toque:

- Criptografía de la bóveda: AES-256-GCM, derivación Argon2id, manejo de
  claves en memoria (`zeroize`), rotación de la contraseña maestra.
- IPC entre el frontend (TypeScript/React) y el backend (Rust): comandos
  Tauri, validación de entradas, fuga de datos descifrados al frontend.
- Windows Hello / TPM: enrolamiento, unwrap y borrado de claves.
- Protección del equipo local: DACL de la base de datos, archivo de
  configuración de la bóveda, protección contra captura de pantalla.
- Portapapeles: copiado protegido, TTL y purga automática.
- WebView2: Content Security Policy y cualquier vía de inyección de scripts.
- Dependencias con vulnerabilidades conocidas (Rust o npm) que afecten a
  la app instalada.

Fuera de alcance: ingeniería social, acceso físico a un equipo ya
desbloqueado por su dueño, y problemas de dependencias que no sean
explotables en AegisVault.

## Qué puedes esperar de nosotros

- Confirmaremos la recepción del reporte y evaluaremos el impacto.
- Trabajaremos la corrección en privado y la publicaremos como una
  versión parche, con su entrada en el CHANGELOG.
- Te daremos crédito en el reporte de la corrección si así lo quieres.
- Te pedimos no publicar los detalles hasta que la corrección esté
  disponible o lo acordemos contigo (divulgación coordinada).

AegisVault es un proyecto personal mantenido por una sola persona, así que
los tiempos de respuesta son según disponibilidad, pero los reportes de
seguridad tienen prioridad sobre cualquier otra tarea.

## Agradecimientos

Gracias a quienes reportan vulnerabilidades de forma responsable y ayudan
a que AegisVault sea más seguro para todos sus usuarios.
