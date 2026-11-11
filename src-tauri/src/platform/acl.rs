// src-tauri/src/platform/acl.rs
use std::path::Path;

#[cfg(windows)]
pub fn current_process_user_sid_string() -> Option<String> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return None;
        }

        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        if needed == 0 {
            let _ = CloseHandle(token);
            return None;
        }

        let mut buf = vec![0u8; needed as usize];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
            needed,
            &mut needed,
        );
        let _ = CloseHandle(token);
        if ok.is_err() {
            return None;
        }

        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut sid_ptr = PWSTR::null();
        if ConvertSidToStringSidW(token_user.User.Sid, &mut sid_ptr).is_err() || sid_ptr.is_null() {
            return None;
        }

        let mut len = 0usize;
        while *sid_ptr.0.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(sid_ptr.0, len);
        let sid_string = String::from_utf16_lossy(slice);
        let _ = LocalFree(Some(HLOCAL(sid_ptr.0 as *mut std::ffi::c_void)));
        Some(sid_string)
    }
}

#[cfg(not(windows))]
pub fn current_process_user_sid_string() -> Option<String> {
    None
}

#[cfg(windows)]
fn apply_explicit_user_dacl(target: &Path, inherit_containers: bool) {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };

    let Some(user_sid) = current_process_user_sid_string() else {
        tracing::warn!("No se pudo obtener el SID de TokenUser para endurecer DACL en {:?}", target);
        return;
    };

    // Usa el SID explícito de TokenUser en lugar de `OW` (OWNER RIGHTS) para evitar bloqueo
    // `ERROR_ACCESS_DENIED` cuando la primera ejecución ocurrió bajo un instalador elevado
    // (donde el propietario del directorio pasa a ser `BUILTIN\Administrators`).
    let sddl_str = if inherit_containers {
        format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user_sid})\0")
    } else {
        format!("D:P(A;;FA;;;SY)(A;;FA;;;{user_sid})\0")
    };

    let sddl: Vec<u16> = sddl_str.encode_utf16().collect();
    let mut path_wide: Vec<u16> = target.as_os_str().encode_wide_null();

    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
        .is_ok()
        {
            let mut dacl_present = false.into();
            let mut dacl_defaulted = false.into();
            let mut dacl_ptr: *mut ACL = std::ptr::null_mut();

            if GetSecurityDescriptorDacl(
                sd,
                &mut dacl_present,
                &mut dacl_ptr,
                &mut dacl_defaulted,
            )
            .is_ok()
                && dacl_present.as_bool()
            {
                let status = SetNamedSecurityInfoW(
                    PCWSTR(path_wide.as_mut_ptr()),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    None,
                    None,
                    Some(dacl_ptr),
                    None,
                );
                if status.is_err() {
                    tracing::warn!("No se pudo aplicar DACL estricta sobre {:?}: {:?}", target, status);
                }
            }
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }
    }
}

#[cfg(windows)]
pub fn harden_directory_acl(dir: &Path) {
    apply_explicit_user_dacl(dir, true);
}

#[cfg(windows)]
pub fn harden_file_acl(file: &Path) {
    if file.exists() {
        apply_explicit_user_dacl(file, false);
    }
}

pub fn harden_vault_db_files(db_path: &Path) {
    harden_file_acl(db_path);
    if let Some(name) = db_path.file_name().and_then(|n| n.to_str()) {
        let wal = db_path.with_file_name(format!("{name}-wal"));
        let shm = db_path.with_file_name(format!("{name}-shm"));
        harden_file_acl(&wal);
        harden_file_acl(&shm);
    }
}

#[cfg(windows)]
trait OsStrWideNull {
    fn encode_wide_null(&self) -> Vec<u16>;
}

#[cfg(windows)]
impl OsStrWideNull for std::ffi::OsStr {
    fn encode_wide_null(&self) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide().chain(std::iter::once(0)).collect()
    }
}

#[cfg(not(windows))]
pub fn harden_directory_acl(_dir: &Path) {}

#[cfg(not(windows))]
pub fn harden_file_acl(_file: &Path) {}

#[cfg(all(test, windows))]
mod acl_tests {
    use super::*;
    use uuid::Uuid;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorDacl, ACCESS_ALLOWED_ACE,
        ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    };

    const ACCESS_ALLOWED_ACE_TYPE_U8: u8 = 0;
    const OBJECT_INHERIT_ACE_U8: u8 = 0x01;
    const CONTAINER_INHERIT_ACE_U8: u8 = 0x02;
    const INHERITED_ACE_U8: u8 = 0x10;
    const FILE_ALL_ACCESS_MASK: u32 = 0x001F_01FF;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ExplicitAceInfo {
        ace_type: u8,
        ace_flags: u8,
        mask: u32,
        sid: String,
    }

    #[derive(Debug)]
    struct InspectedDacl {
        is_protected: bool,
        aces: Vec<ExplicitAceInfo>,
    }

    unsafe fn psid_to_numeric_string(psid: PSID) -> String {
        let mut sid_ptr = PWSTR::null();
        ConvertSidToStringSidW(psid, &mut sid_ptr)
            .expect("ConvertSidToStringSidW debe convertir PSID binario a forma numérica S-1-...");
        let mut len = 0usize;
        while *sid_ptr.0.add(len) != 0 {
            len += 1;
        }
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(sid_ptr.0, len));
        let _ = LocalFree(Some(HLOCAL(sid_ptr.0 as *mut std::ffi::c_void)));
        text
    }

    unsafe fn extract_aces_from_sd(sd: PSECURITY_DESCRIPTOR, dacl_ptr: *const ACL) -> InspectedDacl {
        let mut control = 0u16;
        let mut revision = 0u32;
        GetSecurityDescriptorControl(sd, &mut control, &mut revision)
            .expect("GetSecurityDescriptorControl debe leer flags del descriptor");
        let is_protected = (control & SE_DACL_PROTECTED.0) != 0;

        assert!(
            !dacl_ptr.is_null(),
            "El descriptor de seguridad debe contener una DACL no nula"
        );
        let ace_count = u32::from((*dacl_ptr).AceCount);
        let mut aces = Vec::with_capacity(ace_count as usize);

        for idx in 0..ace_count {
            let mut ace_raw: *mut std::ffi::c_void = std::ptr::null_mut();
            GetAce(dacl_ptr, idx, &mut ace_raw).expect("GetAce debe obtener cada ACE de la DACL");
            let header = &*(ace_raw as *const ACE_HEADER);
            assert_eq!(
                header.AceType, ACCESS_ALLOWED_ACE_TYPE_U8,
                "Solo se esperan ACEs de tipo ACCESS_ALLOWED en la DACL endurecida"
            );

            let allowed = &*(ace_raw as *const ACCESS_ALLOWED_ACE);
            let sid_ptr = PSID(std::ptr::addr_of!(allowed.SidStart) as *mut std::ffi::c_void);
            aces.push(ExplicitAceInfo {
                ace_type: header.AceType,
                ace_flags: header.AceFlags,
                mask: allowed.Mask,
                sid: psid_to_numeric_string(sid_ptr),
            });
        }

        InspectedDacl { is_protected, aces }
    }

    fn inspect_path_dacl(path: &Path) -> InspectedDacl {
        let wide = path.as_os_str().encode_wide_null();
        unsafe {
            let mut dacl_ptr: *mut ACL = std::ptr::null_mut();
            let mut sd = PSECURITY_DESCRIPTOR::default();
            GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl_ptr),
                None,
                &mut sd,
            )
            .ok()
            .expect("GetNamedSecurityInfoW debe leer la DACL binaria del objeto");

            let inspected = extract_aces_from_sd(sd, dacl_ptr);
            let _ = LocalFree(Some(HLOCAL(sd.0)));
            inspected
        }
    }

    #[test]
    fn dacl_uses_explicit_token_user_sid_without_owner_rights() {
        let sid = current_process_user_sid_string().expect("SID de TokenUser debe existir");
        assert!(sid.starts_with("S-1-5-"));

        let temp_dir = std::env::temp_dir().join(format!("aegis_acl_test_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let db_file = temp_dir.join("vault.db");
        std::fs::write(&db_file, b"test").unwrap();

        harden_directory_acl(&temp_dir);
        harden_vault_db_files(&db_file);

        // Nota sobre runners de GitHub Actions (Windows Server 2025):
        // El job corre bajo `runneradmin`, que es la cuenta integrada RID 500 (`S-1-5-21-<maquina>-500`).
        // `ConvertSecurityDescriptorToStringSecurityDescriptorW` abrevia ese SID numérico como el alias
        // SDDL `LA` (`SDDL_LOCAL_ADMIN`), haciendo fallar comparaciones ingenuas de texto sobre la SDDL.
        // Inspeccionamos la DACL binaria (`GetAce` + `ConvertSidToStringSidW` sobre cada `PSID`) para
        // verificar semánticamente los SIDs reales sin depender de alias SDDL.
        let dir_dacl = inspect_path_dacl(&temp_dir);
        let file_dacl = inspect_path_dacl(&db_file);

        assert!(
            dir_dacl.is_protected,
            "La DACL del directorio debe tener SE_DACL_PROTECTED activo: {dir_dacl:?}"
        );
        assert!(
            file_dacl.is_protected,
            "La DACL de vault.db debe tener SE_DACL_PROTECTED activo: {file_dacl:?}"
        );

        let expected_dir_flags = OBJECT_INHERIT_ACE_U8 | CONTAINER_INHERIT_ACE_U8;
        assert!(
            dir_dacl.aces.iter().any(|ace| {
                ace.sid == sid
                    && ace.mask == FILE_ALL_ACCESS_MASK
                    && (ace.ace_flags & expected_dir_flags) == expected_dir_flags
                    && (ace.ace_flags & INHERITED_ACE_U8) == 0
            }),
            "La DACL del directorio debe otorgar FILE_ALL_ACCESS explícito con herencia OICI a TokenUser ({sid}): {dir_dacl:?}"
        );
        assert!(
            dir_dacl
                .aces
                .iter()
                .any(|ace| ace.sid == "S-1-5-18" && ace.mask == FILE_ALL_ACCESS_MASK),
            "La DACL del directorio debe incluir acceso explícito para SYSTEM (S-1-5-18): {dir_dacl:?}"
        );

        assert!(
            file_dacl.aces.iter().any(|ace| {
                ace.sid == sid
                    && ace.mask == FILE_ALL_ACCESS_MASK
                    && (ace.ace_flags & INHERITED_ACE_U8) == 0
            }),
            "La DACL de vault.db debe otorgar FILE_ALL_ACCESS explícito a TokenUser ({sid}): {file_dacl:?}"
        );
        assert!(
            file_dacl
                .aces
                .iter()
                .any(|ace| ace.sid == "S-1-5-18" && ace.mask == FILE_ALL_ACCESS_MASK),
            "La DACL de vault.db debe incluir acceso explícito para SYSTEM (S-1-5-18): {file_dacl:?}"
        );

        // Ninguna ACE puede depender de OWNER RIGHTS (S-1-3-4 / OW) ni abrir acceso a grupos amplios
        let forbidden_sids = [
            "S-1-3-4",      // OWNER RIGHTS (OW)
            "S-1-1-0",      // Everyone (WD)
            "S-1-5-11",     // Authenticated Users (AU)
            "S-1-5-32-545", // BUILTIN\Users (BU)
        ];
        for dacl in [&dir_dacl, &file_dacl] {
            for ace in &dacl.aces {
                assert!(
                    !forbidden_sids.contains(&ace.sid.as_str()),
                    "SID no permitido detectado en DACL: {ace:?}"
                );
                assert!(
                    ace.sid == sid || ace.sid == "S-1-5-18" || ace.sid == "S-1-5-32-544",
                    "ACE inesperada fuera de {{TokenUser, SYSTEM, Administrators}}: {ace:?}"
                );
            }
        }

        // Regresión explícita para el alias SDDL `LA` (`SDDL_LOCAL_ADMIN`, RID 500 en GitHub Actions):
        // verifica que el inspector binario resuelve `LA` a su SID numérico `S-1-5-21-...-500`.
        unsafe {
            let runner_like_sddl: Vec<u16> = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;LA)\0"
                .encode_utf16()
                .collect();
            let mut sd = PSECURITY_DESCRIPTOR::default();
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(runner_like_sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
            .expect("Debe parsear SDDL con alias LA de Windows Server");

            let mut dacl_present = false.into();
            let mut dacl_defaulted = false.into();
            let mut dacl_ptr: *mut ACL = std::ptr::null_mut();
            GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl_ptr, &mut dacl_defaulted)
                .expect("GetSecurityDescriptorDacl debe extraer DACL");
            assert!(dacl_present.as_bool());

            let parsed = extract_aces_from_sd(sd, dacl_ptr);
            assert!(
                parsed
                    .aces
                    .iter()
                    .any(|ace| ace.sid.starts_with("S-1-5-21-") && ace.sid.ends_with("-500")),
                "El alias SDDL 'LA' debe resolverse al SID numérico RID 500 de administrador local: {parsed:?}"
            );
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
