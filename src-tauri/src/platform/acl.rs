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
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

    fn read_dacl_sddl(path: &Path) -> String {
        let wide = path.as_os_str().encode_wide_null();
        unsafe {
            let mut sd = PSECURITY_DESCRIPTOR::default();
            GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                &mut sd,
            )
            .ok()
            .expect("GetNamedSecurityInfoW debe leer DACL");

            let mut sddl_ptr = PWSTR::null();
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut sddl_ptr,
                None,
            )
            .expect("ConvertSecurityDescriptorToStringSecurityDescriptorW debe convertir SDDL");

            let mut len = 0usize;
            while *sddl_ptr.0.add(len) != 0 {
                len += 1;
            }
            let text = String::from_utf16_lossy(std::slice::from_raw_parts(sddl_ptr.0, len));
            let _ = LocalFree(Some(HLOCAL(sddl_ptr.0 as *mut std::ffi::c_void)));
            let _ = LocalFree(Some(HLOCAL(sd.0)));
            text
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

        let dir_sddl = read_dacl_sddl(&temp_dir);
        let file_sddl = read_dacl_sddl(&db_file);

        assert!(dir_sddl.contains(&sid), "SDDL de directorio debe incluir TokenUser SID: {dir_sddl}");
        assert!(!dir_sddl.contains(";;;OW)"), "SDDL no debe depender de OWNER RIGHTS (OW): {dir_sddl}");
        assert!(file_sddl.contains(&sid), "SDDL de archivo debe incluir TokenUser SID: {file_sddl}");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
