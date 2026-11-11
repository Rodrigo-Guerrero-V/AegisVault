// src-tauri/src/platform/acl.rs
use std::path::Path;

#[cfg(windows)]
pub fn harden_directory_acl(dir: &Path) {
    use windows::core::PCWSTR;
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
        SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, ACL,
    };
    use windows::Win32::Foundation::{LocalFree, HLOCAL};

    // SDDL: D:P (DACL protegida sin herencia)
    // (A;OICI;FA;;;SY) -> Control total a SYSTEM
    // (A;OICI;FA;;;OW) -> Control total al Owner actual (SID del usuario creador)
    let sddl: Vec<u16> = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)\0"
        .encode_utf16()
        .collect();
    let mut path_wide: Vec<u16> = dir.as_os_str().encode_wide_null();

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
                    tracing::warn!("No se pudo aplicar DACL estricta sobre {:?}: {:?}", dir, status);
                }
            }
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }
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
