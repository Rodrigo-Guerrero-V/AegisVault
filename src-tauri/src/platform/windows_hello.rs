use crate::crypto::memory::{ProtectedKey, KEY_LEN};
use crate::error::{ErrorCode, VaultError, VaultResult};

pub const SCARD_W_CANCELLED_BY_USER_HR: i32 = 0x8010_006Eu32 as i32;
pub const ERROR_CANCELLED_HR: i32 = 0x8007_04C7u32 as i32;
pub const NTE_USER_CANCELLED_HR: i32 = 0x8009_0036u32 as i32;

pub const NTE_BAD_KEYSET_HR: i32 = 0x8009_0016u32 as i32;
pub const NTE_NO_KEY_HR: i32 = 0x8009_000Du32 as i32;
pub const NTE_NOT_FOUND_HR: i32 = 0x8009_0011u32 as i32;
pub const NTE_PERM_HR: i32 = 0x8009_0010u32 as i32;
pub const NTE_INVALID_HANDLE_HR: i32 = 0x8009_0026u32 as i32;
pub const TPM_E_KEY_NOT_LOADED_HR: i32 = 0x8029_040Fu32 as i32;

pub(crate) fn classify_ncrypt_hresult(code: i32, context: &str) -> VaultError {
    if matches!(
        code,
        SCARD_W_CANCELLED_BY_USER_HR | ERROR_CANCELLED_HR | NTE_USER_CANCELLED_HR
    ) {
        return VaultError::new(
            ErrorCode::HelloCancelled,
            "Autenticación con Windows Hello cancelada por el usuario.",
        );
    }
    if matches!(
        code,
        NTE_BAD_KEYSET_HR
            | NTE_NO_KEY_HR
            | NTE_NOT_FOUND_HR
            | NTE_PERM_HR
            | NTE_INVALID_HANDLE_HR
            | TPM_E_KEY_NOT_LOADED_HR
    ) {
        return VaultError::new(
            ErrorCode::HelloInvalidated,
            "La credencial de Windows Hello cambió o no pudo cargarse desde el TPM. Desbloquea con tu Contraseña Maestra.",
        );
    }
    tracing::error!("Error NCrypt ({}) HRESULT=0x{:08X}", context, code as u32);
    VaultError::internal(format!(
        "No se pudo completar la operación con Windows Hello ({context})."
    ))
}

#[cfg(windows)]
mod imp {
    use super::*;
    use windows::core::{w, HRESULT, PCWSTR};
    use windows::Win32::Security::Cryptography::{
        BCryptCloseAlgorithmProvider, BCryptDestroyKey, BCryptEncrypt, BCryptImportKeyPair,
        BCryptOpenAlgorithmProvider, NCryptCreatePersistedKey, NCryptDecrypt, NCryptDeleteKey,
        NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject, NCryptGetProperty, NCryptOpenKey,
        NCryptOpenStorageProvider, NCryptSetProperty, BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE,
        BCRYPT_OAEP_PADDING_INFO, BCRYPT_PAD_OAEP, BCRYPT_RSAPUBLIC_BLOB, BCRYPT_RSA_ALGORITHM,
        BCRYPT_SHA256_ALGORITHM, CERT_KEY_SPEC, MS_NGC_KEY_STORAGE_PROVIDER, NCRYPT_FLAGS,
        NCRYPT_KEY_HANDLE, NCRYPT_LENGTH_PROPERTY, NCRYPT_OVERWRITE_KEY_FLAG,
        NCRYPT_PAD_OAEP_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
        NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG, NCRYPT_UI_POLICY, NCRYPT_UI_POLICY_PROPERTY,
        NCRYPT_WINDOW_HANDLE_PROPERTY,
    };
    use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;
    use zeroize::Zeroize;

    const NGC_IMPL_TYPE_PROP: PCWSTR = w!("ImplType");
    const RSA_MODULUS_BITS: u32 = 2048;

    struct ProvGuard(NCRYPT_PROV_HANDLE);
    impl Drop for ProvGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = NCryptFreeObject(self.0.into());
                }
            }
        }
    }

    struct KeyGuard(NCRYPT_KEY_HANDLE);
    impl Drop for KeyGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = NCryptFreeObject(self.0.into());
                }
            }
        }
    }

    struct BcryptAlgGuard(BCRYPT_ALG_HANDLE);
    impl Drop for BcryptAlgGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = BCryptCloseAlgorithmProvider(self.0, 0);
                }
            }
        }
    }

    struct BcryptKeyGuard(BCRYPT_KEY_HANDLE);
    impl Drop for BcryptKeyGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = BCryptDestroyKey(self.0);
                }
            }
        }
    }

    fn to_wide_null(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn attach_hwnd(key: NCRYPT_KEY_HANDLE, parent_hwnd: Option<isize>) {
        if let Some(raw_hwnd) = parent_hwnd {
            if raw_hwnd != 0 {
                let bytes = raw_hwnd.to_ne_bytes();
                unsafe {
                    if let Err(err) = NCryptSetProperty(
                        key.into(),
                        NCRYPT_WINDOW_HANDLE_PROPERTY,
                        &bytes,
                        NCRYPT_SILENT_FLAG,
                    ) {
                        tracing::warn!(
                            "No se pudo asociar HWND al diálogo de Windows Hello: {}",
                            err
                        );
                    }
                }
            }
        }
    }

    fn map_ncrypt_error(hr: HRESULT, context: &str) -> VaultError {
        classify_ncrypt_hresult(hr.0, context)
    }

    /// Verifica si el proveedor Microsoft Passport / Windows Hello está provisionado para el usuario actual.
    pub fn is_hello_available() -> bool {
        unsafe {
            let mut prov = NCRYPT_PROV_HANDLE::default();
            if NCryptOpenStorageProvider(&mut prov, MS_NGC_KEY_STORAGE_PROVIDER, 0).is_err() {
                return false;
            }
            let _prov_guard = ProvGuard(prov);

            let mut impl_type = [0u8; 4];
            let mut written = 0u32;
            NCryptGetProperty(
                prov.into(),
                NGC_IMPL_TYPE_PROP,
                Some(&mut impl_type),
                &mut written,
                OBJECT_SECURITY_INFORMATION(NCRYPT_SILENT_FLAG.0),
            )
            .is_ok()
        }
    }

    /// Crea una clave RSA-2048 protegida en Microsoft Passport KSP y envuelve `vault_key` con RSA-OAEP-SHA256.
    pub fn enroll_and_wrap_vault_key(
        key_name: &str,
        vault_key: &ProtectedKey,
        parent_hwnd: Option<isize>,
    ) -> VaultResult<Vec<u8>> {
        let key_name_w = to_wide_null(key_name);

        unsafe {
            let mut prov = NCRYPT_PROV_HANDLE::default();
            NCryptOpenStorageProvider(&mut prov, MS_NGC_KEY_STORAGE_PROVIDER, 0)
                .map_err(|e| map_ncrypt_error(e.code(), "OpenStorageProvider"))?;
            let _prov_guard = ProvGuard(prov);

            let mut ncrypt_key = NCRYPT_KEY_HANDLE::default();
            NCryptCreatePersistedKey(
                prov,
                &mut ncrypt_key,
                BCRYPT_RSA_ALGORITHM,
                PCWSTR(key_name_w.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_OVERWRITE_KEY_FLAG,
            )
            .map_err(|e| map_ncrypt_error(e.code(), "CreatePersistedKey"))?;
            let _key_guard = KeyGuard(ncrypt_key);

            // Garantiza explícitamente RSA-2048 según el Spec v1.2 antes de finalizar la clave
            let key_bits_bytes = RSA_MODULUS_BITS.to_ne_bytes();
            NCryptSetProperty(
                ncrypt_key.into(),
                NCRYPT_LENGTH_PROPERTY,
                &key_bits_bytes,
                NCRYPT_SILENT_FLAG,
            )
            .map_err(|e| map_ncrypt_error(e.code(), "SetKeyLength2048"))?;

            attach_hwnd(ncrypt_key, parent_hwnd);

            // Exige obligatoriamente verificación activa del gesto Windows Hello (alta protección)
            let ui_policy = NCRYPT_UI_POLICY {
                dwVersion: 1,
                dwFlags: NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG,
                pszCreationTitle: PCWSTR::null(),
                pszFriendlyName: w!("AegisVault — Llave de desbloqueo local"),
                pszDescription: w!(
                    "Autoriza el uso de Windows Hello para desenvolver la llave cifrada de AegisVault."
                ),
            };
            let policy_slice = std::slice::from_raw_parts(
                &ui_policy as *const NCRYPT_UI_POLICY as *const u8,
                std::mem::size_of::<NCRYPT_UI_POLICY>(),
            );
            NCryptSetProperty(
                ncrypt_key.into(),
                NCRYPT_UI_POLICY_PROPERTY,
                policy_slice,
                NCRYPT_FLAGS(0),
            )
            .map_err(|e| {
                tracing::error!(
                    "NCrypt rechazó aplicar NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG: {}",
                    e
                );
                map_ncrypt_error(e.code(), "SetUiPolicyHighProtection")
            })?;

            // Dispara el prompt de Windows Hello para sellar la clave en TPM/NGC
            NCryptFinalizeKey(ncrypt_key, NCRYPT_FLAGS(0))
                .map_err(|e| map_ncrypt_error(e.code(), "FinalizeKey"))?;

            // Exportar clave pública RSA del contenedor NGC
            let mut pub_len = 0u32;
            NCryptExportKey(
                ncrypt_key,
                None,
                BCRYPT_RSAPUBLIC_BLOB,
                None,
                None,
                &mut pub_len,
                NCRYPT_SILENT_FLAG,
            )
            .map_err(|e| map_ncrypt_error(e.code(), "ExportPublicKeySize"))?;

            let mut pub_blob = vec![0u8; pub_len as usize];
            NCryptExportKey(
                ncrypt_key,
                None,
                BCRYPT_RSAPUBLIC_BLOB,
                None,
                Some(&mut pub_blob),
                &mut pub_len,
                NCRYPT_SILENT_FLAG,
            )
            .map_err(|e| map_ncrypt_error(e.code(), "ExportPublicKey"))?;
            pub_blob.truncate(pub_len as usize);

            // Importar clave pública en BCrypt y cifrar los 32 bytes de VaultKey con RSA-OAEP-SHA256
            let mut alg = BCRYPT_ALG_HANDLE::default();
            BCryptOpenAlgorithmProvider(
                &mut alg,
                BCRYPT_RSA_ALGORITHM,
                PCWSTR::null(),
                Default::default(),
            )
            .ok()
            .map_err(|e| {
                VaultError::internal(format!("BCryptOpenAlgorithmProvider RSA falló: {e}"))
            })?;
            let _alg_guard = BcryptAlgGuard(alg);

            let mut pub_key = BCRYPT_KEY_HANDLE::default();
            BCryptImportKeyPair(alg, None, BCRYPT_RSAPUBLIC_BLOB, &mut pub_key, &pub_blob, 0)
                .ok()
                .map_err(|e| VaultError::internal(format!("BCryptImportKeyPair RSA falló: {e}")))?;
            let _pub_key_guard = BcryptKeyGuard(pub_key);

            let oaep_info = BCRYPT_OAEP_PADDING_INFO {
                pszAlgId: BCRYPT_SHA256_ALGORITHM,
                pbLabel: std::ptr::null_mut(),
                cbLabel: 0,
            };

            let mut cipher_len = 0u32;
            BCryptEncrypt(
                pub_key,
                Some(vault_key.as_bytes()),
                Some(&oaep_info as *const _ as *const std::ffi::c_void),
                None,
                None,
                &mut cipher_len,
                BCRYPT_PAD_OAEP,
            )
            .ok()
            .map_err(|e| {
                VaultError::internal(format!("Cálculo de tamaño RSA-OAEP-SHA256 falló: {e}"))
            })?;

            let mut wrapped = vec![0u8; cipher_len as usize];
            BCryptEncrypt(
                pub_key,
                Some(vault_key.as_bytes()),
                Some(&oaep_info as *const _ as *const std::ffi::c_void),
                None,
                Some(&mut wrapped),
                &mut cipher_len,
                BCRYPT_PAD_OAEP,
            )
            .ok()
            .map_err(|e| {
                VaultError::internal(format!(
                    "Cifrado RSA-OAEP-SHA256 de VaultKey falló: {e}"
                ))
            })?;

            wrapped.truncate(cipher_len as usize);
            Ok(wrapped)
        }
    }

    /// Invoca Windows Hello en el TPM para desenvolver `hello_wrapped_vk` directamente hacia un `ProtectedKey`.
    pub fn unwrap_vault_key_with_hello(
        key_name: &str,
        wrapped_vk: &[u8],
        parent_hwnd: Option<isize>,
    ) -> VaultResult<ProtectedKey> {
        let key_name_w = to_wide_null(key_name);

        unsafe {
            let mut prov = NCRYPT_PROV_HANDLE::default();
            NCryptOpenStorageProvider(&mut prov, MS_NGC_KEY_STORAGE_PROVIDER, 0)
                .map_err(|e| map_ncrypt_error(e.code(), "OpenStorageProvider"))?;
            let _prov_guard = ProvGuard(prov);

            let mut ncrypt_key = NCRYPT_KEY_HANDLE::default();
            NCryptOpenKey(
                prov,
                &mut ncrypt_key,
                PCWSTR(key_name_w.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
            .map_err(|e| map_ncrypt_error(e.code(), "OpenKey"))?;
            let _key_guard = KeyGuard(ncrypt_key);

            attach_hwnd(ncrypt_key, parent_hwnd);

            let oaep_info = BCRYPT_OAEP_PADDING_INFO {
                pszAlgId: BCRYPT_SHA256_ALGORITHM,
                pbLabel: std::ptr::null_mut(),
                cbLabel: 0,
            };

            let mut plain_buf = [0u8; 64];
            let mut out_len = 0u32;

            let res = NCryptDecrypt(
                ncrypt_key,
                Some(wrapped_vk),
                Some(&oaep_info as *const _ as *const std::ffi::c_void),
                Some(&mut plain_buf),
                &mut out_len,
                NCRYPT_PAD_OAEP_FLAG,
            );

            if let Err(err) = res {
                plain_buf.zeroize();
                return Err(map_ncrypt_error(err.code(), "NCryptDecrypt"));
            }

            if out_len as usize != KEY_LEN {
                plain_buf.zeroize();
                return Err(VaultError::new(
                    ErrorCode::HelloInvalidated,
                    "Longitud inesperada al desenvolver llave con Windows Hello.",
                ));
            }

            let mut raw_vk = [0u8; KEY_LEN];
            raw_vk.copy_from_slice(&plain_buf[..KEY_LEN]);
            plain_buf.zeroize();

            Ok(ProtectedKey::from_mut_bytes(&mut raw_vk))
        }
    }

    /// Destruye de forma silenciosa la clave persistida en Microsoft Passport KSP si existe.
    pub fn delete_persisted_hello_key(key_name: &str) {
        let key_name_w = to_wide_null(key_name);
        unsafe {
            let mut prov = NCRYPT_PROV_HANDLE::default();
            if NCryptOpenStorageProvider(&mut prov, MS_NGC_KEY_STORAGE_PROVIDER, 0).is_err() {
                return;
            }
            let _prov_guard = ProvGuard(prov);

            let mut ncrypt_key = NCRYPT_KEY_HANDLE::default();
            if NCryptOpenKey(
                prov,
                &mut ncrypt_key,
                PCWSTR(key_name_w.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_SILENT_FLAG,
            )
            .is_ok()
            {
                if NCryptDeleteKey(ncrypt_key, 0).is_err() {
                    let _ = NCryptFreeObject(ncrypt_key.into());
                }
            }
        }
    }
}

#[cfg(windows)]
pub use imp::{
    delete_persisted_hello_key, enroll_and_wrap_vault_key, is_hello_available,
    unwrap_vault_key_with_hello,
};

#[cfg(not(windows))]
pub fn is_hello_available() -> bool {
    false
}

#[cfg(not(windows))]
pub fn enroll_and_wrap_vault_key(
    _key_name: &str,
    _vault_key: &ProtectedKey,
    _parent_hwnd: Option<isize>,
) -> VaultResult<Vec<u8>> {
    Err(VaultError::internal(
        "Windows Hello solo está soportado en sistemas Windows.",
    ))
}

#[cfg(not(windows))]
pub fn unwrap_vault_key_with_hello(
    _key_name: &str,
    _wrapped_vk: &[u8],
    _parent_hwnd: Option<isize>,
) -> VaultResult<ProtectedKey> {
    Err(VaultError::internal(
        "Windows Hello solo está soportado en sistemas Windows.",
    ))
}

#[cfg(not(windows))]
pub fn delete_persisted_hello_key(_key_name: &str) {}

#[cfg(test)]
mod phase4_hello_tests {
    use super::*;

    #[test]
    fn tpm_key_not_loaded_maps_to_hello_invalidated_fallback() {
        let err = classify_ncrypt_hresult(TPM_E_KEY_NOT_LOADED_HR, "NCryptDecrypt");
        assert_eq!(err.code, ErrorCode::HelloInvalidated);
    }

    #[test]
    fn user_cancellation_hresults_map_to_hello_cancelled() {
        for hr in [
            SCARD_W_CANCELLED_BY_USER_HR,
            ERROR_CANCELLED_HR,
            NTE_USER_CANCELLED_HR,
        ] {
            let err = classify_ncrypt_hresult(hr, "FinalizeKey");
            assert_eq!(err.code, ErrorCode::HelloCancelled);
        }
    }

    #[cfg(windows)]
    #[test]
    fn bcrypt_rsa_oaep_sha256_encrypt_compiles_and_wraps_32b_key() {
        use windows::core::PCWSTR;
        use windows::Win32::Security::Cryptography::{
            BCryptCloseAlgorithmProvider, BCryptDestroyKey, BCryptEncrypt, BCryptExportKey,
            BCryptFinalizeKeyPair, BCryptGenerateKeyPair, BCryptImportKeyPair,
            BCryptOpenAlgorithmProvider, BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE,
            BCRYPT_OAEP_PADDING_INFO, BCRYPT_PAD_OAEP, BCRYPT_RSAPUBLIC_BLOB,
            BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM,
        };

        // Verifica en `cargo test` sin requerir prompt interactivo de Windows Hello
        // que la ruta exacta BCryptOpenAlgorithmProvider -> BCryptImportKeyPair -> BCryptEncrypt
        // con RSA-2048 + OAEP-SHA256 compila limpio en windows-rs 0.59 y produce un bloque de 256 bytes.
        unsafe {
            let mut alg = BCRYPT_ALG_HANDLE::default();
            BCryptOpenAlgorithmProvider(
                &mut alg,
                BCRYPT_RSA_ALGORITHM,
                PCWSTR::null(),
                Default::default(),
            )
            .ok()
            .expect("BCryptOpenAlgorithmProvider debe tener éxito");

            let mut gen_key = BCRYPT_KEY_HANDLE::default();
            BCryptGenerateKeyPair(alg, &mut gen_key, 2048, 0)
                .ok()
                .expect("BCryptGenerateKeyPair 2048 debe tener éxito");
            BCryptFinalizeKeyPair(gen_key, 0)
                .ok()
                .expect("BCryptFinalizeKeyPair debe tener éxito");

            let mut pub_len = 0u32;
            BCryptExportKey(gen_key, None, BCRYPT_RSAPUBLIC_BLOB, None, &mut pub_len, 0)
                .ok()
                .expect("Tamaño de BCRYPT_RSAPUBLIC_BLOB");
            let mut pub_blob = vec![0u8; pub_len as usize];
            BCryptExportKey(
                gen_key,
                None,
                BCRYPT_RSAPUBLIC_BLOB,
                Some(&mut pub_blob),
                &mut pub_len,
                0,
            )
            .ok()
            .expect("Exportar BCRYPT_RSAPUBLIC_BLOB");
            let _ = BCryptDestroyKey(gen_key);

            let mut imported_pub = BCRYPT_KEY_HANDLE::default();
            BCryptImportKeyPair(
                alg,
                None,
                BCRYPT_RSAPUBLIC_BLOB,
                &mut imported_pub,
                &pub_blob,
                0,
            )
            .ok()
            .expect("BCryptImportKeyPair debe tener éxito");

            let mut raw_vk = [0x5Au8; KEY_LEN];
            let vk = ProtectedKey::from_mut_bytes(&mut raw_vk);

            let oaep_info = BCRYPT_OAEP_PADDING_INFO {
                pszAlgId: BCRYPT_SHA256_ALGORITHM,
                pbLabel: std::ptr::null_mut(),
                cbLabel: 0,
            };

            let mut cipher_len = 0u32;
            BCryptEncrypt(
                imported_pub,
                Some(vk.as_bytes()),
                Some(&oaep_info as *const _ as *const std::ffi::c_void),
                None,
                None,
                &mut cipher_len,
                BCRYPT_PAD_OAEP,
            )
            .ok()
            .expect("Cálculo de tamaño RSA-OAEP-SHA256");
            assert_eq!(cipher_len, 256);

            let mut wrapped = vec![0u8; cipher_len as usize];
            BCryptEncrypt(
                imported_pub,
                Some(vk.as_bytes()),
                Some(&oaep_info as *const _ as *const std::ffi::c_void),
                None,
                Some(&mut wrapped),
                &mut cipher_len,
                BCRYPT_PAD_OAEP,
            )
            .ok()
            .expect("Cifrado efectivo RSA-OAEP-SHA256");
            assert_eq!(wrapped.len(), 256);

            let _ = BCryptDestroyKey(imported_pub);
            let _ = BCryptCloseAlgorithmProvider(alg, 0);
        }
    }
}
