use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use subtle::ConstantTimeEq;
use tauri::{AppHandle, Emitter, Manager};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{VaultError, VaultResult};
use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
pub struct ClipboardArmedPayload {
    pub field: String,
    pub ttl_secs: u64,
}

struct ActiveClipDigest {
    generation: u64,
    digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeStatus {
    Cleared,
    ReplacedOrEmpty,
    LockedBusy,
}

pub struct ClipboardGuard {
    session_mac_key: [u8; 32],
    generation_counter: AtomicU64,
    active: Mutex<Option<ActiveClipDigest>>,
}

impl ClipboardGuard {
    pub fn new() -> Self {
        let mut session_mac_key = [0u8; 32];
        OsRng.fill_bytes(&mut session_mac_key);
        Self {
            session_mac_key,
            generation_counter: AtomicU64::new(0),
            active: Mutex::new(None),
        }
    }

    fn compute_digest(&self, text: &str) -> [u8; 32] {
        *blake3::keyed_hash(&self.session_mac_key, text.as_bytes()).as_bytes()
    }

    pub fn copy_protected(
        &self,
        app: &AppHandle,
        field_label: &str,
        secret_text: &str,
        ttl_secs: u64,
    ) -> VaultResult<()> {
        write_win32_excluded_clipboard(secret_text)?;

        let digest = self.compute_digest(secret_text);
        let gen_id = self.generation_counter.fetch_add(1, Ordering::AcqRel) + 1;

        if let Ok(mut guard) = self.active.lock() {
            *guard = Some(ActiveClipDigest {
                generation: gen_id,
                digest,
            });
        }

        let _ = app.emit(
            "vault://clipboard-armed",
            ClipboardArmedPayload {
                field: field_label.to_string(),
                ttl_secs,
            },
        );

        let handle = app.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(Duration::from_secs(ttl_secs)).await;
            let state = handle.state::<AppState>();
            for attempt in 0..4 {
                let status = state
                    .clipboard
                    .purge_if_matching_generation(Some(&handle), Some(gen_id));
                if status != PurgeStatus::LockedBusy {
                    break;
                }
                tracing::warn!(
                    "Portapapeles ocupado al expirar TTL (intento {}/4); conservando digest activo.",
                    attempt + 1
                );
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
        });

        Ok(())
    }

    pub fn purge_if_matching_generation(
        &self,
        app: Option<&AppHandle>,
        expected_gen: Option<u64>,
    ) -> PurgeStatus {
        let target_digest = {
            let Ok(guard) = self.active.lock() else {
                return PurgeStatus::LockedBusy;
            };
            match (&*guard, expected_gen) {
                (Some(entry), Some(g)) if entry.generation == g => entry.digest,
                (Some(entry), None) => entry.digest,
                _ => return PurgeStatus::ReplacedOrEmpty,
            }
        };

        let status = clear_win32_if_matches(&self.session_mac_key, &target_digest);

        // Solo liberamos el digest activo si el secreto fue borrado o ya fue reemplazado por el usuario
        if matches!(status, PurgeStatus::Cleared | PurgeStatus::ReplacedOrEmpty) {
            if let Ok(mut guard) = self.active.lock() {
                let should_drop = match (&*guard, expected_gen) {
                    (Some(entry), Some(g)) => entry.generation == g,
                    (Some(_), None) => true,
                    _ => false,
                };
                if should_drop {
                    if let Some(mut old) = guard.take() {
                        old.digest.zeroize();
                    }
                }
            }
        }

        if status == PurgeStatus::Cleared {
            if let Some(handle) = app {
                let _ = handle.emit("vault://clipboard-cleared", serde_json::json!({}));
            }
        }
        status
    }
}

impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        let _ = self.purge_if_matching_generation(None, None);
        self.session_mac_key.zeroize();
    }
}

#[cfg(windows)]
fn write_win32_excluded_clipboard(secret_text: &str) -> VaultResult<()> {
    use windows::core::w;
    use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
    };
    use windows::Win32::System::Memory::{
        GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE, GMEM_ZEROINIT,
    };
    use windows::Win32::System::Ole::CF_UNICODETEXT;

    let utf16 = Zeroizing::new(
        secret_text
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .collect::<Vec<u16>>(),
    );

    unsafe {
        // Pequeño reintento si otro proceso de escritorio retiene el portapapeles por unos ms
        let mut opened = false;
        for _ in 0..5 {
            if OpenClipboard(None).is_ok() {
                opened = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(15));
        }
        if !opened {
            return Err(VaultError::internal(
                "El portapapeles de Windows está bloqueado temporalmente por otra aplicación.",
            ));
        }

        struct ClipboardCloser;
        impl Drop for ClipboardCloser {
            fn drop(&mut self) {
                unsafe {
                    let _ = CloseClipboard();
                }
            }
        }
        let _closer = ClipboardCloser;

        EmptyClipboard()
            .map_err(|_| VaultError::internal("No se pudo limpiar el portapapeles previo."))?;

        // 1. Escribir CF_UNICODETEXT
        let byte_len = utf16.len() * std::mem::size_of::<u16>();
        let h_text: HGLOBAL = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, byte_len)
            .map_err(|_| VaultError::internal("GlobalAlloc falló para texto del portapapeles."))?;

        let ptr = GlobalLock(h_text) as *mut u16;
        if ptr.is_null() {
            let _ = GlobalFree(Some(h_text));
            return Err(VaultError::internal("GlobalLock falló al copiar secreto."));
        }
        std::ptr::copy_nonoverlapping(utf16.as_ptr(), ptr, utf16.len());
        let _ = GlobalUnlock(h_text);

        if SetClipboardData(CF_UNICODETEXT.0 as u32, Some(HANDLE(h_text.0))).is_err() {
            let _ = GlobalFree(Some(h_text));
            return Err(VaultError::internal(
                "SetClipboardData falló al escribir CF_UNICODETEXT.",
            ));
        }

        // 2. Banderas Win32 que excluyen el secreto de Win+V y sincronización en la nube
        let fmt_exclude = RegisterClipboardFormatW(w!("ExcludeClipboardContentFromMonitorProcessing"));
        let fmt_history = RegisterClipboardFormatW(w!("CanIncludeInClipboardHistory"));
        let fmt_cloud = RegisterClipboardFormatW(w!("CanUploadToCloudClipboard"));

        for fmt in [fmt_exclude, fmt_history, fmt_cloud] {
            if fmt != 0 {
                if let Ok(h_dword) = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, 4) {
                    let p_dword = GlobalLock(h_dword) as *mut u32;
                    if !p_dword.is_null() {
                        *p_dword = 0u32;
                        let _ = GlobalUnlock(h_dword);
                        if SetClipboardData(fmt, Some(HANDLE(h_dword.0))).is_err() {
                            let _ = GlobalFree(Some(h_dword));
                        }
                    } else {
                        let _ = GlobalFree(Some(h_dword));
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn clear_win32_if_matches(mac_key: &[u8; 32], expected_digest: &[u8; 32]) -> PurgeStatus {
    use windows::Win32::Foundation::HGLOBAL;
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard,
    };
    use windows::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};
    use windows::Win32::System::Ole::CF_UNICODETEXT;

    unsafe {
        let mut opened = false;
        for _ in 0..5 {
            if OpenClipboard(None).is_ok() {
                opened = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(15));
        }
        if !opened {
            return PurgeStatus::LockedBusy;
        }

        struct ClipboardCloser;
        impl Drop for ClipboardCloser {
            fn drop(&mut self) {
                unsafe {
                    let _ = CloseClipboard();
                }
            }
        }
        let _closer = ClipboardCloser;

        let Ok(handle) = GetClipboardData(CF_UNICODETEXT.0 as u32) else {
            return PurgeStatus::ReplacedOrEmpty;
        };
        let h_global = HGLOBAL(handle.0);
        let max_u16 = GlobalSize(h_global) / std::mem::size_of::<u16>();
        if max_u16 == 0 {
            return PurgeStatus::ReplacedOrEmpty;
        }

        let ptr = GlobalLock(h_global) as *const u16;
        if ptr.is_null() {
            return PurgeStatus::LockedBusy;
        }

        let slice = std::slice::from_raw_parts(ptr, max_u16);
        let len = slice.iter().position(|&c| c == 0).unwrap_or(max_u16);
        let current_utf8 = Zeroizing::new(String::from_utf16_lossy(&slice[..len]));
        let _ = GlobalUnlock(h_global);

        let actual_digest = blake3::keyed_hash(mac_key, current_utf8.as_bytes());
        if actual_digest.as_bytes().ct_eq(expected_digest).into() {
            if EmptyClipboard().is_ok() {
                PurgeStatus::Cleared
            } else {
                PurgeStatus::LockedBusy
            }
        } else {
            PurgeStatus::ReplacedOrEmpty
        }
    }
}

#[cfg(not(windows))]
fn write_win32_excluded_clipboard(_secret_text: &str) -> VaultResult<()> {
    Err(VaultError::internal("Portapapeles Win32 solo disponible en Windows."))
}

#[cfg(not(windows))]
fn clear_win32_if_matches(_mac_key: &[u8; 32], _expected_digest: &[u8; 32]) -> PurgeStatus {
    PurgeStatus::ReplacedOrEmpty
}
