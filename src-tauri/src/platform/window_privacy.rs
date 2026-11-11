use tauri::{AppHandle, Manager};

/// Activa o desactiva `WDA_EXCLUDEFROMCAPTURE` sobre la ventana principal para impedir que
/// herramientas de captura de pantalla, compartición de escritorio o Windows Recall registren secretos.
pub fn apply_window_capture_protection(app: &AppHandle, enabled: bool) -> bool {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::UI::WindowsAndMessaging::{
            SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_NONE,
        };

        // En automatización de desarrollo/tests E2E se puede desactivar temporalmente solo en builds debug.
        #[cfg(debug_assertions)]
        if std::env::var_os("AEGISVAULT_DEV_ALLOW_SCREENSHOTS").is_some() {
            return false;
        }

        let Some(win) = app.get_webview_window("main") else {
            return false;
        };
        let Ok(raw_hwnd) = win.hwnd() else {
            return false;
        };
        let hwnd = HWND(raw_hwnd.0);
        let affinity = if enabled {
            WDA_EXCLUDEFROMCAPTURE
        } else {
            WDA_NONE
        };

        unsafe {
            match SetWindowDisplayAffinity(hwnd, affinity) {
                Ok(()) => true,
                Err(err) => {
                    tracing::warn!(
                        "SetWindowDisplayAffinity(enabled={}) devolvió advertencia: {}",
                        enabled,
                        err
                    );
                    false
                }
            }
        }
    }

    #[cfg(not(windows))]
    {
        let _ = (app, enabled);
        false
    }
}
