// src-tauri/src/platform/power_session.rs
use tauri::AppHandle;

#[cfg(windows)]
pub fn spawn_os_lock_watcher(app: AppHandle) {
    use std::sync::OnceLock;
    use tauri::Manager;
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::RemoteDesktop::{
        WTSRegisterSessionNotification, WTSUnRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
        RegisterClassW, TranslateMessage, CW_USEDEFAULT, MSG, PBT_APMSUSPEND, WINDOW_EX_STYLE,
        WM_DESTROY, WM_POWERBROADCAST, WM_WTSSESSION_CHANGE, WNDCLASSW, WS_OVERLAPPEDWINDOW,
        WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK, WTS_SESSION_LOGOFF,
    };

    use crate::state::{AppState, LockReason};

    static APP_HANDLE_CELL: OnceLock<AppHandle> = OnceLock::new();
    let _ = APP_HANDLE_CELL.set(app);

    unsafe extern "system" fn watcher_wndproc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_WTSSESSION_CHANGE => {
                let event_code = wparam.0 as u32;
                if matches!(
                    event_code,
                    WTS_SESSION_LOCK
                        | WTS_SESSION_LOGOFF
                        | WTS_CONSOLE_DISCONNECT
                        | WTS_REMOTE_DISCONNECT
                ) {
                    if let Some(handle) = APP_HANDLE_CELL.get() {
                        let state = handle.state::<AppState>();
                        let _ = state.lock_now(Some(handle), LockReason::OsSessionLock);
                    }
                }
                LRESULT(0)
            }
            WM_POWERBROADCAST => {
                if wparam.0 as u32 == PBT_APMSUSPEND {
                    if let Some(handle) = APP_HANDLE_CELL.get() {
                        let state = handle.state::<AppState>();
                        let _ = state.lock_now(Some(handle), LockReason::OsSuspend);
                    }
                }
                LRESULT(1)
            }
            WM_DESTROY => {
                let _ = WTSUnRegisterSessionNotification(hwnd);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    std::thread::Builder::new()
        .name("aegis-win32-session-watcher".into())
        .spawn(move || unsafe {
            let class_name: PCWSTR = w!("AegisVaultPowerSessionWatcherClass");
            let wc = WNDCLASSW {
                lpfnWndProc: Some(watcher_wndproc),
                lpszClassName: class_name,
                ..Default::default()
            };
            let _ = RegisterClassW(&wc);

            // Ventana top-level invisible (requerida en vez de HWND_MESSAGE para recibir WM_POWERBROADCAST broadcast)
            let Ok(hwnd) = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                class_name,
                w!("AegisVaultSessionWatcher"),
                WS_OVERLAPPEDWINDOW,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                0,
                0,
                None,
                None,
                None,
                None,
            ) else {
                tracing::error!("No se pudo crear ventana oculta para eventos de energía/sesión.");
                return;
            };

            if let Err(err) = WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) {
                tracing::warn!(
                    "WTSRegisterSessionNotification falló (Win+L no notificará): {}",
                    err
                );
            }

            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            let _ = DestroyWindow(hwnd);
        })
        .ok();
}

#[cfg(not(windows))]
pub fn spawn_os_lock_watcher(_app: AppHandle) {}
