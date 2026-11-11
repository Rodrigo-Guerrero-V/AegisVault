use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tokio::sync::Semaphore;
use zeroize::Zeroize;

use crate::crypto::kdf::{expand_vault_subkeys, DerivedVaultSubkeys};
use crate::crypto::memory::ProtectedKey;
use crate::db::VaultDb;
use crate::error::{VaultError, VaultResult};

pub const MIN_LOCK_TIMEOUT_SECS: u64 = 15;
pub const MAX_LOCK_TIMEOUT_SECS: u64 = 3600;
pub const DEFAULT_LOCK_TIMEOUT_SECS: u64 = 300;

pub const MIN_CLIPBOARD_TTL_SECS: u64 = 5;
pub const MAX_CLIPBOARD_TTL_SECS: u64 = 300;
pub const DEFAULT_CLIPBOARD_TTL_SECS: u64 = 25;

pub fn clamp_security_timers(lock_timeout_secs: u64, clipboard_ttl_secs: u64) -> (u64, u64) {
    (
        lock_timeout_secs.clamp(MIN_LOCK_TIMEOUT_SECS, MAX_LOCK_TIMEOUT_SECS),
        clipboard_ttl_secs.clamp(MIN_CLIPBOARD_TTL_SECS, MAX_CLIPBOARD_TTL_SECS),
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedItemOverview {
    pub id: String,
    pub folder_id: Option<String>,
    pub item_type: String,
    pub favorite: bool,
    pub title: String,
    pub subtitle: String,
    pub urls: Vec<String>,
    pub tags: Vec<String>,
    pub updated_at: i64,
}

impl Zeroize for CachedItemOverview {
    fn zeroize(&mut self) {
        self.id.zeroize();
        if let Some(ref mut fid) = self.folder_id {
            fid.zeroize();
        }
        self.folder_id = None;
        self.item_type.zeroize();
        self.favorite = false;
        self.title.zeroize();
        self.subtitle.zeroize();
        for u in &mut self.urls {
            u.zeroize();
        }
        self.urls.clear();
        for t in &mut self.tags {
            t.zeroize();
        }
        self.tags.clear();
        self.updated_at = 0;
    }
}

impl Drop for CachedItemOverview {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub struct UnlockedSession {
    pub vault_key: ProtectedKey,
    pub subkeys: DerivedVaultSubkeys,
    pub folders_cache: HashMap<String, String>,
    pub items_cache: HashMap<String, CachedItemOverview>,
    pub corrupted_count: usize,
}

impl Drop for UnlockedSession {
    fn drop(&mut self) {
        for (mut k, mut v) in self.folders_cache.drain() {
            k.zeroize();
            v.zeroize();
        }
        for (mut k, mut v) in self.items_cache.drain() {
            k.zeroize();
            v.zeroize();
        }
        self.corrupted_count = 0;
    }
}

pub enum VaultLockState {
    Locked,
    Unlocked(UnlockedSession),
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockReason {
    Inactivity,
    Manual,
    OsSessionLock,
    OsSuspend,
}

#[derive(Debug, Clone, Serialize)]
pub struct LockedEventPayload {
    pub reason: LockReason,
}

#[derive(Default)]
struct UnlockThrottle {
    failed_attempts: u32,
    locked_until: Option<Instant>,
}

pub struct AppState {
    pub db: VaultDb,
    pub clipboard: crate::platform::clipboard::ClipboardGuard,
    pub kdf_semaphore: Arc<Semaphore>,
    session: RwLock<VaultLockState>,
    epoch_instant: Instant,
    last_activity_secs: AtomicU64,
    lock_timeout_secs: AtomicU64,
    clipboard_ttl_secs: AtomicU64,
    capture_protection_enabled: AtomicBool,
    unlock_throttle: Mutex<UnlockThrottle>,
    approved_restore_path: Mutex<Option<PathBuf>>,
}

impl AppState {
    pub fn new(db: VaultDb, initial_timeout: u64, initial_clip_ttl: u64) -> Self {
        let (clamped_lock, clamped_clip) = clamp_security_timers(initial_timeout, initial_clip_ttl);
        Self {
            db,
            clipboard: crate::platform::clipboard::ClipboardGuard::new(),
            kdf_semaphore: Arc::new(Semaphore::new(1)),
            session: RwLock::new(VaultLockState::Locked),
            epoch_instant: Instant::now(),
            last_activity_secs: AtomicU64::new(0),
            lock_timeout_secs: AtomicU64::new(clamped_lock),
            clipboard_ttl_secs: AtomicU64::new(clamped_clip),
            capture_protection_enabled: AtomicBool::new(true),
            unlock_throttle: Mutex::new(UnlockThrottle::default()),
            approved_restore_path: Mutex::new(None),
        }
    }

    pub fn now_unix() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    fn monotonic_secs(&self) -> u64 {
        self.epoch_instant.elapsed().as_secs()
    }

    pub fn touch_activity(&self) {
        self.last_activity_secs
            .store(self.monotonic_secs(), Ordering::Release);
    }

    pub fn set_security_prefs(&self, lock_timeout_secs: u64, clipboard_ttl_secs: u64) {
        let (clamped_lock, clamped_clip) =
            clamp_security_timers(lock_timeout_secs, clipboard_ttl_secs);
        self.lock_timeout_secs
            .store(clamped_lock, Ordering::Release);
        self.clipboard_ttl_secs
            .store(clamped_clip, Ordering::Release);
        self.touch_activity();
    }

    pub fn set_capture_protection(&self, enabled: bool) {
        self.capture_protection_enabled
            .store(enabled, Ordering::Release);
    }

    pub fn capture_protection_enabled(&self) -> bool {
        self.capture_protection_enabled.load(Ordering::Acquire)
    }

    pub fn security_prefs(&self) -> (u64, u64) {
        clamp_security_timers(
            self.lock_timeout_secs.load(Ordering::Acquire),
            self.clipboard_ttl_secs.load(Ordering::Acquire),
        )
    }

    pub fn check_unlock_backoff(&self) -> VaultResult<()> {
        let guard = self
            .unlock_throttle
            .lock()
            .map_err(|_| VaultError::internal("Mutex de control de intentos envenenado."))?;
        if let Some(until) = guard.locked_until {
            let now = Instant::now();
            if until > now {
                let rem = until.duration_since(now).as_secs().max(1);
                return Err(VaultError::rate_limited(format!(
                    "Demasiados intentos fallidos de autenticación. Espera {rem}s antes de reintentar."
                )));
            }
        }
        Ok(())
    }

    pub fn record_unlock_failure(&self) -> u64 {
        if let Ok(mut guard) = self.unlock_throttle.lock() {
            guard.failed_attempts = guard.failed_attempts.saturating_add(1);
            let exp = guard.failed_attempts.saturating_sub(1).min(5);
            let delay_secs = (1u64 << exp).min(30);
            guard.locked_until = Some(Instant::now() + Duration::from_secs(delay_secs));
            return delay_secs;
        }
        1
    }

    pub fn reset_unlock_backoff(&self) {
        if let Ok(mut guard) = self.unlock_throttle.lock() {
            guard.failed_attempts = 0;
            guard.locked_until = None;
        }
    }

    pub fn set_approved_restore_path(&self, path: Option<PathBuf>) -> VaultResult<()> {
        let mut guard = self
            .approved_restore_path
            .lock()
            .map_err(|_| VaultError::internal("Mutex de ruta de restauración envenenado."))?;
        *guard = path;
        Ok(())
    }

    pub fn take_approved_restore_path(&self) -> VaultResult<Option<PathBuf>> {
        let mut guard = self
            .approved_restore_path
            .lock()
            .map_err(|_| VaultError::internal("Mutex de ruta de restauración envenenado."))?;
        Ok(guard.take())
    }

    pub fn is_locked(&self) -> bool {
        match self.session.read() {
            Ok(guard) => matches!(*guard, VaultLockState::Locked),
            Err(_) => true,
        }
    }

    pub fn install_unlocked_key(
        &self,
        vault_key: ProtectedKey,
        lock_timeout_secs: u64,
        clipboard_ttl_secs: u64,
        capture_protection_enabled: bool,
    ) -> VaultResult<()> {
        let subkeys = expand_vault_subkeys(&vault_key)?;
        let mut guard = self
            .session
            .write()
            .map_err(|_| VaultError::internal("RwLock de sesión envenenado."))?;

        *guard = VaultLockState::Unlocked(UnlockedSession {
            vault_key,
            subkeys,
            folders_cache: HashMap::new(),
            items_cache: HashMap::new(),
            corrupted_count: 0,
        });

        self.set_security_prefs(lock_timeout_secs, clipboard_ttl_secs);
        self.set_capture_protection(capture_protection_enabled);
        self.reset_unlock_backoff();
        Ok(())
    }

    pub fn with_unlocked<F, T>(&self, f: F) -> VaultResult<T>
    where
        F: FnOnce(&UnlockedSession) -> VaultResult<T>,
    {
        let guard = self
            .session
            .read()
            .map_err(|_| VaultError::internal("RwLock de sesión envenenado."))?;

        match &*guard {
            VaultLockState::Locked => Err(VaultError::locked()),
            VaultLockState::Unlocked(unlocked) => {
                self.touch_activity();
                f(unlocked)
            }
        }
    }

    pub fn with_unlocked_mut<F, T>(&self, f: F) -> VaultResult<T>
    where
        F: FnOnce(&mut UnlockedSession) -> VaultResult<T>,
    {
        let mut guard = self
            .session
            .write()
            .map_err(|_| VaultError::internal("RwLock de sesión envenenado."))?;

        match &mut *guard {
            VaultLockState::Locked => Err(VaultError::locked()),
            VaultLockState::Unlocked(unlocked) => {
                self.touch_activity();
                f(unlocked)
            }
        }
    }

    /// Destruye claves en memoria (Drop -> Zeroize + VirtualUnlock + VirtualFree), compacta/trunca
    /// SQLite WAL y notifica a React si la transición fue desde estado desbloqueado.
    pub fn lock_now(&self, app: Option<&AppHandle>, reason: LockReason) -> VaultResult<bool> {
        let was_unlocked = {
            let mut guard = self
                .session
                .write()
                .map_err(|_| VaultError::internal("RwLock de sesión envenenado al bloquear."))?;
            let previously_open = matches!(*guard, VaultLockState::Unlocked(_));
            *guard = VaultLockState::Locked;
            previously_open
        };

        if was_unlocked {
            self.clipboard.purge_if_matching_generation(app, None);
            if let Err(err) = self.db.sanitize_on_lock() {
                tracing::error!("Error saneando WAL al bloquear bóveda: {}", err);
            }
            if let Some(handle) = app {
                let _ = handle.emit("vault://locked", LockedEventPayload { reason });
            }
        }

        Ok(was_unlocked)
    }

    pub fn check_inactivity_and_lock(&self, app: &AppHandle) {
        if self.is_locked() {
            return;
        }
        // Acotado siempre a 15..=3600s: ningún valor alterado en disco puede desactivar el autobloqueo.
        let timeout = self
            .lock_timeout_secs
            .load(Ordering::Acquire)
            .clamp(MIN_LOCK_TIMEOUT_SECS, MAX_LOCK_TIMEOUT_SECS);
        let last = self.last_activity_secs.load(Ordering::Acquire);
        let elapsed = self.monotonic_secs().saturating_sub(last);
        if elapsed >= timeout {
            let _ = self.lock_now(Some(app), LockReason::Inactivity);
        }
    }
}
