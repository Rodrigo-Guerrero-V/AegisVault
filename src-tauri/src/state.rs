use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

use crate::crypto::kdf::{expand_vault_subkeys, DerivedVaultSubkeys};
use crate::crypto::memory::ProtectedKey;
use crate::db::VaultDb;
use crate::error::{VaultError, VaultResult};

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

pub struct UnlockedSession {
    pub vault_key: ProtectedKey,
    pub subkeys: DerivedVaultSubkeys,
    pub folders_cache: HashMap<String, String>,
    pub items_cache: HashMap<String, CachedItemOverview>,
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

pub struct AppState {
    pub db: VaultDb,
    pub clipboard: crate::platform::clipboard::ClipboardGuard,
    session: RwLock<VaultLockState>,
    epoch_instant: Instant,
    last_activity_secs: AtomicU64,
    lock_timeout_secs: AtomicU64,
    clipboard_ttl_secs: AtomicU64,
}

impl AppState {
    pub fn new(db: VaultDb, initial_timeout: u64, initial_clip_ttl: u64) -> Self {
        Self {
            db,
            clipboard: crate::platform::clipboard::ClipboardGuard::new(),
            session: RwLock::new(VaultLockState::Locked),
            epoch_instant: Instant::now(),
            last_activity_secs: AtomicU64::new(0),
            lock_timeout_secs: AtomicU64::new(initial_timeout),
            clipboard_ttl_secs: AtomicU64::new(initial_clip_ttl),
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
        self.lock_timeout_secs
            .store(lock_timeout_secs, Ordering::Release);
        self.clipboard_ttl_secs
            .store(clipboard_ttl_secs, Ordering::Release);
        self.touch_activity();
    }

    pub fn security_prefs(&self) -> (u64, u64) {
        (
            self.lock_timeout_secs.load(Ordering::Acquire),
            self.clipboard_ttl_secs.load(Ordering::Acquire),
        )
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
        });

        self.set_security_prefs(lock_timeout_secs, clipboard_ttl_secs);
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

    /// Destruye claves en memoria (Drop -> Zeroize + VirtualUnlock), compacta/trunca SQLite WAL
    /// y notifica a React si la transición fue desde estado desbloqueado.
    pub fn lock_now(&self, app: Option<&AppHandle>, reason: LockReason) -> VaultResult<bool> {
        let was_unlocked = {
            let mut guard = self
                .session
                .write()
                .map_err(|_| VaultError::internal("RwLock de sesión envenenado al bloquear."))?;
            let previously_open = matches!(*guard, VaultLockState::Unlocked(_));
            *guard = VaultLockState::Locked; // Dispara Drop de ProtectedKey y HashMaps en memoria
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
        let timeout = self.lock_timeout_secs.load(Ordering::Acquire);
        if timeout == 0 {
            return;
        }
        let last = self.last_activity_secs.load(Ordering::Acquire);
        let elapsed = self.monotonic_secs().saturating_sub(last);
        if elapsed >= timeout {
            let _ = self.lock_now(Some(app), LockReason::Inactivity);
        }
    }
}
