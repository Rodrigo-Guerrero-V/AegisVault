pub mod repo;
pub mod schema;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use rusqlite::Connection;

use crate::error::{VaultError, VaultResult};

pub const APP_DIR_NAME: &str = "AegisVault";
pub const DB_FILE_NAME: &str = "vault.db";

pub struct VaultDb {
    path: PathBuf,
    conn: Mutex<Connection>,
    dirty_deletes: AtomicBool,
}

impl VaultDb {
    pub fn open_default() -> VaultResult<Self> {
        let base_dir = resolve_aegis_data_dir()?;
        std::fs::create_dir_all(&base_dir).map_err(|e| {
            VaultError::internal(format!("No se pudo crear el directorio de datos: {e}"))
        })?;

        crate::platform::acl::harden_directory_acl(&base_dir);

        let db_path = base_dir.join(DB_FILE_NAME);
        // Repara DACLs previas (ej. instalación elevada con `OW`) antes de abrir SQLite
        crate::platform::acl::harden_vault_db_files(&db_path);

        let db = Self::open_at(&db_path)?;
        // Asegura DACL explícita de TokenUser también sobre archivos recién creados (-wal / -shm)
        crate::platform::acl::harden_vault_db_files(&db_path);
        Ok(db)
    }

    pub fn open_at(path: &Path) -> VaultResult<Self> {
        let conn = Connection::open(path)?;
        schema::apply_pragmas_and_schema(&conn)?;

        Ok(Self {
            path: path.to_path_buf(),
            conn: Mutex::new(conn),
            dirty_deletes: AtomicBool::new(false),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn mark_dirty_deletes(&self) {
        self.dirty_deletes.store(true, Ordering::Release);
    }

    pub fn with_conn<F, T>(&self, f: F) -> VaultResult<T>
    where
        F: FnOnce(&mut Connection) -> VaultResult<T>,
    {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| VaultError::internal("Mutex de SQLite envenenado."))?;
        f(&mut guard)
    }

    /// Ejecuta VACUUM si hubo borrados/actualizaciones y trunca vault.db-wal a 0 bytes.
    pub fn sanitize_on_lock(&self) -> VaultResult<()> {
        let guard = self
            .conn
            .lock()
            .map_err(|_| VaultError::internal("Mutex de SQLite envenenado al bloquear."))?;

        if self.dirty_deletes.swap(false, Ordering::AcqRel) {
            if let Err(err) = guard.execute_batch("VACUUM;") {
                self.dirty_deletes.store(true, Ordering::Release);
                tracing::error!("Fallo en VACUUM durante bloqueo: {}", err);
            }
        }

        guard.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }
}

fn resolve_aegis_data_dir() -> VaultResult<PathBuf> {
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        return Ok(PathBuf::from(local_app_data).join(APP_DIR_NAME));
    }
    Err(VaultError::internal(
        "Variable de entorno LOCALAPPDATA no disponible en el sistema.",
    ))
}
