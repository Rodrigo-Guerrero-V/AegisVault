use std::collections::HashSet;
use rusqlite::Connection;

pub const LEGACY_SCHEMA_VERSION: u32 = 1;
pub const CURRENT_SCHEMA_VERSION: u32 = 2;

pub fn apply_pragmas_and_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = FULL;
        PRAGMA foreign_keys = ON;
        PRAGMA secure_delete = ON;
        PRAGMA temp_store = MEMORY;

        CREATE TABLE IF NOT EXISTS vault_config (
            id                  INTEGER PRIMARY KEY CHECK (id = 1),
            schema_version      INTEGER NOT NULL DEFAULT 2,
            kdf_salt            BLOB NOT NULL,
            kdf_mem_kib         INTEGER NOT NULL,
            kdf_iterations      INTEGER NOT NULL,
            kdf_parallelism     INTEGER NOT NULL,
            mk_wrapped_vk       BLOB NOT NULL,
            mk_wrap_nonce       BLOB NOT NULL,
            hello_enabled       INTEGER NOT NULL DEFAULT 0 CHECK (hello_enabled IN (0, 1)),
            hello_key_name      TEXT,
            hello_wrapped_vk    BLOB,
            lock_timeout_secs   INTEGER NOT NULL DEFAULT 300,
            clipboard_ttl_secs  INTEGER NOT NULL DEFAULT 25,
            prefs_nonce         BLOB,
            prefs_ciphertext    BLOB,
            vk_keycheck         BLOB,
            hello_mac           BLOB,
            created_at          INTEGER NOT NULL,
            updated_at          INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS vault_folders (
            id                  TEXT PRIMARY KEY,
            name_nonce          BLOB NOT NULL,
            name_ciphertext     BLOB NOT NULL,
            created_at          INTEGER NOT NULL,
            updated_at          INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS vault_items (
            id                  TEXT PRIMARY KEY,
            folder_id           TEXT REFERENCES vault_folders(id) ON DELETE SET NULL,
            item_type           TEXT NOT NULL CHECK (item_type IN ('login', 'note', 'card')),
            favorite            INTEGER NOT NULL DEFAULT 0 CHECK (favorite IN (0, 1)),
            overview_nonce      BLOB NOT NULL,
            overview_ciphertext BLOB NOT NULL,
            secret_nonce        BLOB NOT NULL,
            secret_ciphertext   BLOB NOT NULL,
            created_at          INTEGER NOT NULL,
            updated_at          INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_vault_items_folder ON vault_items(folder_id);
        CREATE INDEX IF NOT EXISTS idx_vault_items_type ON vault_items(item_type);
        ",
    )?;

    ensure_v2_config_columns(conn)?;
    Ok(())
}

/// Añade de forma idempotente las columnas de integridad introducidas en `schema_version = 2`
/// cuando se abre una base `vault.db` creada originalmente en `v0.1.0` (`schema_version = 1`).
fn ensure_v2_config_columns(conn: &Connection) -> rusqlite::Result<()> {
    let mut existing_cols = HashSet::new();
    {
        let mut stmt = conn.prepare("PRAGMA table_info(vault_config)")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
        for col in rows {
            existing_cols.insert(col?);
        }
    }

    for (col_name, col_type) in [
        ("prefs_nonce", "BLOB"),
        ("prefs_ciphertext", "BLOB"),
        ("vk_keycheck", "BLOB"),
        ("hello_mac", "BLOB"),
    ] {
        if !existing_cols.contains(col_name) {
            conn.execute(
                &format!("ALTER TABLE vault_config ADD COLUMN {col_name} {col_type}"),
                [],
            )?;
        }
    }
    Ok(())
}
