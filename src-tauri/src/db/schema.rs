use rusqlite::Connection;

pub const CURRENT_SCHEMA_VERSION: u32 = 1;

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
            schema_version      INTEGER NOT NULL DEFAULT 1,
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
    )
}
