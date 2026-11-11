use rusqlite::{params, Connection, OptionalExtension};

#[derive(Debug, Clone)]
pub struct VaultConfigRow {
    pub schema_version: u32,
    pub kdf_salt: Vec<u8>,
    pub kdf_mem_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
    pub mk_wrapped_vk: Vec<u8>,
    pub mk_wrap_nonce: Vec<u8>,
    pub hello_enabled: bool,
    pub hello_key_name: Option<String>,
    pub hello_wrapped_vk: Option<Vec<u8>>,
    pub lock_timeout_secs: u64,
    pub clipboard_ttl_secs: u64,
}

pub struct NewVaultConfig<'a> {
    pub schema_version: u32,
    pub kdf_salt: &'a [u8],
    pub kdf_mem_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
    pub mk_wrapped_vk: &'a [u8],
    pub mk_wrap_nonce: &'a [u8],
    pub now: i64,
}

pub fn load_vault_config(conn: &Connection) -> rusqlite::Result<Option<VaultConfigRow>> {
    conn.query_row(
        "SELECT schema_version, kdf_salt, kdf_mem_kib, kdf_iterations, kdf_parallelism,
                mk_wrapped_vk, mk_wrap_nonce, hello_enabled, hello_key_name, hello_wrapped_vk,
                lock_timeout_secs, clipboard_ttl_secs
         FROM vault_config
         WHERE id = 1",
        [],
        |row| {
            Ok(VaultConfigRow {
                schema_version: row.get::<_, u32>(0)?,
                kdf_salt: row.get(1)?,
                kdf_mem_kib: row.get(2)?,
                kdf_iterations: row.get(3)?,
                kdf_parallelism: row.get(4)?,
                mk_wrapped_vk: row.get(5)?,
                mk_wrap_nonce: row.get(6)?,
                hello_enabled: row.get::<_, i64>(7)? != 0,
                hello_key_name: row.get(8)?,
                hello_wrapped_vk: row.get(9)?,
                lock_timeout_secs: row.get::<_, u64>(10)?,
                clipboard_ttl_secs: row.get::<_, u64>(11)?,
            })
        },
    )
    .optional()
}

pub fn insert_initial_config(conn: &Connection, cfg: &NewVaultConfig<'_>) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO vault_config (
            id, schema_version, kdf_salt, kdf_mem_kib, kdf_iterations, kdf_parallelism,
            mk_wrapped_vk, mk_wrap_nonce, hello_enabled, lock_timeout_secs, clipboard_ttl_secs,
            created_at, updated_at
        ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 300, 25, ?8, ?8)",
        params![
            cfg.schema_version,
            cfg.kdf_salt,
            cfg.kdf_mem_kib,
            cfg.kdf_iterations,
            cfg.kdf_parallelism,
            cfg.mk_wrapped_vk,
            cfg.mk_wrap_nonce,
            cfg.now,
        ],
    )?;
    Ok(())
}

/// Rotación atómica de Contraseña Maestra + invalidación de Windows Hello en la misma transacción.
pub fn rotate_master_key_tx(
    conn: &mut Connection,
    new_salt: &[u8],
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
    new_wrapped_vk: &[u8],
    new_wrap_nonce: &[u8],
    now: i64,
) -> rusqlite::Result<Option<String>> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let prev_hello_key: Option<String> = tx
        .query_row(
            "SELECT hello_key_name FROM vault_config WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .optional()?
        .flatten();

    tx.execute(
        "UPDATE vault_config
         SET kdf_salt = ?1,
             kdf_mem_kib = ?2,
             kdf_iterations = ?3,
             kdf_parallelism = ?4,
             mk_wrapped_vk = ?5,
             mk_wrap_nonce = ?6,
             hello_enabled = 0,
             hello_key_name = NULL,
             hello_wrapped_vk = NULL,
             updated_at = ?7
         WHERE id = 1",
        params![
            new_salt,
            mem_kib,
            iterations,
            parallelism,
            new_wrapped_vk,
            new_wrap_nonce,
            now
        ],
    )?;

    tx.commit()?;
    Ok(prev_hello_key)
}

pub fn update_security_prefs_row(
    conn: &Connection,
    lock_timeout_secs: u64,
    clipboard_ttl_secs: u64,
    now: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE vault_config
         SET lock_timeout_secs = ?1,
             clipboard_ttl_secs = ?2,
             updated_at = ?3
         WHERE id = 1",
        params![lock_timeout_secs, clipboard_ttl_secs, now],
    )?;
    Ok(())
}

// Añadir al final de src-tauri/src/db/repo.rs

#[derive(Debug, Clone)]
pub struct RawFolderRow {
    pub id: String,
    pub schema_anchor_updated_at: i64,
    pub name_nonce: Vec<u8>,
    pub name_ciphertext: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct RawItemOverviewRow {
    pub id: String,
    pub folder_id: Option<String>,
    pub item_type: String,
    pub favorite: bool,
    pub overview_nonce: Vec<u8>,
    pub overview_ciphertext: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct RawItemFullRow {
    pub id: String,
    pub folder_id: Option<String>,
    pub item_type: String,
    pub favorite: bool,
    pub overview_nonce: Vec<u8>,
    pub overview_ciphertext: Vec<u8>,
    pub secret_nonce: Vec<u8>,
    pub secret_ciphertext: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct UpsertItemRow<'a> {
    pub id: &'a str,
    pub folder_id: Option<&'a str>,
    pub item_type: &'a str,
    pub favorite: bool,
    pub overview_nonce: &'a [u8],
    pub overview_ciphertext: &'a [u8],
    pub secret_nonce: &'a [u8],
    pub secret_ciphertext: &'a [u8],
    pub now: i64,
}

pub fn list_raw_folders(conn: &Connection) -> rusqlite::Result<Vec<RawFolderRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, name_nonce, name_ciphertext, created_at, updated_at
         FROM vault_folders",
    )?;
    let rows = stmt.query_map([], |r| {
        let updated_at: i64 = r.get(4)?;
        Ok(RawFolderRow {
            id: r.get(0)?,
            schema_anchor_updated_at: updated_at,
            name_nonce: r.get(1)?,
            name_ciphertext: r.get(2)?,
            created_at: r.get(3)?,
            updated_at,
        })
    })?;
    rows.collect()
}

pub fn folder_exists(conn: &Connection, folder_id: &str) -> rusqlite::Result<bool> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM vault_folders WHERE id = ?1",
            params![folder_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

pub fn upsert_folder_row(
    conn: &Connection,
    id: &str,
    name_nonce: &[u8],
    name_ciphertext: &[u8],
    now: i64,
) -> rusqlite::Result<bool> {
    let existed = folder_exists(conn, id)?;
    if existed {
        conn.execute(
            "UPDATE vault_folders
             SET name_nonce = ?2, name_ciphertext = ?3, updated_at = ?4
             WHERE id = ?1",
            params![id, name_nonce, name_ciphertext, now],
        )?;
    } else {
        conn.execute(
            "INSERT INTO vault_folders (id, name_nonce, name_ciphertext, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?4)",
            params![id, name_nonce, name_ciphertext, now],
        )?;
    }
    Ok(existed)
}

pub fn delete_folder_row(conn: &Connection, id: &str) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM vault_folders WHERE id = ?1", params![id])
}

pub fn list_raw_item_overviews(conn: &Connection) -> rusqlite::Result<Vec<RawItemOverviewRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, folder_id, item_type, favorite, overview_nonce, overview_ciphertext,
                created_at, updated_at
         FROM vault_items",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(RawItemOverviewRow {
            id: r.get(0)?,
            folder_id: r.get(1)?,
            item_type: r.get(2)?,
            favorite: r.get::<_, i64>(3)? != 0,
            overview_nonce: r.get(4)?,
            overview_ciphertext: r.get(5)?,
            created_at: r.get(6)?,
            updated_at: r.get(7)?,
        })
    })?;
    rows.collect()
}

pub fn list_all_raw_items_full(conn: &Connection) -> rusqlite::Result<Vec<RawItemFullRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, folder_id, item_type, favorite, overview_nonce, overview_ciphertext,
                secret_nonce, secret_ciphertext, created_at, updated_at
         FROM vault_items",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(RawItemFullRow {
            id: r.get(0)?,
            folder_id: r.get(1)?,
            item_type: r.get(2)?,
            favorite: r.get::<_, i64>(3)? != 0,
            overview_nonce: r.get(4)?,
            overview_ciphertext: r.get(5)?,
            secret_nonce: r.get(6)?,
            secret_ciphertext: r.get(7)?,
            created_at: r.get(8)?,
            updated_at: r.get(9)?,
        })
    })?;
    rows.collect()
}

pub fn get_raw_item_full(
    conn: &Connection,
    item_id: &str,
) -> rusqlite::Result<Option<RawItemFullRow>> {
    conn.query_row(
        "SELECT id, folder_id, item_type, favorite, overview_nonce, overview_ciphertext,
                secret_nonce, secret_ciphertext, created_at, updated_at
         FROM vault_items
         WHERE id = ?1",
        params![item_id],
        |r| {
            Ok(RawItemFullRow {
                id: r.get(0)?,
                folder_id: r.get(1)?,
                item_type: r.get(2)?,
                favorite: r.get::<_, i64>(3)? != 0,
                overview_nonce: r.get(4)?,
                overview_ciphertext: r.get(5)?,
                secret_nonce: r.get(6)?,
                secret_ciphertext: r.get(7)?,
                created_at: r.get(8)?,
                updated_at: r.get(9)?,
            })
        },
    )
    .optional()
}

pub fn item_exists(conn: &Connection, item_id: &str) -> rusqlite::Result<bool> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM vault_items WHERE id = ?1",
            params![item_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

pub fn insert_item_row(conn: &Connection, row: &UpsertItemRow<'_>) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO vault_items (
            id, folder_id, item_type, favorite,
            overview_nonce, overview_ciphertext,
            secret_nonce, secret_ciphertext,
            created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
        params![
            row.id,
            row.folder_id,
            row.item_type,
            i64::from(row.favorite),
            row.overview_nonce,
            row.overview_ciphertext,
            row.secret_nonce,
            row.secret_ciphertext,
            row.now,
        ],
    )?;
    Ok(())
}

pub fn update_item_row(conn: &Connection, row: &UpsertItemRow<'_>) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE vault_items
         SET folder_id = ?2,
             favorite = ?3,
             overview_nonce = ?4,
             overview_ciphertext = ?5,
             secret_nonce = ?6,
             secret_ciphertext = ?7,
             updated_at = ?8
         WHERE id = ?1",
        params![
            row.id,
            row.folder_id,
            i64::from(row.favorite),
            row.overview_nonce,
            row.overview_ciphertext,
            row.secret_nonce,
            row.secret_ciphertext,
            row.now,
        ],
    )?;
    Ok(())
}

pub fn delete_item_row(conn: &Connection, item_id: &str) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM vault_items WHERE id = ?1", params![item_id])
}

pub fn set_hello_enrollment_row(
    conn: &Connection,
    key_name: &str,
    wrapped_vk: &[u8],
    now: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE vault_config
         SET hello_enabled = 1,
             hello_key_name = ?1,
             hello_wrapped_vk = ?2,
             updated_at = ?3
         WHERE id = 1",
        params![key_name, wrapped_vk, now],
    )?;
    Ok(())
}

pub fn clear_hello_enrollment_row(
    conn: &mut Connection,
    now: i64,
) -> rusqlite::Result<Option<String>> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let prev_key: Option<String> = tx
        .query_row(
            "SELECT hello_key_name FROM vault_config WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .optional()?
        .flatten();

    tx.execute(
        "UPDATE vault_config
         SET hello_enabled = 0,
             hello_key_name = NULL,
             hello_wrapped_vk = NULL,
             updated_at = ?1
         WHERE id = 1",
        params![now],
    )?;

    tx.commit()?;
    Ok(prev_key)
}
