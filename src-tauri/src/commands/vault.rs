use serde::{Deserialize, Serialize};
use tauri::State;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{
    aad::{folder_aad, item_overview_aad, item_secret_aad},
    aead::{decrypt_with_aad, encrypt_with_aad},
    memory::ProtectedKey,
    totp::{generate_current_totp, TotpCodeDto},
};
use crate::db::{
    repo::{
        delete_folder_row, delete_item_row, folder_exists, get_raw_item_full, insert_item_row,
        list_raw_folders, list_raw_item_overviews, update_item_row, upsert_folder_row,
        UpsertItemRow,
    },
    schema::CURRENT_SCHEMA_VERSION,
};
use crate::error::{VaultError, VaultResult};
use crate::state::{AppState, CachedItemOverview, UnlockedSession};

const MAX_PASSWORD_HISTORY: usize = 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverviewPayload {
    pub title: String,
    pub subtitle: String,
    pub urls: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordHistoryEntry {
    pub password: String,
    pub changed_at: i64,
}

impl Zeroize for PasswordHistoryEntry {
    fn zeroize(&mut self) {
        self.password.zeroize();
        self.changed_at = 0;
    }
}

impl Drop for PasswordHistoryEntry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecretPayload {
    Login {
        username: String,
        password: String,
        totp_uri: Option<String>,
        notes: Option<String>,
        #[serde(default)]
        password_history: Vec<PasswordHistoryEntry>,
    },
    Note {
        body: String,
    },
    Card {
        cardholder_name: String,
        card_number: String,
        exp_month: String,
        exp_year: String,
        cvv: String,
        pin: Option<String>,
        notes: Option<String>,
    },
}

impl SecretPayload {
    pub fn expected_item_type(&self) -> &'static str {
        match self {
            SecretPayload::Login { .. } => "login",
            SecretPayload::Note { .. } => "note",
            SecretPayload::Card { .. } => "card",
        }
    }
}

impl Zeroize for SecretPayload {
    fn zeroize(&mut self) {
        match self {
            SecretPayload::Login {
                username,
                password,
                totp_uri,
                notes,
                password_history,
            } => {
                username.zeroize();
                password.zeroize();
                if let Some(t) = totp_uri {
                    t.zeroize();
                }
                if let Some(n) = notes {
                    n.zeroize();
                }
                for entry in password_history.iter_mut() {
                    entry.zeroize();
                }
                password_history.clear();
            }
            SecretPayload::Note { body } => body.zeroize(),
            SecretPayload::Card {
                cardholder_name,
                card_number,
                exp_month,
                exp_year,
                cvv,
                pin,
                notes,
            } => {
                cardholder_name.zeroize();
                card_number.zeroize();
                exp_month.zeroize();
                exp_year.zeroize();
                cvv.zeroize();
                if let Some(p) = pin {
                    p.zeroize();
                }
                if let Some(n) = notes {
                    n.zeroize();
                }
            }
        }
    }
}

impl Drop for SecretPayload {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FolderDto {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct ListVaultIndexInput {
    pub search_query: Option<String>,
    pub folder_id: Option<String>,
    pub item_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VaultIndexDto {
    pub folders: Vec<FolderDto>,
    pub items_overview: Vec<CachedItemOverview>,
}

#[derive(Debug, Serialize)]
pub struct ItemDetailDto {
    pub id: String,
    pub folder_id: Option<String>,
    pub item_type: String,
    pub favorite: bool,
    pub overview: OverviewPayload,
    pub secret: SecretPayload,
    pub current_totp: Option<TotpCodeDto>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct SaveItemInput {
    pub id: Option<String>,
    pub folder_id: Option<String>,
    pub item_type: String,
    pub favorite: bool,
    pub overview: OverviewPayload,
    pub secret: SecretPayload,
}

#[derive(Debug, Deserialize)]
pub struct SaveFolderInput {
    pub id: Option<String>,
    pub name: String,
}

pub fn hydrate_session_index(
    db: &crate::db::VaultDb,
    session: &mut UnlockedSession,
) -> VaultResult<()> {
    let (raw_folders, raw_items) = db.with_conn(|conn| {
        Ok((list_raw_folders(conn)?, list_raw_item_overviews(conn)?))
    })?;

    session.folders_cache.clear();
    session.items_cache.clear();

    for f in raw_folders {
        let aad = folder_aad(CURRENT_SCHEMA_VERSION, &f.id);
        match decrypt_with_aad(
            &session.subkeys.overview_key,
            &f.name_nonce,
            &f.name_ciphertext,
            &aad,
        )
        .and_then(|plain| {
            String::from_utf8(plain.to_vec())
                .map_err(|_| VaultError::internal("UTF-8 inválido en carpeta"))
        }) {
            Ok(name) => {
                session.folders_cache.insert(f.id, name);
            }
            Err(err) => {
                tracing::warn!("Omitiendo carpeta corrupta id={}: {}", f.id, err);
            }
        }
    }

    for row in raw_items {
        let aad = item_overview_aad(CURRENT_SCHEMA_VERSION, &row.id, &row.item_type);
        let parsed = decrypt_with_aad(
            &session.subkeys.overview_key,
            &row.overview_nonce,
            &row.overview_ciphertext,
            &aad,
        )
        .and_then(|plain| {
            serde_json::from_slice::<OverviewPayload>(&plain)
                .map_err(|_| VaultError::internal("JSON overview inválido"))
        });

        match parsed {
            Ok(ov) => {
                session.items_cache.insert(
                    row.id.clone(),
                    CachedItemOverview {
                        id: row.id,
                        folder_id: row.folder_id,
                        item_type: row.item_type,
                        favorite: row.favorite,
                        title: ov.title,
                        subtitle: ov.subtitle,
                        urls: ov.urls,
                        tags: ov.tags,
                        updated_at: row.updated_at,
                    },
                );
            }
            Err(err) => {
                tracing::warn!("Omitiendo ítem corrupto id={}: {}", row.id, err);
            }
        }
    }

    Ok(())
}

pub fn decrypt_item_secret(
    secret_key: &ProtectedKey,
    item_id: &str,
    item_type: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> VaultResult<SecretPayload> {
    let aad = item_secret_aad(CURRENT_SCHEMA_VERSION, item_id, item_type);
    let plain = decrypt_with_aad(secret_key, nonce, ciphertext, &aad)?;
    serde_json::from_slice(&plain)
        .map_err(|_| VaultError::internal("Payload secreto corrupto o incompatible."))
}

#[tauri::command]
pub fn list_vault_index(
    state: State<'_, AppState>,
    input: ListVaultIndexInput,
) -> VaultResult<VaultIndexDto> {
    state.with_unlocked(|session| {
        let mut folders: Vec<FolderDto> = session
            .folders_cache
            .iter()
            .map(|(id, name)| FolderDto {
                id: id.clone(),
                name: name.clone(),
            })
            .collect();
        folders.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

        let query_norm = input
            .search_query
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase);

        let mut items_overview: Vec<CachedItemOverview> = session
            .items_cache
            .values()
            .filter(|item| {
                if let Some(ref f_id) = input.folder_id {
                    if item.folder_id.as_deref() != Some(f_id.as_str()) {
                        return false;
                    }
                }
                if let Some(ref t) = input.item_type {
                    if &item.item_type != t {
                        return false;
                    }
                }
                if let Some(ref q) = query_norm {
                    let hit = item.title.to_lowercase().contains(q)
                        || item.subtitle.to_lowercase().contains(q)
                        || item.urls.iter().any(|u| u.to_lowercase().contains(q))
                        || item.tags.iter().any(|tag| tag.to_lowercase().contains(q));
                    if !hit {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        items_overview.sort_by(|a, b| {
            b.favorite
                .cmp(&a.favorite)
                .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
        });

        Ok(VaultIndexDto {
            folders,
            items_overview,
        })
    })
}

#[tauri::command]
pub fn get_item_detail(state: State<'_, AppState>, item_id: String) -> VaultResult<ItemDetailDto> {
    state.with_unlocked(|session| {
        let raw = state
            .db
            .with_conn(|conn| Ok(get_raw_item_full(conn, &item_id)?))?
            .ok_or_else(|| VaultError::validation("El ítem solicitado no existe."))?;

        let ov_aad = item_overview_aad(CURRENT_SCHEMA_VERSION, &raw.id, &raw.item_type);
        let ov_plain = decrypt_with_aad(
            &session.subkeys.overview_key,
            &raw.overview_nonce,
            &raw.overview_ciphertext,
            &ov_aad,
        )?;
        let overview: OverviewPayload = serde_json::from_slice(&ov_plain)
            .map_err(|_| VaultError::internal("Overview JSON inválido."))?;

        let secret = decrypt_item_secret(
            &session.subkeys.secret_key,
            &raw.id,
            &raw.item_type,
            &raw.secret_nonce,
            &raw.secret_ciphertext,
        )?;

        let current_totp = match &secret {
            SecretPayload::Login {
                totp_uri: Some(uri),
                ..
            } if !uri.trim().is_empty() => {
                generate_current_totp(uri, AppState::now_unix() as u64).ok()
            }
            _ => None,
        };

        Ok(ItemDetailDto {
            id: raw.id,
            folder_id: raw.folder_id,
            item_type: raw.item_type,
            favorite: raw.favorite,
            overview,
            secret,
            current_totp,
            created_at: raw.created_at,
            updated_at: raw.updated_at,
        })
    })
}

#[tauri::command]
pub fn save_item(
    state: State<'_, AppState>,
    mut input: SaveItemInput,
) -> VaultResult<CachedItemOverview> {
    if input.overview.title.trim().is_empty() {
        return Err(VaultError::validation("El título del ítem es obligatorio."));
    }
    if input.item_type != input.secret.expected_item_type() {
        return Err(VaultError::validation(
            "El tipo de ítem no coincide con la estructura del payload secreto.",
        ));
    }
    if let SecretPayload::Login { ref password, .. } = input.secret {
        if password.is_empty() {
            return Err(VaultError::validation(
                "La contraseña de una credencial login no puede estar vacía.",
            ));
        }
    }

    state.with_unlocked_mut(|session| {
        let now = AppState::now_unix();
        let item_id = input
            .id
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let existing = state
            .db
            .with_conn(|conn| Ok(get_raw_item_full(conn, &item_id)?))?;

        if let Some(ref folder_id) = input.folder_id {
            let exists = state.db.with_conn(|conn| Ok(folder_exists(conn, folder_id)?))?;
            if !exists {
                return Err(VaultError::validation("La carpeta seleccionada no existe."));
            }
        }

        // Si es actualización, verificar inmutabilidad de item_type y preservar historial de contraseñas
        if let Some(ref prev_row) = existing {
            if prev_row.item_type != input.item_type {
                return Err(VaultError::validation(
                    "No se permite cambiar la categoría de un ítem existente.",
                ));
            }
            let prev_secret = decrypt_item_secret(
                &session.subkeys.secret_key,
                &prev_row.id,
                &prev_row.item_type,
                &prev_row.secret_nonce,
                &prev_row.secret_ciphertext,
            )?;

            if let (
                SecretPayload::Login {
                    password: prev_password,
                    password_history: prev_history,
                    ..
                },
                SecretPayload::Login {
                    password: new_password,
                    password_history: out_history,
                    ..
                },
            ) = (&prev_secret, &mut input.secret)
            {
                let mut merged = prev_history.clone();
                if !prev_password.is_empty() && prev_password != new_password {
                    merged.insert(
                        0,
                        PasswordHistoryEntry {
                            password: prev_password.clone(),
                            changed_at: now,
                        },
                    );
                    merged.truncate(MAX_PASSWORD_HISTORY);
                }
                *out_history = merged;
            }
        }

        // Si es tarjeta, asegurar que el overview solo muestre últimos 4 dígitos enmascarados
        if let SecretPayload::Card { card_number, .. } = &input.secret {
            let digits: String = card_number.chars().filter(|c| c.is_ascii_digit()).collect();
            if input.overview.subtitle.trim().is_empty() && digits.len() >= 4 {
                let tail = &digits[digits.len() - 4..];
                input.overview.subtitle = format!("•••• {tail}");
            }
        }

        let ov_bytes = Zeroizing::new(
            serde_json::to_vec(&input.overview)
                .map_err(|_| VaultError::internal("Error serializando overview."))?,
        );
        let sec_bytes = Zeroizing::new(
            serde_json::to_vec(&input.secret)
                .map_err(|_| VaultError::internal("Error serializando secret."))?,
        );

        let ov_aad = item_overview_aad(CURRENT_SCHEMA_VERSION, &item_id, &input.item_type);
        let sec_aad = item_secret_aad(CURRENT_SCHEMA_VERSION, &item_id, &input.item_type);

        let sealed_ov = encrypt_with_aad(&session.subkeys.overview_key, &ov_bytes, &ov_aad)?;
        let sealed_sec = encrypt_with_aad(&session.subkeys.secret_key, &sec_bytes, &sec_aad)?;

        let is_update = existing.is_some();
        state.db.with_conn(|conn| {
            let row = UpsertItemRow {
                id: &item_id,
                folder_id: input.folder_id.as_deref(),
                item_type: &input.item_type,
                favorite: input.favorite,
                overview_nonce: &sealed_ov.nonce,
                overview_ciphertext: &sealed_ov.ciphertext,
                secret_nonce: &sealed_sec.nonce,
                secret_ciphertext: &sealed_sec.ciphertext,
                now,
            };
            if is_update {
                update_item_row(conn, &row)?;
            } else {
                insert_item_row(conn, &row)?;
            }
            Ok(())
        })?;

        if is_update {
            state.db.mark_dirty_deletes();
        }

        let cached = CachedItemOverview {
            id: item_id.clone(),
            folder_id: input.folder_id,
            item_type: input.item_type,
            favorite: input.favorite,
            title: input.overview.title,
            subtitle: input.overview.subtitle,
            urls: input.overview.urls,
            tags: input.overview.tags,
            updated_at: now,
        };
        session.items_cache.insert(item_id, cached.clone());
        Ok(cached)
    })
}

#[tauri::command]
pub fn delete_item(state: State<'_, AppState>, item_id: String) -> VaultResult<()> {
    state.with_unlocked_mut(|session| {
        let deleted = state.db.with_conn(|conn| Ok(delete_item_row(conn, &item_id)?))?;
        if deleted > 0 {
            state.db.mark_dirty_deletes();
            session.items_cache.remove(&item_id);
        }
        Ok(())
    })
}

#[tauri::command]
pub fn save_folder(state: State<'_, AppState>, input: SaveFolderInput) -> VaultResult<FolderDto> {
    let trimmed = input.name.trim().to_string();
    if trimmed.is_empty() {
        return Err(VaultError::validation(
            "El nombre de la carpeta no puede estar vacío.",
        ));
    }

    state.with_unlocked_mut(|session| {
        let folder_id = input
            .id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let aad = folder_aad(CURRENT_SCHEMA_VERSION, &folder_id);
        let sealed = encrypt_with_aad(&session.subkeys.overview_key, trimmed.as_bytes(), &aad)?;
        let now = AppState::now_unix();

        let was_updated = state.db.with_conn(|conn| {
            Ok(upsert_folder_row(
                conn,
                &folder_id,
                &sealed.nonce,
                &sealed.ciphertext,
                now,
            )?)
        })?;

        if was_updated {
            state.db.mark_dirty_deletes();
        }

        session.folders_cache.insert(folder_id.clone(), trimmed.clone());
        Ok(FolderDto {
            id: folder_id,
            name: trimmed,
        })
    })
}

#[tauri::command]
pub fn delete_folder(state: State<'_, AppState>, id: String) -> VaultResult<()> {
    state.with_unlocked_mut(|session| {
        let removed = state.db.with_conn(|conn| Ok(delete_folder_row(conn, &id)?))?;
        if removed > 0 {
            state.db.mark_dirty_deletes();
            session.folders_cache.remove(&id);
            for item in session.items_cache.values_mut() {
                if item.folder_id.as_deref() == Some(id.as_str()) {
                    item.folder_id = None;
                }
            }
        }
        Ok(())
    })
}
