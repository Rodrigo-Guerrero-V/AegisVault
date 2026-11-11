use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
use zeroize::Zeroizing;

use crate::commands::vault::{decrypt_item_secret, SecretPayload};
use crate::crypto::{
    generator::{generate_password as run_csprng, GeneratedPasswordDto, PasswordGenOptions},
    totp::generate_current_totp,
};
use crate::db::{repo::get_raw_item_full, schema::CURRENT_SCHEMA_VERSION};
use crate::error::{VaultError, VaultResult};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CopyItemFieldInput {
    pub item_id: String,
    pub field: String, // "password" | "username" | "totp" | "card_number" | "cvv" | "pin" | "note_body"
}

#[derive(Debug, Serialize)]
pub struct CopyItemFieldOutput {
    pub expires_in_secs: u64,
}

#[tauri::command]
pub fn generate_password(
    state: State<'_, AppState>,
    options: PasswordGenOptions,
) -> VaultResult<GeneratedPasswordDto> {
    if !state.is_locked() {
        state.touch_activity();
    }
    run_csprng(&options)
}

#[tauri::command]
pub fn copy_item_field(
    app: AppHandle,
    state: State<'_, AppState>,
    input: CopyItemFieldInput,
) -> VaultResult<CopyItemFieldOutput> {
    state.with_unlocked(|session| {
        let raw = state
            .db
            .with_conn(|conn| Ok(get_raw_item_full(conn, &input.item_id)?))?
            .ok_or_else(|| VaultError::validation("Ítem no encontrado."))?;

        let secret = decrypt_item_secret(
            &session.subkeys.secret_key,
            CURRENT_SCHEMA_VERSION,
            &raw.id,
            &raw.item_type,
            &raw.secret_nonce,
            &raw.secret_ciphertext,
        )?;

        let extracted: Zeroizing<String> = match (&secret, input.field.as_str()) {
            (SecretPayload::Login { password, .. }, "password") => {
                Zeroizing::new(password.clone())
            }
            (SecretPayload::Login { username, .. }, "username") => {
                Zeroizing::new(username.clone())
            }
            (
                SecretPayload::Login {
                    totp_uri: Some(uri),
                    ..
                },
                "totp",
            ) => {
                let dto = generate_current_totp(uri, AppState::now_unix() as u64)?;
                Zeroizing::new(dto.code)
            }
            (SecretPayload::Card { card_number, .. }, "card_number") => {
                Zeroizing::new(card_number.clone())
            }
            (SecretPayload::Card { cvv, .. }, "cvv") => Zeroizing::new(cvv.clone()),
            (SecretPayload::Card { pin: Some(p), .. }, "pin") => Zeroizing::new(p.clone()),
            (SecretPayload::Note { body }, "note_body") => Zeroizing::new(body.clone()),
            _ => {
                return Err(VaultError::validation(
                    "El campo solicitado está vacío o no aplica a este tipo de ítem.",
                ))
            }
        };

        if extracted.is_empty() {
            return Err(VaultError::validation(
                "El campo solicitado no contiene ningún valor para copiar.",
            ));
        }

        let (_, ttl_secs) = state.security_prefs();
        state
            .clipboard
            .copy_protected(&app, &input.field, &extracted, ttl_secs)?;

        Ok(CopyItemFieldOutput {
            expires_in_secs: ttl_secs,
        })
    })
}

#[tauri::command]
pub fn clear_clipboard_now(app: AppHandle, state: State<'_, AppState>) -> VaultResult<()> {
    state.clipboard.purge_if_matching_generation(Some(&app), None);
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct CopyTextProtectedInput {
    pub text: String,
    pub field: Option<String>,
}

#[tauri::command]
pub fn copy_text_protected(
    app: AppHandle,
    state: State<'_, AppState>,
    input: CopyTextProtectedInput,
) -> VaultResult<CopyItemFieldOutput> {
    let secret = Zeroizing::new(input.text);
    if secret.is_empty() {
        return Err(VaultError::validation(
            "No hay ningún valor para copiar al portapapeles seguro.",
        ));
    }

    state.with_unlocked(|_| {
        let (_, ttl_secs) = state.security_prefs();
        let label = input.field.as_deref().unwrap_or("generated_password");
        state
            .clipboard
            .copy_protected(&app, label, &secret, ttl_secs)?;

        Ok(CopyItemFieldOutput {
            expires_in_secs: ttl_secs,
        })
    })
}
