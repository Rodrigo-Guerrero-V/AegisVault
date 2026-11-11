use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidCredentials,
    VaultLocked,
    VaultAlreadyInitialized,
    VaultNotInitialized,
    HelloCancelled,
    HelloInvalidated,
    ConsentRequired,
    ValidationError,
    BackupCorrupted,
    InternalError,
}

#[derive(Debug, Clone, Serialize)]
pub struct VaultError {
    pub code: ErrorCode,
    pub message: String,
}

impl VaultError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid_credentials() -> Self {
        Self::new(
            ErrorCode::InvalidCredentials,
            "La contraseña maestra es incorrecta o los datos fueron alterados.",
        )
    }

    pub fn locked() -> Self {
        Self::new(ErrorCode::VaultLocked, "La bóveda se encuentra bloqueada.")
    }

    pub fn validation(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::ValidationError, msg)
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::InternalError, msg)
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:?}] {}", self.code, self.message)
    }
}

impl std::error::Error for VaultError {}

impl From<rusqlite::Error> for VaultError {
    fn from(err: rusqlite::Error) -> Self {
        tracing::error!("SQLite error: {}", err);
        Self::internal("Error interno en el motor de almacenamiento local.")
    }
}

pub type VaultResult<T> = Result<T, VaultError>;
