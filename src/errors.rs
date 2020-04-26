use derive_more::Display;
use std::{convert::From, fmt::Debug};
use thiserror::Error;
use tokio::task::JoinError;
use uuid::Error as ParseError;

use crate::logged_user::TRIGGER_DB_UPDATE;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("Internal Server Error")]
    InternalServerError,
    #[error("BadRequest: {0}")]
    BadRequest(String),
    #[error("Unauthorized")]
    Unauthorized,
    #[error("blocking error {0}")]
    BlockingError(String),
    #[error("JoinError {0}")]
    JoinError(#[from] JoinError),
}

// we can return early in our handlers if UUID provided by the user is not valid
// and provide a custom message
impl From<ParseError> for ServiceError {
    fn from(_: ParseError) -> Self {
        Self::BadRequest("Invalid UUID".into())
    }
}
