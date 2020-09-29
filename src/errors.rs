use actix_web::{error::ResponseError, HttpResponse};
use anyhow::Error as AnyhowError;
use bcrypt::BcryptError;
use openid::error::Error as OpenidError;
use postgres_query::extract::Error as QueryError;
use std::{convert::From, fmt::Debug};
use thiserror::Error;
use tokio::task::JoinError;
use tokio_postgres::error::Error as PostgresError;
use url::ParseError as UrlParseError;
use uuid::Error as ParseError;
use rusoto_core::{RusotoError};
use rusoto_ses::{GetSendQuotaError, SendEmailError, GetSendStatisticsError};

use crate::{logged_user::TRIGGER_DB_UPDATE, static_files};

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
    #[error("AnyhowError {0}")]
    AnyhowError(#[from] AnyhowError),
    #[error("PostgresError {0}")]
    PostgresError(#[from] PostgresError),
    #[error("QueryError {0}")]
    QueryError(#[from] QueryError),
    #[error("BcryptError {0}")]
    BcryptError(#[from] BcryptError),
    #[error("UrlParseError {0}")]
    UrlParseError(#[from] UrlParseError),
    #[error("GetSendQuotaError {0}")]
    GetSendQuotaError(#[from] RusotoError<GetSendQuotaError>),
    #[error("GetSendStatisticsError {0}")]
    GetSendStatisticsError(#[from] RusotoError<GetSendStatisticsError>),
    #[error("SendEmailError {0}")]
    SendEmailError(#[from] RusotoError<SendEmailError>),
}

// we can return early in our handlers if UUID provided by the user is not valid
// and provide a custom message
impl From<ParseError> for ServiceError {
    fn from(_: ParseError) -> Self {
        Self::BadRequest("Invalid UUID".into())
    }
}

impl From<OpenidError> for ServiceError {
    fn from(e: OpenidError) -> Self {
        Self::BadRequest(format!("Openid Error {:?}", e))
    }
}

impl ResponseError for ServiceError {
    fn error_response(&self) -> HttpResponse {
        match *self {
            Self::BadRequest(ref message) => HttpResponse::BadRequest().json(message),
            Self::Unauthorized => {
                TRIGGER_DB_UPDATE.set();
                static_files::login_html()
            }
            _ => {
                HttpResponse::InternalServerError().json("Internal Server Error, Please try later")
            }
        }
    }
}
