use anyhow::Error as AnyhowError;
use auth_server_ext::google_openid::OpenidError;
use bcrypt::BcryptError;
use http::{Error as HTTPError, StatusCode};
use postgres_query::extract::Error as QueryError;
use rusoto_core::RusotoError;
use rusoto_ses::{GetSendQuotaError, GetSendStatisticsError, SendEmailError};
use serde::Serialize;
use std::convert::Infallible;
use std::{convert::From, fmt::Debug};
use thiserror::Error;
use tokio::task::JoinError;
use tokio_postgres::Error as PostgresError;
use url::ParseError as UrlParseError;
use uuid::Error as ParseError;
use warp::{Rejection, Reply};

use auth_server_lib::static_files;
use authorized_users::TRIGGER_DB_UPDATE;

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
    #[error("HTTP error {0}")]
    HTTPError(#[from] HTTPError),
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

impl From<ServiceError> for Rejection {
    fn from(e: ServiceError) -> Self {
        warp::reject::custom(e)
    }
}

#[derive(Serialize)]
struct ErrorMessage {
    code: u16,
    message: String,
}

pub fn error_response(err: Rejection) -> Result<impl Reply, Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "NOT FOUND";
    } else if let Some(service_err) = err.find::<ServiceError>() {
        match service_err {
            ServiceError::BadRequest(message) => {
                code = StatusCode::BAD_REQUEST;
                message = message;
            }
            ServiceError::Unauthorized => {
                TRIGGER_DB_UPDATE.set();
                match static_files::login_html().expect("Unexpected failure") {
                    Ok(b) => return Ok(b),
                    Err(e) => {
                        code = StatusCode::INTERNAL_SERVER_ERROR;
                        message = "Internal Server Error, Please try again later";
                    }
                }
            }
            _ => {
                code = StatusCode::INTERNAL_SERVER_ERROR;
                message = "Internal Server Error, Please try again later";
            }
        }
    } else if let Some(_) = err.find::<warp::reject::MethodNotAllowed>() {
        code = StatusCode::METHOD_NOT_ALLOWED;
        message = "METHOD NOT ALLOWED";
    } else {
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = message = "Internal Server Error, Please try again later";
    };

    let json = warp::reply::json(&ErrorMessage {
        code: code.as_u16(),
        message: message.into(),
    });

    Ok(warp::reply::with_status(json, code))
}
