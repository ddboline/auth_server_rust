use anyhow::Error as AnyhowError;
use auth_server_ext::google_openid::OpenidError;
use bcrypt::BcryptError;
use http::{Error as HTTPError, StatusCode};
use log::error;
use postgres_query::extract::Error as QueryError;
use rusoto_core::RusotoError;
use rusoto_ses::{GetSendQuotaError, GetSendStatisticsError, SendEmailError};
use serde::Serialize;
use serde_json::Error as SerdeJsonError;
use std::{
    convert::{From, Infallible},
    fmt::Debug,
};
use thiserror::Error;
use tokio::task::JoinError;
use tokio_postgres::Error as PostgresError;
use url::ParseError as UrlParseError;
use uuid::Error as ParseError;
use warp::{
    http::uri::InvalidUri,
    reject::{InvalidHeader, MissingCookie, Reject},
    Rejection, Reply,
};

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
    #[error("SerdeJsonError {0}")]
    SerdeJsonError(#[from] SerdeJsonError),
    #[error("InvalidUri {0}")]
    InvalidUri(#[from] InvalidUri),
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

impl Reject for ServiceError {}

#[derive(Serialize)]
struct ErrorMessage {
    code: u16,
    message: String,
}

pub async fn error_response(err: Rejection) -> Result<Box<dyn Reply>, Infallible> {
    let code: StatusCode;
    let message: &str;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "NOT FOUND";
    } else if err.find::<InvalidHeader>().is_some() {
        TRIGGER_DB_UPDATE.set();
        return Ok(Box::new(static_files::login_html().unwrap()));
    } else if let Some(missing_cookie) = err.find::<MissingCookie>() {
        if missing_cookie.name() == "jwt" {
            TRIGGER_DB_UPDATE.set();
            return Ok(Box::new(static_files::login_html().unwrap()));
        }
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal Server Error";
    } else if let Some(service_err) = err.find::<ServiceError>() {
        match service_err {
            ServiceError::BadRequest(msg) => {
                code = StatusCode::BAD_REQUEST;
                message = msg.as_str();
            }
            ServiceError::Unauthorized => {
                TRIGGER_DB_UPDATE.set();
                return Ok(Box::new(static_files::login_html().unwrap()));
            }
            _ => {
                error!("Other error: {:?}", service_err);
                code = StatusCode::INTERNAL_SERVER_ERROR;
                message = "Internal Server Error, Please try again later";
            }
        }
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        code = StatusCode::METHOD_NOT_ALLOWED;
        message = "METHOD NOT ALLOWED";
    } else {
        error!("Unknown error: {:?}", err);
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal Server Error, Please try again later";
    };

    let reply = warp::reply::json(&ErrorMessage {
        code: code.as_u16(),
        message: message.to_string(),
    });
    let reply = warp::reply::with_status(reply, code);

    Ok(Box::new(reply))
}

#[cfg(test)]
mod test {
    use anyhow::Error;
    use warp::Reply;

    use crate::errors::{error_response, ServiceError};

    #[tokio::test]
    async fn test_service_error() -> Result<(), Error> {
        let err = ServiceError::BadRequest("TEST ERROR".into()).into();
        let resp = error_response(err).await?.into_response();
        assert_eq!(resp.status().as_u16(), 400);

        let err = ServiceError::InternalServerError.into();
        let resp = error_response(err).await?.into_response();
        assert_eq!(resp.status().as_u16(), 500);
        Ok(())
    }
}
