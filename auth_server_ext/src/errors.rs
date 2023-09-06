use thiserror::Error;
use rusoto_core::RusotoError;
use rusoto_ses::{GetSendQuotaError, GetSendStatisticsError, SendEmailError};
use time::error::Format as TimeFormatError;
use url::ParseError as UrlParseError;
use openid::error::Error as OpenidError;
use std::time::SystemTimeError;
use tokio::task::JoinError;
use refinery::Error as RefineryError;

use auth_server_lib::errors::AuthServerError;

#[derive(Error, Debug)]
pub enum AuthServerExtError {
    #[error("{0}")]
    AuthServerError(#[from] AuthServerError),
    #[error("GetSendStatisticsError {0}")]
    GetSendStatisticsError(#[from] RusotoError<GetSendStatisticsError>),
    #[error("SendEmailError {0}")]
    SendEmailError(#[from] RusotoError<SendEmailError>),
    #[error("GetSendQuotaError {0}")]
    GetSendQuotaError(#[from] RusotoError<GetSendQuotaError>),
    #[error("TimeFormatError {0}")]
    TimeFormatError(#[from] TimeFormatError),
    #[error("UrlParseError {0}")]
    UrlParseError(#[from] UrlParseError),
    #[error("CSRF Token Invalid")]
    InvalidCsrfToken,
    #[error("Token Expired")]
    ExpiredToken,
    #[error("No User Info")]
    MissingUserInfo,
    #[error("No User")]
    MissingUser,
    #[error("OpenidError {0}")]
    OpenidError(#[from] OpenidError),
    #[error("SystemTimeError {0}")]
    SystemTimeError(#[from] SystemTimeError),
    #[error("JoinError {0}")]
    JoinError(#[from] JoinError),
    #[error("RefineryError {0}")]
    RefineryError(#[from] RefineryError),
}