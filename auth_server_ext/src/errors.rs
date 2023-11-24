use aws_sdk_ses::{
    error::SdkError,
    operation::{
        get_send_quota::GetSendQuotaError, get_send_statistics::GetSendStatisticsError,
        send_email::SendEmailError,
    },
};
use aws_smithy_types::error::operation::BuildError;
use base64::DecodeError;
use openid::error::Error as OpenidError;
use refinery::Error as RefineryError;
use std::time::SystemTimeError;
use thiserror::Error;
use time::error::Format as TimeFormatError;
use tokio::task::JoinError;
use url::ParseError as UrlParseError;

use auth_server_lib::errors::AuthServerError;

#[derive(Error, Debug)]
pub enum AuthServerExtError {
    #[error("{0}")]
    AuthServerError(#[from] AuthServerError),
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
    #[error("No CSRF state")]
    MissingCSRFState,
    #[error("No nonce")]
    MissingNonce,
    #[error("SendEmailError {0}")]
    SendEmailError(#[from] SdkError<SendEmailError>),
    #[error("GetSendQuotaError {0}")]
    GetSendQuotaError(#[from] SdkError<GetSendQuotaError>),
    #[error("MissingQuota")]
    MissingQuota,
    #[error("GetSendStatisticsError {0}")]
    GetSendStatisticsError(#[from] SdkError<GetSendStatisticsError>),
    #[error("DecodeError {0}")]
    DecodeError(#[from] DecodeError),
    #[error("BuildError")]
    BuildError(#[from] BuildError),
}
