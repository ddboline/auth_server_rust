use biscuit::errors::Error as BiscuitError;
use reqwest::{header::InvalidHeaderValue, Error as ReqwestError};
use std::io::Error as IoError;
use thiserror::Error;
use url::ParseError as UrlParseError;
use uuid::Error as UuidError;

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("No Session")]
    NoSession,
    #[error("No Domain")]
    NoDomain,
    #[error("No Expiry")]
    NoExpiry,
    #[error("No Issued At")]
    NoIssuedAt,
    #[error("No Secret File")]
    NoSecretFile,
    #[error("Token not decoded")]
    DecodeFailure,
}

#[derive(Error, Debug)]
pub enum AuthUsersError {
    #[error("{0}")]
    TokenError(#[from] TokenError),
    #[error("Biscuit Error{0}")]
    BiscuitError(#[from] BiscuitError),
    #[error("UUID Error {0}")]
    UuidError(#[from] UuidError),
    #[error("InvalidHeaderValue {0}")]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
    #[error("ReqwestError {0}")]
    ReqwestError(#[from] ReqwestError),
    #[error("UrlParseError {0}")]
    UrlParseError(#[from] UrlParseError),
    #[error("IoError {0}")]
    IoError(#[from] IoError),
}
