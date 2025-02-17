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
    BiscuitError(Box<BiscuitError>),
    #[error("UUID Error {0}")]
    UuidError(Box<UuidError>),
    #[error("InvalidHeaderValue {0}")]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
    #[error("ReqwestError {0}")]
    ReqwestError(#[from] ReqwestError),
    #[error("UrlParseError {0}")]
    UrlParseError(#[from] UrlParseError),
    #[error("IoError {0}")]
    IoError(#[from] IoError),
}

impl From<UuidError> for AuthUsersError {
    fn from(value: UuidError) -> Self {
        Self::UuidError(Box::new(value))
    }
}

impl From<BiscuitError> for AuthUsersError {
    fn from(value: BiscuitError) -> Self {
        Self::BiscuitError(Box::new(value))
    }
}

#[cfg(test)]
mod tests {
    use biscuit::errors::Error as BiscuitError;
    use reqwest::{header::InvalidHeaderValue, Error as ReqwestError};
    use stack_string::StackString;
    use std::io::Error as IoError;
    use url::ParseError as UrlParseError;
    use uuid::Error as UuidError;

    use crate::errors::AuthUsersError;

    #[test]
    fn test_error_size() {
        println!("BiscuitError {}", std::mem::size_of::<BiscuitError>());
        println!(
            "InvalidHeaderValue {}",
            std::mem::size_of::<InvalidHeaderValue>()
        );
        println!("ReqwestError {}", std::mem::size_of::<ReqwestError>());
        println!("IoError {}", std::mem::size_of::<IoError>());
        println!("UrlParseError {}", std::mem::size_of::<UrlParseError>());
        println!("UuidError {}", std::mem::size_of::<UuidError>());
        println!("AuthUsersError {}", std::mem::size_of::<AuthUsersError>());
        println!("StackString {}", std::mem::size_of::<StackString>());
        println!("String {}", std::mem::size_of::<String>());

        assert_eq!(std::mem::size_of::<AuthUsersError>(), 16);
    }
}
