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
    OpenidError(Box<OpenidError>),
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
    SendEmailError(Box<SdkError<SendEmailError>>),
    #[error("GetSendQuotaError {0}")]
    GetSendQuotaError(Box<SdkError<GetSendQuotaError>>),
    #[error("GetSendStatisticsError {0}")]
    GetSendStatisticsError(Box<SdkError<GetSendStatisticsError>>),
    #[error("MissingQuota")]
    MissingQuota,
    #[error("DecodeError {0}")]
    DecodeError(#[from] DecodeError),
    #[error("BuildError")]
    BuildError(Box<BuildError>),
}

impl From<BuildError> for AuthServerExtError {
    fn from(value: BuildError) -> Self {
        Self::BuildError(Box::new(value))
    }
}

impl From<OpenidError> for AuthServerExtError {
    fn from(value: OpenidError) -> Self {
        Self::OpenidError(Box::new(value))
    }
}

impl From<SdkError<SendEmailError>> for AuthServerExtError {
    fn from(value: SdkError<SendEmailError>) -> Self {
        Self::SendEmailError(Box::new(value))
    }
}

impl From<SdkError<GetSendQuotaError>> for AuthServerExtError {
    fn from(value: SdkError<GetSendQuotaError>) -> Self {
        Self::GetSendQuotaError(Box::new(value))
    }
}

impl From<SdkError<GetSendStatisticsError>> for AuthServerExtError {
    fn from(value: SdkError<GetSendStatisticsError>) -> Self {
        Self::GetSendStatisticsError(Box::new(value))
    }
}

#[cfg(test)]
mod tests {
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
    use time::error::Format as TimeFormatError;
    use tokio::task::JoinError;
    use url::ParseError as UrlParseError;

    use auth_server_lib::errors::AuthServerError;

    use crate::errors::AuthServerExtError;

    #[test]
    fn test_error_size() {
        println!("AuthServerError {}", std::mem::size_of::<AuthServerError>());
        println!("TimeFormatError {}", std::mem::size_of::<TimeFormatError>());
        println!("UrlParseError {}", std::mem::size_of::<UrlParseError>());
        println!("OpenidError {}", std::mem::size_of::<OpenidError>());
        println!("SystemTimeError {}", std::mem::size_of::<SystemTimeError>());
        println!("JoinError {}", std::mem::size_of::<JoinError>());
        println!("RefineryError {}", std::mem::size_of::<RefineryError>());
        println!(
            "SdkError<SendEmailError> {}",
            std::mem::size_of::<SdkError<SendEmailError>>()
        );
        println!(
            "SdkError<GetSendQuotaError> {}",
            std::mem::size_of::<SdkError<GetSendQuotaError>>()
        );
        println!(
            "SdkError<GetSendStatisticsError> {}",
            std::mem::size_of::<SdkError<GetSendStatisticsError>>()
        );
        println!("DecodeError {}", std::mem::size_of::<DecodeError>());
        println!("BuildError {}", std::mem::size_of::<BuildError>());

        assert_eq!(std::mem::size_of::<AuthServerExtError>(), 40);
    }
}
