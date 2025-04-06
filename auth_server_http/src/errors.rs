use axum::{
    extract::Json,
    http::header::CONTENT_TYPE,
    response::{IntoResponse, Response},
};
use http::{
    StatusCode,
    header::{InvalidHeaderName, InvalidHeaderValue, ToStrError},
};
use log::error;
use serde::Serialize;
use serde_json::Error as SerdeJsonError;
use serde_yml::Error as YamlError;
use stack_string::{StackString, format_sstr};
use std::{
    fmt::{Debug, Error as FmtError},
    net::AddrParseError,
};
use thiserror::Error;
use tokio::{task::JoinError, time::error::Elapsed};
use url::ParseError as UrlParseError;
use utoipa::{
    IntoResponses, PartialSchema, ToSchema,
    openapi::{ResponseBuilder, ResponsesBuilder, content::ContentBuilder},
};
use uuid::Error as ParseError;

use auth_server_ext::{errors::AuthServerExtError, google_openid::OpenidError};
use auth_server_lib::errors::AuthServerError;
use authorized_users::{LOGIN_HTML, errors::AuthUsersError};

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("Internal Server Error")]
    InternalServerError,
    #[error("BadRequest: {0}")]
    BadRequest(&'static str),
    #[error("Unauthorized")]
    Unauthorized,

    #[error("AuthUsersError {0}")]
    AuthUsersError(#[from] AuthUsersError),
    #[error("InvalidHeaderName {0}")]
    InvalidHeaderName(#[from] InvalidHeaderName),
    #[error("InvalidHeaderValue {0}")]
    InvalidHeaderValue(#[from] InvalidHeaderValue),

    #[error("JoinError {0}")]
    JoinError(#[from] JoinError),
    #[error("AuthServerError {0}")]
    AuthServerError(#[from] AuthServerError),
    #[error("AuthServerExtError {0}")]
    AuthServerExtError(#[from] AuthServerExtError),
    #[error("UrlParseError {0}")]
    UrlParseError(#[from] UrlParseError),
    #[error("SerdeJsonError {0}")]
    SerdeJsonError(#[from] SerdeJsonError),
    #[error("TimeoutElapsed {0}")]
    TimeoutElapsed(#[from] Elapsed),
    #[error("FmtError {0}")]
    FmtError(#[from] FmtError),
    #[error("AddrParseError {0}")]
    AddrParseError(#[from] AddrParseError),
    #[error("ioError {0}")]
    IoError(#[from] std::io::Error),
    #[error("Bad Secret")]
    BadSecret,
    #[error("ToStrError {0}")]
    ToStrError(#[from] ToStrError),
    #[error("YamlError {0}")]
    YamlError(#[from] YamlError),
}

// we can return early in our handlers if UUID provided by the user is not valid
// and provide a custom message
impl From<ParseError> for ServiceError {
    fn from(e: ParseError) -> Self {
        error!("Invalid UUID {e:?}");
        Self::BadRequest("Parse Error")
    }
}

impl From<OpenidError> for ServiceError {
    fn from(e: OpenidError) -> Self {
        error!("Openid Error {e:?}");
        Self::BadRequest("Openid Error")
    }
}

#[derive(Serialize, ToSchema)]
struct ErrorMessage {
    message: StackString,
}

impl axum::response::IntoResponse for ErrorMessage {
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthorized
            | Self::AuthUsersError(_)
            | Self::InvalidHeaderName(_)
            | Self::InvalidHeaderValue(_) => (
                StatusCode::OK,
                [(CONTENT_TYPE, mime::TEXT_HTML.essence_str())],
                LOGIN_HTML,
            )
                .into_response(),
            Self::BadRequest(s) => (
                StatusCode::BAD_REQUEST,
                [(CONTENT_TYPE, mime::TEXT_HTML.essence_str())],
                ErrorMessage { message: s.into() },
            )
                .into_response(),
            e => (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(CONTENT_TYPE, mime::APPLICATION_JSON.essence_str())],
                ErrorMessage {
                    message: format_sstr!("Internal Server Error: {e}"),
                },
            )
                .into_response(),
        }
    }
}

impl IntoResponses for ServiceError {
    fn responses() -> std::collections::BTreeMap<
        String,
        utoipa::openapi::RefOr<utoipa::openapi::response::Response>,
    > {
        let error_message_content = ContentBuilder::new()
            .schema(Some(ErrorMessage::schema()))
            .build();
        ResponsesBuilder::new()
            .response(
                StatusCode::UNAUTHORIZED.as_str(),
                ResponseBuilder::new()
                    .description("Not Authorized")
                    .content(
                        mime::TEXT_HTML.essence_str(),
                        ContentBuilder::new().schema(Some(String::schema())).build(),
                    ),
            )
            .response(
                StatusCode::BAD_REQUEST.as_str(),
                ResponseBuilder::new().description("Bad Request").content(
                    mime::APPLICATION_JSON.essence_str(),
                    error_message_content.clone(),
                ),
            )
            .response(
                StatusCode::INTERNAL_SERVER_ERROR.as_str(),
                ResponseBuilder::new()
                    .description("Internal Server Error")
                    .content(
                        mime::APPLICATION_JSON.essence_str(),
                        error_message_content.clone(),
                    ),
            )
            .build()
            .into()
    }
}

#[cfg(test)]
mod test {
    use serde_json::Error as SerdeJsonError;
    use std::fmt::Error as FmtError;
    use tokio::{task::JoinError, time::error::Elapsed};
    use url::ParseError as UrlParseError;

    use auth_server_ext::errors::AuthServerExtError;
    use auth_server_lib::errors::AuthServerError;
    use authorized_users::errors::AuthUsersError;

    use crate::errors::ServiceError as Error;

    #[test]
    fn test_error_size() {
        println!("JoinError {}", std::mem::size_of::<JoinError>());
        println!("AuthServerError {}", std::mem::size_of::<AuthServerError>());
        println!(
            "AuthServerExtError {}",
            std::mem::size_of::<AuthServerExtError>()
        );
        println!("UrlParseError {}", std::mem::size_of::<UrlParseError>());
        println!("SerdeJsonError {}", std::mem::size_of::<SerdeJsonError>());
        println!("Elapsed {}", std::mem::size_of::<Elapsed>());
        println!("FmtError {}", std::mem::size_of::<FmtError>());
        println!("AuthUsersError {}", std::mem::size_of::<AuthUsersError>());

        assert_eq!(std::mem::size_of::<Error>(), 40);
    }
}
