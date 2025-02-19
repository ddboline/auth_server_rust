use log::error;
use rweb::{
    http::{uri::InvalidUri, Error as HTTPError, StatusCode},
    openapi::{
        ComponentDescriptor, ComponentOrInlineSchema, Entity, Response, ResponseEntity, Responses,
    },
    reject::{InvalidHeader, MissingCookie, Reject},
    Rejection, Reply,
};
use serde::Serialize;
use serde_json::Error as SerdeJsonError;
use std::{
    borrow::Cow,
    convert::Infallible,
    fmt::{Debug, Error as FmtError},
};
use thiserror::Error;
use tokio::{task::JoinError, time::error::Elapsed};
use url::ParseError as UrlParseError;
use uuid::Error as ParseError;

use auth_server_ext::{errors::AuthServerExtError, google_openid::OpenidError};
use auth_server_lib::errors::AuthServerError;
use authorized_users::{errors::AuthUsersError, LOGIN_HTML};

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("Internal Server Error")]
    InternalServerError,
    #[error("BadRequest: {0}")]
    BadRequest(&'static str),
    #[error("Unauthorized")]
    Unauthorized,
    #[error("JoinError {0}")]
    JoinError(#[from] JoinError),
    #[error("AuthServerError {0}")]
    AuthServerError(#[from] AuthServerError),
    #[error("AuthServerExtError {0}")]
    AuthServerExtError(#[from] AuthServerExtError),
    #[error("UrlParseError {0}")]
    UrlParseError(#[from] UrlParseError),
    #[error("HTTP error {0}")]
    HTTPError(#[from] HTTPError),
    #[error("SerdeJsonError {0}")]
    SerdeJsonError(#[from] SerdeJsonError),
    #[error("InvalidUri {0}")]
    InvalidUri(#[from] InvalidUri),
    #[error("TimeoutElapsed {0}")]
    TimeoutElapsed(#[from] Elapsed),
    #[error("FmtError {0}")]
    FmtError(#[from] FmtError),
    #[error("AuthUsersError {0}")]
    AuthUsersError(#[from] AuthUsersError),
    #[error("Bad Secret")]
    BadSecret,
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

impl Reject for ServiceError {}

#[derive(Serialize)]
struct ErrorMessage<'a> {
    code: u16,
    message: &'a str,
}

fn login_html() -> impl Reply {
    rweb::reply::html(LOGIN_HTML)
}

/// # Errors
/// Does not return error (error type is `Infallible`)
#[allow(clippy::missing_panics_doc)]
#[allow(clippy::unused_async)]
pub async fn error_response(err: Rejection) -> Result<Box<dyn Reply>, Infallible> {
    let code: StatusCode;
    let message: &str;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "NOT FOUND";
    } else if err.find::<InvalidHeader>().is_some() {
        return Ok(Box::new(login_html()));
    } else if let Some(missing_cookie) = err.find::<MissingCookie>() {
        if missing_cookie.name() == "jwt" {
            return Ok(Box::new(login_html()));
        }
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal Server Error (missing cookie)";
    } else if let Some(service_err) = err.find::<ServiceError>() {
        match service_err {
            ServiceError::BadRequest(msg) => {
                code = StatusCode::BAD_REQUEST;
                message = msg;
            }
            ServiceError::Unauthorized => {
                return Ok(Box::new(login_html()));
            }
            ServiceError::AuthUsersError(error) => {
                error!("Auth error {error}");
                return Ok(Box::new(login_html()));
            }
            _ => {
                error!("Other error: {:?}", service_err);
                code = StatusCode::INTERNAL_SERVER_ERROR;
                message = "Internal Server Error, Please try again later";
            }
        }
    } else if err.find::<rweb::reject::MethodNotAllowed>().is_some() {
        code = StatusCode::METHOD_NOT_ALLOWED;
        message = "METHOD NOT ALLOWED";
    } else {
        error!("Unknown error: {:?}", err);
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal Server Error, Other";
    };

    let reply = rweb::reply::json(&ErrorMessage {
        code: code.as_u16(),
        message,
    });
    let reply = rweb::reply::with_status(reply, code);

    Ok(Box::new(reply))
}

impl Entity for ServiceError {
    fn type_name() -> Cow<'static, str> {
        rweb::http::Error::type_name()
    }
    fn describe(comp_d: &mut ComponentDescriptor) -> ComponentOrInlineSchema {
        rweb::http::Error::describe(comp_d)
    }
}

impl ResponseEntity for ServiceError {
    fn describe_responses(_: &mut ComponentDescriptor) -> Responses {
        let mut map = Responses::new();

        let error_responses = [
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error"),
            (StatusCode::BAD_REQUEST, "Bad Request"),
            (StatusCode::NOT_FOUND, "Not Found"),
        ];

        for (code, msg) in &error_responses {
            map.insert(
                Cow::Owned(code.as_str().into()),
                Response {
                    description: Cow::Borrowed(*msg),
                    ..Response::default()
                },
            );
        }

        map
    }
}

#[cfg(test)]
mod test {
    use rweb::{
        http::{uri::InvalidUri, Error as HTTPError},
        Reply,
    };
    use serde_json::Error as SerdeJsonError;
    use std::fmt::Error as FmtError;
    use tokio::{task::JoinError, time::error::Elapsed};
    use url::ParseError as UrlParseError;

    use auth_server_ext::errors::AuthServerExtError;
    use auth_server_lib::errors::AuthServerError;
    use authorized_users::errors::AuthUsersError;

    use crate::errors::{error_response, ServiceError as Error};

    #[tokio::test]
    async fn test_service_error() -> Result<(), Error> {
        let err = Error::BadRequest("TEST ERROR").into();
        let resp = error_response(err).await.unwrap().into_response();
        assert_eq!(resp.status().as_u16(), 400);

        let err = Error::InternalServerError.into();
        let resp = error_response(err).await.unwrap().into_response();
        assert_eq!(resp.status().as_u16(), 500);
        Ok(())
    }

    #[test]
    fn test_error_size() {
        println!("JoinError {}", std::mem::size_of::<JoinError>());
        println!("AuthServerError {}", std::mem::size_of::<AuthServerError>());
        println!(
            "AuthServerExtError {}",
            std::mem::size_of::<AuthServerExtError>()
        );
        println!("UrlParseError {}", std::mem::size_of::<UrlParseError>());
        println!("HTTPError {}", std::mem::size_of::<HTTPError>());
        println!("SerdeJsonError {}", std::mem::size_of::<SerdeJsonError>());
        println!("InvalidUri {}", std::mem::size_of::<InvalidUri>());
        println!("Elapsed {}", std::mem::size_of::<Elapsed>());
        println!("FmtError {}", std::mem::size_of::<FmtError>());
        println!("AuthUsersError {}", std::mem::size_of::<AuthUsersError>());

        assert_eq!(std::mem::size_of::<Error>(), 40);
    }
}
