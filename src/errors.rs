use derive_more::Display;
use std::{convert::From, fmt::Debug};
use thiserror::Error;
use tokio::task::JoinError;
use uuid::Error as ParseError;
use warp::{
    http::{
        header::CONTENT_TYPE, status::StatusCode, Error as HttpError, Response as HttpResponse,
    },
    reply::{html, json, with_status, Reply, Response},
};

use crate::logged_user::TRIGGER_DB_UPDATE;

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
    #[error("HttpError {0}")]
    HttpError(#[from] HttpError),
}

// we can return early in our handlers if UUID provided by the user is not valid
// and provide a custom message
impl From<ParseError> for ServiceError {
    fn from(_: ParseError) -> Self {
        Self::BadRequest("Invalid UUID".into())
    }
}

impl ServiceError {
    pub fn handle_error(self) -> Result<Response, HttpError> {
        match self {
            Self::BadRequest(ref message) => HttpResponse::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(CONTENT_TYPE, "application/json; charset=utf-8")
                .body(serde_json::to_string(message).unwrap().into()),
            Self::Unauthorized => {
                TRIGGER_DB_UPDATE.set();
                HttpResponse::builder().status(StatusCode::OK).body(
                    include_str!("../templates/login.html")
                        .replace("main.css", "../auth/main.css")
                        .replace("main.js", "../auth/main.js")
                        .into(),
                )
            }
            _ => HttpResponse::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(CONTENT_TYPE, "application/json; charset=utf-8")
                .body("Internal Server Error, Please try later".into()),
        }
    }
}

impl Reply for ServiceError {
    fn into_response(self) -> Response {
        self.handle_error().unwrap()
    }
}
