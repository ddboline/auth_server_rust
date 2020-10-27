use actix_identity::Identity;
use actix_web::{dev::Payload, FromRequest, HttpRequest};
use futures::{
    executor::block_on,
    future::{ready, Ready},
};
use log::debug;
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use std::env;

use auth_server_lib::{
    authorized_users::{AuthorizedUser, AUTHORIZED_USERS},
    token::Token,
};

use crate::errors::ServiceError as Error;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct LoggedUser {
    pub email: StackString,
}

impl From<AuthorizedUser> for LoggedUser {
    fn from(user: AuthorizedUser) -> Self {
        Self { email: user.email }
    }
}

impl From<LoggedUser> for AuthorizedUser {
    fn from(user: LoggedUser) -> Self {
        Self { email: user.email }
    }
}

fn _from_request(req: &HttpRequest, pl: &mut Payload) -> Result<LoggedUser, actix_web::Error> {
    if let Ok(s) = env::var("TESTENV") {
        if &s == "true" {
            return Ok(LoggedUser {
                email: "user@test".into(),
            });
        }
    }
    if let Some(identity) = block_on(Identity::from_request(req, pl))?.identity() {
        if let Some(user) = Token::decode_token(&identity.into()).ok().map(Into::into) {
            if AUTHORIZED_USERS.is_authorized(&user) {
                return Ok(user.into());
            } else {
                debug!("not authorized {:?}", user);
            }
        }
    }
    Err(Error::Unauthorized.into())
}

impl FromRequest for LoggedUser {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, actix_web::Error>>;
    type Config = ();

    fn from_request(req: &HttpRequest, pl: &mut Payload) -> Self::Future {
        ready(_from_request(req, pl))
    }
}
