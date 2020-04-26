use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use log::debug;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env,
    sync::atomic::{AtomicBool, Ordering},
};
use tokio::sync::RwLock;

use crate::{claim::Claim, errors::ServiceError, pgpool::PgPool, token::Token, user::User};

lazy_static! {
    pub static ref AUTHORIZED_USERS: AuthorizedUsers = AuthorizedUsers::new();
    pub static ref TRIGGER_DB_UPDATE: AuthTrigger = AuthTrigger::new();
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct LoggedUser {
    pub email: String,
}

impl<'a> From<Claim> for LoggedUser {
    fn from(claim: Claim) -> Self {
        Self {
            email: claim.get_email(),
        }
    }
}

// fn _from_request(req: &HttpRequest, pl: &mut Payload) -> Result<LoggedUser, actix_web::Error> {
//     if let Ok(s) = env::var("TESTENV") {
//         if &s == "true" {
//             return Ok(LoggedUser {
//                 email: "user@test".to_string(),
//             });
//         }
//     }
//     if let Some(identity) = block_on(Identity::from_request(req, pl))?.identity() {
//         let user: LoggedUser = Token::decode_token(&identity.into())?.into();
//         if AUTHORIZED_USERS.is_authorized(&user) {
//             return Ok(user);
//         }
//     }
//     Err(ServiceError::Unauthorized.into())
// }

// impl FromRequest for LoggedUser {
//     type Error = actix_web::Error;
//     type Future = Ready<Result<Self, actix_web::Error>>;
//     type Config = ();

//     fn from_request(req: &HttpRequest, pl: &mut Payload) -> Self::Future {
//         ready(_from_request(req, pl))
//     }
// }

#[derive(Clone, Debug, Copy)]
enum AuthStatus {
    Authorized(DateTime<Utc>),
    NotAuthorized,
}

#[derive(Debug, Default)]
pub struct AuthorizedUsers(RwLock<HashMap<LoggedUser, AuthStatus>>);

impl AuthorizedUsers {
    pub fn new() -> Self {
        Self(RwLock::new(HashMap::new()))
    }

    pub async fn is_authorized(&self, user: &LoggedUser) -> bool {
        if let Some(AuthStatus::Authorized(last_time)) = self.0.read().await.get(user) {
            let current_time = Utc::now();
            if (current_time - *last_time).num_minutes() < 15 {
                return true;
            }
        }
        false
    }

    pub async fn store_auth(&self, user: LoggedUser, is_auth: bool) -> Result<(), anyhow::Error> {
        let current_time = Utc::now();
        let status = if is_auth {
            AuthStatus::Authorized(current_time)
        } else {
            AuthStatus::NotAuthorized
        };
        self.0.write().await.insert(user, status);
        Ok(())
    }

    pub async fn merge_users(&self, users: &[LoggedUser]) -> Result<(), anyhow::Error> {
        for user in self.0.read().await.keys() {
            if !users.contains(&user) {
                self.store_auth(user.clone(), false).await?;
            }
        }
        for user in users {
            self.store_auth(user.clone(), true).await?;
        }
        Ok(())
    }

    pub async fn get_users(&self) -> Vec<LoggedUser> {
        self.0.read().await.keys().cloned().collect()
    }
}

#[derive(Debug, Default)]
pub struct AuthTrigger(AtomicBool);

impl AuthTrigger {
    pub fn new() -> Self {
        Self(AtomicBool::new(true))
    }

    pub fn check(&self) -> bool {
        self.0.compare_and_swap(true, false, Ordering::SeqCst)
    }

    pub fn set(&self) {
        self.0.store(true, Ordering::SeqCst)
    }
}

// pub fn fill_auth_from_db(pool: &PgPool) -> Result<(), anyhow::Error> {
//     debug!("{:?}", *TRIGGER_DB_UPDATE);
//     let users: Vec<LoggedUser> = if TRIGGER_DB_UPDATE.check() {
//         User::get_authorized_users(pool)?
//             .into_iter()
//             .map(|user| LoggedUser { email: user.email })
//             .collect()
//     } else {
//         AUTHORIZED_USERS.get_users()
//     };
//     AUTHORIZED_USERS.merge_users(&users)?;
//     debug!("{:?}", *AUTHORIZED_USERS);
//     Ok(())
// }
