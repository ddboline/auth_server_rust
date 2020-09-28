use actix_identity::Identity;
use actix_web::{dev::Payload, FromRequest, HttpRequest};
use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use crossbeam::atomic::AtomicCell;
use futures::{
    executor::block_on,
    future::{ready, Ready},
};
use lazy_static::lazy_static;
use log::debug;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use stack_string::StackString;
use std::{
    cell::Cell,
    collections::HashMap,
    env,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::LocalKey,
};
use tokio::{
    fs::{self, File},
    io::AsyncReadExt,
};

use crate::{
    claim::Claim, errors::ServiceError as Error, pgpool::PgPool, token::Token, user::User,
};

pub const KEY_LENGTH: usize = 32;

type SecretKey = [u8; KEY_LENGTH];

thread_local! {
    static SECRET_KEY_CACHE: Cell<Option<SecretKey>> = Cell::new(None);
    static JWT_SECRET_CACHE: Cell<Option<SecretKey>> = Cell::new(None);
}

lazy_static! {
    pub static ref AUTHORIZED_USERS: AuthorizedUsers = AuthorizedUsers::new();
    pub static ref TRIGGER_DB_UPDATE: AuthTrigger = AuthTrigger::new();
    pub static ref SECRET_KEY: AuthSecret = AuthSecret::new(SECRET_KEY_CACHE);
    pub static ref JWT_SECRET: AuthSecret = AuthSecret::new(JWT_SECRET_CACHE);
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct LoggedUser {
    pub email: StackString,
}

impl<'a> From<Claim> for LoggedUser {
    fn from(claim: Claim) -> Self {
        Self {
            email: claim.get_email().into(),
        }
    }
}

impl From<User> for LoggedUser {
    fn from(user: User) -> Self {
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
        let user: LoggedUser = Token::decode_token(&identity.into())?.into();
        if AUTHORIZED_USERS.is_authorized(&user) {
            return Ok(user);
        } else {
            debug!("not authorized {:?}", user);
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

#[derive(Clone, Debug, Copy)]
enum AuthStatus {
    Authorized(DateTime<Utc>),
    NotAuthorized,
}

#[derive(Debug, Default)]
pub struct AuthorizedUsers(ArcSwap<HashMap<LoggedUser, AuthStatus>>);

impl AuthorizedUsers {
    pub fn new() -> Self {
        Self(ArcSwap::new(Arc::new(HashMap::new())))
    }

    pub fn is_authorized(&self, user: &LoggedUser) -> bool {
        if let Some(AuthStatus::Authorized(last_time)) = self.0.load().get(user) {
            let current_time = Utc::now();
            if (current_time - *last_time).num_minutes() < 15 {
                return true;
            }
        }
        false
    }

    pub fn store_auth(&self, user: LoggedUser, is_auth: bool) -> Result<(), anyhow::Error> {
        let current_time = Utc::now();
        let status = if is_auth {
            AuthStatus::Authorized(current_time)
        } else {
            AuthStatus::NotAuthorized
        };
        let mut auth_map = self.0.load().clone();
        Arc::make_mut(&mut auth_map).insert(user, status);
        self.0.store(auth_map);
        Ok(())
    }

    pub fn merge_users(&self, users: &[LoggedUser]) -> Result<(), anyhow::Error> {
        let mut auth_map = self.0.load().clone();
        let not_auth_users: Vec<_> = auth_map
            .keys()
            .cloned()
            .filter(|user| !users.contains(user))
            .collect();
        for user in not_auth_users {
            if !users.contains(&user) {
                Arc::make_mut(&mut auth_map).insert(user.clone(), AuthStatus::NotAuthorized);
            }
        }
        for user in users {
            Arc::make_mut(&mut auth_map).insert(user.clone(), AuthStatus::Authorized(Utc::now()));
        }
        self.0.store(auth_map);
        Ok(())
    }

    pub fn get_users(&self) -> Vec<LoggedUser> {
        self.0.load().keys().cloned().collect()
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

pub async fn fill_auth_from_db(pool: &PgPool) -> Result<(), anyhow::Error> {
    debug!("{:?}", *TRIGGER_DB_UPDATE);
    let users: Vec<LoggedUser> = if TRIGGER_DB_UPDATE.check() {
        User::get_authorized_users(pool)
            .await?
            .into_iter()
            .map(|user| LoggedUser { email: user.email })
            .collect()
    } else {
        AUTHORIZED_USERS.get_users()
    };
    AUTHORIZED_USERS.merge_users(&users)?;
    debug!("{:?}", *AUTHORIZED_USERS);
    Ok(())
}

pub struct AuthSecret(
    AtomicCell<Option<SecretKey>>,
    LocalKey<Cell<Option<SecretKey>>>,
);

impl AuthSecret {
    pub fn new(cache: LocalKey<Cell<Option<SecretKey>>>) -> Self {
        Self(AtomicCell::new(None), cache)
    }

    pub fn get(&'static self) -> SecretKey {
        if let Some(key) = self.1.with(|cache| cache.get()) {
            key
        } else if let Some(key) = self.0.load() {
            self.1.with(|cache| cache.set(Some(key)));
            key
        } else {
            panic!("Attempting to use uninitialized secret key");
        }
    }

    pub fn set(&self, key: SecretKey) {
        self.0.store(Some(key));
    }

    pub async fn read_from_file(&self, p: &Path) -> Result<(), anyhow::Error> {
        let mut secret = [0_u8; KEY_LENGTH];
        let mut f = File::open(p).await?;
        f.read_exact(&mut secret).await?;
        self.0.store(Some(secret));
        Ok(())
    }
}

pub async fn update_secret(p: &Path) -> Result<(), anyhow::Error> {
    if p.exists() {
        Ok(())
    } else {
        create_secret(p).await
    }
}

pub async fn create_secret(p: &Path) -> Result<(), anyhow::Error> {
    fs::write(p, &get_random_key()).await?;
    Ok(())
}

pub fn get_random_key() -> SmallVec<SecretKey> {
    (0..KEY_LENGTH).map(|_| thread_rng().gen::<u8>()).collect()
}

pub async fn get_secrets<T: AsRef<Path>>(
    secret_path: T,
    jwt_secret_path: T,
) -> Result<(), anyhow::Error> {
    SECRET_KEY.read_from_file(secret_path.as_ref()).await?;
    JWT_SECRET.read_from_file(jwt_secret_path.as_ref()).await
}
