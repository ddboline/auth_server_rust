#![allow(clippy::must_use_candidate)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::unseparated_literal_suffix)]

pub mod claim;
pub mod token;

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use crossbeam::atomic::AtomicCell;
use im::HashMap;
use lazy_static::lazy_static;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use stack_string::StackString;
use std::{
    cell::Cell,
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
pub struct AuthorizedUser {
    pub email: StackString,
}

#[derive(Clone, Debug, Copy)]
enum AuthStatus {
    Authorized(DateTime<Utc>),
    NotAuthorized,
}

#[derive(Debug, Default)]
pub struct AuthorizedUsers(ArcSwap<HashMap<AuthorizedUser, AuthStatus>>);

impl AuthorizedUsers {
    pub fn new() -> Self {
        Self(ArcSwap::new(Arc::new(HashMap::new())))
    }

    pub fn is_authorized(&self, user: &AuthorizedUser) -> bool {
        if let Some(AuthStatus::Authorized(last_time)) = self.0.load().get(user) {
            let current_time = Utc::now();
            if (current_time - *last_time).num_minutes() < 15 {
                return true;
            }
        }
        false
    }

    pub fn store_auth(&self, user: AuthorizedUser, is_auth: bool) -> Result<(), anyhow::Error> {
        let current_time = Utc::now();
        let status = if is_auth {
            AuthStatus::Authorized(current_time)
        } else {
            AuthStatus::NotAuthorized
        };
        let auth_map = Arc::new(self.0.load().update(user, status));
        self.0.store(auth_map);
        Ok(())
    }

    pub fn merge_users(&self, users: &[AuthorizedUser]) -> Result<(), anyhow::Error> {
        let mut auth_map = (*self.0.load().clone()).clone();
        let not_auth_users: Vec<_> = auth_map
            .keys()
            .cloned()
            .filter(|user| !users.contains(user))
            .collect();
        for user in not_auth_users {
            if !users.contains(&user) {
                auth_map.insert(user.clone(), AuthStatus::NotAuthorized);
            }
        }
        for user in users {
            auth_map.insert(user.clone(), AuthStatus::Authorized(Utc::now()));
        }
        self.0.store(Arc::new(auth_map));
        Ok(())
    }

    pub fn get_users(&self) -> Vec<AuthorizedUser> {
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

pub struct AuthSecret(
    AtomicCell<Option<SecretKey>>,
    LocalKey<Cell<Option<SecretKey>>>,
);

impl AuthSecret {
    pub fn new(cache: LocalKey<Cell<Option<SecretKey>>>) -> Self {
        Self(AtomicCell::new(None), cache)
    }

    pub fn get(&'static self) -> SecretKey {
        if let Some(key) = self.1.with(Cell::get) {
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
        if p.exists() {
            let mut secret = [0_u8; KEY_LENGTH];
            let mut f = File::open(p).await?;
            f.read_exact(&mut secret).await?;
            self.0.store(Some(secret));
            Ok(())
        } else {
            Err(anyhow::format_err!(
                "Secret file {} doesn't exist",
                p.to_string_lossy()
            ))
        }
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
    let mut rng = thread_rng();
    (0..KEY_LENGTH).map(|_| rng.gen::<u8>()).collect()
}

pub fn get_random_nonce() -> Vec<u8> {
    let mut rng = thread_rng();
    (0..96).map(|_| rng.gen::<u8>()).collect()
}

pub async fn get_secrets<T: AsRef<Path>>(
    secret_path: T,
    jwt_secret_path: T,
) -> Result<(), anyhow::Error> {
    SECRET_KEY.read_from_file(secret_path.as_ref()).await?;
    JWT_SECRET.read_from_file(jwt_secret_path.as_ref()).await
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
