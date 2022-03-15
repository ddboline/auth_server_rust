#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]

pub mod authorized_user;
pub mod claim;
pub mod token;

use arc_swap::ArcSwap;
pub use authorized_user::AuthorizedUser;
use biscuit::{jwk, jws, Empty};
use chrono::{DateTime, Utc};
use crossbeam::atomic::AtomicCell;
use im::HashMap;
use lazy_static::lazy_static;
use rand::{
    distributions::{Distribution, Standard},
    thread_rng,
};
use stack_string::StackString;
use std::{
    cell::Cell,
    collections::HashSet,
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

#[derive(Clone, Debug, Copy)]
enum AuthStatus {
    Authorized(DateTime<Utc>),
    NotAuthorized,
}

#[derive(Debug, Default)]
pub struct AuthorizedUsers(ArcSwap<HashMap<StackString, AuthStatus>>);

impl AuthorizedUsers {
    #[must_use]
    pub fn new() -> Self {
        Self(ArcSwap::new(Arc::new(HashMap::new())))
    }

    pub fn is_authorized(&self, user: &AuthorizedUser) -> bool {
        if let Some(AuthStatus::Authorized(last_time)) = self.0.load().get(user.email.as_str()) {
            let current_time = Utc::now();
            if (current_time - *last_time).num_minutes() < 15 {
                return true;
            }
        }
        false
    }

    pub fn store_auth(&self, user: AuthorizedUser, is_auth: bool) {
        let current_time = Utc::now();
        let status = if is_auth {
            AuthStatus::Authorized(current_time)
        } else {
            AuthStatus::NotAuthorized
        };
        let auth_map = Arc::new(self.0.load().update(user.email, status));
        self.0.store(auth_map);
    }

    pub fn merge_users(
        &self,
        users: impl IntoIterator<Item = impl Into<StackString>>,
    ) {
        let users: HashSet<StackString> = users.into_iter().map(Into::into).collect();
        let mut auth_map = (*self.0.load().clone()).clone();
        let not_auth_users: Vec<_> = auth_map
            .keys()
            .filter(|user| !users.contains(*user))
            .cloned()
            .collect();
        for user in not_auth_users {
            auth_map.insert(user, AuthStatus::NotAuthorized);
        }
        for user in users {
            auth_map.insert(user, AuthStatus::Authorized(Utc::now()));
        }
        self.0.store(Arc::new(auth_map));
    }

    pub fn get_users(&self) -> Vec<StackString> {
        self.0.load().keys().cloned().collect()
    }
}

#[derive(Debug, Default)]
pub struct AuthTrigger(AtomicBool);

impl AuthTrigger {
    #[must_use]
    pub fn new() -> Self {
        Self(AtomicBool::new(true))
    }

    pub fn check(&self) -> bool {
        match self
            .0
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(x) | Err(x) => x,
        }
    }

    pub fn set(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

pub struct AuthSecret(
    AtomicCell<Option<SecretKey>>,
    LocalKey<Cell<Option<SecretKey>>>,
);

impl AuthSecret {
    #[must_use]
    pub fn new(cache: LocalKey<Cell<Option<SecretKey>>>) -> Self {
        Self(AtomicCell::new(None), cache)
    }

    #[allow(clippy::missing_panics_doc)]
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

    pub fn get_jws_secret(&'static self) -> jws::Secret {
        jws::Secret::Bytes(self.get().into())
    }

    pub fn get_jwk_secret(&'static self) -> jwk::JWK<Empty> {
        jwk::JWK::new_octet_key(&self.get(), Empty::default())
    }

    pub fn set(&self, key: SecretKey) {
        self.0.store(Some(key));
    }

    /// # Errors
    /// Returns error if reading file fails
    pub async fn read_from_file(&self, p: impl AsRef<Path>) -> Result<(), anyhow::Error> {
        let p = p.as_ref();
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

/// # Errors
/// Return error if `create_secret` fails
pub async fn update_secret(p: impl AsRef<Path>) -> Result<(), anyhow::Error> {
    let p = p.as_ref();
    if p.exists() {
        Ok(())
    } else {
        create_secret(p).await
    }
}

/// # Errors
/// Return error if writing fails
pub async fn create_secret(p: impl AsRef<Path>) -> Result<(), anyhow::Error> {
    fs::write(p, &get_random_key()).await?;
    Ok(())
}

#[must_use]
pub fn get_random_key() -> SecretKey {
    let mut rng = thread_rng();
    Standard.sample(&mut rng)
}

#[must_use]
pub fn get_random_nonce() -> [u8; 12] {
    let mut rng = thread_rng();
    Standard.sample(&mut rng)
}

/// # Errors
/// Returns error if reading secrets files fails
pub async fn get_secrets(
    secret_path: impl AsRef<Path>,
    jwt_secret_path: impl AsRef<Path>,
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
