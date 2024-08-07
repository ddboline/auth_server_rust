use deadpool_postgres::{Client, Config, Pool};
use stack_string::StackString;
use std::fmt;
use tokio_postgres::{Config as PgConfig, NoTls};

pub use tokio_postgres::Transaction as PgTransaction;

use crate::errors::AuthServerError as Error;

/// Wrapper around `deadpool_postgres::Pool`, two pools are considered equal if
/// they have the same connection string The only way to use `PgPool` is through
/// the get method, which returns a `PooledConnection` object
#[derive(Clone, Default)]
pub struct PgPool {
    pgurl: StackString,
    pool: Option<Pool>,
}

impl fmt::Debug for PgPool {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PgPool {}", self.pgurl)
    }
}

impl PartialEq for PgPool {
    fn eq(&self, other: &Self) -> bool {
        self.pgurl == other.pgurl
    }
}

impl PgPool {
    /// # Errors
    /// Returns error if setup of pool fails
    pub fn new(pgurl: impl AsRef<str>) -> Result<Self, Error> {
        let pgurl = pgurl.as_ref();
        let pgconf: PgConfig = pgurl.parse()?;

        let mut config = Config::default();

        if let tokio_postgres::config::Host::Tcp(s) = &pgconf.get_hosts()[0] {
            config.host.replace(s.to_string());
        }
        if let Some(u) = pgconf.get_user() {
            config.user.replace(u.to_string());
        }
        if let Some(p) = pgconf.get_password() {
            config
                .password
                .replace(String::from_utf8_lossy(p).to_string());
        }
        if let Some(db) = pgconf.get_dbname() {
            config.dbname.replace(db.to_string());
        }

        let pool = config.builder(NoTls)?.max_size(4).build()?;

        Ok(Self {
            pgurl: pgurl.into(),
            pool: Some(pool),
        })
    }

    /// # Errors
    /// Returns error if pool doesn't exist or extracting client fails
    pub async fn get(&self) -> Result<Client, Error> {
        self.pool
            .as_ref()
            .ok_or_else(|| Error::MissingPool)?
            .get()
            .await
            .map_err(|_| Error::DeadPoolError)
    }
}
