use anyhow::{format_err, Error};
use argon2::{
    password_hash::Error as ArgonError, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    PasswordVerifier, Version,
};
use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use postgres_query::{query, FromSqlRow};
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use uuid::Uuid;

use authorized_users::AuthorizedUser;

use crate::{get_random_string, pgpool::PgPool};

lazy_static! {
    static ref ARGON: Argon = Argon::new().expect("Failed to init Argon");
}

struct Argon(Argon2<'static>);

impl Argon {
    fn new() -> Result<Self, ArgonError> {
        Ok(Self(Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15360, 2, 1, None)?,
        )))
    }

    fn hash_password(&self, plain: &str) -> Result<String, ArgonError> {
        let salt = get_random_string(16);
        let hash = self.0.hash_password(plain.as_bytes(), &salt)?;
        Ok(hash.to_string())
    }

    fn verify_password(&self, hashed: &str, password: &str) -> Result<(), ArgonError> {
        self.0
            .verify_password(password.as_bytes(), &PasswordHash::new(hashed)?)
    }
}

#[derive(FromSqlRow, Serialize, Deserialize, PartialEq, Debug)]
pub struct User {
    pub email: StackString,
    // password here is always the hashed password
    password: StackString,
    pub created_at: DateTime<Utc>,
}

impl User {
    pub fn from_details(email: &str, password: &str) -> Self {
        let password = ARGON
            .hash_password(password)
            .expect("Argon Hash Failed")
            .into();
        Self {
            email: email.into(),
            password,
            created_at: Utc::now(),
        }
    }

    pub fn set_password(&mut self, password: &str) {
        self.password = ARGON
            .hash_password(password)
            .expect("Argon Hash Failed")
            .into();
    }

    pub fn verify_password(&self, password: &str) -> Result<bool, Error> {
        match ARGON.verify_password(&self.password, password) {
            Ok(()) => Ok(true),
            Err(ArgonError::Password) => Ok(false),
            Err(e) => Err(format_err!("{:?}", e)),
        }
    }

    pub async fn get_authorized_users(pool: &PgPool) -> Result<Vec<Self>, Error> {
        let query = query!("SELECT * FROM users");
        let conn = pool.get().await?;
        query.fetch(&conn).await.map_err(Into::into)
    }

    pub async fn get_number_users(pool: &PgPool) -> Result<i64, Error> {
        let query = query!("SELECT count(*) FROM users");
        let conn = pool.get().await?;
        let (count,) = query.fetch_one(&conn).await?;
        Ok(count)
    }

    pub async fn get_by_email(email: &str, pool: &PgPool) -> Result<Option<Self>, Error> {
        let query = query!("SELECT * FROM users WHERE email = $email", email = email);
        let conn = pool.get().await?;
        query.fetch_opt(&conn).await.map_err(Into::into)
    }

    pub async fn insert(&self, pool: &PgPool) -> Result<(), Error> {
        let query = query!(
            "
            INSERT INTO users (email, password, created_at)
            VALUES ($email, $password, $created_at)",
            email = self.email,
            password = self.password,
            created_at = self.created_at
        );
        let conn = pool.get().await?;
        query.execute(&conn).await?;
        Ok(())
    }

    pub async fn update(&self, pool: &PgPool) -> Result<(), Error> {
        let query = query!(
            "UPDATE users set password = $password WHERE email = $email",
            password = self.password,
            email = self.email,
        );
        let conn = pool.get().await?;
        query.execute(&conn).await?;
        Ok(())
    }

    pub async fn upsert(&self, pool: &PgPool) -> Result<(), Error> {
        if Self::get_by_email(&self.email, pool).await?.is_some() {
            self.update(pool).await
        } else {
            self.insert(pool).await
        }
    }

    pub async fn delete(&self, pool: &PgPool) -> Result<(), Error> {
        let query = query!("DELETE FROM users WHERE email = $email", email = self.email);
        let conn = pool.get().await?;
        query.execute(&conn).await?;
        Ok(())
    }
}

impl From<User> for AuthorizedUser {
    fn from(user: User) -> Self {
        Self {
            email: user.email,
            session: Uuid::new_v4(),
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Error;
    use chrono::Utc;
    use log::debug;

    use crate::{
        config::Config,
        get_random_string,
        pgpool::PgPool,
        user::{Argon, User},
        AUTH_APP_MUTEX,
    };

    #[tokio::test]
    async fn test_create_delete_user() -> Result<(), Error> {
        let _lock = AUTH_APP_MUTEX.lock().await;
        let config = Config::init_config()?;
        let pool = PgPool::new(&config.database_url);

        let email = format!("{}@localhost", get_random_string(32));

        assert_eq!(User::get_by_email(&email, &pool).await?, None);

        let password = get_random_string(32);
        let user = User::from_details(&email, &password);
        println!("{}", user.password);

        user.insert(&pool).await?;
        let mut db_user = User::get_by_email(&email, &pool).await?.unwrap();
        debug!("{:?}", db_user);
        assert!(db_user.verify_password(&password)?);

        let password = get_random_string(32);
        db_user.set_password(&password);
        db_user.upsert(&pool).await?;

        let db_user = User::get_by_email(&email, &pool).await?.unwrap();
        debug!("{:?}", db_user);
        assert!(db_user.verify_password(&password)?);

        db_user.delete(&pool).await?;
        assert_eq!(User::get_by_email(&email, &pool).await?, None);
        Ok(())
    }

    #[test]
    fn test_verify_argon2() -> Result<(), Error> {
        let user = User {
            email: "test@localhost".into(),
            password: "$argon2id$v=19$m=15360,t=2,\
                       p=1$kCY9hyy6ZE3c71Np$kLz4pb6M5IbBz7jLgwG+xxFudnPPvSAWVC5muM/jh8E"
                .into(),
            created_at: Utc::now(),
        };
        assert!(user.verify_password("password").unwrap());
        Ok(())
    }

    #[tokio::test]
    async fn test_get_authorized_users_get_number_users() -> Result<(), Error> {
        let _lock = AUTH_APP_MUTEX.lock().await;
        let config = Config::init_config()?;
        let pool = PgPool::new(&config.database_url);
        let count = User::get_number_users(&pool).await? as usize;
        let users = User::get_authorized_users(&pool).await?;
        debug!("{:?}", users);
        assert_eq!(count, users.len());
        Ok(())
    }

    #[test]
    fn test_argon2() -> Result<(), Error> {
        let argon = Argon::new().unwrap();
        let password = "password";
        let hash = argon.hash_password(password).unwrap();
        assert_eq!(argon.verify_password(&hash, password), Ok(()));
        Ok(())
    }
}
