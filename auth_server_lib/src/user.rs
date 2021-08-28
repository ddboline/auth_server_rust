use anyhow::Error;
use bcrypt::{hash, verify};
use chrono::{DateTime, Utc};
use postgres_query::{query, FromSqlRow};
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use uuid::Uuid;

use authorized_users::AuthorizedUser;

use crate::{config::Config, pgpool::PgPool};

fn hash_password(plain: &str, hash_rounds: u32) -> String {
    // get the hashing cost from the env variable or use default
    hash(plain, hash_rounds).expect("Password Hashing failed")
}

#[derive(FromSqlRow, Serialize, Deserialize, PartialEq, Debug)]
pub struct User {
    pub email: StackString,
    // password here is always the hashed password
    password: StackString,
    pub created_at: DateTime<Utc>,
}

impl User {
    pub fn from_details(email: &str, password: &str, config: &Config) -> Self {
        let password = hash_password(password, config.hash_rounds).into();
        Self {
            email: email.into(),
            password,
            created_at: Utc::now(),
        }
    }

    pub fn set_password(&mut self, password: &str, config: &Config) {
        self.password = hash_password(password, config.hash_rounds).into();
    }

    pub fn verify_password(&self, password: &str) -> Result<bool, Error> {
        verify(password, &self.password).map_err(Into::into)
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
    use log::debug;

    use crate::{config::Config, get_random_string, pgpool::PgPool, user::User, AUTH_APP_MUTEX};

    #[tokio::test]
    async fn test_create_delete_user() -> Result<(), Error> {
        let _lock = AUTH_APP_MUTEX.lock().await;
        let config = Config::init_config()?;
        let pool = PgPool::new(&config.database_url);

        let email = format!("{}@localhost", get_random_string(32));

        assert_eq!(User::get_by_email(&email, &pool).await?, None);

        let password = get_random_string(32);
        let user = User::from_details(&email, &password, &config);

        user.insert(&pool).await?;
        let mut db_user = User::get_by_email(&email, &pool).await?.unwrap();
        debug!("{:?}", db_user);
        assert!(db_user.verify_password(&password)?);

        let password = get_random_string(32);
        db_user.set_password(&password, &config);
        db_user.upsert(&pool).await?;

        let db_user = User::get_by_email(&email, &pool).await?.unwrap();
        debug!("{:?}", db_user);
        assert!(db_user.verify_password(&password)?);

        db_user.delete(&pool).await?;
        assert_eq!(User::get_by_email(&email, &pool).await?, None);
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
}
