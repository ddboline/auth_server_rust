use bcrypt::{hash, verify};
use chrono::{DateTime, Utc};
use postgres_query::FromSqlRow;
use serde::{Deserialize, Serialize};
use stack_string::StackString;

use crate::{app::CONFIG, errors::ServiceError as Error, pgpool::PgPool};

pub fn hash_password(plain: &str) -> StackString {
    // get the hashing cost from the env variable or use default
    hash(plain, CONFIG.hash_rounds)
        .expect("Password Hashing failed")
        .into()
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
        let password = hash_password(password);
        Self {
            email: email.into(),
            password,
            created_at: Utc::now(),
        }
    }

    pub fn set_password(&mut self, password: &str) {
        self.password = hash_password(password);
    }

    pub fn verify_password(&self, password: &str) -> Result<bool, Error> {
        verify(password, &self.password).map_err(Into::into)
    }

    pub async fn get_authorized_users(pool: &PgPool) -> Result<Vec<Self>, Error> {
        let query = postgres_query::query!("SELECT * FROM users");
        pool.get()
            .await?
            .query(query.sql(), query.parameters())
            .await?
            .into_iter()
            .map(|row| Self::from_row(&row).map_err(Into::into))
            .collect()
    }

    pub async fn get_number_users(pool: &PgPool) -> Result<i64, Error> {
        let query = postgres_query::query!("SELECT count(*) FROM users");
        let count = pool
            .get()
            .await?
            .query_one(query.sql(), query.parameters())
            .await?
            .try_get(0)?;
        Ok(count)
    }

    pub async fn get_by_email(email: &str, pool: &PgPool) -> Result<Option<Self>, Error> {
        let query =
            postgres_query::query!("SELECT * FROM users WHERE email = $email", email = email);
        pool.get()
            .await?
            .query_opt(query.sql(), query.parameters())
            .await?
            .map(|row| Self::from_row(&row))
            .transpose()
            .map_err(Into::into)
    }

    pub async fn insert(&self, pool: &PgPool) -> Result<(), Error> {
        let query = postgres_query::query!(
            "
            INSERT INTO users (email, password, created_at)
            VALUES ($email, $password, $created_at)",
            email = self.email,
            password = self.password,
            created_at = self.created_at
        );
        pool.get()
            .await?
            .execute(query.sql(), query.parameters())
            .await?;
        Ok(())
    }

    pub async fn update(&self, pool: &PgPool) -> Result<(), Error> {
        let query = postgres_query::query!(
            "UPDATE users set password = $password WHERE email = $email",
            password = self.password,
            email = self.email,
        );
        pool.get()
            .await?
            .execute(query.sql(), query.parameters())
            .await?;
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
        let query =
            postgres_query::query!("DELETE FROM users WHERE email = $email", email = self.email);
        pool.get()
            .await?
            .execute(query.sql(), query.parameters())
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Error;

    use crate::{
        app::{get_random_string, CONFIG},
        pgpool::PgPool,
        user::User,
    };

    #[tokio::test]
    #[ignore]
    async fn test_create_delete_user() -> Result<(), Error> {
        let pool = PgPool::new(&CONFIG.database_url);

        let email = format!("{}@localhost", get_random_string(32));

        assert_eq!(User::get_by_email(&email, &pool).await?, None);

        let password = get_random_string(32);
        let user = User::from_details(&email, &password);

        user.insert(&pool).await?;
        let mut db_user = User::get_by_email(&email, &pool).await?.unwrap();
        println!("{:?}", db_user);
        assert!(db_user.verify_password(&password)?);

        let password = get_random_string(32);
        db_user.set_password(&password);
        db_user.upsert(&pool).await?;

        let db_user = User::get_by_email(&email, &pool).await?.unwrap();
        println!("{:?}", db_user);
        assert!(db_user.verify_password(&password)?);

        db_user.delete(&pool).await?;
        assert_eq!(User::get_by_email(&email, &pool).await?, None);
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_authorized_users_get_number_users() -> Result<(), Error> {
        let pool = PgPool::new(&CONFIG.database_url);
        let count = User::get_number_users(&pool).await? as usize;
        let users = User::get_authorized_users(&pool).await?;
        println!("{:?}", users);
        assert_eq!(count, users.len());
        Ok(())
    }
}
