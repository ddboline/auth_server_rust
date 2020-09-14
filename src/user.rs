use chrono::{DateTime, Utc};
use postgres_query::FromSqlRow;
use serde::{Deserialize, Serialize};
use stack_string::StackString;

use crate::errors::ServiceError as Error;
use crate::pgpool::PgPool;

#[derive(FromSqlRow, Serialize, Deserialize)]
pub struct User {
    pub email: StackString,
    pub password: StackString,
    pub created_at: DateTime<Utc>,
}

impl User {
    pub fn from_details(email: &str, password: &str) -> Self {
        Self {
            email: email.into(),
            password: password.into(),
            created_at: Utc::now(),
        }
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
}
