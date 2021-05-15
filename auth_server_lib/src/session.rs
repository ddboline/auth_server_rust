use anyhow::Error;
use chrono::{DateTime, Utc};
use postgres_query::FromSqlRow;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stack_string::StackString;
use uuid::Uuid;

use crate::pgpool::PgPool;

#[derive(FromSqlRow, Serialize, Deserialize, PartialEq, Debug)]
pub struct Session {
    pub id: Uuid,
    pub email: StackString,
    pub created_at: DateTime<Utc>,
    pub session_data: Value,
}

impl Session {
    pub fn new(email: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            email: email.into(),
            created_at: Utc::now(),
            session_data: Value::Null,
        }
    }

    pub fn get_session_cookie(
        &self,
        domain: &str,
        expiration_seconds: i64,
    ) -> Result<String, Error> {
        Ok(format!(
            "session={}; HttpOnly; Path=/; Domain={}; Max-Age={}",
            self.id, domain, expiration_seconds
        ))
    }

    pub async fn get_session(pool: &PgPool, id: &Uuid) -> Result<Option<Self>, Error> {
        let query = postgres_query::query!("SELECT * FROM sessions WHERE id = $id", id = id);
        let row = pool
            .get()
            .await?
            .query_opt(query.sql(), query.parameters())
            .await?;
        let session = row.map(|r| Self::from_row(&r)).transpose()?;
        Ok(session)
    }

    pub async fn get_by_email(pool: &PgPool, email: &str) -> Result<Vec<Self>, Error> {
        let query =
            postgres_query::query!("SELECT * FROM sessions WHERE email = $email", email = email);
        pool.get()
            .await?
            .query(query.sql(), query.parameters())
            .await?
            .into_iter()
            .map(|row| Self::from_row(&row).map_err(Into::into))
            .collect()
    }

    pub async fn insert(&self, pool: &PgPool) -> Result<(), Error> {
        let query = postgres_query::query!(
            "
            INSERT INTO sessions (id, email, session_data)
            VALUES ($id, $email, $session_data)",
            id = self.id,
            email = self.email,
            session_data = self.session_data
        );
        pool.get()
            .await?
            .execute(query.sql(), query.parameters())
            .await?;
        Ok(())
    }

    pub async fn update(&self, pool: &PgPool) -> Result<(), Error> {
        let query = postgres_query::query!(
            "
            UPDATE sessions SET session_data = $session_data
            WHERE id=$id AND email=$email",
            id = self.id,
            email = self.email,
            session_data = self.session_data,
        );
        pool.get()
            .await?
            .execute(query.sql(), query.parameters())
            .await?;
        Ok(())
    }

    pub async fn upsert(&self, pool: &PgPool) -> Result<(), Error> {
        if Self::get_session(pool, &self.id).await?.is_some() {
            self.update(pool).await
        } else {
            self.insert(pool).await
        }
    }

    pub async fn delete(&self, pool: &PgPool) -> Result<(), Error> {
        let query = postgres_query::query!("DELETE FROM sessions WHERE id = $id", id = self.id);
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

    use crate::{config::Config, pgpool::PgPool, session::Session, user::User};

    #[tokio::test]
    async fn test_session() -> Result<(), Error> {
        let config = Config::init_config()?;
        let pool = PgPool::new(&config.database_url);

        let user = User::from_details("test@example.com", "abc123", &config);
        user.insert(&pool).await?;

        let mut session = Session::new("test@example.com");

        session.session_data = "TEST DATA".into();

        session.insert(&pool).await?;

        let new_session = Session::get_session(&pool, &session.id).await?;
        assert!(new_session.is_some());
        let new_session = new_session.unwrap();
        assert_eq!(new_session.email, session.email);
        assert_eq!(new_session.session_data, session.session_data);

        session.delete(&pool).await?;
        user.delete(&pool).await?;
        Ok(())
    }
}
