use anyhow::Error;
use chrono::{DateTime, Utc};
use postgres_query::{query, FromSqlRow};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stack_string::StackString;
use uuid::Uuid;

use crate::pgpool::PgPool;

#[derive(FromSqlRow, Serialize, Deserialize, PartialEq, Debug)]
pub struct SessionData {
    pub id: Uuid,
    pub session_id: Uuid,
    pub session_key: StackString,
    pub session_value: Value,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
}

impl SessionData {
    pub fn new(session_id: Uuid, key: &str, value: Value) -> Self {
        Self {
            id: Uuid::new_v4(),
            session_id,
            session_key: key.into(),
            session_value: value,
            created_at: Utc::now(),
            modified_at: Utc::now(),
        }
    }

    pub async fn get_all_session_data(pool: &PgPool) -> Result<Vec<Self>, Error> {
        let query = query!("SELECT * FROM session_values");
        let conn = pool.get().await?;
        query.fetch(&conn).await.map_err(Into::into)
    }

    pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>, Error> {
        let query = query!(
            "
                SELECT * FROM session_values
                WHERE id = $id
            ",
            id = id,
        );
        let conn = pool.get().await?;
        query.fetch_opt(&conn).await.map_err(Into::into)
    }

    pub async fn get_by_session_id(pool: &PgPool, session_id: Uuid) -> Result<Vec<Self>, Error> {
        let query = query!(
            "SELECT * FROM session_values WHERE session_id = $session_id",
            session_id = session_id
        );
        let conn = pool.get().await?;
        query.fetch(&conn).await.map_err(Into::into)
    }

    pub async fn get_by_session_key(
        pool: &PgPool,
        session_id: Uuid,
        session_key: &str,
    ) -> Result<Option<Self>, Error> {
        let query = query!(
            "
                SELECT * FROM session_values
                WHERE session_id = $session_id AND session_key = $session_key
            ",
            session_id = session_id,
            session_key = session_key
        );
        let conn = pool.get().await?;
        query.fetch_opt(&conn).await.map_err(Into::into)
    }

    pub async fn insert(&self, pool: &PgPool) -> Result<(), Error> {
        let query = query!(
            "
                INSERT INTO session_values (id, session_id, session_key, session_value)
                VALUES ($id, $session_id, $session_key, $session_value)
            ",
            id = self.id,
            session_id = self.session_id,
            session_key = self.session_key,
            session_value = self.session_value,
        );
        let conn = pool.get().await?;
        query.execute(&conn).await?;
        Ok(())
    }

    pub async fn update(&self, pool: &PgPool) -> Result<(), Error> {
        let query = query!(
            "
                UPDATE session_values
                SET session_value=$session_value,modified_at=now()
                WHERE id=$id
                  AND session_id=$session_id
                  AND session_key=$session_key
            ",
            id = self.id,
            session_id = self.session_id,
            session_key = self.session_key,
            session_value = self.session_value
        );
        let conn = pool.get().await?;
        query.execute(&conn).await?;
        Ok(())
    }

    pub async fn upsert(&self, pool: &PgPool) -> Result<(), Error> {
        if Self::get_by_id(pool, self.id).await?.is_some() {
            self.update(pool).await
        } else {
            self.insert(pool).await
        }
    }

    pub async fn delete(&self, pool: &PgPool) -> Result<(), Error> {
        let query = query!("DELETE FROM session_values WHERE id = $id", id = self.id);
        let conn = pool.get().await?;
        query.execute(&conn).await?;
        Ok(())
    }
}
