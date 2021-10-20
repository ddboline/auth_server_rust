use anyhow::Error;
use chrono::{DateTime, Duration, Utc};
use postgres_query::{query, FromSqlRow};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stack_string::StackString;
use uuid::Uuid;

use crate::{get_random_string, pgpool::PgPool, session_data::SessionData};

#[derive(FromSqlRow, Serialize, Deserialize, PartialEq, Debug)]
pub struct Session {
    pub id: Uuid,
    pub email: StackString,
    pub created_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
    pub secret_key: StackString,
}

impl Default for Session {
    fn default() -> Self {
        Self::new("")
    }
}

#[derive(FromSqlRow, Serialize, Deserialize, PartialEq, Debug)]
pub struct SessionSummary {
    pub session_id: Uuid,
    pub email_address: StackString,
    pub created_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
    pub number_of_data_objects: i64,
}

impl Default for SessionSummary {
    fn default() -> Self {
        Self {
            session_id: Uuid::new_v4(),
            email_address: "".into(),
            created_at: Utc::now(),
            last_accessed: Utc::now(),
            number_of_data_objects: 0,
        }
    }
}

impl Session {
    pub fn new(email: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            email: email.into(),
            created_at: Utc::now(),
            last_accessed: Utc::now(),
            secret_key: get_random_string(16).into(),
        }
    }

    pub async fn get_session(pool: &PgPool, id: Uuid) -> Result<Option<Self>, Error> {
        let query = query!("SELECT * FROM sessions WHERE id = $id", id = id);
        let conn = pool.get().await?;
        query.fetch_opt(&conn).await.map_err(Into::into)
    }

    pub async fn get_all_sessions(pool: &PgPool) -> Result<Vec<Self>, Error> {
        let query = query!("SELECT * FROM sessions");
        let conn = pool.get().await?;
        query.fetch(&conn).await.map_err(Into::into)
    }

    pub async fn get_session_summary(pool: &PgPool) -> Result<Vec<SessionSummary>, Error> {
        let query = query!(
            "
                SELECT s.id as session_id,
                       s.email as email_address,
                       s.created_at,
                       s.last_accessed,
                       count(sv) as number_of_data_objects
                FROM sessions s
                LEFT JOIN session_values sv ON s.id = sv.session_id
                GROUP BY 1,2,3,4
                ORDER BY created_at
            "
        );
        let conn = pool.get().await?;
        query.fetch(&conn).await.map_err(Into::into)
    }

    pub async fn get_by_email(pool: &PgPool, email: &str) -> Result<Vec<Self>, Error> {
        let query = query!("SELECT * FROM sessions WHERE email = $email", email = email);
        let conn = pool.get().await?;
        query.fetch(&conn).await.map_err(Into::into)
    }

    pub async fn get_number_sessions(pool: &PgPool) -> Result<i64, Error> {
        let query = query!("SELECT count(*) FROM sessions");
        let conn = pool.get().await?;
        let (count,) = query.fetch_one(&conn).await?;
        Ok(count)
    }

    pub async fn insert(&self, pool: &PgPool) -> Result<(), Error> {
        let query = query!(
            "
            INSERT INTO sessions (id, email, secret_key)
            VALUES ($id, $email, $secret_key)",
            id = self.id,
            email = self.email,
            secret_key = self.secret_key,
        );
        let conn = pool.get().await?;
        query.execute(&conn).await?;
        Ok(())
    }

    pub async fn upsert(&self, pool: &PgPool) -> Result<(), Error> {
        if Self::get_session(pool, self.id).await?.is_none() {
            self.insert(pool).await?;
        }
        Ok(())
    }

    pub async fn delete(&self, pool: &PgPool) -> Result<(), Error> {
        let query = query!("DELETE FROM sessions WHERE id = $id", id = self.id);
        let conn = pool.get().await?;
        query.execute(&conn).await?;
        Ok(())
    }

    pub async fn cleanup(pool: &PgPool, expiration_seconds: i64) -> Result<(), Error> {
        let time = Utc::now() - Duration::seconds(expiration_seconds);
        let query = query!(
            "
                DELETE FROM session_values d
                WHERE d.session_id IN (
                    SELECT id
                    FROM sessions
                    WHERE last_accessed < $time
                )
            ",
            time = time,
        );
        let conn = pool.get().await?;
        query.execute(&conn).await?;
        let query = query!(
            "DELETE FROM sessions WHERE last_accessed < $time",
            time = time
        );
        let conn = pool.get().await?;
        query.execute(&conn).await?;
        Ok(())
    }

    pub async fn get_session_data(
        &self,
        pool: &PgPool,
        session_key: &str,
    ) -> Result<Option<SessionData>, Error> {
        let query = query!(
            "
                SELECT *
                FROM session_values
                WHERE session_id=$id
                  AND session_key=$session_key
            ",
            id = self.id,
            session_key = session_key
        );
        let conn = pool.get().await?;
        query.fetch_opt(&conn).await.map_err(Into::into)
    }

    pub async fn get_all_session_data(&self, pool: &PgPool) -> Result<Vec<SessionData>, Error> {
        SessionData::get_by_session_id(pool, self.id)
            .await
            .map_err(Into::into)
    }

    #[allow(clippy::option_if_let_else)]
    pub async fn set_session_data(
        &self,
        pool: &PgPool,
        session_key: &str,
        session_value: Value,
    ) -> Result<SessionData, Error> {
        let session_data =
            if let Some(mut session_data) = self.get_session_data(pool, session_key).await? {
                session_data.session_value = session_value;
                session_data
            } else {
                SessionData::new(self.id, session_key, session_value)
            };
        session_data.upsert(pool).await?;
        Ok(session_data)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Error;
    use std::collections::{HashMap, HashSet};

    use crate::{config::Config, pgpool::PgPool, session::Session, user::User, AUTH_APP_MUTEX};

    #[tokio::test]
    async fn test_session() -> Result<(), Error> {
        let _lock = AUTH_APP_MUTEX.lock().await;
        let config = Config::init_config()?;
        let pool = PgPool::new(&config.database_url);

        let user = User::from_details("test@example.com", "abc123");
        user.insert(&pool).await?;

        let session = Session::new("test@example.com");

        session.insert(&pool).await?;

        let session_data = session
            .set_session_data(&pool, "test", "TEST DATA".into())
            .await?;

        let all_sessions = Session::get_all_sessions(&pool).await?;
        assert!(!all_sessions.is_empty());
        let all_sessions: HashSet<_> = all_sessions.into_iter().map(|s| s.id).collect();
        assert!(all_sessions.contains(&session.id));

        let new_session = Session::get_session(&pool, session.id).await?;
        assert!(new_session.is_some());
        let new_session = new_session.unwrap();
        assert_eq!(new_session.email, session.email);
        let new_session_data = new_session.get_session_data(&pool, "test").await?.unwrap();
        assert_eq!(new_session_data.session_value, session_data.session_value);

        new_session
            .set_session_data(&pool, "test", "NEW TEST DATA".into())
            .await?;

        let new_session = Session::get_by_email(&pool, &session.email).await?;
        assert!(!new_session.is_empty());
        let session_len = new_session.len();
        let new_session_map: HashMap<_, _> = new_session.into_iter().map(|s| (s.id, s)).collect();
        assert_eq!(session_len, new_session_map.len());
        let new_session = new_session_map.get(&session.id).unwrap();
        assert_eq!(new_session.id, session.id);
        let new_session_data = new_session.get_session_data(&pool, "test").await?.unwrap();
        assert_eq!(new_session_data.session_value, "NEW TEST DATA");

        new_session_data.delete(&pool).await?;
        session.delete(&pool).await?;
        user.delete(&pool).await?;
        Ok(())
    }
}
