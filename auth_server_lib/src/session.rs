use anyhow::Error;
use chrono::{DateTime, Duration, Utc};
use postgres_query::{query, FromSqlRow};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stack_string::StackString;
use uuid::Uuid;

use crate::{get_random_string, pgpool::PgPool};

#[derive(FromSqlRow, Serialize, Deserialize, PartialEq, Debug)]
pub struct Session {
    pub id: Uuid,
    pub email: StackString,
    pub created_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
    pub session_data: Value,
    pub secret_key: StackString,
}

impl Default for Session {
    fn default() -> Self {
        Self::new("")
    }
}

impl Session {
    pub fn new(email: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            email: email.into(),
            created_at: Utc::now(),
            last_accessed: Utc::now(),
            session_data: Value::Null,
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

    pub async fn get_by_email(pool: &PgPool, email: &str) -> Result<Vec<Self>, Error> {
        let query = query!("SELECT * FROM sessions WHERE email = $email", email = email);
        let conn = pool.get().await?;
        query.fetch(&conn).await.map_err(Into::into)
    }

    pub async fn insert(&self, pool: &PgPool) -> Result<(), Error> {
        let query = query!(
            "
            INSERT INTO sessions (id, email, session_data, secret_key)
            VALUES ($id, $email, $session_data, $secret_key)",
            id = self.id,
            email = self.email,
            session_data = self.session_data,
            secret_key = self.secret_key,
        );
        let conn = pool.get().await?;
        query.execute(&conn).await?;
        Ok(())
    }

    pub async fn update(&self, pool: &PgPool) -> Result<(), Error> {
        let query = query!(
            "
            UPDATE sessions
            SET session_data=$session_data,last_accessed=now()
            WHERE id=$id AND email=$email",
            id = self.id,
            email = self.email,
            session_data = self.session_data,
        );
        let conn = pool.get().await?;
        query.execute(&conn).await?;
        Ok(())
    }

    pub async fn upsert(&self, pool: &PgPool) -> Result<(), Error> {
        if Self::get_session(pool, self.id).await?.is_some() {
            self.update(pool).await
        } else {
            self.insert(pool).await
        }
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
            "DELETE FROM sessions WHERE last_accessed < $time",
            time = time
        );
        let conn = pool.get().await?;
        query.execute(&conn).await?;
        Ok(())
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

        let mut session = Session::new("test@example.com");

        session.session_data = "TEST DATA".into();

        session.insert(&pool).await?;

        let all_sessions = Session::get_all_sessions(&pool).await?;
        assert!(!all_sessions.is_empty());
        let all_sessions: HashSet<_> = all_sessions.into_iter().map(|s| s.id).collect();
        assert!(all_sessions.contains(&session.id));

        let new_session = Session::get_session(&pool, session.id).await?;
        assert!(new_session.is_some());
        let mut new_session = new_session.unwrap();
        assert_eq!(new_session.email, session.email);
        assert_eq!(new_session.session_data, session.session_data);

        new_session.session_data = "NEW TEST DATA".into();
        new_session.upsert(&pool).await?;

        let new_session = Session::get_by_email(&pool, &session.email).await?;
        assert!(!new_session.is_empty());
        let session_len = new_session.len();
        let new_session_map: HashMap<_, _> = new_session.into_iter().map(|s| (s.id, s)).collect();
        assert_eq!(session_len, new_session_map.len());
        let new_session = new_session_map.get(&session.id).unwrap();
        assert_eq!(new_session.id, session.id);
        assert_eq!(&new_session.session_data, "NEW TEST DATA");

        session.delete(&pool).await?;
        user.delete(&pool).await?;
        Ok(())
    }
}
