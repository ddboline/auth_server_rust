use checksums::{Algorithm, hash_reader};
use log::debug;
use postgres_query::{FromSqlRow, Query, client::GenericClient, query};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stack_string::StackString;
use std::cmp::PartialEq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use authorized_users::{JWT_SECRET, SECRET_KEY};

use crate::{
    date_time_wrapper::DateTimeWrapper,
    errors::AuthServerError as Error,
    get_random_string,
    pgpool::{PgPool, PgTransaction},
    session_data::SessionData,
};

#[derive(FromSqlRow, Serialize, Deserialize, Debug, Eq)]
pub struct Session {
    id: Uuid,
    email: StackString,
    created_at: DateTimeWrapper,
    last_accessed: DateTimeWrapper,
    secret_key: StackString,
    key_hash: Option<StackString>,
}

impl PartialEq for Session {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.email == other.email && self.secret_key == other.secret_key
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new("")
    }
}

impl Session {
    #[must_use]
    pub fn get_id(&self) -> Uuid {
        self.id
    }

    #[must_use]
    pub fn get_email(&self) -> &str {
        self.email.as_str()
    }

    #[must_use]
    pub fn get_created_at(&self) -> DateTimeWrapper {
        self.created_at
    }

    #[must_use]
    pub fn get_secret_key(&self) -> &str {
        self.secret_key.as_str()
    }
}

#[derive(FromSqlRow, Serialize, Deserialize, Debug, Eq, Clone)]
pub struct SessionSummary {
    session_id: Uuid,
    email_address: StackString,
    created_at: DateTimeWrapper,
    last_accessed: DateTimeWrapper,
    number_of_data_objects: i64,
}

impl SessionSummary {
    #[must_use]
    pub fn get_session_id(&self) -> Uuid {
        self.session_id
    }

    #[must_use]
    pub fn get_email_address(&self) -> &str {
        &self.email_address
    }

    #[must_use]
    pub fn get_number_of_data_objects(&self) -> i64 {
        self.number_of_data_objects
    }

    #[must_use]
    pub fn get_created_at(&self) -> DateTimeWrapper {
        self.created_at
    }
}

impl PartialEq for SessionSummary {
    fn eq(&self, other: &Self) -> bool {
        self.session_id == other.session_id
            && self.email_address == other.email_address
            && self.number_of_data_objects == other.number_of_data_objects
    }
}

impl Default for SessionSummary {
    fn default() -> Self {
        Self {
            session_id: Uuid::new_v4(),
            email_address: "".into(),
            created_at: DateTimeWrapper::now(),
            last_accessed: DateTimeWrapper::now(),
            number_of_data_objects: 0,
        }
    }
}

impl Session {
    pub fn new(email: impl Into<StackString>) -> Self {
        let mut buf = Vec::new();
        buf.extend(&SECRET_KEY.get());
        buf.extend(JWT_SECRET.get());
        let key_hash = Some(Self::get_key_hash());
        Self {
            id: Uuid::new_v4(),
            email: email.into(),
            created_at: DateTimeWrapper::now(),
            last_accessed: DateTimeWrapper::now(),
            secret_key: get_random_string(16),
            key_hash,
        }
    }

    pub fn get_key_hash() -> StackString {
        let mut buf = Vec::new();
        buf.extend(&SECRET_KEY.get());
        buf.extend(JWT_SECRET.get());
        hash_reader(&mut buf.as_slice(), Algorithm::MD5)
            .as_str()
            .into()
    }

    /// # Errors
    /// Returns error if db connection fails or `get_session_conn` fails
    pub async fn get_session(pool: &PgPool, id: Uuid) -> Result<Option<Self>, Error> {
        let mut conn = pool.get().await?;
        let tran = conn.transaction().await?;
        let conn: &PgTransaction = &tran;
        let result = Self::get_session_conn(conn, id).await?;
        tran.commit().await?;
        Ok(result)
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn get_session_conn<C>(conn: &C, id: Uuid) -> Result<Option<Self>, Error>
    where
        C: GenericClient + Sync,
    {
        let query = query!("SELECT * FROM sessions WHERE id = $id", id = id);
        query.fetch_opt(conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn get_all_sessions(pool: &PgPool) -> Result<Vec<Self>, Error> {
        let query = query!("SELECT * FROM sessions");
        let conn = pool.get().await?;
        query.fetch(&conn).await.map_err(Into::into)
    }

    fn get_session_query() -> Query<'static> {
        query!(
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
        )
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn get_session_summary(pool: &PgPool) -> Result<Vec<SessionSummary>, Error> {
        let query = Self::get_session_query();
        let conn = pool.get().await?;
        query.fetch(&conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn get_by_email(pool: &PgPool, email: impl AsRef<str>) -> Result<Vec<Self>, Error> {
        let email = email.as_ref();
        let query = query!("SELECT * FROM sessions WHERE email = $email", email = email);
        let conn = pool.get().await?;
        query.fetch(&conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn get_number_sessions(pool: &PgPool) -> Result<u64, Error> {
        let query = query!("SELECT count(*) FROM sessions");
        let conn = pool.get().await?;
        let (count,) = query.fetch_one::<(i64,), _>(&conn).await?;
        Ok(count as u64)
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn insert(&self, pool: &PgPool) -> Result<(), Error> {
        let mut conn = pool.get().await?;
        let tran = conn.transaction().await?;
        let conn: &PgTransaction = &tran;
        self.insert_conn(conn).await?;
        tran.commit().await?;
        Ok(())
    }

    fn insert_query(&self) -> Query {
        query!(
            "
            INSERT INTO sessions (id, email, secret_key, key_hash)
            VALUES ($id, $email, $secret_key, $key_hash)",
            id = self.id,
            email = self.email,
            secret_key = self.secret_key,
            key_hash = self.key_hash,
        )
    }

    async fn insert_conn<C>(&self, conn: &C) -> Result<(), Error>
    where
        C: GenericClient + Sync,
    {
        let query = self.insert_query();
        query.execute(&conn).await?;
        Ok(())
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn upsert(&self, pool: &PgPool) -> Result<(), Error> {
        let mut conn = pool.get().await?;
        let tran = conn.transaction().await?;
        let conn: &PgTransaction = &tran;
        if Self::get_session_conn(conn, self.id).await?.is_none() {
            self.insert_conn(conn).await?;
        }
        tran.commit().await?;
        Ok(())
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn delete(&self, pool: &PgPool) -> Result<(), Error> {
        let mut conn = pool.get().await?;
        let tran = conn.transaction().await?;
        let conn: &PgTransaction = &tran;
        self.delete_conn(conn).await?;
        tran.commit().await?;
        Ok(())
    }

    async fn delete_conn<C>(&self, conn: &C) -> Result<(), Error>
    where
        C: GenericClient + Sync,
    {
        let query = query!("DELETE FROM sessions WHERE id = $id", id = self.id);
        query.execute(&conn).await?;
        Ok(())
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn cleanup(
        pool: &PgPool,
        expiration_seconds: u32,
        key_hash: &str,
    ) -> Result<u64, Error> {
        let mut conn = pool.get().await?;
        let tran = conn.transaction().await?;
        let conn: &PgTransaction = &tran;
        let result = Self::cleanup_conn(conn, expiration_seconds, key_hash).await?;
        tran.commit().await?;
        Ok(result)
    }

    async fn cleanup_conn<C>(
        conn: &C,
        expiration_seconds: u32,
        key_hash: &str,
    ) -> Result<u64, Error>
    where
        C: GenericClient + Sync,
    {
        let mut result = 0;
        let time = OffsetDateTime::now_utc() - Duration::seconds(expiration_seconds.into());
        let query = query!(
            "
                DELETE FROM session_values d
                WHERE d.session_id IN (
                    SELECT id
                    FROM sessions
                    WHERE last_accessed < $time
                       OR (key_hash IS NOT NULL AND key_hash != $key_hash)
                )
            ",
            time = time,
            key_hash = key_hash,
        );
        result += query.execute(conn).await?;
        let query = query!(
            "DELETE FROM sessions WHERE last_accessed < $time OR (key_hash IS NOT NULL AND \
             key_hash != $key_hash)",
            time = time,
            key_hash = key_hash,
        );
        result += query.execute(conn).await?;
        Ok(result)
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn get_session_data(
        &self,
        pool: &PgPool,
        session_key: impl AsRef<str>,
    ) -> Result<Option<SessionData>, Error> {
        let mut conn = pool.get().await?;
        let tran = conn.transaction().await?;
        let conn: &PgTransaction = &tran;
        let result = self.get_session_data_conn(conn, session_key).await?;
        tran.commit().await?;
        Ok(result)
    }

    async fn get_session_data_conn<C>(
        &self,
        conn: &C,
        session_key: impl AsRef<str>,
    ) -> Result<Option<SessionData>, Error>
    where
        C: GenericClient + Sync,
    {
        let session_key = session_key.as_ref();
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
        query.fetch_opt(&conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn get_all_session_data(&self, pool: &PgPool) -> Result<Vec<SessionData>, Error> {
        SessionData::get_by_session_id(pool, self.id).await
    }

    /// # Errors
    /// Returns error if db query fails
    #[allow(clippy::option_if_let_else)]
    pub async fn set_session_data(
        &self,
        pool: &PgPool,
        session_key: impl AsRef<str>,
        session_value: Value,
    ) -> Result<SessionData, Error> {
        let session_key = session_key.as_ref();
        let mut conn = pool.get().await?;
        let tran = conn.transaction().await?;
        let conn: &PgTransaction = &tran;
        let result = self
            .set_session_data_conn(conn, session_key, session_value)
            .await?;
        tran.commit().await?;
        Ok(result)
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn set_session_data_conn<C>(
        &self,
        conn: &C,
        session_key: impl AsRef<str>,
        session_value: Value,
    ) -> Result<SessionData, Error>
    where
        C: GenericClient + Sync,
    {
        let session_key = session_key.as_ref();
        let session_data =
            if let Some(mut session_data) = self.get_session_data_conn(conn, session_key).await? {
                session_data.set_session_value(session_value);
                session_data
            } else {
                SessionData::new(self.id, session_key, session_value)
            };
        session_data.upsert_conn(conn).await?;
        Ok(session_data)
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn set_session_from_cache(
        pool: &PgPool,
        session: Uuid,
        secret_key: impl AsRef<str>,
        session_key: impl AsRef<str>,
        payload: Value,
    ) -> Result<Option<SessionData>, Error> {
        let mut conn = pool.get().await?;
        let tran = conn.transaction().await?;
        let conn: &PgTransaction = &tran;

        if let Some(session_obj) = Session::get_session_conn(conn, session).await? {
            if session_obj.secret_key != secret_key.as_ref() {
                return Err(Error::BadSecret);
            }
            let session_data = session_obj
                .set_session_data_conn(conn, &session_key, payload.clone())
                .await?;
            debug!("session_data {session_data:?}",);
            tran.commit().await?;
            Ok(Some(session_data))
        } else {
            Ok(None)
        }
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn delete_session_data_from_cache(
        pool: &PgPool,
        session: Uuid,
        secret_key: impl AsRef<str>,
        session_key: impl AsRef<str>,
    ) -> Result<(), Error> {
        if let Some(session_obj) = Session::get_session(pool, session).await? {
            if session_obj.secret_key != secret_key.as_ref() {
                return Err(Error::BadSecret);
            }
            if let Some(session_data) = session_obj.get_session_data(pool, session_key).await? {
                session_data.delete(pool).await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use stack_string::format_sstr;
    use std::collections::{HashMap, HashSet};

    use crate::{
        AUTH_APP_MUTEX, config::Config, errors::AuthServerError as Error, get_random_string,
        pgpool::PgPool, session::Session, user::User,
    };
    use authorized_users::get_secrets;

    #[tokio::test]
    async fn test_session() -> Result<(), Error> {
        let _lock = AUTH_APP_MUTEX.lock().await;
        let config = Config::init_config()?;
        let pool = PgPool::new(&config.database_url)?;

        get_secrets(&config.secret_path, &config.jwt_secret_path)
            .await
            .unwrap();

        let email = format_sstr!("test+session{}@example.com", get_random_string(32));
        let user = User::from_details(&email, "abc123")?;
        user.insert(&pool).await?;

        let session = Session::new(email.clone());

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
        assert_eq!(
            new_session_data.get_session_value(),
            session_data.get_session_value()
        );

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
        assert_eq!(new_session_data.get_session_value(), "NEW TEST DATA");

        assert_eq!(
            new_session.key_hash.as_ref().unwrap(),
            &Session::get_key_hash()
        );

        new_session_data.delete(&pool).await?;
        session.delete(&pool).await?;
        user.delete(&pool).await?;
        Ok(())
    }
}
