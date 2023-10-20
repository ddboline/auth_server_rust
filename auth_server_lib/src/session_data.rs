use futures::Stream;
use postgres_query::{client::GenericClient, query, Error as PqError, FromSqlRow};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stack_string::StackString;
use uuid::Uuid;

use crate::{
    date_time_wrapper::DateTimeWrapper,
    errors::AuthServerError as Error,
    pgpool::{PgPool, PgTransaction},
    session::Session,
};

#[derive(FromSqlRow, Serialize, Deserialize, PartialEq, Debug, Eq)]
pub struct SessionData {
    pub id: Uuid,
    pub session_id: Uuid,
    pub session_key: StackString,
    pub session_value: Value,
    pub created_at: DateTimeWrapper,
    pub modified_at: DateTimeWrapper,
}

impl SessionData {
    pub fn new(session_id: Uuid, key: impl Into<StackString>, value: Value) -> Self {
        Self {
            id: Uuid::new_v4(),
            session_id,
            session_key: key.into(),
            session_value: value,
            created_at: DateTimeWrapper::now(),
            modified_at: DateTimeWrapper::now(),
        }
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn get_all_session_data(
        pool: &PgPool,
    ) -> Result<impl Stream<Item = Result<Self, PqError>>, Error> {
        let query = query!("SELECT * FROM session_values");
        let conn = pool.get().await?;
        query.fetch_streaming(&conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>, Error> {
        let conn = pool.get().await?;
        Self::get_by_id_conn(&conn, id).await.map_err(Into::into)
    }

    async fn get_by_id_conn<C>(conn: &C, id: Uuid) -> Result<Option<Self>, Error>
    where
        C: GenericClient + Sync,
    {
        let query = query!(
            "
                SELECT * FROM session_values
                WHERE id = $id
            ",
            id = id,
        );
        query.fetch_opt(conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn get_by_session_id_streaming(
        pool: &PgPool,
        session_id: Uuid,
    ) -> Result<impl Stream<Item = Result<Self, PqError>>, Error> {
        let query = query!(
            "SELECT * FROM session_values WHERE session_id = $session_id ORDER BY created_at",
            session_id = session_id
        );
        let conn = pool.get().await?;
        query.fetch_streaming(&conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn get_by_session_id(pool: &PgPool, session_id: Uuid) -> Result<Vec<Self>, Error> {
        let query = query!(
            "SELECT * FROM session_values WHERE session_id = $session_id ORDER BY created_at",
            session_id = session_id
        );
        let conn = pool.get().await?;
        query.fetch(&conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn get_by_session_key(
        pool: &PgPool,
        session_id: Uuid,
        session_key: impl AsRef<str>,
    ) -> Result<Option<Self>, Error> {
        let session_key = session_key.as_ref();
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

    /// # Errors
    /// Returns error if db query fails
    pub async fn get_number_entries(pool: &PgPool) -> Result<i64, Error> {
        let query = query!("SELECT count(*) FROM session_values");
        let conn = pool.get().await?;
        let (count,) = query.fetch_one(&conn).await?;
        Ok(count)
    }

    async fn insert_conn<C>(&self, conn: &C) -> Result<(), Error>
    where
        C: GenericClient + Sync,
    {
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
        query.execute(conn).await?;
        Ok(())
    }

    async fn update_conn<C>(&self, conn: &C) -> Result<(), Error>
    where
        C: GenericClient + Sync,
    {
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
        query.execute(conn).await?;
        Ok(())
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn upsert(&self, pool: &PgPool) -> Result<(), Error> {
        let mut conn = pool.get().await?;
        let tran = conn.transaction().await?;
        let conn: &PgTransaction = &tran;
        self.update_conn(conn).await?;
        tran.commit().await?;
        Ok(())
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn upsert_conn<C>(&self, conn: &C) -> Result<(), Error>
    where
        C: GenericClient + Sync,
    {
        if Self::get_by_id_conn(conn, self.id).await?.is_some() {
            self.update_conn(conn).await?;
        } else {
            self.insert_conn(conn).await?;
        }
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
        let query = query!("DELETE FROM session_values WHERE id = $id", id = self.id);
        query.execute(&conn).await?;
        Ok(())
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn get_session_from_cache(
        pool: &PgPool,
        session: Uuid,
        secret_key: &str,
        session_key: &str,
    ) -> Result<Option<SessionData>, Error> {
        if let Some(session_obj) = Session::get_session(pool, session).await? {
            if session_obj.secret_key != secret_key {
                Err(Error::BadSecret)
            } else if let Some(session_data) =
                session_obj.get_session_data(pool, &session_key).await?
            {
                Ok(Some(session_data))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
}
