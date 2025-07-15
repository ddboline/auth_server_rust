use futures::TryStreamExt;
use postgres_query::{Error as PqError, client::GenericClient, query_dyn};
use serde::{Deserialize, Serialize};
use stack_string::{StackString, format_sstr};
use std::convert::TryFrom;
use url::Url;

use crate::{
    errors::AuthServerError as Error,
    pgpool::{PgPool, PgTransaction},
};

#[derive(Serialize, Deserialize)]
pub(crate) struct TomlEntry {
    database_url: Option<Url>,
    table: Option<StackString>,
    email_field: Option<StackString>,
}

#[derive(Debug)]
pub struct Entry {
    database_url: Url,
    table: StackString,
    email_field: StackString,
}

impl TryFrom<TomlEntry> for Entry {
    type Error = Error;
    fn try_from(value: TomlEntry) -> Result<Self, Self::Error> {
        let database_url = value.database_url.ok_or_else(|| Error::MissingDbUrl)?;
        let table = value.table.ok_or_else(|| Error::MissingTable)?;
        let email_field = value.email_field.unwrap_or_else(|| "email".into());
        Ok(Self {
            database_url,
            table,
            email_field,
        })
    }
}

impl Entry {
    /// # Errors
    /// Returns error if setup of pool fails
    pub fn get_pool(&self) -> Result<PgPool, Error> {
        PgPool::new(self.database_url.as_str())
    }

    #[must_use]
    pub fn get_database_url(&self) -> &Url {
        &self.database_url
    }

    #[must_use]
    pub fn get_table(&self) -> &str {
        self.table.as_str()
    }

    #[must_use]
    pub fn get_email_field(&self) -> &str {
        self.email_field.as_str()
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn get_authorized_users(&self) -> Result<Vec<StackString>, Error> {
        let pool = self.get_pool()?;
        let email_field = &self.email_field;
        let table = &self.table;
        let query = format_sstr!("SELECT {email_field} FROM {table}");
        let query = query_dyn!(&query)?;
        let conn = pool.get().await?;
        query
            .query_streaming(&conn)
            .await?
            .and_then(|row| async move {
                let email: StackString = row.try_get(0).map_err(PqError::BeginTransaction)?;
                Ok(email)
            })
            .try_collect()
            .await
            .map_err(Into::into)
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn add_user(&self, email: impl AsRef<str>) -> Result<(), Error> {
        let pool = self.get_pool()?;
        let mut conn = pool.get().await?;
        let tran = conn.transaction().await?;
        let conn: &PgTransaction = &tran;
        self.add_user_conn(conn, email).await?;
        tran.commit().await?;
        Ok(())
    }

    async fn add_user_conn<C>(&self, conn: &C, email: impl AsRef<str>) -> Result<(), Error>
    where
        C: GenericClient + Sync,
    {
        let email = email.as_ref();
        let query = format_sstr!(
            "INSERT INTO {table} ({email_field}) VALUES ($email)",
            table = self.table,
            email_field = self.email_field,
        );
        let query = query_dyn!(&query, email = email)?;
        query.execute(&conn).await?;
        Ok(())
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn remove_user(&self, email: impl AsRef<str>) -> Result<(), Error> {
        let pool = self.get_pool()?;
        let mut conn = pool.get().await?;
        let tran = conn.transaction().await?;
        let conn: &PgTransaction = &tran;
        self.remove_user_conn(conn, email).await?;
        tran.commit().await?;
        Ok(())
    }

    async fn remove_user_conn<C>(&self, conn: &C, email: impl AsRef<str>) -> Result<(), Error>
    where
        C: GenericClient + Sync,
    {
        let email = email.as_ref();
        let query = format_sstr!(
            "DELETE FROM {table} WHERE {email_field} = $email",
            table = self.table,
            email_field = self.email_field
        );
        let query = query_dyn!(&query, email = email)?;
        query.execute(&conn).await?;
        Ok(())
    }
}
