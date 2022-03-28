use anyhow::{format_err, Error};
use postgres_query::{client::GenericClient, query_dyn};
use serde::{Deserialize, Serialize};
use stack_string::{format_sstr, StackString};
use std::convert::TryFrom;
use url::Url;

use crate::pgpool::{PgPool, PgTransaction};

#[derive(Serialize, Deserialize)]
pub(crate) struct TomlEntry {
    database_url: Option<Url>,
    table: Option<StackString>,
    email_field: Option<StackString>,
}

#[derive(Debug)]
pub struct Entry {
    pub database_url: Url,
    pub table: StackString,
    pub email_field: StackString,
}

impl TryFrom<TomlEntry> for Entry {
    type Error = Error;
    fn try_from(value: TomlEntry) -> Result<Self, Self::Error> {
        let database_url = value
            .database_url
            .ok_or_else(|| format_err!("Missing database url"))?;
        let table = value.table.ok_or_else(|| format_err!("Missing table"))?;
        let email_field = value.email_field.unwrap_or_else(|| "email".into());
        Ok(Self {
            database_url,
            table,
            email_field,
        })
    }
}

impl Entry {
    #[must_use]
    pub fn get_pool(&self) -> PgPool {
        PgPool::new(self.database_url.as_str())
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn get_authorized_users(&self) -> Result<Vec<StackString>, Error> {
        let pool = self.get_pool();
        let query = format_sstr!(
            "SELECT {email_field} FROM {table}",
            table = self.table,
            email_field = self.email_field
        );
        let query = query_dyn!(&query)?;
        let conn = pool.get().await?;
        let emails: Vec<(StackString,)> = query.fetch(&conn).await?;
        let emails = emails.into_iter().map(|(s,)| s).collect();
        Ok(emails)
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn add_user(&self, email: impl AsRef<str>) -> Result<(), Error> {
        let pool = self.get_pool();
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
        let pool = self.get_pool();
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
