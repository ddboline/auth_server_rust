use anyhow::{format_err, Error};
use postgres_query::query_dyn;
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use std::convert::TryFrom;
use url::Url;

use crate::pgpool::PgPool;

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
    pub fn get_pool(&self) -> PgPool {
        PgPool::new(&self.database_url.as_str())
    }

    pub async fn get_authorized_users(&self) -> Result<Vec<StackString>, Error> {
        let pool = self.get_pool();
        let query = format!(
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

    pub async fn add_user(&self, email: &str) -> Result<(), Error> {
        let pool = self.get_pool();
        let query = format!(
            "INSERT INTO {table} ({email_field}) VALUES ($email)",
            table = self.table,
            email_field = self.email_field,
        );
        let query = query_dyn!(&query, email = email)?;
        let conn = pool.get().await?;
        query.execute(&conn).await?;
        Ok(())
    }

    pub async fn remove_user(&self, email: &str) -> Result<(), Error> {
        let pool = self.get_pool();
        let query = format!(
            "DELETE FROM {table} WHERE {email_field} = $email",
            table = self.table,
            email_field = self.email_field
        );
        let query = query_dyn!(&query, email = email)?;
        let conn = pool.get().await?;
        query.execute(&conn).await?;
        Ok(())
    }
}
