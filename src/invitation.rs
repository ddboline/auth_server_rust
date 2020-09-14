use chrono::{DateTime, Utc};
use postgres_query::FromSqlRow;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ServiceError as Error;
use crate::pgpool::PgPool;

#[derive(FromSqlRow, Serialize, Deserialize)]
pub struct Invitation {
    pub id: Uuid,
    pub email: String,
    pub expires_at: DateTime<Utc>,
}

impl Invitation {
    pub async fn get_by_uuid(uuid: &Uuid, pool: &PgPool) -> Result<Option<Self>, Error> {
        let query = postgres_query::query!("SELECT * FROM invitiations WHERE id = $id", id = uuid);
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
            INSERT INTO invitations (id, email, expires_at)
            VALUES ($id, $email, $expires_at)",
            id = self.id,
            email = self.email,
            expires_at = self.expires_at,
        );
        pool.get()
            .await?
            .execute(query.sql(), query.parameters())
            .await?;
        Ok(())
    }

    pub async fn delete(&self, pool: &PgPool) -> Result<(), Error> {
        let query = postgres_query::query!("DELETE FROM invitations WHERE id = $id", id = self.id);
        pool.get()
            .await?
            .execute(query.sql(), query.parameters())
            .await?;
        Ok(())
    }
}
