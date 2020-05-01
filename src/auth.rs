use anyhow::Error;
use bcrypt::verify;
use postgres_query::query;
use serde::Deserialize;

use crate::pgpool::PgPool;

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub email: String,
    pub password: String,
}

impl AuthRequest {
    pub async fn authenticate(&self, pool: &PgPool) -> Result<bool, Error> {
        let query = query!(
            "SELECT password FROM users WHERE email = $email",
            email = self.email
        );
        let password: String = pool
            .get()
            .await?
            .query_one(query.sql(), query.parameters())
            .await?
            .try_get("password")?;
        verify(&password, &self.password).map_err(Into::into)
    }
}
