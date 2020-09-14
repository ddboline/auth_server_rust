use serde::Deserialize;

use crate::{errors::ServiceError as Error, pgpool::PgPool, user::User};

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub email: String,
    pub password: String,
}

impl AuthRequest {
    pub async fn authenticate(&self, pool: &PgPool) -> Result<Option<User>, Error> {
        if let Some(user) = User::get_by_email(&self.email, pool).await? {
            if user.verify_password(&self.password)? {
                return Ok(Some(user));
            }
        }
        Err(Error::BadRequest("Invalid username or password".into()))
    }
}
