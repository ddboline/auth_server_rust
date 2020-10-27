use anyhow::{format_err, Error};
use serde::Deserialize;

use crate::{pgpool::PgPool, user::User};

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
        Err(format_err!("Invalid username or password"))
    }
}

#[cfg(test)]
mod test {
    use anyhow::Error;

    use crate::{auth::AuthRequest, config::Config, get_random_string, pgpool::PgPool};

    #[tokio::test]
    async fn test_authenticate() -> Result<(), Error> {
        let config = Config::init_config()?;
        let pool = PgPool::new(&config.database_url);

        let email = format!("{}@localhost", get_random_string(32));
        let password = get_random_string(32);

        let req = AuthRequest { email, password };
        let resp = req.authenticate(&pool).await;
        assert_eq!(
            resp.unwrap_err().to_string(),
            "Invalid username or password".to_string()
        );

        Ok(())
    }
}
