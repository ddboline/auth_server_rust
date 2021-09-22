use anyhow::{format_err, Error};
use rweb::Schema;
use serde::Deserialize;
use tokio::task::spawn_blocking;

use auth_server_lib::{pgpool::PgPool, user::User};

#[derive(Debug, Deserialize, Schema)]
pub struct AuthRequest {
    #[schema(description = "Email Address")]
    pub email: String,
    #[schema(description = "Password")]
    pub password: String,
}

impl AuthRequest {
    pub async fn authenticate(&self, pool: &PgPool) -> Result<User, Error> {
        let password = self.password.clone();
        if let Some(user) = User::get_by_email(&self.email, pool).await? {
            if let Ok(Some(user)) = spawn_blocking(move || {
                user.verify_password(&password)
                    .map(|v| if v { Some(user) } else { None })
            })
            .await?
            {
                return Ok(user);
            }
        } else {
            spawn_blocking(move || User::fake_verify(&password)).await??;
        }
        Err(format_err!("Invalid username or password"))
    }
}

#[cfg(test)]
mod test {
    use anyhow::Error;

    use auth_server_lib::{config::Config, get_random_string, pgpool::PgPool};

    use crate::auth::AuthRequest;

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
