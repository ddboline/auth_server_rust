use log::error;
use rweb::Schema;
use serde::Deserialize;
use stack_string::StackString;
use tokio::task::spawn_blocking;

use auth_server_lib::{config::Config, pgpool::PgPool, session::Session, user::User};
use authorized_users::AuthorizedUser;

use crate::{
    errors::ServiceError as Error,
    logged_user::{LoggedUser, UserCookies},
};

#[derive(Debug, Deserialize, Schema)]
#[schema(component = "AuthRequest")]
pub struct AuthRequest {
    #[schema(description = "Email Address", example = r#""test@example.com""#)]
    pub email: StackString,
    #[schema(description = "Password")]
    pub password: StackString,
}

impl AuthRequest {
    /// # Errors
    /// Returns error if
    ///     * `User::get_by_email` fails
    ///     * `user.verify_password` fails or panics
    ///     * `User::fake_verify` fails or panics
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
        Err(Error::BadRequest("Invalid username or password"))
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn login_user_jwt(
        &self,
        pool: &PgPool,
        config: &Config,
    ) -> Result<(LoggedUser, Session, UserCookies<'static>), Error> {
        let session = Session::new(self.email.as_str());
        session.insert(pool).await.map_err(|e| {
            error!("error on session insert {e}");
            e
        })?;

        let user = self.authenticate(pool).await?;
        let user: AuthorizedUser = user.into();
        let mut user: LoggedUser = user.into();
        user.session = session.id.into();
        user.secret_key = session.secret_key.clone();
        let cookies = user
            .get_jwt_cookie(&config.domain, config.expiration_seconds, config.secure)
            .map_err(|e| {
                error!("Failed to create_token {e}");
                Error::BadRequest("Failed to create_token")
            })?;
        Ok((user, session, cookies))
    }
}

#[cfg(test)]
mod test {
    use stack_string::format_sstr;

    use auth_server_lib::{config::Config, get_random_string, pgpool::PgPool};

    use crate::{auth::AuthRequest, errors::ServiceError as Error};

    #[tokio::test]
    async fn test_authenticate() -> Result<(), Error> {
        let config = Config::init_config()?;
        let pool = PgPool::new(&config.database_url);

        let email = format_sstr!("{}@localhost", get_random_string(32));
        let password = get_random_string(32);

        let req = AuthRequest { email, password };
        let resp = req.authenticate(&pool).await;
        assert!(resp.is_err());
        match resp {
            Err(Error::BadRequest(e)) => assert_eq!(e, "Invalid username or password"),
            _ => assert!(false, "Unexpected result of authentication"),
        };
        Ok(())
    }
}
