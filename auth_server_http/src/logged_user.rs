use cookie::{time::Duration, Cookie};
use log::debug;
use rweb::{filters::{cookie::cookie, BoxedFilter}, Filter, Rejection, Schema, FromRequest};
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use std::{
    convert::{TryFrom, TryInto},
    str::FromStr,
};
use uuid::Uuid;

use authorized_users::{token::Token, AuthorizedUser, AUTHORIZED_USERS};

use crate::errors::ServiceError as Error;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Schema)]
pub struct LoggedUser {
    #[schema(description = "Email Address")]
    pub email: StackString,
    #[schema(description = "Session ID")]
    pub session: Uuid,
    #[schema(description = "Secret Key")]
    pub secret_key: StackString,
}

pub struct UserCookies<'a> {
    pub session_id: Cookie<'a>,
    pub jwt: Cookie<'a>,
}

impl LoggedUser {
    /// # Errors
    /// Returns error if `Token::create_token` fails
    pub fn get_jwt_cookie(
        &self,
        domain: impl AsRef<str>,
        expiration_seconds: i64,
        secure: bool,
    ) -> Result<UserCookies<'static>, Error> {
        let domain = domain.as_ref();
        let session = self.session;
        let session_id = Cookie::build("session-id", session.to_string())
            .path("/")
            .http_only(true)
            .domain(domain.to_string())
            .max_age(Duration::seconds(expiration_seconds))
            .secure(secure)
            .finish();
        let token = Token::create_token(
            self.email.clone(),
            domain,
            expiration_seconds,
            session,
            self.secret_key.clone(),
        )?;
        let jwt = Cookie::build("jwt", token.to_string())
            .path("/")
            .http_only(true)
            .domain(domain.to_string())
            .max_age(Duration::seconds(expiration_seconds))
            .secure(secure)
            .finish();
        Ok(UserCookies { session_id, jwt })
    }

    pub fn clear_jwt_cookie(
        &self,
        domain: impl AsRef<str>,
        expiration_seconds: i64,
        secure: bool,
    ) -> UserCookies<'static> {
        let domain = domain.as_ref();
        let session = self.session;
        let session_id = Cookie::build("session-id", session.to_string())
            .path("/")
            .http_only(true)
            .domain(domain.to_string())
            .max_age(Duration::seconds(expiration_seconds))
            .secure(secure)
            .finish();
        let jwt = Cookie::build("jwt", "".to_string())
            .path("/")
            .http_only(true)
            .domain(domain.to_string())
            .max_age(Duration::seconds(expiration_seconds))
            .secure(secure)
            .finish();
        UserCookies { session_id, jwt }
    }

    /// # Errors
    /// Returns `Error::Unauthorized` if session id does not match
    pub fn verify_session_id(&self, session_id: Uuid) -> Result<(), Error> {
        if self.session == session_id {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }

    #[must_use]
    pub fn filter() -> impl Filter<Extract = (Self,), Error = Rejection> + Copy {
        cookie("session-id")
            .and(cookie("jwt"))
            .and_then(|id: Uuid, user: Self| async move {
                user.verify_session_id(id)
                    .map(|_| user)
                    .map_err(rweb::reject::custom)
            })
    }
}

impl FromRequest for LoggedUser {
    type Filter = BoxedFilter<(Self,)>;

    fn new() -> Self::Filter {
        Self::filter().boxed()
    }
}

impl From<AuthorizedUser> for LoggedUser {
    fn from(user: AuthorizedUser) -> Self {
        Self {
            email: user.email,
            session: user.session,
            secret_key: user.secret_key,
        }
    }
}

impl From<LoggedUser> for AuthorizedUser {
    fn from(user: LoggedUser) -> Self {
        Self {
            email: user.email,
            session: user.session,
            secret_key: user.secret_key,
        }
    }
}

impl TryFrom<Token> for LoggedUser {
    type Error = Error;
    fn try_from(token: Token) -> Result<Self, Self::Error> {
        let user = token.try_into()?;
        if AUTHORIZED_USERS.is_authorized(&user) {
            Ok(user.into())
        } else {
            debug!("NOT AUTHORIZED {:?}", user);
            Err(Error::Unauthorized)
        }
    }
}

impl FromStr for LoggedUser {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut buf = StackString::new();
        buf.push_str(s);
        let token: Token = buf.into();
        token.try_into()
    }
}

#[cfg(test)]
mod tests {
    use authorized_users::AuthorizedUser;

    use crate::logged_user::LoggedUser;

    #[test]
    fn test_authorized_user_to_logged_user() {
        let email = "test@localhost";
        let user = AuthorizedUser {
            email: email.into(),
            ..AuthorizedUser::default()
        };

        let user: LoggedUser = user.into();

        assert_eq!(user.email, email);
    }
}
