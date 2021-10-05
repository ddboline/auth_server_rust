use cookie::{time::Duration, Cookie};
use log::debug;
use rweb::{filters::cookie::cookie, Filter, Rejection, Schema};
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
}

pub struct UserCookies<'a> {
    pub session_id: Cookie<'a>,
    pub jwt: Cookie<'a>,
}

impl LoggedUser {
    pub fn get_jwt_cookie(
        &self,
        domain: &str,
        expiration_seconds: i64,
        secure: bool,
    ) -> Result<UserCookies<'static>, Error> {
        let session = self.session;
        let session_id = Cookie::build("session-id", session.to_string())
            .path("/")
            .http_only(true)
            .domain(domain.to_string())
            .max_age(Duration::seconds(expiration_seconds))
            .secure(secure)
            .finish();

        let token = Token::create_token(&self.email, domain, expiration_seconds, session)?;
        let jwt = Cookie::build("jwt", token.to_string())
            .path("/")
            .http_only(true)
            .domain(domain.to_string())
            .max_age(Duration::seconds(expiration_seconds))
            .secure(secure)
            .finish();
        Ok(UserCookies { session_id, jwt })
    }

    pub fn verify_session_id(&self, session_id: Uuid) -> Result<(), Error> {
        if self.session == session_id {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }

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

impl From<AuthorizedUser> for LoggedUser {
    fn from(user: AuthorizedUser) -> Self {
        Self {
            email: user.email,
            session: user.session,
        }
    }
}

impl From<LoggedUser> for AuthorizedUser {
    fn from(user: LoggedUser) -> Self {
        Self {
            email: user.email,
            session: user.session,
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
        let token: Token = s.to_string().into();
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
