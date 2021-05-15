use log::debug;
use rweb::Schema;
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
    pub email: StackString,
    pub session: Option<StackString>,
}

impl LoggedUser {
    pub fn get_jwt_cookie(
        &self,
        domain: &str,
        expiration_seconds: i64,
        session: Uuid,
    ) -> Result<String, Error> {
        let token = Token::create_token(&self.email, domain, expiration_seconds, session)?;
        Ok(format!(
            "jwt={}; HttpOnly; Path=/; Domain={}; Max-Age={}",
            token, domain, expiration_seconds
        ))
    }
}

impl From<AuthorizedUser> for LoggedUser {
    fn from(user: AuthorizedUser) -> Self {
        Self {
            email: user.email,
            session: user.session.map(|x| x.to_string().into()),
        }
    }
}

impl From<LoggedUser> for AuthorizedUser {
    fn from(user: LoggedUser) -> Self {
        Self {
            email: user.email,
            session: user.session.and_then(|x| x.parse().ok()),
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
            session: None,
        };

        let user: LoggedUser = user.into();

        assert_eq!(user.email, email);
    }
}
