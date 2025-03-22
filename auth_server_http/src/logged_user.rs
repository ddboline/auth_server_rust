use auth_server_lib::pgpool::PgPool;
use cookie::{time::Duration, Cookie};
use log::debug;
use serde::{Deserialize, Serialize};
use stack_string::{StackString, format_sstr};
use std::{
    cmp::PartialEq,
    convert::{Infallible, TryFrom, TryInto},
    hash::Hash,
    str::FromStr,
};
use uuid::Uuid;
use time::OffsetDateTime;
use axum::extract::{FromRequestParts, OptionalFromRequestParts};
use std::future::Future;
use http::request::Parts;
use axum_extra::extract::CookieJar;
use utoipa::ToSchema;
use http::HeaderMap;
use http::header::SET_COOKIE;

use auth_server_lib::session::Session;
use authorized_users::{token::Token, AuthorizedUser, AUTHORIZED_USERS};

use crate::errors::ServiceError as Error;

#[derive(Debug, Serialize, Deserialize, Eq, Clone, ToSchema)]
// #[schema(component = "LoggedUser")]
pub struct LoggedUser {
    /// Email Address
    #[schema(example = r#""user@example.com""#)]
    pub email: StackString,
    /// Session ID
    pub session: Uuid,
    /// Secret Key
    pub secret_key: StackString,
    /// User Created At
    pub created_at: OffsetDateTime,
}

impl PartialEq for LoggedUser {
    fn eq(&self, other: &Self) -> bool {
        self.email == other.email
            && self.session == other.session
            && self.secret_key == other.secret_key
    }
}

impl Hash for LoggedUser {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.email.hash(state);
        self.session.hash(state);
        self.secret_key.hash(state);
    }
}

#[derive(Debug)]
pub struct UserCookies<'a> {
    session: Cookie<'a>,
    jwt: Cookie<'a>,
}

impl UserCookies<'_> {
    #[must_use]
    pub fn get_session_cookie_str(&self) -> StackString {
        StackString::from_display(self.session.encoded())
    }

    #[must_use]
    pub fn get_jwt_cookie_str(&self) -> StackString {
        StackString::from_display(self.jwt.encoded())
    }

    pub fn get_headers(&self) -> Result<HeaderMap, Error> {
        let mut headers = HeaderMap::new();
        headers.append(SET_COOKIE, self.get_session_cookie_str().as_str().try_into()?);
        headers.append(SET_COOKIE, self.get_jwt_cookie_str().as_str().try_into()?);
        Ok(headers)
    }
}

impl LoggedUser {
    /// # Errors
    /// Returns error if `Token::create_token` fails
    pub fn get_jwt_cookie(
        &self,
        domain: impl AsRef<str>,
        expiration_seconds: u32,
        secure: bool,
    ) -> Result<UserCookies<'static>, Error> {
        let domain: String = domain.as_ref().into();
        let session_id: Uuid = self.session.into();
        let session = Cookie::build(("session-id", session_id.to_string()))
            .path("/")
            .http_only(true)
            .domain(domain.clone())
            .max_age(Duration::seconds(expiration_seconds.into()))
            .secure(secure)
            .build();
        let token = Token::create_token(
            self.email.clone(),
            &domain,
            expiration_seconds,
            session_id,
            self.secret_key.clone(),
        )?;
        let jwt = Cookie::build(("jwt", token.to_string()))
            .path("/")
            .http_only(true)
            .domain(domain)
            .max_age(Duration::seconds(expiration_seconds.into()))
            .secure(secure)
            .build();
        Ok(UserCookies { session, jwt })
    }

    pub fn clear_jwt_cookie(
        &self,
        domain: impl AsRef<str>,
        expiration_seconds: u32,
        secure: bool,
    ) -> UserCookies<'static> {
        let domain = domain.as_ref();
        let session_id = self.session;
        let session = Cookie::build(("session-id", session_id.to_string()))
            .path("/")
            .http_only(true)
            .domain(domain.to_string())
            .max_age(Duration::seconds(expiration_seconds.into()))
            .secure(secure)
            .build();
        let jwt = Cookie::build(("jwt", String::new()))
            .path("/")
            .http_only(true)
            .domain(domain.to_string())
            .max_age(Duration::seconds(expiration_seconds.into()))
            .secure(secure)
            .build();
        UserCookies { session, jwt }
    }

    /// # Errors
    /// Returns `Error::Unauthorized` if session id does not match
    pub fn verify_session_id(self, session_id: Uuid) -> Result<Self, Error> {
        if self.session == session_id {
            Ok(self)
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn delete_user_session(session_id: Uuid, pool: &PgPool) -> Result<(), Error> {
        if let Some(session_obj) = Session::get_session(pool, session_id).await? {
            for session_data in session_obj.get_all_session_data(pool).await? {
                session_data.delete(pool).await?;
            }
            session_obj.delete(pool).await?;
        }
        Ok(())
    }

    fn extract_user_from_cookies(cookie_jar: CookieJar) -> Option<LoggedUser> {
        let session_id: Uuid = StackString::from_display(cookie_jar.get("session-id")?.encoded()).strip_prefix("session-id=")?.parse().ok()?;
        debug!("session_id {session_id:?}");
        let user: LoggedUser = StackString::from_display(cookie_jar.get("jwt")?.encoded()).strip_prefix("jwt=")?.parse().ok()?;
        debug!("user {user:?}");
        user.verify_session_id(session_id).ok()
    }
}

impl<S> FromRequestParts<S> for LoggedUser where S: Send + Sync {
    type Rejection = Error;

    fn from_request_parts(parts: &mut Parts, state: &S,) -> impl Future<Output = Result<Self,Self::Rejection>> +Send {
        async move {
            let cookie_jar = CookieJar::from_request_parts(parts, state).await.expect("extract failed");
            debug!("cookie_jar {cookie_jar:?}");
            let user = LoggedUser::extract_user_from_cookies(cookie_jar).ok_or_else(|| Error::Unauthorized)?;
            Ok(user)
        }        
    }
}

impl<S> OptionalFromRequestParts<S> for LoggedUser
 where S: Send + Sync
{
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Option<Self>, Self::Rejection>> + Send {
        async move {
            let cookie_jar = CookieJar::from_request_parts(parts, state).await.expect("extract failed");
            Ok(LoggedUser::extract_user_from_cookies(cookie_jar))
        }
    }
}

// impl FromRequest for LoggedUser {
//     type Filter = BoxedFilter<(Self,)>;

//     fn new() -> Self::Filter {
//         Self::filter().boxed()
//     }
// }

impl From<AuthorizedUser> for LoggedUser {
    fn from(user: AuthorizedUser) -> Self {
        Self {
            email: user.email,
            session: user.session.into(),
            secret_key: user.secret_key,
            created_at: user.created_at.into(),
        }
    }
}

impl From<LoggedUser> for AuthorizedUser {
    fn from(user: LoggedUser) -> Self {
        Self {
            email: user.email,
            session: user.session.into(),
            secret_key: user.secret_key,
            created_at: user.created_at.into(),
        }
    }
}

impl TryFrom<Token> for LoggedUser {
    type Error = Error;
    fn try_from(token: Token) -> Result<Self, Self::Error> {
        match token.try_into() {
            Ok(user) => {
                if AUTHORIZED_USERS.is_authorized(&user) {
                    return Ok(user.into());
                }
                debug!("NOT AUTHORIZED {:?}", user);
            }
            Err(e) => {
                debug!("token decode error {e}");
            }
        }
        Err(Error::Unauthorized)
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
