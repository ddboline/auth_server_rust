use reqwest::{Client, header::HeaderValue};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use stack_string::{StackString, format_sstr};
use std::{cmp::PartialEq, convert::TryFrom, hash::Hash};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::{errors::AuthUsersError as Error, token::Token};

#[derive(Debug, Serialize, Deserialize, Clone, Eq)]
pub struct AuthorizedUser {
    email: StackString,
    session: Uuid,
    secret_key: StackString,
    created_at: OffsetDateTime,
}

impl PartialEq for AuthorizedUser {
    fn eq(&self, other: &Self) -> bool {
        self.email == other.email
            && self.session == other.session
            && self.secret_key == other.secret_key
    }
}

impl Hash for AuthorizedUser {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.email.hash(state);
        self.session.hash(state);
        self.secret_key.hash(state);
    }
}

impl Default for AuthorizedUser {
    fn default() -> Self {
        Self {
            email: StackString::default(),
            session: Uuid::default(),
            secret_key: StackString::default(),
            created_at: OffsetDateTime::now_utc(),
        }
    }
}

impl TryFrom<Token> for AuthorizedUser {
    type Error = Error;
    fn try_from(token: Token) -> Result<Self, Self::Error> {
        let claim = token.decode_token()?;
        Ok(claim.into())
    }
}

impl AuthorizedUser {
    #[must_use]
    pub fn new(email: &str, session: Uuid, secret_key: &str) -> Self {
        Self {
            email: email.into(),
            session,
            secret_key: secret_key.into(),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn with_email(mut self, email: &str) -> Self {
        self.email = email.into();
        self
    }

    #[must_use]
    pub fn with_created_at(mut self, created_at: OffsetDateTime) -> Self {
        self.created_at = created_at;
        self
    }

    #[must_use]
    pub fn get_email(&self) -> &str {
        self.email.as_str()
    }

    #[must_use]
    pub fn get_session(&self) -> Uuid {
        self.session
    }

    #[must_use]
    pub fn get_secret_key(&self) -> &str {
        self.secret_key.as_str()
    }

    #[must_use]
    pub fn get_created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// # Errors
    /// Returns error if api call fails
    pub async fn get_session_data<T: DeserializeOwned>(
        base_url: &Url,
        session: Uuid,
        secret_key: &str,
        client: &Client,
        key: &str,
    ) -> Result<T, Error> {
        let url = base_url.join(format_sstr!("/api/session/{key}").as_str())?;
        let session_str = format_sstr!("{session}");
        let value = HeaderValue::from_str(&session_str)?;
        let secret_key = HeaderValue::from_str(secret_key)?;
        client
            .get(url.as_str())
            .header("session", value)
            .header("secret-key", secret_key)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }

    /// # Errors
    /// Returns error if api call fails
    pub async fn set_session_data<T: Serialize>(
        base_url: &Url,
        session: Uuid,
        secret_key: &str,
        client: &Client,
        key: &str,
        data: &T,
    ) -> Result<(), Error> {
        let url = base_url.join(format_sstr!("/api/session/{key}").as_str())?;
        let session_str = format_sstr!("{session}");
        let value = HeaderValue::from_str(&session_str)?;
        let secret_key = HeaderValue::from_str(secret_key)?;
        client
            .post(url.as_str())
            .header("session", value)
            .header("secret-key", secret_key)
            .json(data)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// # Errors
    /// Returns error if api call fails
    pub async fn rm_session_data(
        base_url: &Url,
        session: Uuid,
        secret_key: &str,
        client: &Client,
        key: &str,
    ) -> Result<(), Error> {
        let url = base_url.join(format_sstr!("/api/session/{key}").as_str())?;
        let session_str = format_sstr!("{session}");
        let value = HeaderValue::from_str(&session_str)?;
        let secret_key = HeaderValue::from_str(secret_key)?;
        client
            .delete(url.as_str())
            .header("session", value)
            .header("secret-key", secret_key)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use uuid::Uuid;

    use crate::{
        AuthorizedUser, JWT_SECRET, KEY_LENGTH, SECRET_KEY, errors::AuthUsersError, get_random_key,
        token::Token,
    };

    #[test]
    fn test_auth_user() -> Result<(), AuthUsersError> {
        let mut secret_key = [0u8; KEY_LENGTH];
        secret_key.copy_from_slice(&get_random_key());

        SECRET_KEY.set(secret_key);
        JWT_SECRET.set(secret_key);

        let key = "0123456789abcdef";
        let session = Uuid::new_v4();
        let token = Token::create_token("test@example.com", "example.com", 3600, session, key)?;
        let user: AuthorizedUser = token.try_into()?;
        assert_eq!(user.session, session);
        Ok(())
    }
}
