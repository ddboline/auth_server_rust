use biscuit::{ClaimsSet, RegisteredClaims};
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use std::convert::TryFrom;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    errors::{AuthUsersError as Error, TokenError},
    AuthorizedUser,
};

// JWT claim
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claim {
    domain: StackString,
    expiry: i64,
    issued_at: i64,
    email: StackString,
    session: Uuid,
    secret_key: StackString,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PrivateClaim {
    email: StackString,
    secret_key: StackString,
}

// struct to get converted to token and back
impl Claim {
    pub fn with_email(
        email: impl Into<StackString>,
        domain: impl Into<StackString>,
        expiration_seconds: i64,
        session: Uuid,
        secret_key: impl Into<StackString>,
    ) -> Self {
        let issued_at = OffsetDateTime::now_utc().unix_timestamp();
        let expiry =
            (OffsetDateTime::now_utc() + Duration::seconds(expiration_seconds)).unix_timestamp();
        Self {
            domain: domain.into(),
            email: email.into(),
            session,
            issued_at,
            expiry,
            secret_key: secret_key.into(),
        }
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
    pub fn get_registered_claims(&self) -> RegisteredClaims {
        RegisteredClaims {
            issuer: Some(self.domain.clone().into()),
            subject: Some("auth".into()),
            issued_at: Some(self.issued_at.into()),
            expiry: Some(self.expiry.into()),
            id: Some(self.session.to_string()),
            ..RegisteredClaims::default()
        }
    }

    #[must_use]
    pub fn get_private_claims(&self) -> PrivateClaim {
        PrivateClaim {
            email: self.email.clone(),
            secret_key: self.secret_key.clone(),
        }
    }
}

impl TryFrom<ClaimsSet<PrivateClaim>> for Claim {
    type Error = Error;

    fn try_from(claim_set: ClaimsSet<PrivateClaim>) -> Result<Self, Self::Error> {
        let reg = &claim_set.registered;
        let pri = claim_set.private;
        let session: Uuid = reg.id.as_ref().ok_or(TokenError::NoSession)?.parse()?;
        let domain = reg.issuer.as_ref().ok_or(TokenError::NoDomain)?.into();
        let expiry = reg.expiry.ok_or(TokenError::NoExpiry)?.timestamp();
        let issued_at = reg.issued_at.ok_or(TokenError::NoIssuedAt)?.timestamp();
        let email = pri.email;
        let secret_key = pri.secret_key;
        Ok(Self {
            domain,
            expiry,
            issued_at,
            email,
            session,
            secret_key,
        })
    }
}

impl From<Claim> for AuthorizedUser {
    fn from(claim: Claim) -> Self {
        Self {
            email: claim.get_email().into(),
            session: claim.session,
            secret_key: claim.secret_key,
            created_at: None,
        }
    }
}
