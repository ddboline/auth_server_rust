use anyhow::{format_err, Error};
use biscuit::{ClaimsSet, RegisteredClaims};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use std::convert::TryFrom;
use uuid::Uuid;

use crate::AuthorizedUser;

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
        Self {
            domain: domain.into(),
            email: email.into(),
            session,
            issued_at: Utc::now().timestamp(),
            expiry: (Utc::now() + Duration::seconds(expiration_seconds)).timestamp(),
            secret_key: secret_key.into(),
        }
    }

    pub fn get_email(&self) -> &str {
        self.email.as_str()
    }

    pub fn get_session(&self) -> Uuid {
        self.session
    }

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
        let session: Uuid = reg
            .id
            .as_ref()
            .ok_or_else(|| format_err!("No session"))?
            .parse()?;
        let domain = reg
            .issuer
            .as_ref()
            .ok_or_else(|| format_err!("No domain"))?
            .into();
        let expiry = reg
            .expiry
            .ok_or_else(|| format_err!("No expiry"))?
            .timestamp();
        let issued_at = reg
            .issued_at
            .ok_or_else(|| format_err!("No iss"))?
            .timestamp();
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
        }
    }
}
