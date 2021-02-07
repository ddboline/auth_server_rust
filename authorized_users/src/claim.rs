use biscuit::RegisteredClaims;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use stack_string::StackString;

use crate::AuthorizedUser;

// JWT claim
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claim {
    domain: StackString,
    expiry: i64,
    issued_at: i64,
    email: StackString,
}

impl From<Claim> for RegisteredClaims {
    fn from(claim: Claim) -> Self {
        Self {
            issuer: Some(claim.domain.into()),
            subject: Some("auth".into()),
            issued_at: Some(claim.issued_at.into()),
            expiry: Some(claim.expiry.into()),
            id: Some(claim.email.into()),
            ..Self::default()
        }
    }
}

// struct to get converted to token and back
impl Claim {
    pub fn with_email(email: &str, domain: &str, expiration_seconds: i64) -> Self {
        Self {
            domain: domain.into(),
            email: email.into(),
            issued_at: Utc::now().timestamp(),
            expiry: (Utc::now() + Duration::seconds(expiration_seconds)).timestamp(),
        }
    }

    pub fn get_email(&self) -> &str {
        self.email.as_str()
    }
}

impl From<Claim> for AuthorizedUser {
    fn from(claim: Claim) -> Self {
        Self {
            email: claim.get_email().into(),
        }
    }
}
