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

    pub fn get_registered_claims(&self) -> RegisteredClaims {
        RegisteredClaims {
            issuer: Some(self.domain.clone().into()),
            subject: Some("auth".into()),
            issued_at: Some(self.issued_at.into()),
            expiry: Some(self.expiry.into()),
            id: Some(self.email.clone().into()),
            ..RegisteredClaims::default()
        }
    }
}

impl From<Claim> for AuthorizedUser {
    fn from(claim: Claim) -> Self {
        Self {
            email: claim.get_email().into(),
        }
    }
}
