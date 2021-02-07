use biscuit::RegisteredClaims;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use stack_string::StackString;

use crate::AuthorizedUser;

// JWT claim
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claim {
    // issuer
    iss: StackString,
    // subject
    sub: StackString,
    // issued at
    iat: i64,
    // expiry
    exp: i64,
    // user email
    email: StackString,
}

impl From<Claim> for RegisteredClaims {
    fn from(claim: Claim) -> Self {
        Self {
            issuer: Some(claim.iss.into()),
            subject: Some(claim.sub.into()),
            issued_at: Some(claim.iat.into()),
            expiry: Some(claim.exp.into()),
            id: Some(claim.email.into()),
            ..Self::default()
        }
    }
}

// struct to get converted to token and back
impl Claim {
    pub fn with_email(email: &str, domain: &str, expiration_seconds: i64) -> Self {
        Self {
            iss: domain.into(),
            sub: "auth".into(),
            email: email.into(),
            iat: Utc::now().timestamp(),
            exp: (Utc::now() + Duration::seconds(expiration_seconds)).timestamp(),
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
