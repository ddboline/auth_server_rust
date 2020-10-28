use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use stack_string::StackString;

use crate::AuthorizedUser;

// JWT claim
#[derive(Debug, Serialize, Deserialize)]
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
