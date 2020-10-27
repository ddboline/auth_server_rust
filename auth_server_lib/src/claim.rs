use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use stack_string::StackString;

use authorized_users::AuthorizedUser;

use crate::config::Config;

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
    pub fn with_email(email: &str, config: &Config) -> Self {
        Self {
            iss: config.domain.clone(),
            sub: "auth".into(),
            email: email.into(),
            iat: Utc::now().timestamp(),
            exp: (Utc::now() + Duration::seconds(config.expiration_seconds)).timestamp(),
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
