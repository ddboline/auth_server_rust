use chrono::{Duration, Local};
use serde::{Deserialize, Serialize};
use std::env;

// JWT claim
#[derive(Debug, Serialize, Deserialize)]
pub struct Claim {
    // issuer
    iss: String,
    // subject
    sub: String,
    // issued at
    iat: i64,
    // expiry
    exp: i64,
    // user email
    email: String,
}

// struct to get converted to token and back
impl Claim {
    pub fn with_email(email: &str) -> Self {
        let domain = env::var("DOMAIN").unwrap_or_else(|_| "localhost".to_string());
        Self {
            iss: domain,
            sub: "auth".into(),
            email: email.to_owned(),
            iat: Local::now().timestamp(),
            exp: (Local::now() + Duration::hours(24)).timestamp(),
        }
    }

    pub fn get_email(self) -> String {
        self.email
    }
}
