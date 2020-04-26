use chrono::{DateTime, Utc};

pub struct User {
    pub email: String,
    pub password: String,
    pub created_at: DateTime<Utc>,
}
