use chrono::{DateTime, Utc};
use uuid::Uuid;

pub struct Invitation {
    pub id: Uuid,
    pub email: String,
    pub expires_at: DateTime<Utc>,
}
