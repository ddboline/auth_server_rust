pub struct Invitation {
    pub id: Uuid,
    pub email: String,
    pub expires_at: NaiveDateTime,
}
