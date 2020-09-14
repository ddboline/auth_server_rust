use derive_more::{From, Into};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::env;

use crate::{claim::Claim, errors::ServiceError, logged_user::LoggedUser};

const DEFAULT_ALGORITHM: Algorithm = Algorithm::HS256;

#[derive(From, Into)]
pub struct Token(String);

impl Token {
    pub fn create_token(data: &LoggedUser) -> Result<Self, ServiceError> {
        let claims = Claim::with_email(data.email.as_str());
        encode(
            &Header::new(DEFAULT_ALGORITHM),
            &claims,
            &EncodingKey::from_secret(get_secret().as_ref()),
        )
        .map(Into::into)
        .map_err(|_err| ServiceError::InternalServerError)
    }

    pub fn decode_token(token: &Self) -> Result<Claim, ServiceError> {
        decode::<Claim>(
            &token.0,
            &DecodingKey::from_secret(get_secret().as_ref()),
            &Validation::new(DEFAULT_ALGORITHM),
        )
        .map(|data| Ok(data.claims))
        .map_err(|_err| ServiceError::Unauthorized)?
    }
}

fn get_secret() -> String {
    env::var("JWT_SECRET").unwrap_or_else(|_| "my secret".into())
}
