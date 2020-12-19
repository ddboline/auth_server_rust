use anyhow::{format_err, Error};
use derive_more::{From, Into};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

use crate::{claim::Claim, AuthorizedUser, JWT_SECRET};

const DEFAULT_ALGORITHM: Algorithm = Algorithm::HS256;

#[derive(From, Into)]
pub struct Token(String);

impl Token {
    pub fn create_token(
        data: &AuthorizedUser,
        domain: &str,
        expiration_seconds: i64,
    ) -> Result<Self, Error> {
        let claims = Claim::with_email(data.email.as_str(), domain, expiration_seconds);
        encode(
            &Header::new(DEFAULT_ALGORITHM),
            &claims,
            &EncodingKey::from_secret(&JWT_SECRET.get()),
        )
        .map(Into::into)
        .map_err(|e| format_err!("Internal Error {}", e))
    }

    pub fn decode_token(token: &Self) -> Result<Claim, Error> {
        decode::<Claim>(
            &token.0,
            &DecodingKey::from_secret(&JWT_SECRET.get()),
            &Validation::new(DEFAULT_ALGORITHM),
        )
        .map(|data| Ok(data.claims))
        .map_err(|e| format_err!("Unauthorized {}", e))?
    }
}
