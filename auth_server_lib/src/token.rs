use anyhow::{format_err, Error};
use derive_more::{From, Into};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

use authorized_users::{AuthorizedUser, JWT_SECRET};

use crate::{claim::Claim, config::Config};

const DEFAULT_ALGORITHM: Algorithm = Algorithm::HS256;

#[derive(From, Into)]
pub struct Token(String);

impl Token {
    pub fn create_token(data: &AuthorizedUser, config: &Config) -> Result<Self, Error> {
        let claims = Claim::with_email(data.email.as_str(), config);
        encode(
            &Header::new(DEFAULT_ALGORITHM),
            &claims,
            &EncodingKey::from_secret(&JWT_SECRET.get()),
        )
        .map(Into::into)
        .map_err(|_err| format_err!("Internal Error {}", _err))
    }

    pub fn decode_token(token: &Self) -> Result<Claim, Error> {
        decode::<Claim>(
            &token.0,
            &DecodingKey::from_secret(&JWT_SECRET.get()),
            &Validation::new(DEFAULT_ALGORITHM),
        )
        .map(|data| Ok(data.claims))
        .map_err(|_err| format_err!("Unauthorized {}", _err))?
    }
}
