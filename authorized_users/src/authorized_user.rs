use anyhow::Error;
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use std::convert::TryFrom;
use uuid::Uuid;

use crate::token::Token;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Default)]
pub struct AuthorizedUser {
    pub email: StackString,
    pub session: Uuid,
    pub secret_key: StackString,
}

impl TryFrom<Token> for AuthorizedUser {
    type Error = Error;
    fn try_from(token: Token) -> Result<Self, Self::Error> {
        let claim = token.decode_token()?;
        Ok(claim.into())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Error;
    use std::convert::TryInto;
    use uuid::Uuid;

    use crate::{get_random_key, token::Token, AuthorizedUser, JWT_SECRET, KEY_LENGTH, SECRET_KEY};

    #[test]
    fn test_auth_user() -> Result<(), Error> {
        let mut secret_key = [0u8; KEY_LENGTH];
        secret_key.copy_from_slice(&get_random_key());

        SECRET_KEY.set(secret_key);
        JWT_SECRET.set(secret_key);

        let key = "0123456789abcdef";
        let session = Uuid::new_v4();
        let token = Token::create_token("test@example.com", "example.com", 3600, session, key)?;
        let user: AuthorizedUser = token.try_into()?;
        assert_eq!(user.session, session);
        Ok(())
    }
}
