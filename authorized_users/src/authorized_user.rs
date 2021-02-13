use anyhow::Error;
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use std::convert::TryFrom;

use crate::token::Token;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct AuthorizedUser {
    pub email: StackString,
}

impl TryFrom<Token> for AuthorizedUser {
    type Error = Error;
    fn try_from(token: Token) -> Result<Self, Self::Error> {
        let claim = token.decode_token()?;
        Ok(claim.into())
    }
}
