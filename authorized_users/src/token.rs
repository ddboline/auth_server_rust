use biscuit::{
    ClaimsSet, Empty, JWE, JWT,
    jwa::{
        ContentEncryptionAlgorithm, EncryptionOptions, KeyManagementAlgorithm, SignatureAlgorithm,
    },
    jwe, jws,
};
use derive_more::{Display, From, Into};
use log::debug;
use stack_string::StackString;
use std::convert::TryInto;
use uuid::Uuid;

use crate::{
    JWT_SECRET, SECRET_KEY,
    claim::{Claim, PrivateClaim},
    errors::{AuthUsersError as Error, TokenError},
    get_random_nonce,
};

const SG_ALGORITHM: SignatureAlgorithm = SignatureAlgorithm::HS256;
const KM_ALGORITHM: KeyManagementAlgorithm = KeyManagementAlgorithm::A256GCMKW;
const CE_ALGORITHM: ContentEncryptionAlgorithm = ContentEncryptionAlgorithm::A256GCM;

#[derive(From, Into, Display)]
pub struct Token(StackString);

impl Token {
    /// # Errors
    /// Returns error if encoding jwt or encrypting jwe fails
    #[allow(clippy::similar_names)]
    pub fn create_token(
        email: impl Into<StackString>,
        domain: impl Into<StackString>,
        expiration_seconds: u32,
        session: Uuid,
        secret_key: impl Into<StackString>,
    ) -> Result<Self, Error> {
        let claims = Claim::with_email(email, domain, expiration_seconds, session, secret_key);
        let claimset = ClaimsSet {
            registered: claims.get_registered_claims(),
            private: claims.get_private_claims(),
        };
        let header = jws::RegisteredHeader {
            algorithm: SG_ALGORITHM,
            ..jws::RegisteredHeader::default()
        };
        let jwt = JWT::new_decoded(header.into(), claimset);
        debug!("jwt {:?}", jwt);

        let jws = jwt.into_encoded(&JWT_SECRET.get_jws_secret())?;
        debug!("jws {:?}", jws);

        let jwe_header = jwe::RegisteredHeader {
            cek_algorithm: KM_ALGORITHM,
            enc_algorithm: CE_ALGORITHM,
            media_type: Some("JOSE".to_string()),
            content_type: Some("JOSE".to_string()),
            ..jwe::RegisteredHeader::default()
        };
        let jwe = JWE::new_decrypted(jwe_header.into(), jws);
        debug!("jwe {:?}", jwe);

        let options = EncryptionOptions::AES_GCM {
            nonce: get_random_nonce().into(),
        };
        let encrypted_jwe = jwe.encrypt(&SECRET_KEY.get_jwk_secret(), &options)?;

        Ok(Token(encrypted_jwe.unwrap_encrypted().to_string().into()))
    }

    /// # Errors
    /// Returns error if decrypting jwe or decoding jwt fails
    #[allow(clippy::similar_names)]
    pub fn decode_token(&self) -> Result<Claim, Error> {
        let token: JWE<PrivateClaim, Empty, Empty> = JWE::new_encrypted(&self.0);

        if let jwe::Compact::Decrypted { payload, .. } =
            token.into_decrypted(&SECRET_KEY.get_jwk_secret(), KM_ALGORITHM, CE_ALGORITHM)?
        {
            if let jws::Compact::Decoded { payload, .. } =
                payload.into_decoded(&JWT_SECRET.get_jws_secret(), SG_ALGORITHM)?
            {
                return payload.try_into();
            }
        }
        Err(TokenError::DecodeFailure.into())
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use log::debug;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::{
        AuthorizedUser, JWT_SECRET, KEY_LENGTH, SECRET_KEY, errors::AuthUsersError as Error,
        get_random_key, token::Token,
    };

    #[test]
    fn test_token() -> Result<(), Error> {
        let mut secret_key = [0u8; KEY_LENGTH];
        secret_key.copy_from_slice(&get_random_key());

        SECRET_KEY.set(secret_key);
        JWT_SECRET.set(secret_key);

        let session = Uuid::new_v4();
        let secret = URL_SAFE_NO_PAD.encode(&secret_key);

        let user = AuthorizedUser {
            email: "test@local".into(),
            session,
            secret_key: secret.into(),
            created_at: OffsetDateTime::now_utc(),
        };

        let token = Token::create_token(
            user.email.clone(),
            "localhost",
            3600,
            session,
            user.secret_key.clone(),
        )?;

        debug!("token {}", token);

        let claim = token.decode_token()?;

        let obs_user: AuthorizedUser = claim.into();

        debug!("{}", obs_user.email);

        assert_eq!(user, obs_user);
        Ok(())
    }
}
