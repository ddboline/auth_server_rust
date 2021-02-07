use anyhow::Error;
use biscuit::{
    jwa::{
        ContentEncryptionAlgorithm, EncryptionOptions, KeyManagementAlgorithm, SignatureAlgorithm,
    },
    jwe,
    jwk::JWK,
    jws,
    jws::Secret,
    ClaimsSet, Empty, JWE, JWT,
};
use derive_more::{Display, From, Into};
use log::debug;

use crate::{claim::Claim, get_random_nonce, AuthorizedUser, JWT_SECRET, SECRET_KEY};

const SG_ALGORITHM: SignatureAlgorithm = SignatureAlgorithm::HS256;
const KM_ALGORITHM: KeyManagementAlgorithm = KeyManagementAlgorithm::A256GCMKW;
const CE_ALGORITHM: ContentEncryptionAlgorithm = ContentEncryptionAlgorithm::A256GCM;

#[derive(From, Into, Display)]
pub struct Token(String);

impl Token {
    pub fn create_token(
        data: &AuthorizedUser,
        domain: &str,
        expiration_seconds: i64,
    ) -> Result<Self, Error> {
        let claims = Claim::with_email(data.email.as_str(), domain, expiration_seconds);
        let claimset = ClaimsSet {
            registered: claims.clone().into(),
            private: claims,
        };
        let header = jws::RegisteredHeader {
            algorithm: SG_ALGORITHM,
            ..jws::RegisteredHeader::default()
        };
        let jwt = JWT::new_decoded(header.into(), claimset);
        debug!("jwt {:?}", jwt);
        let jws_secret = Secret::Bytes(JWT_SECRET.get().into());
        let jwe_secret = JWK::new_octet_key(&SECRET_KEY.get(), Empty::default());

        let jws = jwt.into_encoded(&jws_secret)?;
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
            nonce: get_random_nonce(),
        };
        let encrypted_jwe = jwe.encrypt(&jwe_secret, &options)?;

        Ok(Token(encrypted_jwe.unwrap_encrypted().to_string()))
    }

    pub fn decode_token(&self) -> Result<Claim, Error> {
        let jws_secret = Secret::Bytes(JWT_SECRET.get().into());
        let jwe_secret = JWK::new_octet_key(&SECRET_KEY.get(), Empty::default());

        let token: JWE<Claim, Empty, Empty> = JWE::new_encrypted(&self.0);

        let decrypted_jwe = token.into_decrypted(&jwe_secret, KM_ALGORITHM, CE_ALGORITHM)?;
        let decrypted_jws = decrypted_jwe.payload()?.clone();
        let token = decrypted_jws.into_decoded(&jws_secret, SG_ALGORITHM)?;
        Ok(token.payload()?.private.clone())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Error;
    use log::debug;

    use crate::{get_random_key, token::Token, AuthorizedUser, JWT_SECRET, KEY_LENGTH, SECRET_KEY};

    #[test]
    fn test_token() -> Result<(), Error> {
        let mut secret_key = [0u8; KEY_LENGTH];
        secret_key.copy_from_slice(&get_random_key());

        SECRET_KEY.set(secret_key);
        JWT_SECRET.set(secret_key);

        let user = AuthorizedUser {
            email: "test@local".into(),
        };

        let token = Token::create_token(&user, "localhost", 3600)?;

        debug!("token {}", token);

        let claim = token.decode_token()?;

        let obs_user: AuthorizedUser = claim.into();

        debug!("{}", obs_user.email);

        assert_eq!(user, obs_user);
        Ok(())
    }
}
