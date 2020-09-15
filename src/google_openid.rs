use crate::errors::ServiceError as Error;
use base64::{encode_config, URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use log::debug;
use openid::{DiscoveredClient, Options, Userinfo};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use url::Url;

use crate::{app::CONFIG, logged_user::LoggedUser, pgpool::PgPool, token::Token, user::User};

lazy_static! {
    pub static ref CSRF_TOKENS: RwLock<HashMap<StackString, CrsfTokenCache>> =
        RwLock::new(HashMap::new());
}

#[derive(Clone)]
pub struct GoogleClient(Arc<RwLock<DiscoveredClient>>);

impl GoogleClient {
    pub async fn new() -> Result<Self, Error> {
        get_google_client()
            .await
            .map(|client| Self(Arc::new(RwLock::new(client))))
    }

    pub async fn get_auth_url(&self, payload: GetAuthUrlData) -> Result<Url, Error> {
        let final_url: Url = payload
            .final_url
            .parse()
            .map_err(|err| Error::BlockingError(format!("Failed to parse url {:?}", err)))?;

        let options = Options {
            scope: Some("email".into()),
            state: Some(get_random_string().into()),
            nonce: Some(get_random_string().into()),
            ..Options::default()
        };
        let authorize_url = self.0.read().await.auth_url(&options);
        let Options { state, nonce, .. } = options;
        let csrf_state = state.expect("No CSRF state").into();
        let nonce = nonce.expect("No nonce").into();

        CSRF_TOKENS.write().await.insert(
            csrf_state,
            CrsfTokenCache {
                nonce,
                final_url,
                timestamp: Utc::now(),
            },
        );
        Ok(authorize_url)
    }

    pub async fn run_callback(
        &self,
        callback_query: &CallbackQuery,
        pool: &PgPool,
    ) -> Result<Option<(Token, StackString)>, Error> {
        let CallbackQuery { code, state } = callback_query;
        let value = CSRF_TOKENS.write().await.remove(state);
        if let Some(CrsfTokenCache {
            nonce, final_url, ..
        }) = value
        {
            debug!("Nonce {:?}", nonce);

            let userinfo = match request_userinfo(&(*self.0.read().await), code, &nonce).await {
                Ok(userinfo) => userinfo,
                Err(e) => {
                    let new_client = get_google_client().await?;
                    *self.0.write().await = new_client;
                    return Err(e);
                }
            };

            if let Some(user_email) = &userinfo.email {
                if let Some(user) = User::get_by_email(user_email, &pool).await? {
                    let user: LoggedUser = user.into();

                    let token = Token::create_token(&user)?;
                    let body = format!(
                        "{}'{}'{}",
                        r#"<script>!function(){let url = "#,
                        final_url,
                        r#";location.replace(url);}();</script>"#
                    );
                    return Ok(Some((token, body.into())));
                }
            }
            Err(Error::BadRequest("Oauth failed".into()))
        } else {
            Err(Error::BadRequest("Csrf Token invalid".into()))
        }
    }
}

pub struct CrsfTokenCache {
    pub nonce: StackString,
    pub final_url: Url,
    pub timestamp: DateTime<Utc>,
}

fn get_random_string() -> StackString {
    let random_bytes: Vec<u8> = (0..16).map(|_| thread_rng().gen::<u8>()).collect();
    encode_config(&random_bytes, URL_SAFE_NO_PAD).into()
}

pub async fn cleanup_token_map() {
    let expired_keys: Vec<_> = CSRF_TOKENS
        .read()
        .await
        .iter()
        .filter_map(|(k, t)| {
            if (Utc::now() - t.timestamp).num_seconds() > 3600 {
                Some(k.clone())
            } else {
                None
            }
        })
        .collect();
    for key in expired_keys {
        CSRF_TOKENS.write().await.remove(&key);
    }
}

pub async fn get_google_client() -> Result<DiscoveredClient, Error> {
    let google_client_id = CONFIG.google_client_id.clone().into();
    let google_client_secret = CONFIG.google_client_secret.clone().into();
    let issuer_url = Url::parse("https://accounts.google.com").expect("Invalid issuer URL");
    let redirect_url = format!("https://{}/api/callback", CONFIG.domain);

    DiscoveredClient::discover(
        google_client_id,
        google_client_secret,
        Some(redirect_url),
        issuer_url,
    )
    .await
    .map_err(Into::into)
}

#[derive(Serialize, Deserialize)]
pub struct GetAuthUrlData {
    pub final_url: StackString,
}

#[derive(Serialize, Deserialize)]
pub struct CallbackQuery {
    pub code: StackString,
    pub state: StackString,
}

pub async fn request_userinfo(
    client: &DiscoveredClient,
    code: &str,
    nonce: &str,
) -> Result<Userinfo, Error> {
    let token = client.authenticate(code, Some(nonce), None).await?;
    let userinfo = client.request_userinfo(&token).await?;
    Ok(userinfo)
}

#[cfg(test)]
mod tests {
    use anyhow::Error;
    use std::path::Path;

    use crate::google_openid::{GetAuthUrlData, GoogleClient};

    #[tokio::test]
    #[ignore]
    async fn test_google_openid() -> Result<(), Error> {
        let config_dir = dirs::config_dir().expect("No CONFIG directory");
        let env_file = config_dir.join("rust_auth_server").join("config.env");

        if env_file.exists() {
            dotenv::from_path(&env_file).ok();
        } else if Path::new("config.env").exists() {
            dotenv::from_filename("config.env").ok();
        } else {
            dotenv::dotenv().ok();
        }

        let client = GoogleClient::new().await?;
        let payload = GetAuthUrlData {
            final_url: "https://localhost".into(),
        };
        let url = client.get_auth_url(payload).await?;

        assert_eq!(url.domain(), Some("accounts.google.com"));
        assert!(url
            .as_str()
            .contains("redirect_uri=https%3A%2F%2Fwww.ddboline.net%2Fapi%2Fcallback"));
        assert!(url.as_str().contains("scope=openid+email"));
        assert!(url.as_str().contains("response_type=code"));
        Ok(())
    }
}
