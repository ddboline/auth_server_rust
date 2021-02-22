use anyhow::{format_err, Error};
use arc_swap::ArcSwap;
use base64::{encode_config, URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use im::HashMap;
use lazy_static::lazy_static;
use log::debug;
pub use openid::error::Error as OpenidError;
use openid::{DiscoveredClient, Options, Userinfo};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use std::sync::Arc;
use url::Url;

use authorized_users::AuthorizedUser;

use auth_server_lib::{config::Config, pgpool::PgPool, user::User};

lazy_static! {
    pub static ref CSRF_TOKENS: ArcSwap<HashMap<StackString, CrsfTokenCache>> =
        ArcSwap::new(Arc::new(HashMap::new()));
}

#[derive(Clone)]
pub struct CrsfTokenCache {
    pub nonce: StackString,
    pub final_url: Url,
    pub timestamp: DateTime<Utc>,
}

impl CrsfTokenCache {
    fn new(nonce: &str, final_url: Url) -> Self {
        Self {
            nonce: nonce.into(),
            final_url,
            timestamp: Utc::now(),
        }
    }
}

#[derive(Clone)]
pub struct GoogleClient(Arc<DiscoveredClient>);

impl GoogleClient {
    pub async fn new(config: &Config) -> Result<Self, Error> {
        get_google_client(config)
            .await
            .map(|client| Self(Arc::new(client)))
    }

    pub async fn get_auth_url(&self, payload: GetAuthUrlData) -> Result<Url, Error> {
        let final_url: Url = payload
            .final_url
            .parse()
            .map_err(|err| format_err!("Failed to parse url {:?}", err))?;

        let options = Options {
            scope: Some("email".into()),
            state: Some(get_random_string().into()),
            nonce: Some(get_random_string().into()),
            ..Options::default()
        };
        let authorize_url = self.0.auth_url(&options);
        let Options { state, nonce, .. } = options;
        let csrf_state = state.expect("No CSRF state").into();
        let nonce = nonce.expect("No nonce");

        CSRF_TOKENS.store(Arc::new(
            CSRF_TOKENS
                .load()
                .update(csrf_state, CrsfTokenCache::new(&nonce, final_url)),
        ));
        Ok(authorize_url)
    }

    pub async fn run_callback(
        &self,
        callback_query: &CallbackQuery,
        pool: &PgPool,
    ) -> Result<Option<(AuthorizedUser, String)>, Error> {
        let CallbackQuery { code, state } = callback_query;

        if let Some((
            CrsfTokenCache {
                nonce, final_url, ..
            },
            tokens,
        )) = CSRF_TOKENS.load().extract(state)
        {
            CSRF_TOKENS.store(Arc::new(tokens));
            debug!("Nonce {:?}", nonce);

            let userinfo = self.request_userinfo(code, &nonce).await?;

            if let Some(user_email) = &userinfo.email {
                if let Some(user) = User::get_by_email(user_email, &pool).await? {
                    let user: AuthorizedUser = user.into();

                    let body = format!(
                        "{}'{}'{}",
                        r#"<script>!function(){let url = "#,
                        final_url,
                        r#";location.replace(url);}();</script>"#
                    );
                    return Ok(Some((user, body)));
                }
            }
            Err(format_err!("Oauth failed"))
        } else {
            Err(format_err!("Csrf Token invalid"))
        }
    }

    pub async fn request_userinfo(&self, code: &str, nonce: &str) -> Result<Userinfo, Error> {
        let token = self
            .0
            .authenticate(code, Some(nonce), None)
            .await
            .map_err(|e| format_err!("Openid Error {:?}", e))?;
        let userinfo = self
            .0
            .request_userinfo(&token)
            .await
            .map_err(|e| format_err!("Openid Error {:?}", e))?;
        Ok(userinfo)
    }
}

fn get_random_string() -> StackString {
    let mut rng = thread_rng();
    let mut random_bytes = [0u8; 16];
    rng.fill(&mut random_bytes);
    encode_config(&random_bytes, URL_SAFE_NO_PAD).into()
}

pub async fn cleanup_token_map() {
    let mut tokens = (*CSRF_TOKENS.load().clone()).clone();
    let expired_keys: Vec<_> = tokens
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
        tokens.remove(&key);
    }
    CSRF_TOKENS.store(Arc::new(tokens));
}

pub async fn get_google_client(config: &Config) -> Result<DiscoveredClient, Error> {
    let google_client_id = config.google_client_id.clone().into();
    let google_client_secret = config.google_client_secret.clone().into();
    let issuer_url = Url::parse("https://accounts.google.com").expect("Invalid issuer URL");
    let redirect_url = format!("https://{}/api/callback", config.domain);

    DiscoveredClient::discover(
        google_client_id,
        google_client_secret,
        Some(redirect_url),
        issuer_url,
    )
    .await
    .map_err(|e| format_err!("Openid Error {:?}", e))
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

#[cfg(test)]
mod tests {
    use anyhow::Error;

    use auth_server_lib::config::Config;

    use crate::google_openid::{GetAuthUrlData, GoogleClient};

    #[tokio::test]
    async fn test_google_openid() -> Result<(), Error> {
        let config = Config::init_config()?;

        let client = GoogleClient::new(&config).await?;
        let payload = GetAuthUrlData {
            final_url: "https://localhost".into(),
        };
        let url = client.get_auth_url(payload).await?;
        let redirect_uri = format!(
            "redirect_uri=https%3A%2F%2F{}%2Fapi%2Fcallback",
            config.domain
        );

        assert_eq!(url.domain(), Some("accounts.google.com"));
        assert!(url.as_str().contains(&redirect_uri));
        assert!(url.as_str().contains("scope=openid+email"));
        assert!(url.as_str().contains("response_type=code"));
        Ok(())
    }
}
