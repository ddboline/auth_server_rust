use anyhow::{format_err, Error};
use base64::{encode_config, URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use crossbeam::atomic::AtomicCell;
use log::{debug, error};
pub use openid::error::{Error as OpenidError, ClientError};
use openid::{DiscoveredClient, Options, Userinfo};
use rand::{thread_rng, Rng};
use stack_string::StackString;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, Notify},
    time::sleep,
};
use url::Url;

use authorized_users::AuthorizedUser;

use auth_server_lib::{config::Config, pgpool::PgPool, user::User};

#[derive(Clone, Copy, Debug, PartialEq)]
enum TokenState {
    New,
    Authorized,
    Expired,
}

#[derive(Clone)]
pub struct CsrfTokenCache {
    nonce: StackString,
    timestamp: DateTime<Utc>,
    notify: Arc<Notify>,
    is_ready: Arc<AtomicCell<TokenState>>,
}

impl CsrfTokenCache {
    fn new(nonce: &str) -> Self {
        let notify = Arc::new(Notify::new());
        let is_ready = Arc::new(AtomicCell::new(TokenState::New));
        Self {
            nonce: nonce.into(),
            timestamp: Utc::now(),
            notify,
            is_ready,
        }
    }
}

#[derive(Clone)]
pub struct GoogleClient {
    client: Arc<DiscoveredClient>,
    csrf_tokens: Arc<Mutex<HashMap<StackString, CsrfTokenCache>>>,
}

impl GoogleClient {
    pub async fn new(config: &Config) -> Result<Self, Error> {
        let csrf_tokens = Arc::new(Mutex::new(HashMap::new()));
        loop {
            match get_google_client(config).await {
                Ok(client) => {
                    return Ok(Self {
                        client: Arc::new(client),
                        csrf_tokens,
                    });
                }
                Err(OpenidError::ClientError(ClientError::Reqwest(e))) => {
                    debug!("Reqwest error {}", e);
                    sleep(Duration::from_secs(1)).await;
                }
                Err(e) => {
                    error!("Encountered error {:?}, sleep and try again", e);
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    pub async fn get_auth_url(&self) -> Result<(StackString, Url), Error> {
        let options = Options {
            scope: Some("email".into()),
            state: Some(get_random_string().into()),
            nonce: Some(get_random_string().into()),
            ..Options::default()
        };
        let authorize_url = self.client.auth_url(&options);
        let Options { state, nonce, .. } = options;
        let csrf_state: StackString = state.expect("No CSRF state").into();
        let nonce = nonce.expect("No nonce");

        self.csrf_tokens
            .lock()
            .await
            .insert(csrf_state.clone(), CsrfTokenCache::new(&nonce));
        Ok((csrf_state, authorize_url))
    }

    pub async fn wait_csrf(&self, csrf_state: &str) -> Result<(), Error> {
        let (notify, is_ready) = if let Some(state) = self.csrf_tokens.lock().await.get(csrf_state)
        {
            (state.notify.clone(), state.is_ready.clone())
        } else {
            return Ok(());
        };
        if is_ready.load() != TokenState::New {
            return Ok(());
        }
        notify.notified().await;
        Ok(())
    }

    pub async fn run_callback(
        &self,
        code: &str,
        state: &str,
        pool: &PgPool,
    ) -> Result<Option<AuthorizedUser>, Error> {
        let CsrfTokenCache {
            nonce,
            timestamp,
            notify,
            is_ready,
        } = self
            .csrf_tokens
            .lock()
            .await
            .remove(state)
            .ok_or_else(|| format_err!("CSRF Token Invalid"))?;
        if (Utc::now() - timestamp).num_seconds() > 3600 {
            is_ready.store(TokenState::Expired);
            notify.notify_waiters();
            return Err(format_err!("Token expired"));
        }
        debug!("Nonce {:?}", nonce);
        let userinfo = self.request_userinfo(code, &nonce).await?;
        let user_email = &userinfo.email.ok_or_else(|| format_err!("No userinfo"))?;
        let user = User::get_by_email(user_email, &pool)
            .await?
            .ok_or_else(|| format_err!("No User"))?;
        let user: AuthorizedUser = user.into();
        is_ready.store(TokenState::Authorized);
        notify.notify_waiters();
        Ok(Some(user))
    }

    pub async fn request_userinfo(&self, code: &str, nonce: &str) -> Result<Userinfo, Error> {
        let token = self
            .client
            .authenticate(code, Some(nonce), None)
            .await
            .map_err(|e| format_err!("Openid Error {:?}", e))?;
        let userinfo = self
            .client
            .request_userinfo(&token)
            .await
            .map_err(|e| format_err!("Openid Error {:?}", e))?;
        Ok(userinfo)
    }

    pub async fn cleanup_token_map(&self) {
        let expired_keys: Vec<_> = self
            .csrf_tokens
            .lock()
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
            self.csrf_tokens.lock().await.remove(&key);
        }
    }
}

fn get_random_string() -> StackString {
    let mut rng = thread_rng();
    let mut random_bytes = [0u8; 16];
    rng.fill(&mut random_bytes);
    encode_config(&random_bytes, URL_SAFE_NO_PAD).into()
}

pub async fn get_google_client(config: &Config) -> Result<DiscoveredClient, OpenidError> {
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
}

#[cfg(test)]
mod tests {
    use anyhow::Error;

    use auth_server_lib::{config::Config, AUTH_APP_MUTEX};

    use crate::google_openid::GoogleClient;

    #[tokio::test]
    async fn test_google_openid() -> Result<(), Error> {
        let _lock = AUTH_APP_MUTEX.lock().await;
        let config = Config::init_config()?;

        let client = GoogleClient::new(&config).await?;
        let (_, url) = client.get_auth_url().await?;
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
