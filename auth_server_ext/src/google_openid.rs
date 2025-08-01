use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use crossbeam::atomic::AtomicCell;
use log::{debug, error};
pub use openid::error::{ClientError, Error as OpenidError};
use openid::{DiscoveredClient, Options, Userinfo};
use rand::{
    distr::{Distribution, StandardUniform},
    rng as thread_rng,
};
use stack_string::StackString;
use std::{collections::HashMap, str, sync::Arc, time::Duration};
use time::OffsetDateTime;
use tokio::{
    sync::{Mutex, Notify},
    time::sleep,
};
use url::Url;

use authorized_users::AuthorizedUser;

use auth_server_lib::{config::Config, pgpool::PgPool, user::User};

use crate::errors::AuthServerExtError as Error;

#[derive(Clone, Copy, Debug, PartialEq)]
enum TokenState {
    New,
    Authorized,
    Expired,
}

#[derive(Clone)]
pub struct CsrfTokenCache {
    nonce: StackString,
    timestamp: OffsetDateTime,
    notify: Arc<Notify>,
    is_ready: Arc<AtomicCell<TokenState>>,
}

impl CsrfTokenCache {
    fn new(nonce: impl Into<StackString>) -> Self {
        let notify = Arc::new(Notify::new());
        let is_ready = Arc::new(AtomicCell::new(TokenState::New));
        Self {
            nonce: nonce.into(),
            timestamp: OffsetDateTime::now_utc(),
            notify,
            is_ready,
        }
    }
}

#[derive(Clone)]
pub struct GoogleClient {
    client: Arc<DiscoveredClient>,
    csrf_tokens: Arc<Mutex<HashMap<StackString, CsrfTokenCache>>>,
    mock_email: Option<StackString>,
}

impl GoogleClient {
    /// # Errors
    /// Return error if openid client intialization fails
    pub async fn new(config: &Config) -> Result<Self, Error> {
        let csrf_tokens = Arc::new(Mutex::new(HashMap::new()));
        let mut delay = 1;
        loop {
            match get_google_client(config).await {
                Ok(client) => {
                    return Ok(Self {
                        client: Arc::new(client),
                        csrf_tokens,
                        mock_email: None,
                    });
                }
                Err(OpenidError::ClientError(ClientError::Reqwest(e))) => {
                    debug!("Reqwest error {e}",);
                    sleep(Duration::from_secs(1)).await;
                }
                Err(e) => {
                    if delay > 256 {
                        return Err(e.into());
                    }
                    error!("Encountered error {e:?}, sleep and try again",);
                    sleep(Duration::from_secs(delay)).await;
                    delay *= 2;
                }
            }
        }
    }

    /// # Errors
    /// Returns error if missing CSRF state or Nonce
    pub async fn get_auth_url_csrf(
        &self,
        state: Option<&str>,
    ) -> Result<(Url, StackString), Error> {
        let state: String = state
            .map_or_else(get_token_string, |s| self.encode(s))
            .into();
        let options = Options {
            scope: Some("email".into()),
            state: Some(state.clone()),
            nonce: Some(get_token_string().into()),
            ..Options::default()
        };
        let authorize_url = self.client.auth_url(&options);
        let Options { state, nonce, .. } = options;
        let csrf_state: StackString = state.ok_or(Error::MissingCSRFState)?.into();
        let nonce = nonce.ok_or(Error::MissingNonce)?;

        self.csrf_tokens
            .lock()
            .await
            .insert(csrf_state.clone(), CsrfTokenCache::new(nonce));
        Ok((authorize_url, csrf_state))
    }

    #[must_use]
    pub fn encode(&self, input: &str) -> StackString {
        URL_SAFE_NO_PAD.encode(input).into()
    }

    #[must_use]
    pub fn decode(&self, input: &str) -> Option<StackString> {
        let buf = URL_SAFE_NO_PAD.decode(input).ok()?;
        StackString::from_utf8(&buf).ok()
    }

    pub async fn wait_csrf(&self, csrf_state: impl AsRef<str>) {
        let (notify, is_ready) =
            if let Some(state) = self.csrf_tokens.lock().await.get(csrf_state.as_ref()) {
                (state.notify.clone(), state.is_ready.clone())
            } else {
                return;
            };
        if is_ready.load() != TokenState::New {
            return;
        }
        notify.notified().await;
    }

    /// # Errors
    /// Returns error if
    ///     * CSRF token is invalid
    ///     * Userinfo request fails or is empty
    ///     * User in userinfo doesn't exist
    pub async fn run_callback(
        &self,
        code: impl AsRef<str>,
        state: impl AsRef<str>,
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
            .remove(state.as_ref())
            .ok_or_else(|| Error::InvalidCsrfToken)?;
        if (OffsetDateTime::now_utc() - timestamp).whole_seconds() > 3600 {
            is_ready.store(TokenState::Expired);
            notify.notify_waiters();
            return Err(Error::ExpiredToken);
        }
        debug!("Nonce {nonce:?}",);
        let user = if let Some(mock_email) = &self.mock_email {
            Self::mock_user(mock_email.as_str())
        } else {
            let userinfo = self.request_userinfo(code, &nonce).await?;
            let user_email = &userinfo.email.ok_or_else(|| Error::MissingUserInfo)?;
            User::get_by_email(user_email, pool)
                .await?
                .ok_or_else(|| Error::MissingUser)?
                .into()
        };
        is_ready.store(TokenState::Authorized);
        notify.notify_waiters();
        Ok(Some(user))
    }

    async fn request_userinfo(
        &self,
        code: impl AsRef<str>,
        nonce: impl AsRef<str>,
    ) -> Result<Userinfo, Error> {
        let token = self
            .client
            .authenticate(code.as_ref(), Some(nonce.as_ref()), None)
            .await?;
        self.client
            .request_userinfo(&token)
            .await
            .map_err(Into::into)
    }

    fn mock_user(mock_email: &str) -> AuthorizedUser {
        AuthorizedUser::default().with_email(mock_email)
    }

    pub async fn cleanup_token_map(&self) {
        for key in self.csrf_tokens.lock().await.iter().filter_map(|(k, t)| {
            if (OffsetDateTime::now_utc() - t.timestamp).whole_seconds() > 3600 {
                Some(k.clone())
            } else {
                None
            }
        }) {
            self.csrf_tokens.lock().await.remove(&key);
        }
    }
}

fn get_token_string() -> StackString {
    let mut rng = thread_rng();
    let random_bytes: [u8; 16] = StandardUniform.sample(&mut rng);
    let mut buf = [0u8; 22];
    let encoded_size = URL_SAFE_NO_PAD
        .encode_slice(random_bytes, &mut buf)
        .expect("Buffer too small");
    debug_assert!(encoded_size == 22);
    let buf = str::from_utf8(&buf).expect("Invalid buffer");
    let mut output = StackString::new();
    output.push_str(buf);
    output
}

async fn get_google_client(config: &Config) -> Result<DiscoveredClient, OpenidError> {
    let google_client_id = config.google_client_id.clone().into();
    let google_client_secret: String = config.google_client_secret.clone().into();
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
    use stack_string::format_sstr;
    use std::time::SystemTime;
    use tokio::{
        task::{JoinHandle, spawn},
        time::{Duration, sleep},
    };

    use auth_server_lib::{AUTH_APP_MUTEX, config::Config, pgpool::PgPool};

    use crate::{
        errors::AuthServerExtError as Error,
        google_openid::{GoogleClient, get_token_string},
    };

    #[tokio::test]
    async fn test_google_openid() -> Result<(), Error> {
        let _lock = AUTH_APP_MUTEX.lock().await;
        let config = Config::init_config()?;
        let pool = PgPool::new(&config.database_url)?;

        let mut client = GoogleClient::new(&config).await?;
        client.mock_email = Some("test+openid@example.com".into());
        let (url, state) = client.get_auth_url_csrf(Some("test-redirect-url")).await?;
        let redirect_uri = format_sstr!(
            "redirect_uri=https%3A%2F%2F{}%2Fapi%2Fcallback",
            config.domain
        );

        assert_eq!(url.domain(), Some("accounts.google.com"));
        assert!(url.as_str().contains(redirect_uri.as_str()));
        assert!(url.as_str().contains("scope=openid+email"));
        assert!(url.as_str().contains("response_type=code"));

        let task: JoinHandle<Result<_, Error>> = spawn({
            let state = state.clone();
            let client = client.clone();
            let time = SystemTime::now();
            async move {
                client.wait_csrf(&state).await;
                let elapsed = time.elapsed()?;
                Ok(elapsed.as_secs_f64())
            }
        });

        sleep(Duration::from_secs(2)).await;
        let result = client
            .run_callback("mock_code", state.as_str(), &pool)
            .await?;
        let url = client.decode(&state).unwrap();
        assert_eq!(&url, "test-redirect-url");
        assert!(result.is_some());
        assert_eq!(result.unwrap().get_email(), "test+openid@example.com");

        let x = task.await??;
        assert!(x > 2.0);
        Ok(())
    }

    #[test]
    fn test_get_token_string() -> Result<(), Error> {
        let s = get_token_string();
        assert_eq!(s.len(), 22);
        Ok(())
    }
}
