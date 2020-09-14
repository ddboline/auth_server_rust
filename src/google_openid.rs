use crate::errors::ServiceError;
use base64::{encode_config, URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use openid::{DiscoveredClient, Options, Userinfo};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env::var, sync::Arc};
use tokio::sync::RwLock;
use url::Url;

lazy_static! {
    pub static ref CSRF_TOKENS: RwLock<HashMap<String, CrsfTokenCache>> =
        RwLock::new(HashMap::new());
}

pub type GoogleClient = RwLock<Arc<DiscoveredClient>>;

pub struct CrsfTokenCache {
    pub nonce: String,
    pub final_url: Url,
    pub timestamp: DateTime<Utc>,
}

fn get_random_string() -> String {
    let random_bytes: Vec<u8> = (0..16).map(|_| thread_rng().gen::<u8>()).collect();
    encode_config(&random_bytes, URL_SAFE_NO_PAD)
}

pub async fn cleanup_token_map() {
    let expired_keys: Vec<_> = CSRF_TOKENS
        .read()
        .await
        .iter()
        .filter_map(|(k, t)| {
            if (Utc::now() - t.timestamp).num_seconds() > 3600 {
                Some(k.to_string())
            } else {
                None
            }
        })
        .collect();
    for key in expired_keys {
        CSRF_TOKENS.write().await.remove(&key);
    }
}

pub async fn get_google_client() -> Result<DiscoveredClient, ServiceError> {
    let google_client_id =
        var("GOOGLE_CLIENT_ID").expect("Missing the GOOGLE_CLIENT_ID environment variable.");
    let google_client_secret = var("GOOGLE_CLIENT_SECRET")
        .expect("Missing the GOOGLE_CLIENT_SECRET environment variable.");
    let issuer_url = Url::parse("https://accounts.google.com").expect("Invalid issuer URL");

    let domain = var("DOMAIN").unwrap_or_else(|_| "localhost".to_string());
    let redirect_url = format!("https://{}/api/callback", domain);

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
    pub final_url: String,
}

pub fn get_auth_url(client: &DiscoveredClient) -> (Url, Options) {
    let options = Options {
        scope: Some("email".into()),
        state: Some(get_random_string()),
        nonce: Some(get_random_string()),
        ..Options::default()
    };
    let url = client.auth_url(&options);
    (url, options)
}

#[derive(Serialize, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

pub async fn request_userinfo(
    client: &DiscoveredClient,
    code: &str,
    nonce: &str,
) -> Result<Userinfo, ServiceError> {
    let token = client.authenticate(code, Some(nonce), None).await?;
    let userinfo = client.request_userinfo(&token).await?;
    Ok(userinfo)
}

#[cfg(test)]
mod tests {
    use anyhow::Error;
    use std::path::Path;

    use crate::google_openid::{get_auth_url, get_google_client};

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

        let client = get_google_client().await?;
        let (url, _) = get_auth_url(&client);
        assert_eq!(url.domain(), Some("accounts.google.com"));
        assert!(url
            .as_str()
            .contains("redirect_uri=https%3A%2F%2Fwww.ddboline.net%2Fapi%2Fcallback"));
        assert!(url.as_str().contains("scope=openid+email"));
        assert!(url.as_str().contains("response_type=code"));
        Ok(())
    }
}
