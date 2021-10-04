use anyhow::{format_err, Context, Error};
use derive_more::Deref;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use url::Url;

use stack_string::StackString;

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigInner {
    #[serde(default = "default_database_url")]
    pub database_url: StackString,
    #[serde(default = "default_sending_email_address")]
    pub sending_email_address: StackString,
    #[serde(default = "default_callback")]
    pub callback_url: Url,
    #[serde(default = "default_domain")]
    pub domain: StackString,
    #[serde(default = "default_port")]
    pub port: u32,
    #[serde(default = "default_expiration_seconds")]
    pub expiration_seconds: i64,
    #[serde(default = "default_key")]
    pub google_client_id: StackString,
    #[serde(default = "default_key")]
    pub google_client_secret: StackString,
    #[serde(default = "default_secret_path")]
    pub secret_path: PathBuf,
    #[serde(default = "default_secret_path")]
    pub jwt_secret_path: PathBuf,
    #[serde(default = "default_auth_user_config_path")]
    pub auth_user_config_path: PathBuf,
    #[serde(default = "default_secure")]
    pub secure: bool,
}

fn default_secure() -> bool {
    true
}
fn default_database_url() -> StackString {
    "postgresql://user:password@host:1234/test_db".into()
}
fn default_sending_email_address() -> StackString {
    "test@localhost".into()
}
fn default_domain() -> StackString {
    "localhost".into()
}
fn default_port() -> u32 {
    3000
}
fn default_callback() -> Url {
    "http://localhost:3000/register.html"
        .parse()
        .expect("Failed to parse")
}
fn default_expiration_seconds() -> i64 {
    24 * 3600
}
fn default_key() -> StackString {
    "0123".repeat(8).into()
}
fn default_secret_path() -> PathBuf {
    dirs::config_dir()
        .unwrap()
        .join("auth_server_rust")
        .join("secret.bin")
}
fn default_auth_user_config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap()
        .join("auth_server_rust")
        .join("auth_user_config.toml")
}

#[derive(Debug, Clone, Deref)]
pub struct Config(Arc<ConfigInner>);

impl Config {
    pub fn from_inner(inner: ConfigInner) -> Self {
        Self(Arc::new(inner))
    }

    pub fn init_config() -> Result<Self, Error> {
        let fname = Path::new("config.env");
        let config_dir = dirs::config_dir().ok_or_else(|| format_err!("No CONFIG directory"))?;
        let default_fname = config_dir.join("auth_server_rust").join("config.env");

        let env_file = if fname.exists() {
            fname
        } else {
            &default_fname
        };

        dotenv::dotenv().ok();

        if env_file.exists() {
            dotenv::from_path(env_file).ok();
        }

        let conf: ConfigInner = envy::from_env().context("Envy parsing failed")?;

        Ok(Self::from_inner(conf))
    }
}
