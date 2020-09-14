use anyhow::{format_err, Error};
use std::{env::var, ops::Deref, path::Path, sync::Arc};

use crate::stack_string::StackString;

#[derive(Default, Debug)]
pub struct ConfigInner {
    pub database_url: StackString,
    pub sending_email_address: StackString,
    pub secret_key: StackString,
    pub domain: StackString,
}

macro_rules! set_config_must {
    ($s:ident, $id:ident) => {
        $s.$id = var(&stringify!($id).to_uppercase())
            .map(Into::into)
            .map_err(|e| format_err!("{} must be set: {}", stringify!($id).to_uppercase(), e))?;
    };
}

macro_rules! set_config_default {
    ($s:ident, $id:ident, $d:expr) => {
        $s.$id = var(&stringify!($id).to_uppercase()).map_or_else(|_| $d, Into::into);
    };
}

#[derive(Default, Debug, Clone)]
pub struct Config(Arc<ConfigInner>);

impl Deref for Config {
    type Target = ConfigInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_inner(inner: ConfigInner) -> Self {
        Self(Arc::new(inner))
    }

    pub fn init_config() -> Result<Self, Error> {
        let fname = Path::new("config.env");
        let config_dir = dirs::config_dir().ok_or_else(|| format_err!("No CONFIG directory"))?;
        let default_fname = config_dir.join("aws_app_rust").join("config.env");

        let env_file = if fname.exists() {
            fname
        } else {
            &default_fname
        };

        dotenv::dotenv().ok();

        if env_file.exists() {
            dotenv::from_path(env_file).ok();
        }

        let mut conf = ConfigInner::default();

        set_config_must!(conf, database_url);
        set_config_must!(conf, sending_email_address);
        set_config_must!(conf, secret_key);
        set_config_default!(conf, domain, "localhost".into());

        Ok(Self(Arc::new(conf)))
    }
}
