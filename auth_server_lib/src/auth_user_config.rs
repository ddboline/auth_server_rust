use derive_more::{Deref, IntoIterator};
use stack_string::StackString;
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    fmt::Debug,
    fs,
    path::Path,
    str::FromStr,
};

use crate::{
    errors::AuthServerError as Error,
    toml_entry::{Entry, TomlEntry},
};

type ConfigToml = HashMap<String, TomlEntry>;

#[derive(Debug, Deref, IntoIterator)]
pub struct AuthUserConfig(HashMap<StackString, Entry>);

impl AuthUserConfig {
    /// # Errors
    /// Returns an error if reading or parsing toml file fails
    pub fn new(p: impl AsRef<Path>) -> Result<Self, Error> {
        let p = p.as_ref();
        Self::from_path(p)
    }

    fn from_path(p: impl AsRef<Path>) -> Result<Self, Error> {
        let p = p.as_ref();
        let data = fs::read_to_string(p)?;
        let config: ConfigToml = toml::from_str(&data)?;
        config.try_into()
    }
}

impl FromStr for AuthUserConfig {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let config: ConfigToml = toml::from_str(s)?;
        config.try_into()
    }
}

impl TryFrom<ConfigToml> for AuthUserConfig {
    type Error = Error;
    fn try_from(item: ConfigToml) -> Result<Self, Self::Error> {
        let result: Result<HashMap<_, _>, Error> = item
            .into_iter()
            .map(|(key, entry)| {
                let entry: Entry = entry.try_into()?;
                Ok((key.into(), entry))
            })
            .collect();
        result.map(AuthUserConfig)
    }
}

#[cfg(test)]
mod tests {
    use log::debug;
    use url::Url;

    use crate::{auth_user_config::AuthUserConfig, errors::AuthServerError};

    #[test]
    fn test_auth_user_config() -> Result<(), AuthServerError> {
        let data = include_str!("../../tests/data/test_config.toml");
        let config: AuthUserConfig = data.parse()?;
        debug!("{:?}", config);
        assert_eq!(config.len(), 2);
        let entry = config.get("aws_app_rust").unwrap();
        let url: Url = "postgresql://user:password@localhost:5432/aws_app_cache".parse()?;
        assert_eq!(entry.get_database_url(), &url,);
        assert_eq!(entry.get_table(), "authorized_users");
        assert_eq!(entry.get_email_field(), "email");
        Ok(())
    }
}
