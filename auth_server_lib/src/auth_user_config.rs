use anyhow::{Context, Error};
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

use crate::toml_entry::{Entry, TomlEntry};

type ConfigToml = HashMap<String, TomlEntry>;

#[derive(Debug, Deref, IntoIterator)]
pub struct AuthUserConfig(HashMap<StackString, Entry>);

impl AuthUserConfig {
    pub fn new<P>(p: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let p = p.as_ref();
        Self::from_path(p)
    }

    fn from_path(p: &Path) -> Result<Self, Error> {
        let data = fs::read_to_string(p).with_context(|| format!("Failed to open {:?}", p))?;
        let config: ConfigToml =
            toml::from_str(&data).with_context(|| format!("Failed to parse toml in {:?}", p))?;
        config.try_into()
    }
}

impl FromStr for AuthUserConfig {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let config: ConfigToml =
            toml::from_str(s).with_context(|| format!("Failed to parse toml {}", s))?;
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
    use anyhow::Error;
    use log::debug;

    use crate::auth_user_config::AuthUserConfig;

    #[test]
    fn test_auth_user_config() -> Result<(), Error> {
        let data = include_str!("../../tests/data/test_config.toml");
        let config: AuthUserConfig = data.parse()?;
        debug!("{:?}", config);
        assert_eq!(config.len(), 2);
        let entry = config.get("aws_app_rust").unwrap();
        assert_eq!(
            entry.database_url,
            "postgresql://user:password@localhost:5432/aws_app_cache".parse()?
        );
        assert_eq!(entry.table, "authorized_users");
        assert_eq!(entry.email_field, "email");
        Ok(())
    }
}
