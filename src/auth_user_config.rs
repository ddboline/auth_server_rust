use anyhow::{format_err, Error};
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use std::{
    collections::{hash_map::IntoIter, HashMap},
    convert::{TryFrom, TryInto},
    fs,
    ops::Deref,
    path::Path,
    str::FromStr,
};
use url::Url;

#[derive(Debug)]
pub struct AuthUserConfig(HashMap<StackString, Entry>);

impl AuthUserConfig {
    pub fn new(p: &Path) -> Result<Self, Error> {
        let data = fs::read_to_string(p)?;
        let config: ConfigToml = toml::from_str(&data)?;
        config.try_into()
    }
}

impl Deref for AuthUserConfig {
    type Target = HashMap<StackString, Entry>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for AuthUserConfig {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let config: ConfigToml = toml::from_str(s)?;
        config.try_into()
    }
}

impl IntoIterator for AuthUserConfig {
    type Item = (StackString, Entry);
    type IntoIter = IntoIter<StackString, Entry>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[derive(Debug)]
pub struct Entry {
    pub database_url: Url,
    pub table: StackString,
    pub email_field: StackString,
}

impl TryFrom<ConfigToml> for AuthUserConfig {
    type Error = Error;
    fn try_from(item: ConfigToml) -> Result<Self, Self::Error> {
        let result: Result<HashMap<_, _>, Error> = item
            .into_iter()
            .map(|(key, entry)| {
                let database_url = entry
                    .database_url
                    .ok_or_else(|| format_err!("No database_url"))?;
                let table = entry.table.ok_or_else(|| format_err!("No table"))?;
                let email_field = entry.email_field.unwrap_or_else(|| "email".into());
                Ok((
                    key.into(),
                    Entry {
                        database_url,
                        table,
                        email_field,
                    },
                ))
            })
            .collect();
        result.map(AuthUserConfig)
    }
}

type ConfigToml = HashMap<String, TomlEntry>;

#[derive(Serialize, Deserialize)]
struct TomlEntry {
    database_url: Option<Url>,
    table: Option<StackString>,
    email_field: Option<StackString>,
}

#[cfg(test)]
mod tests {
    use anyhow::Error;

    use crate::auth_user_config::AuthUserConfig;

    #[test]
    fn test_auth_user_config() -> Result<(), Error> {
        let data = include_str!("../tests/data/test_config.toml");
        let config: AuthUserConfig = data.parse()?;
        println!("{:?}", config);
        assert_eq!(config.len(), 2);
        Ok(())
    }
}
