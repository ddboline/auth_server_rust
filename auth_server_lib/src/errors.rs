use argon2::password_hash::Error as ArgonError;
use deadpool_postgres::{BuildError, ConfigError};
use envy::Error as EnvyError;
use postgres_query::{Error as QueryError, extract::Error as QueryExtractError};
use serde_json::Error as SerdeJsonError;
use serde_yml::Error as YamlError;
use std::{io::Error as IoError, net::AddrParseError};
use stdout_channel::StdoutChannelError;
use thiserror::Error;
use time::error::{Format as TimeFormatError, Parse as TimeParseError};
use tokio::task::JoinError;
use tokio_postgres::Error as PostgresError;
use toml::de::Error as TomlError;
use url::ParseError as UrlParseError;
use uuid::Error as UuidError;

use authorized_users::errors::AuthUsersError;

#[derive(Error, Debug)]
pub enum AuthServerError {
    #[error("AuthUsers Error {0}")]
    AuthUsersError(#[from] AuthUsersError),
    #[error("QueryError {0}")]
    QueryError(Box<QueryError>),
    #[error("QueryExtractError {0}")]
    QueryExtractError(Box<QueryExtractError>),
    #[error("PostgresError {0}")]
    PostgresError(#[from] PostgresError),
    #[error("IoError {0}")]
    IoError(#[from] IoError),
    #[error("SerdeJsonError {0}")]
    SerdeJsonError(#[from] SerdeJsonError),
    #[error("TomlError {0}")]
    TomlError(Box<TomlError>),
    #[error("DeadPoolError")]
    DeadPoolError,
    #[error("UrlParseError {0}")]
    UrlParseError(#[from] UrlParseError),
    #[error("EnvyError {0}")]
    EnvyError(#[from] EnvyError),
    #[error("JoinError {0}")]
    JoinError(#[from] JoinError),
    #[error("StdoutChannelError {0}")]
    StdoutChannelError(#[from] StdoutChannelError),
    #[error("Missing database url")]
    MissingDbUrl,
    #[error("Missing table")]
    MissingTable,
    #[error("ArgonError {0}")]
    ArgonError(#[from] ArgonError),
    #[error("No Pool Exists")]
    MissingPool,
    #[error("TimeFormatError {0}")]
    TimeFormatError(#[from] TimeFormatError),
    #[error("TimeParseError {0}")]
    TimeParseError(Box<TimeParseError>),
    #[error("YamlError {0}")]
    YamlError(#[from] YamlError),
    #[error("AddrParseError {0}")]
    AddrParseError(#[from] AddrParseError),
    #[error("UuidError {0}")]
    UuidError(#[from] UuidError),
    #[error("Bad Secret")]
    BadSecret,
    #[error("ConfigError {0}")]
    ConfigError(#[from] ConfigError),
    #[error("BuildError {0}")]
    BuildError(#[from] BuildError),
}

impl From<TimeParseError> for AuthServerError {
    fn from(value: TimeParseError) -> Self {
        Self::TimeParseError(Box::new(value))
    }
}

impl From<TomlError> for AuthServerError {
    fn from(value: TomlError) -> Self {
        Self::TomlError(Box::new(value))
    }
}

impl From<QueryExtractError> for AuthServerError {
    fn from(value: QueryExtractError) -> Self {
        Self::QueryExtractError(Box::new(value))
    }
}

impl From<QueryError> for AuthServerError {
    fn from(value: QueryError) -> Self {
        Self::QueryError(Box::new(value))
    }
}

#[cfg(test)]
mod tests {
    use argon2::password_hash::Error as ArgonError;
    use deadpool_postgres::{BuildError, ConfigError};
    use envy::Error as EnvyError;
    use postgres_query::{Error as QueryError, extract::Error as QueryExtractError};
    use serde_json::Error as SerdeJsonError;
    use serde_yml::Error as YamlError;
    use std::{io::Error as IoError, net::AddrParseError};
    use stdout_channel::StdoutChannelError;
    use time::error::{Format as TimeFormatError, Parse as TimeParseError};
    use tokio::task::JoinError;
    use tokio_postgres::Error as PostgresError;
    use toml::de::Error as TomlError;
    use url::ParseError as UrlParseError;
    use uuid::Error as UuidError;

    use authorized_users::errors::AuthUsersError;

    use crate::errors::AuthServerError;

    #[test]
    fn test_error_size() {
        println!("ArgonError {}", std::mem::size_of::<ArgonError>());
        println!("BuildError {}", std::mem::size_of::<BuildError>());
        println!("ConfigError {}", std::mem::size_of::<ConfigError>());
        println!("EnvyError {}", std::mem::size_of::<EnvyError>());
        println!(
            "QueryExtractError {}",
            std::mem::size_of::<QueryExtractError>()
        );
        println!("QueryError {}", std::mem::size_of::<QueryError>());
        println!("SerdeJsonError {}", std::mem::size_of::<SerdeJsonError>());
        println!("YamlError {}", std::mem::size_of::<YamlError>());
        println!("AddrParseError {}", std::mem::size_of::<AddrParseError>());
        println!("IoError {}", std::mem::size_of::<IoError>());
        println!(
            "StdoutChannelError {}",
            std::mem::size_of::<StdoutChannelError>()
        );
        println!("TimeFormatError {}", std::mem::size_of::<TimeFormatError>());
        println!("TimeParseError {}", std::mem::size_of::<TimeParseError>());
        println!("JoinError {}", std::mem::size_of::<JoinError>());
        println!("PostgresError {}", std::mem::size_of::<PostgresError>());
        println!("TomlError {}", std::mem::size_of::<TomlError>());
        println!("UrlParseError {}", std::mem::size_of::<UrlParseError>());
        println!("UuidError {}", std::mem::size_of::<UuidError>());
        println!("AuthUsersError {}", std::mem::size_of::<AuthUsersError>());

        assert_eq!(std::mem::size_of::<AuthServerError>(), 32);
    }
}
