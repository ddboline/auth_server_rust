use argon2::password_hash::Error as ArgonError;
use deadpool::managed::PoolError as DeadPoolError;
use envy::Error as EnvyError;
use postgres_query::{extract::Error as QueryExtractError, Error as QueryError};
use serde_json::Error as SerdeJsonError;
use serde_yaml::Error as YamlError;
use stack_string::StackString;
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
    #[error("AuthServerError {0}")]
    AuthServerError(StackString),
    #[error("AuthUsers Error {0}")]
    AuthUsersError(#[from] AuthUsersError),
    #[error("QueryError {0}")]
    QueryError(#[from] QueryError),
    #[error("QueryExtractError {0}")]
    QueryExtractError(#[from] QueryExtractError),
    #[error("PostgresError {0}")]
    PostgresError(#[from] PostgresError),
    #[error("IoError {0}")]
    IoError(#[from] IoError),
    #[error("SerdeJsonError {0}")]
    SerdeJsonError(#[from] SerdeJsonError),
    #[error("TomlError {0}")]
    TomlError(#[from] TomlError),
    #[error("DeadPoolError {0}")]
    DeadPoolError(#[from] DeadPoolError<PostgresError>),
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
    TimeParseError(#[from] TimeParseError),
    #[error("YamlError {0}")]
    YamlError(#[from] YamlError),
    #[error("AddrParseError {0}")]
    AddrParseError(#[from] AddrParseError),
    #[error("UuidError {0}")]
    UuidError(#[from] UuidError),
}
