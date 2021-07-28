#![allow(clippy::must_use_candidate)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::unseparated_literal_suffix)]
#![allow(clippy::default_trait_access)]

pub mod app;
pub mod auth;
pub mod errors;
pub mod logged_user;
pub mod routes;
pub mod uuid_wrapper;
pub mod datetime_wrapper;

use rweb::Schema;
use serde::{Serialize};

use auth_server_ext::ses_client::{SesQuotas, EmailStats};

use crate::datetime_wrapper::DateTimeWrapper;

#[derive(Default, Debug, Serialize, Schema)]
pub struct SesQuotasWrapper {
    pub max_24_hour_send: f64,
    pub max_send_rate: f64,
    pub sent_last_24_hours: f64,
}

impl From<SesQuotas> for SesQuotasWrapper {
    fn from(item: SesQuotas) -> Self {
        Self {
            max_24_hour_send: item.max_24_hour_send,
            max_send_rate: item.max_send_rate,
            sent_last_24_hours: item.sent_last_24_hours,
        }
    }
}

#[derive(Default, Debug, Serialize, Schema)]
pub struct EmailStatsWrapper {
    pub bounces: i64,
    pub complaints: i64,
    pub delivery_attempts: i64,
    pub rejects: i64,
    pub min_timestamp: Option<DateTimeWrapper>,
    pub max_timestamp: Option<DateTimeWrapper>,
}

impl From<EmailStats> for EmailStatsWrapper {
    fn from(item: EmailStats) -> Self {
        Self {
            bounces: item.bounces,
            complaints: item.complaints,
            delivery_attempts: item.delivery_attempts,
            rejects: item.rejects,
            min_timestamp: item.min_timestamp.map(Into::into),
            max_timestamp: item.max_timestamp.map(Into::into),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
