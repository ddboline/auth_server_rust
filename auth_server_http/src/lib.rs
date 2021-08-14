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

use chrono::{DateTime, Utc};
use rweb::Schema;
use serde::Serialize;

use auth_server_ext::ses_client::{EmailStats, SesQuotas};

#[derive(Default, Debug, Serialize, Schema)]
pub struct SesQuotasWrapper {
    #[schema(description = "Maximum Emails per Day")]
    pub max_24_hour_send: f64,
    #[schema(description = "Maximum Emails per Second")]
    pub max_send_rate: f64,
    #[schema(description = "Emails Send in Last Day")]
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
    #[schema(description = "Number of Bounced Emails")]
    pub bounces: i64,
    #[schema(description = "Number of Complaints")]
    pub complaints: i64,
    #[schema(description = "Number of Delivery Attempts")]
    pub delivery_attempts: i64,
    #[schema(description = "Number of Rejected Emails")]
    pub rejects: i64,
    #[schema(description = "Earliest Record")]
    pub min_timestamp: Option<DateTime<Utc>>,
    #[schema(description = "Latest Record")]
    pub max_timestamp: Option<DateTime<Utc>>,
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
