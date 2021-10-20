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
#![allow(clippy::unused_async)]

pub mod app;
pub mod auth;
pub mod errors;
pub mod logged_user;
pub mod routes;
pub mod session_data_cache;

use chrono::{DateTime, Utc};
use derive_more::{From, Into};
use rweb::Schema;
use rweb_helper::derive_rweb_schema;
use serde::Serialize;
use stack_string::StackString;
use uuid::Uuid;

use auth_server_ext::ses_client::{EmailStats, SesQuotas};
use auth_server_lib::session::SessionSummary;

#[derive(Into, From, Default, Debug, Serialize)]
pub struct SesQuotasWrapper(SesQuotas);

derive_rweb_schema!(SesQuotasWrapper, _SesQuotasWrapper);

#[allow(dead_code)]
#[derive(Schema)]
struct _SesQuotasWrapper {
    #[schema(description = "Maximum Emails per Day")]
    max_24_hour_send: f64,
    #[schema(description = "Maximum Emails per Second")]
    max_send_rate: f64,
    #[schema(description = "Emails Send in Last Day")]
    sent_last_24_hours: f64,
}

#[derive(Into, From, Default, Debug, Serialize)]
pub struct EmailStatsWrapper(EmailStats);

derive_rweb_schema!(EmailStatsWrapper, _EmailStatsWrapper);

#[allow(dead_code)]
#[derive(Schema)]
struct _EmailStatsWrapper {
    #[schema(description = "Number of Bounced Emails")]
    bounces: i64,
    #[schema(description = "Number of Complaints")]
    complaints: i64,
    #[schema(description = "Number of Delivery Attempts")]
    delivery_attempts: i64,
    #[schema(description = "Number of Rejected Emails")]
    rejects: i64,
    #[schema(description = "Earliest Record")]
    min_timestamp: Option<DateTime<Utc>>,
    #[schema(description = "Latest Record")]
    max_timestamp: Option<DateTime<Utc>>,
}

#[derive(Into, From, Default, Debug, Serialize)]
pub struct SessionSummaryWrapper(SessionSummary);

derive_rweb_schema!(SessionSummaryWrapper, _SessionSummaryWrapper);

#[allow(dead_code)]
#[derive(Schema)]
struct _SessionSummaryWrapper {
    #[schema(description = "Session ID")]
    session_id: Uuid,
    #[schema(description = "Email Address")]
    email_address: StackString,
    #[schema(description = "Last Accessed")]
    last_accessed: DateTime<Utc>,
    #[schema(description = "Create At")]
    created_at: DateTime<Utc>,
    #[schema(description = "Number of Data Objects")]
    number_of_data_objects: i64,
}
