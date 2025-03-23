#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::unused_async)]
#![allow(clippy::ignored_unit_patterns)]
#![allow(clippy::similar_names)]
#![allow(clippy::doc_markdown)]

pub mod app;
pub mod auth;
pub mod elements;
pub mod errors;
pub mod logged_user;
pub mod routes;
pub mod session_data_cache;

use derive_more::{From, Into};
use serde::Serialize;
use stack_string::StackString;
use time::OffsetDateTime;
use utoipa::ToSchema;
use utoipa_helper::derive_utoipa_schema;
use uuid::Uuid;

use auth_server_ext::ses_client::{EmailStats, SesQuotas};
use auth_server_lib::session::SessionSummary;

#[derive(Into, From, Default, Debug, Serialize, Clone, Copy)]
pub struct SesQuotasWrapper(SesQuotas);

derive_utoipa_schema!(SesQuotasWrapper, _SesQuotasWrapper);

#[allow(dead_code)]
#[derive(ToSchema)]
/// SesQuotas
#[schema(as = SesQuotas)]
struct _SesQuotasWrapper {
    /// Maximum Emails per Day
    max_24_hour_send: f64,
    /// Maximum Emails per Second
    max_send_rate: f64,
    /// Emails Send in Last Day
    sent_last_24_hours: f64,
}

#[derive(Into, From, Default, Debug, Serialize, Clone, Copy)]
pub struct EmailStatsWrapper(EmailStats);

derive_utoipa_schema!(EmailStatsWrapper, _EmailStatsWrapper);

#[allow(dead_code)]
#[derive(ToSchema)]
// #[schema(component = "EmailStats")]
#[schema(as = EmailStats)]
struct _EmailStatsWrapper {
    /// Number of Bounced Emails
    bounces: i64,
    /// Number of Complaints
    complaints: i64,
    /// Number of Delivery Attempts
    delivery_attempts: i64,
    /// Number of Rejected Emails
    rejects: i64,
    /// Earliest Record
    min_timestamp: Option<OffsetDateTime>,
    /// Latest Record
    max_timestamp: Option<OffsetDateTime>,
}

#[derive(Into, From, Default, Debug, Serialize)]
pub struct SessionSummaryWrapper(SessionSummary);

derive_utoipa_schema!(SessionSummaryWrapper, _SessionSummaryWrapper);

#[allow(dead_code)]
#[derive(ToSchema)]
/// SessionSummary
#[schema(as = SessionSummary)]
struct _SessionSummaryWrapper {
    /// Session ID
    session_id: Uuid,
    /// Email Address
    email_address: StackString,
    /// Last Accessed
    last_accessed: OffsetDateTime,
    /// Create At
    created_at: OffsetDateTime,
    /// Number of Data Objects
    number_of_data_objects: i64,
}

#[cfg(test)]
mod test {
    use utoipa_helper::derive_utoipa_test;

    use crate::{
        _EmailStatsWrapper, _SesQuotasWrapper, _SessionSummaryWrapper, EmailStatsWrapper,
        SesQuotasWrapper, SessionSummaryWrapper,
    };

    #[test]
    fn test_types() {
        derive_utoipa_test!(SesQuotasWrapper, _SesQuotasWrapper);
        derive_utoipa_test!(EmailStatsWrapper, _EmailStatsWrapper);
        derive_utoipa_test!(SessionSummaryWrapper, _SessionSummaryWrapper);
    }
}
