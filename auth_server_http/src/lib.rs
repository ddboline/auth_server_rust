#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::unused_async)]
#![allow(clippy::ignored_unit_patterns)]

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
use utoipa::{ToSchema, PartialSchema};

use auth_server_ext::ses_client::{EmailStats, SesQuotas};
use auth_server_lib::session::SessionSummary;

macro_rules! derive_utoipa_schema {
    ($T0:ty, $T1:ty) => {
        impl utoipa::PartialSchema for $T0 {
            fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
                <$T1>::schema()
            }
        }

        impl utoipa::ToSchema for $T0 {
            fn name() -> std::borrow::Cow<'static, str> {
                assert_eq!(std::mem::size_of::<$T0>(), std::mem::size_of::<$T1>());
                <$T1>::name()
            }
            fn schemas(
                schemas: &mut Vec<(
                    String,
                    utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>,
                )>,
            ) {
                    <$T1>::schemas(schemas)
            }
        }
    };
}

#[derive(Into, From, Default, Debug, Serialize, Clone, Copy)]
pub struct SesQuotasWrapper(SesQuotas);

derive_utoipa_schema!(SesQuotasWrapper, _SesQuotasWrapper);

// #[allow(dead_code)]
#[derive(ToSchema)]
// #[schema(component = "SesQuotas")]
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

// #[derive(Into, From, Default, Debug, Serialize)]
// pub struct SessionSummaryWrapper(SessionSummary);

// derive_rweb_schema!(SessionSummaryWrapper, _SessionSummaryWrapper);

// #[allow(dead_code)]
// #[derive(Schema)]
// #[schema(component = "SessionSummary")]
// struct _SessionSummaryWrapper {
//     #[schema(description = "Session ID")]
//     session_id: UuidWrapper,
//     #[schema(description = "Email Address")]
//     email_address: StackString,
//     #[schema(description = "Last Accessed")]
//     last_accessed: DateTimeType,
//     #[schema(description = "Create At")]
//     created_at: DateTimeType,
//     #[schema(description = "Number of Data Objects")]
//     number_of_data_objects: i64,
// }

// #[cfg(test)]
// mod test {
//     use rweb_helper::derive_rweb_test;

//     use crate::{
//         EmailStatsWrapper, SesQuotasWrapper, SessionSummaryWrapper, _EmailStatsWrapper,
//         _SesQuotasWrapper, _SessionSummaryWrapper,
//     };

//     #[test]
//     fn test_types() {
//         derive_rweb_test!(SesQuotasWrapper, _SesQuotasWrapper);
//         derive_rweb_test!(EmailStatsWrapper, _EmailStatsWrapper);
//         derive_rweb_test!(SessionSummaryWrapper, _SessionSummaryWrapper);
//     }
// }
