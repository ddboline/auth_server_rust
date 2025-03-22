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

mod iso8601 {
    use serde::{de, Deserialize, Deserializer, Serializer};
    use stack_string::StackString;
    use std::borrow::Cow;
    use time::{
        format_description::well_known::Rfc3339, macros::format_description, OffsetDateTime,
        UtcOffset,
    };

    use auth_server_lib::errors::AuthServerError as Error;

    type DateTimeType = OffsetDateTime;

    #[must_use]
    fn convert_datetime_to_str(datetime: OffsetDateTime) -> StackString {
        datetime
            .to_offset(UtcOffset::UTC)
            .format(format_description!(
                "[year]-[month]-[day]T[hour]:[minute]:[second]Z"
            ))
            .unwrap_or_else(|_| String::new())
            .into()
    }

    /// # Errors
    /// Return error if `parse_from_rfc3339` fails
    fn convert_str_to_datetime(s: &str) -> Result<OffsetDateTime, Error> {
        let s: Cow<str> = if s.contains('Z') {
            s.replace('Z', "+00:00").into()
        } else {
            s.into()
        };
        OffsetDateTime::parse(&s, &Rfc3339)
            .map(|x| x.to_offset(UtcOffset::UTC))
            .map_err(Into::into)
    }

    /// # Errors
    /// Returns error if serialization fails
    pub fn serialize<S>(date: &DateTimeType, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&convert_datetime_to_str((*date).into()))
    }

    /// # Errors
    /// Returns error if deserialization fails
    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTimeType, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        convert_str_to_datetime(&s)
            .map_err(de::Error::custom)
            .map(Into::into)
    }
}

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
