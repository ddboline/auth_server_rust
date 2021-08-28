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

use chrono::{DateTime, Utc};
use derive_more::{From, Into};
use rweb::{
    openapi::{ComponentDescriptor, ComponentOrInlineSchema, Entity},
    Schema,
};
use serde::Serialize;
use std::borrow::Cow;

use auth_server_ext::ses_client::{EmailStats, SesQuotas};

#[derive(Into, From, Default, Debug, Serialize)]
pub struct SesQuotasWrapper(SesQuotas);

impl Entity for SesQuotasWrapper {
    fn type_name() -> Cow<'static, str> {
        _SesQuotasWrapper::type_name()
    }
    fn describe(comp_d: &mut ComponentDescriptor) -> ComponentOrInlineSchema {
        _SesQuotasWrapper::describe(comp_d)
    }
}

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

impl Entity for EmailStatsWrapper {
    fn type_name() -> Cow<'static, str> {
        _EmailStatsWrapper::type_name()
    }
    fn describe(comp_d: &mut ComponentDescriptor) -> ComponentOrInlineSchema {
        _EmailStatsWrapper::describe(comp_d)
    }
}

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
