#![allow(clippy::default_trait_access)]

use anyhow::Error;
use rusoto_core::Region;
use rusoto_ses::{Body, Content, Destination, Message, SendEmailRequest, Ses, SesClient};
use serde::Serialize;
use stack_string::format_sstr;
use std::fmt;
use sts_profile_auth::get_client_sts;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use auth_server_lib::date_time_wrapper::DateTimeWrapper;

#[derive(Clone)]
pub struct SesInstance {
    ses_client: SesClient,
}

impl fmt::Debug for SesInstance {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SesInstance")
    }
}

impl Default for SesInstance {
    fn default() -> Self {
        Self::new(None)
    }
}

impl SesInstance {
    #[must_use]
    pub fn new(region: Option<Region>) -> Self {
        let region = region.unwrap_or(Region::UsEast1);
        Self {
            ses_client: get_client_sts!(SesClient, region).expect("Failed to open SesClient"),
        }
    }

    /// # Errors
    /// Returns error if send email fails
    pub async fn send_email(
        &self,
        src: impl Into<String>,
        dest: impl Into<String>,
        sub: impl Into<String>,
        msg: impl Into<String>,
    ) -> Result<(), Error> {
        let req = SendEmailRequest {
            source: src.into(),
            destination: Destination {
                to_addresses: Some(vec![dest.into()]),
                ..Destination::default()
            },
            message: Message {
                subject: Content {
                    data: sub.into(),
                    ..Content::default()
                },
                body: Body {
                    html: Some(Content {
                        data: msg.into(),
                        ..Content::default()
                    }),
                    ..Body::default()
                },
            },
            ..SendEmailRequest::default()
        };
        self.ses_client.send_email(req).await?;
        Ok(())
    }

    /// # Errors
    /// Returns error if
    ///     * `get_send_quota` api call fails
    ///     * `get_send_statistics` api call fails
    pub async fn get_statistics(&self) -> Result<Statistics, Error> {
        let quota = self.ses_client.get_send_quota().await?;
        let stats = self
            .ses_client
            .get_send_statistics()
            .await?
            .send_data_points
            .unwrap_or_default()
            .into_iter()
            .filter_map(|point| {
                Some(EmailStats {
                    bounces: point.bounces?,
                    complaints: point.complaints?,
                    delivery_attempts: point.delivery_attempts?,
                    rejects: point.rejects?,
                    min_timestamp: point
                        .timestamp
                        .as_ref()
                        .and_then(|t| OffsetDateTime::parse(t, &Rfc3339).ok())
                        .map(Into::into),
                    ..EmailStats::default()
                })
            })
            .fold(EmailStats::default(), |mut stats, point| {
                stats.bounces += point.bounces;
                stats.complaints += point.complaints;
                stats.delivery_attempts += point.delivery_attempts;
                stats.rejects += point.rejects;
                if let Some(timestamp) = point.min_timestamp {
                    if stats.min_timestamp.is_none() || Some(timestamp) < stats.min_timestamp {
                        stats.min_timestamp = Some(timestamp);
                    }
                    if stats.max_timestamp.is_none() || Some(timestamp) > stats.max_timestamp {
                        stats.max_timestamp = Some(timestamp);
                    }
                }
                stats
            });
        let quotas = SesQuotas {
            max_24_hour_send: quota.max_24_hour_send.unwrap_or(0.0),
            max_send_rate: quota.max_send_rate.unwrap_or(0.0),
            sent_last_24_hours: quota.sent_last_24_hours.unwrap_or(0.0),
        };
        Ok(Statistics { quotas, stats })
    }
}

#[derive(Default, Debug, Serialize)]
pub struct SesQuotas {
    pub max_24_hour_send: f64,
    pub max_send_rate: f64,
    pub sent_last_24_hours: f64,
}

#[derive(Default, Debug, Serialize)]
pub struct EmailStats {
    pub bounces: i64,
    pub complaints: i64,
    pub delivery_attempts: i64,
    pub rejects: i64,
    pub min_timestamp: Option<DateTimeWrapper>,
    pub max_timestamp: Option<DateTimeWrapper>,
}

impl fmt::Display for EmailStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "EmailStats(\n\tbounces: {b},\n\tcomplaints: {c},\n\tdelivery_attempts: \
             {d},\n\trejects: {r},\n{mn}{mx})",
            b = self.bounces,
            c = self.complaints,
            d = self.delivery_attempts,
            r = self.rejects,
            mn = if let Some(min_timestamp) =
                self.min_timestamp.and_then(|t| t.format(&Rfc3339).ok())
            {
                format_sstr!("\tmin_timestamp: {min_timestamp},\n")
            } else {
                "".into()
            },
            mx = if let Some(max_timestamp) =
                self.max_timestamp.and_then(|t| t.format(&Rfc3339).ok())
            {
                format_sstr!("\tmax_timestamp: {max_timestamp},\n")
            } else {
                "".into()
            },
        )
    }
}

#[derive(Debug, Default)]
pub struct Statistics {
    pub quotas: SesQuotas,
    pub stats: EmailStats,
}

#[cfg(test)]
mod tests {
    use crate::ses_client::SesInstance;

    #[test]
    fn test_debug() {
        let ses = SesInstance::default();
        assert_eq!(&format!("{:?}", ses), "SesInstance");
    }
}
