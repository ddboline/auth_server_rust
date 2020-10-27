use anyhow::Error;
use chrono::{DateTime, Utc};
use rusoto_core::Region;
use rusoto_ses::{Body, Content, Destination, Message, SendEmailRequest, Ses, SesClient};
use std::fmt;
use sts_profile_auth::get_client_sts;

#[derive(Clone)]
pub struct SesInstance {
    ses_client: SesClient,
    region: Region,
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
    pub fn new(region: Option<Region>) -> Self {
        let region = region.unwrap_or(Region::UsEast1);
        Self {
            ses_client: get_client_sts!(SesClient, region.clone())
                .expect("Failed to open SesClient"),
            region,
        }
    }

    pub async fn send_email(
        &self,
        src: &str,
        dest: &str,
        sub: &str,
        msg: &str,
    ) -> Result<(), Error> {
        let req = SendEmailRequest {
            source: src.to_string(),
            destination: Destination {
                to_addresses: Some(vec![dest.to_string()]),
                ..Destination::default()
            },
            message: Message {
                subject: Content {
                    data: sub.to_string(),
                    ..Content::default()
                },
                body: Body {
                    html: Some(Content {
                        data: msg.to_string(),
                        ..Content::default()
                    }),
                    ..Body::default()
                },
            },
            ..SendEmailRequest::default()
        };
        self.ses_client
            .send_email(req)
            .await
            .map_err(Into::into)
            .map(|_| ())
    }

    pub async fn get_statistics(&self) -> Result<(SesQuotas, EmailStats), Error> {
        let quota = self.ses_client.get_send_quota().await?;
        let stats = self
            .ses_client
            .get_send_statistics()
            .await?
            .send_data_points
            .unwrap_or_else(Vec::new)
            .into_iter()
            .filter_map(|point| {
                Some(EmailStats {
                    bounces: point.bounces?,
                    complaints: point.complaints?,
                    delivery_attempts: point.delivery_attempts?,
                    rejects: point.rejects?,
                    min_timestamp: Some(point.timestamp?.parse().ok()?),
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
        let quota = SesQuotas {
            max_24_hour_send: quota.max_24_hour_send.unwrap_or(0.0),
            max_send_rate: quota.max_send_rate.unwrap_or(0.0),
            sent_last_24_hours: quota.sent_last_24_hours.unwrap_or(0.0),
        };
        Ok((quota, stats))
    }
}

#[derive(Default, Debug)]
pub struct SesQuotas {
    pub max_24_hour_send: f64,
    pub max_send_rate: f64,
    pub sent_last_24_hours: f64,
}

#[derive(Default, Debug)]
pub struct EmailStats {
    pub bounces: i64,
    pub complaints: i64,
    pub delivery_attempts: i64,
    pub rejects: i64,
    pub min_timestamp: Option<DateTime<Utc>>,
    pub max_timestamp: Option<DateTime<Utc>>,
}
