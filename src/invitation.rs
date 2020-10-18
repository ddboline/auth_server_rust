use chrono::{DateTime, Duration, Utc};
use log::debug;
use postgres_query::FromSqlRow;
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use uuid::Uuid;

use crate::{app::CONFIG, errors::ServiceError as Error, pgpool::PgPool, ses_client::SesInstance};

#[derive(FromSqlRow, Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
pub struct Invitation {
    pub id: Uuid,
    pub email: StackString,
    pub expires_at: DateTime<Utc>,
}

impl Invitation {
    pub fn from_email(email: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            email: email.into(),
            expires_at: Utc::now() + Duration::hours(24),
        }
    }

    pub async fn get_all(pool: &PgPool) -> Result<Vec<Self>, Error> {
        let query = postgres_query::query!("SELECT * FROM invitations");
        pool.get()
            .await?
            .query(query.sql(), query.parameters())
            .await?
            .into_iter()
            .map(|row| Self::from_row(&row).map_err(Into::into))
            .collect()
    }

    pub async fn get_number_invitations(pool: &PgPool) -> Result<i64, Error> {
        let query = postgres_query::query!("SELECT count(*) FROM invitations");
        let count = pool
            .get()
            .await?
            .query_one(query.sql(), query.parameters())
            .await?
            .try_get(0)?;
        Ok(count)
    }

    pub async fn get_by_uuid(uuid: &Uuid, pool: &PgPool) -> Result<Option<Self>, Error> {
        let query = postgres_query::query!("SELECT * FROM invitations WHERE id = $id", id = uuid);
        pool.get()
            .await?
            .query_opt(query.sql(), query.parameters())
            .await?
            .map(|row| Self::from_row(&row))
            .transpose()
            .map_err(Into::into)
    }

    pub async fn insert(&self, pool: &PgPool) -> Result<(), Error> {
        let query = postgres_query::query!(
            "
            INSERT INTO invitations (id, email, expires_at)
            VALUES ($id, $email, $expires_at)",
            id = self.id,
            email = self.email,
            expires_at = self.expires_at,
        );
        pool.get()
            .await?
            .execute(query.sql(), query.parameters())
            .await?;
        Ok(())
    }

    pub async fn delete(&self, pool: &PgPool) -> Result<(), Error> {
        let query = postgres_query::query!("DELETE FROM invitations WHERE id = $id", id = self.id);
        pool.get()
            .await?
            .execute(query.sql(), query.parameters())
            .await?;
        Ok(())
    }

    pub async fn send_invitation(&self, callback_url: &str) -> Result<(), Error> {
        let ses = SesInstance::new(None);

        let sending_email = &CONFIG.sending_email_address;

        let email_body = format!(
            "Please click on the link below to complete registration. <br/>
             <a href=\"{url}?id={id}&email={email}\">
             {url}</a> <br>
             your Invitation expires on <strong>{exp}</strong>",
            url = callback_url,
            id = self.id,
            email = self.email,
            exp = self
                .expires_at
                .format("%I:%M %p %A, %-d %B, %C%y")
                .to_string(),
        );

        ses.send_email(
            &sending_email,
            &self.email,
            "You have been invited to join Simple-Auth-Server Rust",
            &email_body,
        )
        .await
        .map(|_| debug!("Success"))
        .map_err(|e| Error::BadRequest(format!("Bad request {:?}", e)))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        app::{get_random_string, CONFIG},
        errors::ServiceError as Error,
        invitation::Invitation,
        pgpool::PgPool,
    };

    #[tokio::test]
    async fn test_send_invitation() -> Result<(), Error> {
        let new_invitation = Invitation::from_email("ddboline.im@gmail.com");
        new_invitation.send_invitation("test_url").await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_create_delete_invitation() -> Result<(), Error> {
        let pool = PgPool::new(&CONFIG.database_url);
        let email = format!("{}@localhost", get_random_string(32));
        let invitation = Invitation::from_email(&email);
        let uuid = &invitation.id;
        invitation.insert(&pool).await?;

        let invitation = Invitation::get_by_uuid(uuid, &pool).await?.unwrap();
        println!("{:?}", invitation);

        invitation.delete(&pool).await?;

        assert!(Invitation::get_by_uuid(uuid, &pool).await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn test_get_all_get_number_invitations() -> Result<(), Error> {
        let pool = PgPool::new(&CONFIG.database_url);
        let invitations = Invitation::get_all(&pool).await?;
        let count = Invitation::get_number_invitations(&pool).await? as usize;
        assert_eq!(invitations.len(), count);
        Ok(())
    }
}
