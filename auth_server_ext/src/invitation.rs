use anyhow::Error;
use chrono::{DateTime, Duration, Utc};
use log::debug;
use postgres_query::{query, FromSqlRow};
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use uuid::Uuid;

use auth_server_lib::pgpool::PgPool;

use crate::ses_client::SesInstance;

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
        let query = query!("SELECT * FROM invitations");
        let conn = pool.get().await?;
        query.fetch(&conn).await.map_err(Into::into)
    }

    pub async fn get_number_invitations(pool: &PgPool) -> Result<i64, Error> {
        let query = query!("SELECT count(*) FROM invitations");
        let conn = pool.get().await?;
        let (count,) = query.fetch_one(&conn).await?;
        Ok(count)
    }

    pub async fn get_by_uuid(uuid: &Uuid, pool: &PgPool) -> Result<Option<Self>, Error> {
        let query = query!("SELECT * FROM invitations WHERE id = $id", id = uuid);
        let conn = pool.get().await?;
        query.fetch_opt(&conn).await.map_err(Into::into)
    }

    pub async fn insert(&self, pool: &PgPool) -> Result<(), Error> {
        let query = query!(
            "
            INSERT INTO invitations (id, email, expires_at)
            VALUES ($id, $email, $expires_at)",
            id = self.id,
            email = self.email,
            expires_at = self.expires_at,
        );
        let conn = pool.get().await?;
        query.execute(&conn).await?;
        Ok(())
    }

    pub async fn delete(&self, pool: &PgPool) -> Result<(), Error> {
        let query = query!("DELETE FROM invitations WHERE id = $id", id = self.id);
        let conn = pool.get().await?;
        query.execute(&conn).await?;
        Ok(())
    }

    pub async fn send_invitation(
        &self,
        sending_email: &str,
        callback_url: &str,
    ) -> Result<(), Error> {
        let ses = SesInstance::new(None);

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
            sending_email,
            &self.email,
            "You have been invited to join Simple-Auth-Server Rust",
            &email_body,
        )
        .await?;
        debug!("Success");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Error;
    use futures::try_join;
    use log::debug;

    use auth_server_lib::{config::Config, get_random_string, pgpool::PgPool, AUTH_APP_MUTEX};

    use crate::invitation::Invitation;

    #[tokio::test]
    async fn test_send_invitation() -> Result<(), Error> {
        let config = Config::init_config()?;
        let email = format!("ddboline+{}@gmail.com", get_random_string(32));
        let new_invitation = Invitation::from_email(&email);
        new_invitation
            .send_invitation(&config.sending_email_address, "test_url")
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_create_delete_invitation() -> Result<(), Error> {
        let _lock = AUTH_APP_MUTEX.lock().await;
        let config = Config::init_config()?;
        let pool = PgPool::new(&config.database_url);
        let email = format!("{}@localhost", get_random_string(32));
        let invitation = Invitation::from_email(&email);
        let uuid = &invitation.id;
        invitation.insert(&pool).await?;

        let invitation = Invitation::get_by_uuid(uuid, &pool).await?.unwrap();
        debug!("{:?}", invitation);

        invitation.delete(&pool).await?;

        assert!(Invitation::get_by_uuid(uuid, &pool).await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn test_get_all_get_number_invitations() -> Result<(), Error> {
        let _lock = AUTH_APP_MUTEX.lock().await;
        let config = Config::init_config()?;
        let pool = PgPool::new(&config.database_url);
        let (invitations, count) = try_join!(
            Invitation::get_all(&pool),
            Invitation::get_number_invitations(&pool)
        )?;
        assert_eq!(invitations.len(), count as usize);
        Ok(())
    }
}
