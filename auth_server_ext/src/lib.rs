#![allow(clippy::must_use_candidate)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::unseparated_literal_suffix)]

pub mod google_openid;
pub mod ses_client;

use anyhow::Error;
use log::debug;

use auth_server_lib::invitation::Invitation;

use crate::ses_client::SesInstance;

pub async fn send_invitation(
    ses: &SesInstance,
    invite: &Invitation,
    sending_email: &str,
    callback_url: &str,
) -> Result<(), Error> {
    let email_body = format!(
        "Please click on the link below to complete registration. <br/>
         <a href=\"{url}?id={id}&email={email}\">
         {url}</a> <br>
         your Invitation expires on <strong>{exp}</strong>",
        url = callback_url,
        id = invite.id,
        email = invite.email,
        exp = invite
            .expires_at
            .format("%I:%M %p %A, %-d %B, %C%y")
            .to_string(),
    );

    ses.send_email(
        sending_email,
        &invite.email,
        "You have been invited to join Simple-Auth-Server Rust",
        &email_body,
    )
    .await?;
    debug!("Success");
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Error;

    use auth_server_lib::{config::Config, get_random_string, invitation::Invitation};

    use crate::{send_invitation, ses_client::SesInstance};

    #[tokio::test]
    async fn test_send_invitation() -> Result<(), Error> {
        let config = Config::init_config()?;
        let ses = SesInstance::new(None);

        let email = format!("ddboline+{}@gmail.com", get_random_string(32));
        let new_invitation = Invitation::from_email(&email);
        send_invitation(
            &ses,
            &new_invitation,
            &config.sending_email_address,
            "test_url",
        )
        .await?;
        Ok(())
    }
}
