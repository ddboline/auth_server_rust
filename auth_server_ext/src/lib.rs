#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]

pub mod google_openid;
pub mod ses_client;

use anyhow::Error;
use log::debug;
use stack_string::{format_sstr, StackString};
use std::fmt::Write;
use url::Url;

use auth_server_lib::invitation::Invitation;

use crate::ses_client::SesInstance;

/// # Errors
/// Returns error if send email fails
pub async fn send_invitation(
    ses: &SesInstance,
    invite: &Invitation,
    sending_email: impl AsRef<str>,
    callback_url: &Url,
) -> Result<(), Error> {
    let dt_str = StackString::from_display(invite.expires_at.format("%I:%M %p %A, %-d %B, %C%y"));
    let email_body = format_sstr!(
        "Please click on the link below to complete registration. <br/>
         <a href=\"{url}?id={id}&email={email}\">
         {url}</a> <br>
         your Invitation expires on <strong>{exp}</strong>",
        url = callback_url,
        id = invite.id,
        email = invite.email,
        exp = dt_str,
    );

    ses.send_email(
        sending_email.as_ref(),
        invite.email.as_str(),
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
    use stack_string::format_sstr;
    use std::fmt::Write;

    use auth_server_lib::{config::Config, get_random_string, invitation::Invitation};

    use crate::{send_invitation, ses_client::SesInstance};

    #[tokio::test]
    async fn test_send_invitation() -> Result<(), Error> {
        let config = Config::init_config()?;
        let ses = SesInstance::new(None);

        let email = format_sstr!("ddboline+{}@gmail.com", get_random_string(32));
        let new_invitation = Invitation::from_email(&email);
        let callback_url = "https://localhost".parse()?;
        send_invitation(
            &ses,
            &new_invitation,
            &config.sending_email_address,
            &callback_url,
        )
        .await?;
        Ok(())
    }
}
