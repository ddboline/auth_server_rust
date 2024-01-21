#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]

pub mod errors;
pub mod google_openid;
pub mod ses_client;

use log::debug;
use stack_string::format_sstr;
use time::macros::format_description;
use url::Url;

use auth_server_lib::invitation::Invitation;

use crate::{errors::AuthServerExtError as Error, ses_client::SesInstance};

/// # Errors
/// Returns error if send email fails
pub async fn send_invitation(
    ses: &SesInstance,
    invite: &Invitation,
    sending_email: impl AsRef<str>,
    callback_url: &Url,
) -> Result<(), Error> {
    let dt_str = invite.expires_at.format(format_description!(
        "[hour repr:12]:[minute] [period] [weekday], [day padding:none] [month repr:short], [year]"
    ))?;
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
    use stack_string::format_sstr;

    use auth_server_lib::{config::Config, get_random_string, invitation::Invitation};

    use crate::{errors::AuthServerExtError as Error, send_invitation, ses_client::SesInstance};

    #[tokio::test]
    async fn test_send_invitation() -> Result<(), Error> {
        let config = Config::init_config()?;
        let sdk_config = aws_config::load_from_env().await;
        let ses = SesInstance::new(&sdk_config);

        let email = format_sstr!("ddboline+{}@ddboline.net", get_random_string(32));
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

    #[test]
    fn test_time_format() -> Result<(), Error> {
        use time::macros::{datetime, format_description};

        let dt = datetime!(2021-05-01 13:12:05.012).assume_utc();
        let dt_str = dt.format(format_description!(
            "[hour repr:12]:[minute] [period] [weekday], [day padding:none] [month repr:short], \
             [year]"
        ))?;
        assert_eq!(dt_str, String::from("01:12 PM Saturday, 1 May, 2021"));

        let dt_str = dt.format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second]Z"
        ))?;
        assert_eq!(dt_str, String::from("2021-05-01T13:12:05Z"));
        Ok(())
    }
}
