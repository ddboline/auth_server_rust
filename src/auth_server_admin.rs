use anyhow::Error;
use chrono::Utc;
use futures::try_join;
use stack_string::StackString;
use stdout_channel::StdoutChannel;
use structopt::StructOpt;
use uuid::Uuid;

use auth_server_rust::{
    app::CONFIG,
    invitation::Invitation,
    logged_user::{LoggedUser, AUTHORIZED_USERS},
    pgpool::PgPool,
    ses_client::SesInstance,
    user::User,
};

#[derive(StructOpt, Debug)]
enum AuthServerOptions {
    /// List user email addresses
    List,
    /// List invitations
    ListInvites,
    SendInvite {
        #[structopt(short = "u", long)]
        email: StackString,
    },
    RmInvite {
        #[structopt(short="u", long, parse(try_from_str=parse_uuid))]
        id: Uuid,
    },
    /// Add new user
    Add {
        #[structopt(short = "u", long)]
        email: StackString,
        #[structopt(short, long)]
        password: StackString,
    },
    /// Remove user
    Rm {
        #[structopt(short = "u", long)]
        email: StackString,
    },
    /// Register
    Register {
        #[structopt(short, long)]
        invitation_id: StackString,
        #[structopt(short, long)]
        password: StackString,
    },
    /// Change password
    Change {
        #[structopt(short = "u", long)]
        email: StackString,
        #[structopt(short, long)]
        password: StackString,
    },
    /// Verify password
    Verify {
        #[structopt(short = "u", long)]
        email: StackString,
        #[structopt(short, long)]
        password: StackString,
    },
    /// Get Status of Server / Ses
    Status,
}

impl AuthServerOptions {
    pub async fn process_args(&self, pool: &PgPool, stdout: &StdoutChannel) -> Result<(), Error> {
        match self {
            AuthServerOptions::List => {
                for user in User::get_authorized_users(&pool).await? {
                    stdout.send(format!("{}", user.email));
                }
            }
            AuthServerOptions::ListInvites => {
                for invite in Invitation::get_all(&pool).await? {
                    stdout.send(serde_json::to_string(&invite)?);
                }
            }
            AuthServerOptions::SendInvite { email } => {
                let invitation = Invitation::from_email(&email);
                invitation.insert(&pool).await?;
                invitation
                    .send_invitation(&CONFIG.callback_url.as_str())
                    .await?;
                stdout.send(format!("Invitation sent to {}", email));
            }
            AuthServerOptions::RmInvite { id } => {
                if let Some(invitation) = Invitation::get_by_uuid(&id, &pool).await? {
                    invitation.delete(&pool).await?;
                }
            }
            AuthServerOptions::Add { email, password } => {
                if User::get_by_email(&email, &pool).await?.is_none() {
                    let user = User::from_details(&email, &password);
                    user.insert(&pool).await?;
                    stdout.send(format!("Add user {}", user.email));
                } else {
                    stdout.send(format!("User {} exists", email));
                }
            }
            AuthServerOptions::Rm { email } => {
                if let Some(user) = User::get_by_email(&email, &pool).await? {
                    user.delete(&pool).await?;
                    stdout.send(format!("Deleted user {}", user.email));
                } else {
                    stdout.send(format!("User {} does not exist", email));
                }
            }
            AuthServerOptions::Register {
                invitation_id,
                password,
            } => {
                let uuid = Uuid::parse_str(invitation_id)?;
                if let Some(invitation) = Invitation::get_by_uuid(&uuid, &pool).await? {
                    if invitation.expires_at > Utc::now() {
                        let user = User::from_details(&invitation.email, password);
                        user.upsert(&pool).await?;
                        invitation.delete(&pool).await?;
                        let user: LoggedUser = user.into();
                        AUTHORIZED_USERS.store_auth(user.clone(), true)?;
                        stdout.send(serde_json::to_string(&user)?);
                    } else {
                        invitation.delete(&pool).await?;
                    }
                }
            }
            AuthServerOptions::Change { email, password } => {
                if let Some(mut user) = User::get_by_email(&email, &pool).await? {
                    user.set_password(&password);
                    user.update(&pool).await?;
                    stdout.send(format!("Password updated for {}", email));
                } else {
                    stdout.send(format!("User {} does not exist", email));
                }
            }
            AuthServerOptions::Verify { email, password } => {
                if let Some(user) = User::get_by_email(&email, &pool).await? {
                    if user.verify_password(&password)? {
                        stdout.send("Password correct".to_string());
                    } else {
                        stdout.send("Password incorrect".to_string());
                    }
                } else {
                    stdout.send(format!("User {} does not exist", email));
                }
            }
            AuthServerOptions::Status => {
                let ses = SesInstance::new(None);
                let (number_users, number_invitations, (quota, stats)) = try_join!(
                    User::get_number_users(&pool),
                    Invitation::get_number_invitations(&pool),
                    ses.get_statistics(),
                )?;
                stdout.send(format!(
                    "Users: {}\nInvitations: {}\n",
                    number_users, number_invitations
                ));
                stdout.send(format!("{:#?}", quota));
                stdout.send(format!("{:#?}", stats,));
            }
        }
        Ok(())
    }
}

fn parse_uuid(s: &str) -> Result<Uuid, Error> {
    Uuid::parse_str(s).map_err(Into::into)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let opts = AuthServerOptions::from_args();
    let pool = PgPool::new(&CONFIG.database_url);
    let stdout = StdoutChannel::new();

    opts.process_args(&pool, &stdout).await?;
    stdout.close().await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use anyhow::Error;
    use std::collections::HashSet;
    use stdout_channel::{MockStdout, StdoutChannel};

    use auth_server_rust::{
        app::get_random_string, invitation::Invitation, pgpool::PgPool, user::User,
    };

    use super::{AuthServerOptions, CONFIG};

    #[tokio::test]
    async fn test_process_args() -> Result<(), Error> {
        let pool = PgPool::new(&CONFIG.database_url);
        let email = format!("{}@localhost", get_random_string(32));
        let password = get_random_string(32);
        let invitation = Invitation::from_email(&email);
        invitation.insert(&pool).await?;

        let invitations: HashSet<_> = Invitation::get_all(&pool).await?.into_iter().collect();

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        let opts = AuthServerOptions::ListInvites;
        opts.process_args(&pool, &stdout).await?;

        stdout.close().await?;

        assert_eq!(mock_stderr.lock().await.len(), 0);
        assert_eq!(mock_stdout.lock().await.len(), invitations.len());
        let mut stdout_invitations = HashSet::new();
        for line in mock_stdout.lock().await.iter() {
            let inv: Invitation = serde_json::from_str(line.as_str())?;
            stdout_invitations.insert(inv.id);
        }
        println!("{:?}", stdout_invitations);
        println!("{:?}", invitation);
        assert!(stdout_invitations.contains(&invitation.id));

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        let opts = AuthServerOptions::Register {
            invitation_id: invitation.id.to_string().into(),
            password: password.into(),
        };
        opts.process_args(&pool, &stdout).await?;

        stdout.close().await?;

        assert_eq!(mock_stderr.lock().await.len(), 0);
        assert_eq!(mock_stdout.lock().await.len(), invitations.len());

        let users = User::get_authorized_users(&pool).await?;

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        let opts = AuthServerOptions::List;
        opts.process_args(&pool, &stdout).await?;

        stdout.close().await?;

        assert_eq!(mock_stderr.lock().await.len(), 0);
        assert_eq!(mock_stdout.lock().await.len(), users.len());
        println!("{:?}", mock_stdout.lock().await);

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        let password = get_random_string(32);
        let opts = AuthServerOptions::Change {
            email: email.clone().into(),
            password: password.clone().into(),
        };
        opts.process_args(&pool, &stdout).await?;

        stdout.close().await?;

        assert_eq!(mock_stderr.lock().await.len(), 0);
        assert!(mock_stdout
            .lock()
            .await
            .join("")
            .contains("Password updated"));
        println!("{:?}", mock_stdout.lock().await);

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        let opts = AuthServerOptions::Verify {
            email: email.clone().into(),
            password: password.into(),
        };
        opts.process_args(&pool, &stdout).await?;

        stdout.close().await?;

        assert_eq!(mock_stderr.lock().await.len(), 0);
        let result = mock_stdout.lock().await.join("\n");
        println!("{}", result);
        assert!(result.contains("Password correct"));

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        let opts = AuthServerOptions::Rm {
            email: email.into(),
        };
        opts.process_args(&pool, &stdout).await?;

        stdout.close().await?;

        assert_eq!(mock_stderr.lock().await.len(), 0);
        assert!(mock_stdout.lock().await[0].contains("Deleted user"));

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());
        let opts = AuthServerOptions::Status;
        opts.process_args(&pool, &stdout).await?;

        stdout.close().await?;

        assert_eq!(mock_stderr.lock().await.len(), 0);
        assert!(mock_stdout.lock().await.join("").contains("EmailStats"));

        Ok(())
    }
}
