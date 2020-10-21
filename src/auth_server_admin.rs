use anyhow::Error;
use chrono::Utc;
use futures::future::try_join_all;
use futures::try_join;
use itertools::Itertools;
use stack_string::StackString;
use std::collections::{BTreeSet, HashMap};
use stdout_channel::StdoutChannel;
use structopt::StructOpt;
use uuid::Uuid;

use auth_server_rust::auth_user_config::AuthUserConfig;
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
    /// Add User to App
    AddToApp {
        #[structopt(short, long)]
        email: StackString,
        #[structopt(short, long)]
        app: StackString,
    },
    /// Remove User from App
    RemoveFromApp {
        #[structopt(short, long)]
        email: StackString,
        #[structopt(short, long)]
        app: StackString,
    },
}

impl AuthServerOptions {
    pub async fn process_args(&self, pool: &PgPool, stdout: &StdoutChannel) -> Result<(), Error> {
        match self {
            AuthServerOptions::List => {
                let auth_app_map = get_auth_user_app_map().await?;

                for user in User::get_authorized_users(&pool).await? {
                    stdout.send(format!(
                        "{} {}",
                        user.email,
                        if let Some(apps) = auth_app_map.get(&user.email) {
                            apps.iter().join(" ")
                        } else {
                            "".to_string()
                        }
                    ));
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
            AuthServerOptions::AddToApp { email, app } => {
                if let Ok(auth_user_config) = AuthUserConfig::new(&CONFIG.auth_user_config_path) {
                    if let Some(entry) = auth_user_config.get(app.as_str()) {
                        entry.add_user(email.as_str()).await?;
                    }
                }
            }
            AuthServerOptions::RemoveFromApp { email, app } => {
                if let Ok(auth_user_config) = AuthUserConfig::new(&CONFIG.auth_user_config_path) {
                    if let Some(entry) = auth_user_config.get(app.as_str()) {
                        entry.remove_user(email.as_str()).await?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn parse_uuid(s: &str) -> Result<Uuid, Error> {
    Uuid::parse_str(s).map_err(Into::into)
}

async fn get_auth_user_app_map() -> Result<HashMap<StackString, BTreeSet<StackString>>, Error> {
    let mut auth_app_map: HashMap<_, BTreeSet<_>> = HashMap::new();
    if let Ok(auth_user_config) = AuthUserConfig::new(&CONFIG.auth_user_config_path) {
        let futures = auth_user_config.into_iter().map(|(key, val)| async move {
            val.get_authorized_users().await.map(|users| (key, users))
        });
        let results: Result<Vec<_>, Error> = try_join_all(futures).await;
        for (key, users) in results? {
            for user in users {
                auth_app_map.entry(user).or_default().insert(key.clone());
            }
        }
    }
    Ok(auth_app_map)
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
        println!("invitation {:?}", stdout_invitations);
        println!("invitation {:?}", invitation);
        assert!(stdout_invitations.contains(&invitation.id));

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        println!("start register");
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

        println!("start list");
        let opts = AuthServerOptions::List;
        opts.process_args(&pool, &stdout).await?;

        stdout.close().await?;

        assert_eq!(mock_stderr.lock().await.len(), 0);
        assert_eq!(mock_stdout.lock().await.len(), users.len());
        println!("list users {:?}", mock_stdout.lock().await);

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
        println!("change pwd {:?}", mock_stdout.lock().await);

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
        println!("verify {}", result);
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
