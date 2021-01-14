use anyhow::Error;
use chrono::Utc;
use futures::{future::try_join_all, try_join};
use itertools::Itertools;
use stack_string::StackString;
use std::collections::{BTreeSet, HashMap};
use stdout_channel::StdoutChannel;
use structopt::StructOpt;
use uuid::Uuid;
use refinery::embed_migrations;

use authorized_users::{AuthorizedUser, AUTHORIZED_USERS};

use auth_server_lib::{
    auth_user_config::AuthUserConfig, config::Config, pgpool::PgPool, user::User,
};

use crate::{invitation::Invitation, ses_client::SesInstance};

embed_migrations!("../migrations");

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
    RunMigrations,
}

impl AuthServerOptions {
    #[allow(clippy::too_many_lines)]
    pub async fn process_args(&self, pool: &PgPool, stdout: &StdoutChannel) -> Result<(), Error> {
        let config = Config::init_config()?;
        match self {
            AuthServerOptions::List => {
                let auth_app_map = get_auth_user_app_map(&config).await?;

                for user in User::get_authorized_users(&pool).await? {
                    stdout.send(format!(
                        "{} {}",
                        user.email,
                        auth_app_map
                            .get(&user.email)
                            .map_or_else(|| "".to_string(), |apps| apps.iter().join(" "))
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
                    .send_invitation(&config.sending_email_address, config.callback_url.as_str())
                    .await?;
                stdout.send(format!("Invitation {} sent to {}", invitation.id, email));
            }
            AuthServerOptions::RmInvite { id } => {
                if let Some(invitation) = Invitation::get_by_uuid(&id, &pool).await? {
                    invitation.delete(&pool).await?;
                }
            }
            AuthServerOptions::Add { email, password } => {
                if User::get_by_email(&email, &pool).await?.is_none() {
                    let user = User::from_details(&email, &password, &config);
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
                        let user = User::from_details(&invitation.email, password, &config);
                        user.upsert(&pool).await?;
                        invitation.delete(&pool).await?;
                        let user: AuthorizedUser = user.into();
                        AUTHORIZED_USERS.store_auth(user.clone(), true)?;
                        stdout.send(serde_json::to_string(&user)?);
                    } else {
                        invitation.delete(&pool).await?;
                    }
                }
            }
            AuthServerOptions::Change { email, password } => {
                if let Some(mut user) = User::get_by_email(&email, &pool).await? {
                    user.set_password(&password, &config);
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
                if let Ok(auth_user_config) = AuthUserConfig::new(&config.auth_user_config_path) {
                    if let Some(entry) = auth_user_config.get(app.as_str()) {
                        entry.add_user(email.as_str()).await?;
                    }
                }
            }
            AuthServerOptions::RemoveFromApp { email, app } => {
                if let Ok(auth_user_config) = AuthUserConfig::new(&config.auth_user_config_path) {
                    if let Some(entry) = auth_user_config.get(app.as_str()) {
                        entry.remove_user(email.as_str()).await?;
                    }
                }
            },
            RunMigrations => {
                let conn = pool.get_client().await?;
                migrations::runner().run_async(&mut conn).await?;
            }
        }
        Ok(())
    }
}

fn parse_uuid(s: &str) -> Result<Uuid, Error> {
    Uuid::parse_str(s).map_err(Into::into)
}

async fn get_auth_user_app_map(
    config: &Config,
) -> Result<HashMap<StackString, BTreeSet<StackString>>, Error> {
    let mut auth_app_map: HashMap<_, BTreeSet<_>> = HashMap::new();
    if let Ok(auth_user_config) = AuthUserConfig::new(&config.auth_user_config_path) {
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

pub async fn run_cli() -> Result<(), Error> {
    let opts = AuthServerOptions::from_args();
    let config = Config::init_config()?;
    let pool = PgPool::new(&config.database_url);
    let stdout = StdoutChannel::new();

    opts.process_args(&pool, &stdout).await?;
    stdout.close().await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use anyhow::Error;
    use rand::{thread_rng, Rng};
    use std::collections::HashSet;
    use stdout_channel::{MockStdout, StdoutChannel};
    use uuid::Uuid;

    use auth_server_lib::{config::Config, pgpool::PgPool, user::User, AUTH_APP_MUTEX};

    use crate::{auth_server_admin::AuthServerOptions, invitation::Invitation};

    pub fn get_random_string(n: usize) -> String {
        let mut rng = thread_rng();
        (0..)
            .filter_map(|_| {
                let c: char = (rng.gen::<u8>() & 0x7f).into();
                match c {
                    'A'..='Z' | 'a'..='z' | '0'..='9' => Some(c),
                    _ => None,
                }
            })
            .take(n)
            .collect()
    }

    #[tokio::test]
    async fn test_process_args() -> Result<(), Error> {
        let _lock = AUTH_APP_MUTEX.lock();
        let config = Config::init_config()?;
        let pool = PgPool::new(&config.database_url);
        let email = format!("ddboline+{}@gmail.com", get_random_string(32));
        let password = get_random_string(32);

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        let opts = AuthServerOptions::SendInvite {
            email: email.clone().into(),
        };
        opts.process_args(&pool, &stdout).await?;
        stdout.close().await?;
        let invitation_uuid: Uuid = mock_stdout.lock().await[0]
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()?;
        let invitation = Invitation::get_by_uuid(&invitation_uuid, &pool)
            .await?
            .unwrap();

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
        assert_eq!(mock_stdout.lock().await.len(), 1);
        println!("{} {}", email, mock_stdout.lock().await.join("\n"));
        assert!(mock_stdout.lock().await[0].contains(&email));

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

        let email = format!("ddboline+{}@gmail.com", get_random_string(32));
        let password = get_random_string(32);

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        let opts = AuthServerOptions::Add {
            email: email.clone().into(),
            password: password.into(),
        };
        opts.process_args(&pool, &stdout).await?;
        stdout.close().await?;

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        let opts = AuthServerOptions::AddToApp {
            email: email.clone().into(),
            app: "movie_collection_rust".into(),
        };
        opts.process_args(&pool, &stdout).await?;
        stdout.close().await?;

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        let opts = AuthServerOptions::RemoveFromApp {
            email: email.clone().into(),
            app: "movie_collection_rust".into(),
        };
        opts.process_args(&pool, &stdout).await?;
        stdout.close().await?;

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        let opts = AuthServerOptions::Rm {
            email: email.clone().into(),
        };
        opts.process_args(&pool, &stdout).await?;
        stdout.close().await?;

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        let opts = AuthServerOptions::SendInvite {
            email: email.clone().into(),
        };
        opts.process_args(&pool, &stdout).await?;
        stdout.close().await?;
        let invitation_uuid: Uuid = mock_stdout.lock().await[0]
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()?;

        let opts = AuthServerOptions::RmInvite {
            id: invitation_uuid.clone(),
        };
        opts.process_args(&pool, &stdout).await?;
        stdout.close().await?;
        assert!(Invitation::get_by_uuid(&invitation_uuid, &pool)
            .await?
            .is_none());

        Ok(())
    }
}
