use anyhow::{Context, Error};
use chrono::Utc;
use futures::{future::try_join_all, try_join};
use itertools::Itertools;
use refinery::embed_migrations;
use stack_string::{format_sstr, StackString};
use std::{
    collections::{BTreeSet, HashMap},
    fmt::Write,
};
use stdout_channel::StdoutChannel;
use structopt::StructOpt;
use tokio::task::spawn_blocking;
use uuid::Uuid;

use auth_server_ext::{
    send_invitation,
    ses_client::{SesInstance, Statistics},
};
use auth_server_lib::{
    auth_user_config::AuthUserConfig, config::Config, invitation::Invitation, pgpool::PgPool,
    session::Session, session_data::SessionData, user::User,
};
use authorized_users::{AuthorizedUser, AUTHORIZED_USERS};

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
    RmInvites {
        #[structopt(short = "u", long)]
        ids: Vec<Uuid>,
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
        invitation_id: Uuid,
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
    /// List Sessions
    ListSessions {
        #[structopt(short, long)]
        email: Option<StackString>,
    },
    ListSessionData {
        #[structopt(short, long)]
        id: Option<Uuid>,
    },
    /// Delete Sessions
    RmSessions {
        #[structopt(short, long)]
        ids: Vec<Uuid>,
    },
}

impl AuthServerOptions {
    #[allow(clippy::too_many_lines)]
    pub async fn process_args(
        self,
        pool: &PgPool,
        stdout: &StdoutChannel<StackString>,
    ) -> Result<(), Error> {
        let config = Config::init_config()?;
        match self {
            AuthServerOptions::List => {
                let auth_app_map = get_auth_user_app_map(&config)
                    .await
                    .context("Failed to get auth_user_app_map")?;

                for user in User::get_authorized_users(pool)
                    .await
                    .context("Failed to get_authorized_users")?
                {
                    stdout.send(format_sstr!(
                        "{} {}",
                        user.email,
                        auth_app_map
                            .get(&user.email)
                            .map_or_else(String::new, |apps| apps.iter().join(" "))
                    ));
                }
            }
            AuthServerOptions::ListInvites => {
                for invite in Invitation::get_all(pool)
                    .await
                    .context("Failed to get_all")?
                {
                    stdout
                        .send(serde_json::to_string(&invite).with_context(|| {
                            format_sstr!("Failed to parse invite {:?}", invite)
                        })?);
                }
            }
            AuthServerOptions::SendInvite { email } => {
                let ses = SesInstance::new(None);
                let invitation = Invitation::from_email(email.clone());
                invitation
                    .insert(pool)
                    .await
                    .context("Failed to insert invitation")?;
                send_invitation(
                    &ses,
                    &invitation,
                    &config.sending_email_address,
                    &config.callback_url,
                )
                .await
                .with_context(|| {
                    format_sstr!(
                        "Failed to send invitation {} {}",
                        config.sending_email_address,
                        config.callback_url.as_str()
                    )
                })?;
                stdout.send(format_sstr!(
                    "Invitation {} sent to {}",
                    invitation.id,
                    email
                ));
            }
            AuthServerOptions::RmInvites { ids } => {
                for id in ids {
                    if let Some(invitation) = Invitation::get_by_uuid(id, pool)
                        .await
                        .with_context(|| format_sstr!("Failed to get id {}", id))?
                    {
                        invitation
                            .delete(pool)
                            .await
                            .with_context(|| format_sstr!("Failed to delete {}", invitation.id))?;
                    }
                }
            }
            AuthServerOptions::Add { email, password } => {
                if User::get_by_email(email.clone(), pool)
                    .await
                    .with_context(|| format_sstr!("failed to get_by_email {}", email))?
                    .is_none()
                {
                    let user = User::from_details(email, password);
                    user.insert(pool)
                        .await
                        .with_context(|| format_sstr!("Failed to insert {:?}", user))?;
                    stdout.send(format_sstr!("Add user {}", user.email));
                } else {
                    stdout.send(format_sstr!("User {} exists", email));
                }
            }
            AuthServerOptions::Rm { email } => {
                for session in Session::get_by_email(pool, email.clone())
                    .await
                    .with_context(|| format_sstr!("failed to get sessions by email {}", email))?
                {
                    for session_data in session.get_all_session_data(pool).await? {
                        session_data.delete(pool).await?;
                    }
                    session.delete(pool).await?;
                }
                if let Some(user) = User::get_by_email(email.clone(), pool)
                    .await
                    .with_context(|| format_sstr!("failed to get_by_email {}", email))?
                {
                    user.delete(pool)
                        .await
                        .with_context(|| format_sstr!("Failed to delete {:?}", user))?;
                    stdout.send(format_sstr!("Deleted user {}", user.email));
                } else {
                    stdout.send(format_sstr!("User {} does not exist", email));
                }
            }
            AuthServerOptions::Register {
                invitation_id,
                password,
            } => {
                if let Some(invitation) = Invitation::get_by_uuid(invitation_id, pool)
                    .await
                    .with_context(|| format_sstr!("Failed to get id {}", invitation_id))?
                {
                    if invitation.expires_at > Utc::now() {
                        let user = User::from_details(invitation.email.clone(), password);
                        user.upsert(pool).await?;
                        invitation.delete(pool).await?;
                        let user: AuthorizedUser = user.into();
                        AUTHORIZED_USERS.store_auth(user.clone(), true)?;
                        stdout.send(serde_json::to_string(&user)?);
                    } else {
                        invitation.delete(pool).await?;
                    }
                }
            }
            AuthServerOptions::Change { email, password } => {
                if let Some(mut user) = User::get_by_email(email.clone(), pool).await? {
                    user.set_password(password);
                    user.update(pool).await?;
                    stdout.send(format_sstr!("Password updated for {}", email));
                } else {
                    stdout.send(format_sstr!("User {} does not exist", email));
                }
            }
            AuthServerOptions::Verify { email, password } => {
                if let Some(user) = User::get_by_email(email.clone(), pool).await? {
                    let password = password.clone();
                    if spawn_blocking(move || user.verify_password(&password)).await?? {
                        stdout.send("Password correct");
                    } else {
                        stdout.send("Password incorrect");
                    }
                } else {
                    stdout.send(format_sstr!("User {} does not exist", email));
                }
            }
            AuthServerOptions::Status => {
                let ses = SesInstance::new(None);
                let (number_users, number_invitations, Statistics { quotas, stats }) = try_join!(
                    User::get_number_users(pool),
                    Invitation::get_number_invitations(pool),
                    ses.get_statistics(),
                )?;
                stdout.send(format_sstr!(
                    "Users: {}\nInvitations: {}\n",
                    number_users,
                    number_invitations
                ));
                stdout.send(format_sstr!("{:#?}", quotas));
                stdout.send(format_sstr!("{:#?}", stats,));
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
            }
            AuthServerOptions::RunMigrations => {
                let mut client = pool.get().await?;
                migrations::runner().run_async(&mut **client).await?;
            }
            AuthServerOptions::ListSessions { email } => {
                let sessions = if let Some(email) = email {
                    Session::get_by_email(pool, email).await?
                } else {
                    Session::get_all_sessions(pool).await?
                };
                for session in sessions {
                    stdout.send(serde_json::to_string(&session)?);
                }
            }
            AuthServerOptions::ListSessionData { id } => {
                if let Some(id) = id {
                    if let Some(session_obj) = Session::get_session(pool, id).await? {
                        for session_data in session_obj.get_all_session_data(pool).await? {
                            stdout.send(serde_json::to_string(&session_data)?);
                        }
                    }
                } else {
                    for session_data in SessionData::get_all_session_data(pool).await? {
                        stdout.send(serde_json::to_string(&session_data)?);
                    }
                }
            }
            AuthServerOptions::RmSessions { ids } => {
                for id in ids {
                    if let Some(session) = Session::get_session(pool, id).await? {
                        for session_data in session.get_all_session_data(pool).await? {
                            session_data.delete(pool).await?;
                        }
                        session.delete(pool).await?;
                    }
                }
            }
        }
        Ok(())
    }
}

async fn get_auth_user_app_map(
    config: &Config,
) -> Result<HashMap<StackString, BTreeSet<StackString>>, Error> {
    if let Ok(auth_user_config) = AuthUserConfig::new(&config.auth_user_config_path) {
        let futures = auth_user_config.into_iter().map(|(key, val)| async move {
            val.get_authorized_users().await.map(|users| (key, users))
        });
        let results: Result<Vec<_>, Error> = try_join_all(futures).await;

        let auth_app_map: HashMap<_, BTreeSet<_>> =
            results?
                .into_iter()
                .fold(HashMap::new(), |mut h, (key, users)| {
                    for user in users {
                        h.entry(user).or_default().insert(key.clone());
                    }
                    h
                });
        Ok(auth_app_map)
    } else {
        Ok(HashMap::default())
    }
}

#[allow(clippy::missing_panics_doc)]
#[allow(clippy::missing_errors_doc)]
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
    use log::debug;
    use rand::{
        distributions::{Alphanumeric, DistString},
        thread_rng,
    };
    use stack_string::format_sstr;
    use std::{collections::HashSet, fmt::Write};
    use stdout_channel::{MockStdout, StdoutChannel};
    use uuid::Uuid;

    use auth_server_lib::{
        config::Config, invitation::Invitation, pgpool::PgPool, user::User, AUTH_APP_MUTEX,
    };

    use crate::AuthServerOptions;

    pub fn get_random_string(n: usize) -> String {
        let mut rng = thread_rng();
        Alphanumeric.sample_string(&mut rng, n)
    }

    #[tokio::test]
    async fn test_process_args() -> Result<(), Error> {
        let _lock = AUTH_APP_MUTEX.lock().await;
        let config = Config::init_config()?;
        let pool = PgPool::new(&config.database_url);
        let email = format_sstr!("ddboline+{}@gmail.com", get_random_string(32));
        let password = get_random_string(32);

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        AuthServerOptions::SendInvite {
            email: email.clone().into(),
        }
        .process_args(&pool, &stdout)
        .await?;
        stdout.close().await?;
        let invitation_uuid: Uuid = mock_stdout.lock().await[0]
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()?;
        let invitation = Invitation::get_by_uuid(invitation_uuid, &pool)
            .await?
            .unwrap();

        let invitations: HashSet<_> = Invitation::get_all(&pool).await?.into_iter().collect();

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        AuthServerOptions::ListInvites
            .process_args(&pool, &stdout)
            .await?;

        stdout.close().await?;

        assert_eq!(mock_stderr.lock().await.len(), 0);
        assert_eq!(mock_stdout.lock().await.len(), invitations.len());
        let mut stdout_invitations = HashSet::new();
        for line in mock_stdout.lock().await.iter() {
            let inv: Invitation = serde_json::from_str(line.as_str())?;
            stdout_invitations.insert(inv.id);
        }
        debug!("invitation {:?}", stdout_invitations);
        debug!("invitation {:?}", invitation);
        assert!(stdout_invitations.contains(&invitation.id));

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        debug!("start register");
        AuthServerOptions::Register {
            invitation_id: invitation.id,
            password: password.into(),
        }
        .process_args(&pool, &stdout)
        .await?;

        stdout.close().await?;

        assert_eq!(mock_stderr.lock().await.len(), 0);
        assert_eq!(mock_stdout.lock().await.len(), 1);
        debug!("{} {}", email, mock_stdout.lock().await.join("\n"));
        assert!(mock_stdout.lock().await[0].contains(email.as_str()));

        let users = User::get_authorized_users(&pool).await?;

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        debug!("start list");
        AuthServerOptions::List.process_args(&pool, &stdout).await?;

        stdout.close().await?;

        assert_eq!(mock_stderr.lock().await.len(), 0);
        assert_eq!(mock_stdout.lock().await.len(), users.len());
        debug!("list users {:?}", mock_stdout.lock().await);

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        let password = get_random_string(32);
        AuthServerOptions::Change {
            email: email.clone().into(),
            password: password.clone().into(),
        }
        .process_args(&pool, &stdout)
        .await?;

        stdout.close().await?;

        assert_eq!(mock_stderr.lock().await.len(), 0);
        assert!(mock_stdout
            .lock()
            .await
            .join("")
            .contains("Password updated"));
        debug!("change pwd {:?}", mock_stdout.lock().await);

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        AuthServerOptions::Verify {
            email: email.clone().into(),
            password: password.into(),
        }
        .process_args(&pool, &stdout)
        .await?;

        stdout.close().await?;

        assert_eq!(mock_stderr.lock().await.len(), 0);
        let result = mock_stdout.lock().await.join("\n");
        debug!("verify {}", result);
        assert!(result.contains("Password correct"));

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        AuthServerOptions::Rm {
            email: email.into(),
        }
        .process_args(&pool, &stdout)
        .await?;

        stdout.close().await?;

        assert_eq!(mock_stderr.lock().await.len(), 0);
        assert!(mock_stdout.lock().await[0].contains("Deleted user"));

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());
        AuthServerOptions::Status
            .process_args(&pool, &stdout)
            .await?;

        stdout.close().await?;

        assert_eq!(mock_stderr.lock().await.len(), 0);
        assert!(mock_stdout.lock().await.join("").contains("EmailStats"));

        let email = format_sstr!("ddboline+{}@gmail.com", get_random_string(32));
        let password = get_random_string(32);

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        AuthServerOptions::Add {
            email: email.clone().into(),
            password: password.into(),
        }
        .process_args(&pool, &stdout)
        .await?;
        stdout.close().await?;

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        AuthServerOptions::AddToApp {
            email: email.clone().into(),
            app: "movie_collection_rust".into(),
        }
        .process_args(&pool, &stdout)
        .await?;
        stdout.close().await?;

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        AuthServerOptions::RemoveFromApp {
            email: email.clone().into(),
            app: "movie_collection_rust".into(),
        }
        .process_args(&pool, &stdout)
        .await?;
        stdout.close().await?;

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        AuthServerOptions::Rm {
            email: email.clone().into(),
        }
        .process_args(&pool, &stdout)
        .await?;
        stdout.close().await?;

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        AuthServerOptions::SendInvite {
            email: email.clone().into(),
        }
        .process_args(&pool, &stdout)
        .await?;
        stdout.close().await?;
        let invitation_uuid: Uuid = mock_stdout.lock().await[0]
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()?;

        AuthServerOptions::RmInvites {
            ids: vec![invitation_uuid.clone()],
        }
        .process_args(&pool, &stdout)
        .await?;
        stdout.close().await?;
        assert!(Invitation::get_by_uuid(invitation_uuid, &pool)
            .await?
            .is_none());

        Ok(())
    }
}
