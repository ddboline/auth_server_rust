use anyhow::{Context, Error};
use clap::Parser;
use futures::{stream::FuturesUnordered, try_join, TryStreamExt};
use itertools::Itertools;
use refinery::embed_migrations;
use stack_string::{format_sstr, StackString};
use std::collections::{BTreeSet, HashMap};
use stdout_channel::StdoutChannel;
use time::OffsetDateTime;
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

#[derive(Parser, Debug)]
enum AuthServerOptions {
    /// List user email addresses
    List,
    /// List invitations
    ListInvites,
    SendInvite {
        #[clap(short = 'u', long)]
        email: StackString,
    },
    RmInvites {
        #[clap(short = 'u', long)]
        ids: Vec<Uuid>,
    },
    /// Add new user
    Add {
        #[clap(short = 'u', long)]
        email: StackString,
        #[clap(short, long)]
        password: StackString,
    },
    /// Remove user
    Rm {
        #[clap(short = 'u', long)]
        email: StackString,
    },
    /// Register
    Register {
        #[clap(short, long)]
        invitation_id: Uuid,
        #[clap(short, long)]
        password: StackString,
    },
    /// Change password
    Change {
        #[clap(short = 'u', long)]
        email: StackString,
        #[clap(short, long)]
        password: StackString,
    },
    /// Verify password
    Verify {
        #[clap(short = 'u', long)]
        email: StackString,
        #[clap(short, long)]
        password: StackString,
    },
    /// Get Status of Server / Ses
    Status,
    /// Add User to App
    AddToApp {
        #[clap(short, long)]
        email: StackString,
        #[clap(short, long)]
        app: StackString,
    },
    /// Remove User from App
    RemoveFromApp {
        #[clap(short, long)]
        email: StackString,
        #[clap(short, long)]
        app: StackString,
    },
    RunMigrations,
    /// List Sessions
    ListSessions {
        #[clap(short, long)]
        email: Option<StackString>,
    },
    ListSessionData {
        #[clap(short, long)]
        id: Option<Uuid>,
    },
    /// Delete Sessions
    RmSessions {
        #[clap(short, long)]
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
                let mut stream = Box::pin(
                    User::get_authorized_users(pool)
                        .await
                        .context("Failed to get_authorized_users")?,
                );
                while let Some(user) = stream.try_next().await? {
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
                let mut stream = Box::pin(Invitation::get_all_streaming(pool).await?);
                while let Some(invite) = stream.try_next().await? {
                    stdout.send(
                        serde_json::to_string(&invite)
                            .with_context(|| format_sstr!("Failed to parse invite {invite:?}"))?,
                    );
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
                        .with_context(|| format_sstr!("Failed to get id {id}"))?
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
                    .with_context(|| format_sstr!("failed to get_by_email {email}"))?
                    .is_none()
                {
                    let user = User::from_details(email, password);
                    user.insert(pool)
                        .await
                        .with_context(|| format_sstr!("Failed to insert {user:?}"))?;
                    stdout.send(format_sstr!("Add user {}", user.email));
                } else {
                    stdout.send(format_sstr!("User {email} exists"));
                }
            }
            AuthServerOptions::Rm { email } => {
                for session in Session::get_by_email(pool, email.clone())
                    .await
                    .with_context(|| format_sstr!("failed to get sessions by email {email}"))?
                {
                    for session_data in session.get_all_session_data(pool).await? {
                        session_data.delete(pool).await?;
                    }
                    session.delete(pool).await?;
                }
                if let Some(user) = User::get_by_email(email.clone(), pool)
                    .await
                    .with_context(|| format_sstr!("failed to get_by_email {email}"))?
                {
                    user.delete(pool)
                        .await
                        .with_context(|| format_sstr!("Failed to delete {user:?}"))?;
                    stdout.send(format_sstr!("Deleted user {}", user.email));
                } else {
                    stdout.send(format_sstr!("User {email} does not exist"));
                }
            }
            AuthServerOptions::Register {
                invitation_id,
                password,
            } => {
                if let Some(invitation) = Invitation::get_by_uuid(invitation_id, pool)
                    .await
                    .with_context(|| format_sstr!("Failed to get id {invitation_id}"))?
                {
                    if invitation.expires_at > OffsetDateTime::now_utc().into() {
                        let user = User::from_details(invitation.email.clone(), password);
                        user.upsert(pool).await?;
                        invitation.delete(pool).await?;
                        let user: AuthorizedUser = user.into();
                        AUTHORIZED_USERS.store_auth(user.clone(), true);
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
                    stdout.send(format_sstr!("Password updated for {email}"));
                } else {
                    stdout.send(format_sstr!("User {email} does not exist"));
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
                    stdout.send(format_sstr!("User {email} does not exist"));
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
                    "Users: {number_users}\nInvitations: {number_invitations}\n",
                ));
                stdout.send(format_sstr!("{quotas:#?}"));
                stdout.send(format_sstr!("{stats}"));
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
                    let mut stream = Box::pin(SessionData::get_all_session_data(pool).await?);
                    while let Some(session_data) = stream.try_next().await? {
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
        let futures: FuturesUnordered<_> =
            auth_user_config
                .into_iter()
                .map(|(key, val)| async move {
                    val.get_authorized_users().await.map(|users| (key, users))
                })
                .collect();

        let auth_app_map: HashMap<_, BTreeSet<_>> = futures
            .try_fold(
                HashMap::<_, BTreeSet<_>>::new(),
                |mut h, (key, users)| async move {
                    for user in users {
                        h.entry(user).or_default().insert(key.clone());
                    }
                    Ok(h)
                },
            )
            .await?;
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
    use futures::TryStreamExt;
    use log::debug;
    use rand::{
        distributions::{Alphanumeric, DistString},
        thread_rng,
    };
    use stack_string::format_sstr;
    use std::collections::HashSet;
    use stdout_channel::{MockStdout, StdoutChannel};
    use uuid::Uuid;

    use auth_server_lib::{
        config::Config, invitation::Invitation, pgpool::PgPool, session::Session, user::User,
        AUTH_APP_MUTEX,
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

        let result: Result<HashSet<_>, _> = Invitation::get_all_streaming(&pool)
            .await?
            .try_collect()
            .await;
        let invitations = result?;

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

        let result: Result<Vec<_>, _> =
            User::get_authorized_users(&pool).await?.try_collect().await;
        let users = result?;

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

        let user = User::from_details("test@example.com", "abc123");
        user.insert(&pool).await?;
        let session = Session::new("test@example.com");
        session.insert(&pool).await?;
        let session_data = session
            .set_session_data(&pool, "test", "TEST DATA".into())
            .await?;

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        AuthServerOptions::ListSessions {
            email: Some("test@example.com".into()),
        }
        .process_args(&pool, &stdout)
        .await?;
        stdout.close().await?;
        for line in mock_stdout.lock().await.iter() {
            assert!(line.contains("test@example.com"));
        }

        let mock_stdout = MockStdout::new();
        let mock_stderr = MockStdout::new();
        let stdout = StdoutChannel::with_mock_stdout(mock_stdout.clone(), mock_stderr.clone());

        AuthServerOptions::ListSessionData {
            id: Some(session_data.session_id),
        }
        .process_args(&pool, &stdout)
        .await?;
        stdout.close().await?;
        for line in mock_stdout.lock().await.iter() {
            assert!(line.contains("TEST DATA"));
        }

        AuthServerOptions::RmSessions {
            ids: vec![session_data.session_id],
        }
        .process_args(&pool, &stdout)
        .await?;
        stdout.close().await?;

        user.delete(&pool).await?;

        Ok(())
    }
}
