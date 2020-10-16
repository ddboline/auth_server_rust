use anyhow::Error;
use futures::try_join;
use stack_string::StackString;
use structopt::StructOpt;
use uuid::Uuid;

use auth_server_rust::stdout_channel::StdoutChannel;
use auth_server_rust::{
    app::CONFIG, invitation::Invitation, pgpool::PgPool, ses_client::SesInstance, user::User,
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
                    stdout.send(format!("{:?}", invite));
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
                        stdout.send(format!("Password correct"));
                    } else {
                        stdout.send(format!("Password incorrect"));
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
