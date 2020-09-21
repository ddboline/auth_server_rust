use anyhow::Error;
use stack_string::StackString;
use structopt::StructOpt;
use uuid::Uuid;

use auth_server_rust::{app::CONFIG, invitation::Invitation, pgpool::PgPool, user::User};

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
}

fn parse_uuid(s: &str) -> Result<Uuid, Error> {
    Uuid::parse_str(s).map_err(Into::into)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let opts = AuthServerOptions::from_args();
    let pool = PgPool::new(&CONFIG.database_url);

    match opts {
        AuthServerOptions::List => {
            for user in User::get_authorized_users(&pool).await? {
                println!("{}", user.email);
            }
        }
        AuthServerOptions::ListInvites => {
            for invite in Invitation::get_all(&pool).await? {
                println!("{:?}", invite);
            }
        }
        AuthServerOptions::SendInvite { email } => {
            let invitation = Invitation::from_email(&email);
            invitation.insert(&pool).await?;
            invitation
                .send_invitation(&CONFIG.callback_url.as_str())
                .await?;
            println!("Invitation sent to {}", email);
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
                println!("Add user {}", user.email);
            } else {
                println!("User {} exists", email);
            }
        }
        AuthServerOptions::Rm { email } => {
            if let Some(user) = User::get_by_email(&email, &pool).await? {
                user.delete(&pool).await?;
                println!("Deleted user {}", user.email);
            } else {
                println!("User {} does not exist", email);
            }
        }
        AuthServerOptions::Change { email, password } => {
            if let Some(mut user) = User::get_by_email(&email, &pool).await? {
                user.set_password(&password);
                user.update(&pool).await?;
                println!("Password updated for {}", email);
            } else {
                println!("User {} does not exist", email);
            }
        }
        AuthServerOptions::Verify { email, password } => {
            if let Some(user) = User::get_by_email(&email, &pool).await? {
                if user.verify_password(&password)? {
                    println!("Password correct");
                } else {
                    println!("Password incorrect");
                }
            } else {
                println!("User {} does not exist", email);
            }
        }
    };
    Ok(())
}
