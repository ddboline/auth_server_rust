use anyhow::Error;
use stack_string::StackString;
use structopt::StructOpt;

use auth_server_rust::app::CONFIG;
use auth_server_rust::pgpool::PgPool;
use auth_server_rust::user::User;

#[derive(StructOpt, Debug)]
enum AuthServerOptions {
    List,
    Add {
        #[structopt(short="u", long)]
        email: StackString,
        #[structopt(short, long)]
        password: StackString
    },
    Rm {
        #[structopt(short="u", long)]
        email: StackString
    },
    Change {
        #[structopt(short="u", long)]
        email: StackString,
        #[structopt(short, long)]
        password: StackString,
        #[structopt(short, long)]
        new_password: StackString,
    },
    Verify {
        #[structopt(short="u", long)]
        email: StackString,
        #[structopt(short, long)]
        password: StackString,
    },
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
        AuthServerOptions::Add {email, password} => {
            if User::get_by_email(&email, &pool).await?.is_none() {
                let user = User::from_details(&email, &password);
                user.insert(&pool).await?;
                println!("Add user {}", user.email);
            } else {
                println!("User {} exists", email);
            }
        }
        AuthServerOptions::Rm {email} => {
            if let Some(user) = User::get_by_email(&email, &pool).await? {
                user.delete(&pool).await?;
                println!("Deleted user {}", user.email);
            } else {
                println!("User {} does not exist", email);
            }
        }
        AuthServerOptions::Change {email, password, new_password} => {
            if let Some(mut user) = User::get_by_email(&email, &pool).await? {
                if user.verify_password(&password)? {
                    user.set_password(&new_password);
                    user.update(&pool).await?;
                    println!("Password updated for {}", email);
                } else {
                    println!("Incorrect password");
                }
            } else {
                println!("User {} does not exist", email);
            }
        }
        AuthServerOptions::Verify {email, password} => {
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