use actix_identity::{CookieIdentityPolicy, IdentityService};
use actix_web::{web, App, HttpServer};
use anyhow::Error;
use lazy_static::lazy_static;
use rand::{thread_rng, Rng};
use stack_string::StackString;
use std::time::Duration;
use tokio::{task::spawn, time::interval};

use crate::{
    config::Config,
    google_openid::GoogleClient,
    logged_user::{
        create_secret, fill_auth_from_db, get_secrets, update_secret, KEY_LENGTH, SECRET_KEY,
    },
    pgpool::PgPool,
    routes::{
        auth_url, callback, change_password_user, get_me, login, logout, register_email,
        register_user,
    },
    static_files::{change_password, index_html, login_html, main_css, main_js, register_html},
};

lazy_static! {
    pub static ref CONFIG: Config = Config::init_config().expect("Failed to init config");
}

pub fn get_random_string(n: usize) -> String {
    (0..)
        .filter_map(|_| {
            let c: char = thread_rng().gen::<u8>().into();
            match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' => Some(c),
                _ => None,
            }
        })
        .take(n)
        .collect()
}

async fn update_secrets() -> Result<(), Error> {
    update_secret(&CONFIG.jwt_secret_path, Some(24 * 3600)).await
}

pub struct AppState {
    pub pool: PgPool,
}

pub async fn start_app() -> Result<(), Error> {
    if !CONFIG.secret_path.exists() {
        create_secret(&CONFIG.secret_path).await?;
    }
    update_secrets().await?;
    run_app(CONFIG.port, SECRET_KEY.load(), CONFIG.domain.clone()).await
}

async fn run_app(
    port: u32,
    cookie_secret: [u8; KEY_LENGTH],
    domain: StackString,
) -> Result<(), Error> {
    async fn _update_db(pool: PgPool) {
        let mut i = interval(Duration::from_secs(60));
        loop {
            let p = pool.clone();
            fill_auth_from_db(&p).await.unwrap_or(());
            i.tick().await;
        }
    }

    get_secrets(&CONFIG.secret_path, &CONFIG.jwt_secret_path).await?;
    let google_client = GoogleClient::new().await?;
    let pool = PgPool::new(&CONFIG.database_url);

    spawn(_update_db(pool.clone()));

    HttpServer::new(move || {
        App::new()
            .data(google_client.clone())
            .data(AppState { pool: pool.clone() })
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&cookie_secret)
                    .name("auth")
                    .path("/")
                    .domain(domain.as_str())
                    .max_age(CONFIG.expiration_seconds)
                    .secure(false),
            ))
            .service(
                web::scope("/api")
                    .service(
                        web::resource("/auth")
                            .route(web::post().to(login))
                            .route(web::delete().to(logout))
                            .route(web::get().to(get_me)),
                    )
                    .service(web::resource("/invitation").route(web::post().to(register_email)))
                    .service(
                        web::resource("/register/{invitation_id}")
                            .route(web::post().to(register_user)),
                    )
                    .service(
                        web::resource("/password_change")
                            .route(web::post().to(change_password_user)),
                    )
                    .service(web::resource("/auth_url").route(web::post().to(auth_url)))
                    .service(web::resource("/callback").route(web::get().to(callback))),
            )
            .service(
                web::scope("/auth")
                    .service(web::resource("/index.html").route(web::get().to(index_html)))
                    .service(web::resource("/main.css").route(web::get().to(main_css)))
                    .service(web::resource("/main.js").route(web::get().to(main_js)))
                    .service(web::resource("/register.html").route(web::get().to(register_html)))
                    .service(web::resource("/login.html").route(web::get().to(login_html)))
                    .service(
                        web::resource("/change_password.html")
                            .route(web::get().to(change_password)),
                    ),
            )
    })
    .bind(&format!("localhost:{}", port))?
    .run()
    .await
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use anyhow::Error;
    use maplit::hashmap;

    use crate::{
        app::{get_random_string, run_app, CONFIG},
        invitation::Invitation,
        logged_user::{get_random_key, LoggedUser, KEY_LENGTH},
        pgpool::PgPool,
        user::User,
    };

    #[test]
    fn test_get_random_string() -> Result<(), Error> {
        let rs = get_random_string(32);
        println!("{}", rs);
        assert_eq!(rs.len(), 32);
        Ok(())
    }

    #[actix_rt::test]
    #[ignore]
    async fn test_create_user() -> Result<(), Error> {
        let pool = PgPool::new(&CONFIG.database_url);
        let email = format!("{}@localhost", get_random_string(32));
        let password = get_random_string(32);
        let invitation = Invitation::from_email(&email);
        let uuid = invitation.id.clone().to_string();
        invitation.insert(&pool).await?;

        let mut secret_key = [0u8; KEY_LENGTH];
        secret_key.copy_from_slice(&get_random_key());
        let test_port = 12345;
        actix_rt::spawn(async move {
            run_app(test_port, secret_key, "localhost".into())
                .await
                .unwrap()
        });

        tokio::time::delay_for(tokio::time::Duration::from_secs(10)).await;

        let url = format!("http://localhost:{}/api/register/{}", test_port, uuid);
        let data = hashmap! {
            "password" => &password,
        };

        let client = reqwest::Client::builder().cookie_store(true).build()?;
        println!("register");
        let resp: LoggedUser = client
            .post(&url)
            .json(&data)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        println!("registered {:?}", resp);
        assert_eq!(resp.email.as_str(), email.as_str());

        assert!(Invitation::get_by_uuid(&uuid, &pool).await?.is_none());

        let url = format!("http://localhost:{}/api/auth", test_port);
        let data = hashmap! {
            "email" => &email,
            "password" => &password,
        };
        println!("login");
        let resp: LoggedUser = client
            .post(&url)
            .json(&data)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        println!("logged in {:?}", resp);
        assert_eq!(resp.email.as_str(), email.as_str());

        println!("get me");
        let resp: LoggedUser = client
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        println!("I am: {:?}", resp);
        assert_eq!(resp.email.as_str(), email.as_str());

        let url = format!("http://localhost:{}/api/password_change", test_port);
        let new_password = get_random_string(32);
        let data = hashmap! {
            "email" => &email,
            "password" => &new_password,
        };
        println!("change password");
        let text = client
            .post(&url)
            .json(&data)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        println!("password changed {:?}", text);
        assert_eq!(text.as_str(), "password updated");

        let user = User::get_by_email(&email, &pool).await?.unwrap();
        assert!(user.verify_password(&new_password)?);

        user.delete(&pool).await?;
        assert_eq!(User::get_by_email(&email, &pool).await?, None);

        Ok(())
    }
}
