use actix_identity::{CookieIdentityPolicy, IdentityService};
use actix_web::{web, App, HttpServer};
use anyhow::Error;
use lazy_static::lazy_static;
use rand::{thread_rng, Rng};
use std::{path::Path, time::Duration};
use tokio::{task::spawn, time::interval};

use crate::{
    config::Config,
    google_openid::GoogleClient,
    logged_user::fill_auth_from_db,
    pgpool::PgPool,
    routes::{
        auth_url, callback, change_password_user, get_me, login, logout, register_email,
        register_user,
    },
    static_files::{change_password, index_html, login_html, main_css, main_js, register_html},
};

lazy_static! {
    pub static ref CONFIG: Config = Config::init_config().expect("Failed to init config");
    pub static ref SECRET_KEY: Vec<u8> =
        get_secret(&CONFIG.secret_path).expect("Failure reading secret file");
    pub static ref JWT_SECRET: Vec<u8> =
        get_secret(&CONFIG.jwt_secret_path).expect("Failure reading jwt secret file");
}

fn get_secret(p: &Path) -> Result<Vec<u8>, Error> {
    use std::fs::{read, write, File};
    if !p.exists() || File::open(p)?.metadata()?.created()?.elapsed()?.as_secs() > 7 * 24 * 3600 {
        let random_bytes: Vec<u8> = (0..32).map(|_| thread_rng().gen::<u8>()).collect();
        write(p, &random_bytes)?;
    }
    read(p).map_err(Into::into)
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

pub struct AppState {
    pub pool: PgPool,
}

pub async fn start_app() -> Result<(), Error> {
    async fn _update_db(pool: PgPool) {
        let mut i = interval(Duration::from_secs(60));
        loop {
            i.tick().await;
            let p = pool.clone();
            fill_auth_from_db(&p).await.unwrap_or(());
        }
    }
    let google_client = GoogleClient::new().await?;
    let pool = PgPool::new(&CONFIG.database_url);

    spawn(_update_db(pool.clone()));

    HttpServer::new(move || {
        App::new()
            .data(google_client.clone())
            .data(AppState { pool: pool.clone() })
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&SECRET_KEY)
                    .name("auth")
                    .path("/")
                    .domain(CONFIG.domain.as_str())
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
    .bind(&format!("127.0.0.1:{}", CONFIG.port))?
    .run()
    .await
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use anyhow::Error;

    use crate::app::get_random_string;

    #[test]
    fn test_get_random_string() -> Result<(), Error> {
        let rs = get_random_string(32);
        println!("{}", rs);
        assert_eq!(rs.len(), 32);
        Ok(())
    }
}
