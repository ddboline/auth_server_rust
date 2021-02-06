use anyhow::Error;
use lazy_static::lazy_static;
use log::debug;
use stack_string::StackString;
use std::sync::Arc;
use std::time::Duration;
use tokio::{task::spawn, time::interval};

use auth_server_ext::google_openid::GoogleClient;
use auth_server_lib::{
    config::Config,
    pgpool::PgPool,
    static_files::{change_password, index_html, login_html, main_css, main_js, register_html},
    user::User,
};
use authorized_users::{
    get_secrets, update_secret, AuthorizedUser, AUTHORIZED_USERS, KEY_LENGTH, SECRET_KEY,
    TRIGGER_DB_UPDATE,
};

use crate::errors::error_response;
use crate::routes::{
    auth_url, callback, change_password_user, get_me, login, logout, register_email, register_user,
    status, test_get_me, test_login, test_logout,
};

lazy_static! {
    pub static ref CONFIG: Config = Config::init_config().expect("Failed to init config");
}

async fn update_secrets() -> Result<(), Error> {
    update_secret(&CONFIG.secret_path).await?;
    update_secret(&CONFIG.jwt_secret_path).await
}

pub struct AppState {
    pub pool: PgPool,
    pub google_client: GoogleClient,
    pub secret: [u8; KEY_LENGTH],
}

pub async fn start_app() -> Result<(), Error> {
    update_secrets().await?;
    get_secrets(&CONFIG.secret_path, &CONFIG.jwt_secret_path).await?;
    run_app(CONFIG.port, SECRET_KEY.get(), CONFIG.domain.clone()).await
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

    let google_client = GoogleClient::new(&CONFIG).await?;
    let pool = PgPool::new(&CONFIG.database_url);

    spawn(_update_db(pool.clone()));

    let app = Arc::new(AppState {
        pool: pool.clone(),
        google_client: google_client.clone(),
        secret: cookie_secret,
    });

    let data = warp::any().map(move || app.clone());
    let cors = warp::cors()
        .allow_methods(vec!["GET", "POST", "DELETE"])
        .allow_header("content-type")
        .allow_header("authorization")
        .allow_any_origin()
        .build();

    let post = warp::post()
        .and(warp::path::end())
        .and(data.clone())
        .and(warp::body::json())
        .and(warp::addr::remote())
        .and_then(|data, auth_data, ip| async move { login(data, auth_data, ip) });

    let delete = warp::delete().and(logout);
    let get = warp::get().and(get_me);
    let auth_path = warp::path("auth").and(post.or(delete).or(get));
    let invitation_path = warp::path("invitation")
        .and(warp::post())
        .and(register_email);
    let register_path = warp::post().and(warp::path!("register" / StackString).map(register_user));
    let password_change_path = warp::path("password_change")
        .and(warp::post())
        .and(change_password_user);
    let auth_url_path = warp::path("auth_url").and(warp::post()).and(auth_url);
    let callback_path = warp::path("callback").and(warp::get()).and(callback);
    let status_path = warp::path("status").and(warp::get()).and(status);

    let api = warp::path("api").and(
        auth_path
            .or(invitation_path)
            .or(register_path)
            .or(password_change_path)
            .or(auth_url_path)
            .or(callback_path)
            .or(status_path),
    );

    let index_html_path = warp::path("index.html").and(warp::get()).and(index_html);
    let main_css_path = warp::path("main.css").and(warp::get()).and(main_css);
    let main_js_path = warp::path("main.js").and(warp::get()).and(main_js);
    let register_html_path = warp::path("register.html")
        .and(warp::get())
        .and(register_html);
    let login_html_path = warp::path("login.html").and(warp::get()).and(login_html);
    let change_password_path = warp::path("change_password.html")
        .and(warp::get())
        .and(change_password);
    let auth = warp::path("auth").and(
        index_html_path
            .or(main_css_path)
            .or(main_js_path)
            .or(register_html_path)
            .or(login_html_path)
            .or(change_password_path),
    );

    let routes = api.or(auth).recover(error_response).with(cors);

    warp::serve(routes)
        .bind(&format!("localhost:{}", port))
        .await;

    Ok(())
}

pub async fn run_test_app(
    port: u32,
    cookie_secret: [u8; KEY_LENGTH],
    domain: StackString,
) -> Result<(), Error> {
    let google_client = GoogleClient::new(&CONFIG).await?;
    let pool = PgPool::new(&CONFIG.database_url);

    let app = Arc::new(AppState {
        pool: pool.clone(),
        google_client: google_client.clone(),
        secret: cookie_secret,
    });

    let cors = warp::cors()
        .allow_methods(vec!["GET", "POST", "DELETE"])
        .allow_header("content-type")
        .allow_header("authorization")
        .allow_any_origin()
        .build();

    let post = warp::post().and(test_login);
    let delete = warp::delete().and(test_logout);
    let get = warp::get().and(test_get_me);
    let auth_path = warp::path("auth").and(post.or(delete).or(get));

    let routes = auth_path.recover(error_response).with(cors);

    warp::serve(routes)
        .bind(&format!("localhost:{}", port))
        .await;

    Ok(())
}

pub async fn fill_auth_from_db(pool: &PgPool) -> Result<(), anyhow::Error> {
    debug!("{:?}", *TRIGGER_DB_UPDATE);
    let users: Vec<AuthorizedUser> = if TRIGGER_DB_UPDATE.check() {
        User::get_authorized_users(pool)
            .await?
            .into_iter()
            .map(|user| AuthorizedUser { email: user.email })
            .collect()
    } else {
        AUTHORIZED_USERS.get_users()
    };
    AUTHORIZED_USERS.merge_users(&users)?;
    debug!("{:?}", *AUTHORIZED_USERS);
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Error;
    use maplit::hashmap;

    use auth_server_ext::invitation::Invitation;
    use auth_server_lib::{get_random_string, pgpool::PgPool, user::User, AUTH_APP_MUTEX};
    use authorized_users::{get_random_key, JWT_SECRET, KEY_LENGTH, SECRET_KEY};

    use crate::{
        app::{run_app, run_test_app, CONFIG},
        logged_user::LoggedUser,
    };

    #[test]
    fn test_get_random_string() -> Result<(), Error> {
        let rs = get_random_string(32);
        println!("{}", rs);
        assert_eq!(rs.len(), 32);
        Ok(())
    }

    #[actix_rt::test]
    async fn test_test_app() -> Result<(), Error> {
        let _lock = AUTH_APP_MUTEX.lock();

        std::env::set_var("TESTENV", "true");
        let email = format!("{}@localhost", get_random_string(32));
        let password = get_random_string(32);

        let mut secret_key = [0u8; KEY_LENGTH];
        secret_key.copy_from_slice(&get_random_key());

        SECRET_KEY.set(secret_key);
        JWT_SECRET.set(secret_key);

        let test_port = 54321;
        actix_rt::spawn(async move {
            run_test_app(test_port, secret_key, "localhost".into())
                .await
                .unwrap()
        });

        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

        let client = reqwest::Client::builder().cookie_store(true).build()?;
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
        assert_eq!(resp.email.as_str(), "user@test");

        std::env::remove_var("TESTENV");
        Ok(())
    }

    #[actix_rt::test]
    async fn test_create_user() -> Result<(), Error> {
        let _lock = AUTH_APP_MUTEX.lock();

        let pool = PgPool::new(&CONFIG.database_url);
        let email = format!("{}@localhost", get_random_string(32));
        let password = get_random_string(32);
        let invitation = Invitation::from_email(&email);
        invitation.insert(&pool).await?;

        let mut secret_key = [0u8; KEY_LENGTH];
        secret_key.copy_from_slice(&get_random_key());

        SECRET_KEY.set(secret_key);
        JWT_SECRET.set(secret_key);

        let test_port = 12345;
        actix_rt::spawn(async move {
            run_app(test_port, secret_key, "localhost".into())
                .await
                .unwrap()
        });

        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

        let url = format!(
            "http://localhost:{}/api/register/{}",
            test_port, &invitation.id
        );
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

        assert!(Invitation::get_by_uuid(&invitation.id, &pool)
            .await?
            .is_none());

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
