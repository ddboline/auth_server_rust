use anyhow::Error;
use log::debug;
use stack_string::StackString;
use std::{net::SocketAddr, time::Duration};
use tokio::{task::spawn, time::interval};
use warp::Filter;

use auth_server_ext::google_openid::GoogleClient;
use auth_server_lib::{
    config::Config,
    pgpool::PgPool,
    static_files::{change_password, index_html, login_html, main_css, main_js, register_html},
    user::User,
};
use authorized_users::{
    get_secrets, update_secret, AuthorizedUser, AUTHORIZED_USERS, TRIGGER_DB_UPDATE,
};

use crate::{
    errors::error_response,
    routes::{
        auth_url, callback, change_password_user, get_me, login, logout, register_email,
        register_user, status, test_login,
    },
};

async fn update_secrets(config: &Config) -> Result<(), Error> {
    update_secret(&config.secret_path).await?;
    update_secret(&config.jwt_secret_path).await
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub pool: PgPool,
    pub google_client: GoogleClient,
}

pub async fn start_app() -> Result<(), Error> {
    let config = Config::init_config()?;
    update_secrets(&config).await?;
    get_secrets(&config.secret_path, &config.jwt_secret_path).await?;
    run_app(config).await
}

async fn run_app(config: Config) -> Result<(), Error> {
    async fn _update_db(pool: PgPool) {
        let mut i = interval(Duration::from_secs(60));
        loop {
            let p = pool.clone();
            fill_auth_from_db(&p).await.unwrap_or(());
            i.tick().await;
        }
    }

    let google_client = GoogleClient::new(&config).await?;
    let pool = PgPool::new(&config.database_url);

    spawn(_update_db(pool.clone()));

    let app = AppState {
        config: config.clone(),
        pool: pool.clone(),
        google_client: google_client.clone(),
    };

    let data = warp::any().map(move || app.clone());

    let post = warp::post()
        .and(warp::path::end())
        .and(data.clone())
        .and(warp::body::json())
        .and_then(login);

    let delete = warp::delete()
        .and(warp::path::end())
        .and(warp::cookie("jwt"))
        .and(data.clone())
        .and_then(logout);

    let get = warp::get().and(warp::cookie("jwt")).and_then(get_me);

    let auth_path = warp::path("auth").and(warp::path::end()).and(post.or(delete).or(get));

    let invitation_path = warp::path("invitation")
        .and(warp::post())
        .and(warp::path::end())
        .and(data.clone())
        .and(warp::body::json())
        .and_then(register_email);

    let register_path = warp::path!("register" / StackString)
        .and(warp::post())
        .and(warp::path::end())
        .and(data.clone())
        .and(warp::body::json())
        .and_then(register_user);

    let password_change_path = warp::path("password_change")
        .and(warp::post())
        .and(warp::path::end())
        .and(warp::cookie("jwt"))
        .and(data.clone())
        .and(warp::body::json())
        .and_then(change_password_user);

    let auth_url_path = warp::path("auth_url")
        .and(warp::post())
        .and(warp::path::end())
        .and(data.clone())
        .and(warp::body::json())
        .and_then(auth_url);

    let callback_path = warp::path("callback")
        .and(warp::get())
        .and(warp::path::end())
        .and(data.clone())
        .and(warp::filters::query::query())
        .and_then(callback);

    let status_path = warp::path("status")
        .and(warp::get())
        .and(data.clone())
        .and_then(status);

    let api_scope = warp::path("api").and(
        auth_path
            .or(invitation_path)
            .or(register_path)
            .or(password_change_path)
            .or(auth_url_path)
            .or(callback_path)
            .or(status_path),
    );

    let index_html_path = warp::path("index.html").and(warp::get()).map(index_html);
    let main_css_path = warp::path("main.css").and(warp::get()).map(main_css);
    let main_js_path = warp::path("main.js").and(warp::get()).map(main_js);
    let register_html_path = warp::path("register.html")
        .and(warp::get())
        .map(register_html);
    let login_html_path = warp::path("login.html").and(warp::get()).map(login_html);
    let change_password_path = warp::path("change_password.html")
        .and(warp::get())
        .map(change_password);
    let auth_scope = warp::path("auth").and(
        index_html_path
            .or(main_css_path)
            .or(main_js_path)
            .or(register_html_path)
            .or(login_html_path)
            .or(change_password_path),
    );
    let cors = warp::cors()
        .allow_methods(vec!["GET", "POST", "DELETE"])
        .allow_header("content-type")
        .allow_header("jwt")
        .allow_any_origin()
        .build();

    let routes = api_scope.or(auth_scope).recover(error_response).with(cors);
    let addr: SocketAddr = format!("127.0.0.1:{}", config.port).parse()?;
    debug!("{:?}", addr);
    warp::serve(routes).bind(addr).await;

    Ok(())
}

#[allow(clippy::similar_names)]
pub async fn run_test_app(config: Config) -> Result<(), Error> {
    let google_client = GoogleClient::new(&config).await?;
    let pool = PgPool::new(&config.database_url);

    let app = AppState {
        config: config.clone(),
        pool: pool.clone(),
        google_client: google_client.clone(),
    };

    let port = config.port;
    let data = warp::any().map(move || app.clone());

    let post = warp::post()
        .and(warp::path::end())
        .and(warp::body::json())
        .and(data.clone())
        .and_then(test_login);

    let delete = warp::delete()
        .and(warp::path::end())
        .and(warp::cookie("jwt"))
        .and(data.clone())
        .and_then(logout);

    let get = warp::get()
        .and(warp::path::end())
        .and(warp::cookie("jwt"))
        .and_then(get_me);

    let auth_path = warp::path!("api" / "auth").and(post.or(delete).or(get));

    let cors = warp::cors()
        .allow_methods(vec!["GET", "POST", "DELETE"])
        .allow_header("content-type")
        .allow_header("authorization")
        .allow_any_origin()
        .build();

    let routes = auth_path.recover(error_response).with(cors);

    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse()?;
    warp::serve(routes).bind(addr).await;

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
    use log::debug;
    use maplit::hashmap;
    use std::env;

    use auth_server_ext::invitation::Invitation;
    use auth_server_lib::{
        config::Config, get_random_string, pgpool::PgPool, user::User, AUTH_APP_MUTEX,
    };
    use authorized_users::{get_random_key, JWT_SECRET, KEY_LENGTH, SECRET_KEY};

    use crate::{
        app::{run_app, run_test_app},
        logged_user::LoggedUser,
    };

    #[test]
    fn test_get_random_string() -> Result<(), Error> {
        let rs = get_random_string(32);
        debug!("{}", rs);
        assert_eq!(rs.len(), 32);
        Ok(())
    }

    #[tokio::test]
    async fn test_test_app() -> Result<(), Error> {
        let _lock = AUTH_APP_MUTEX.lock();

        env::set_var("TESTENV", "true");
        let email = format!("{}@localhost", get_random_string(32));
        let password = get_random_string(32);

        let mut secret_key = [0u8; KEY_LENGTH];
        secret_key.copy_from_slice(&get_random_key());

        SECRET_KEY.set(secret_key);
        JWT_SECRET.set(secret_key);

        let test_port = 54321;

        env::set_var("PORT", test_port.to_string());
        env::set_var("DOMAIN", "localhost");
        let config = Config::init_config()?;

        debug!("{} {}", config.port, config.domain);
        tokio::task::spawn({
            env_logger::init();
            let config = config.clone();
            async move { run_test_app(config).await.unwrap() }
        });

        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

        let client = reqwest::Client::builder().cookie_store(true).build()?;
        let url = format!("http://localhost:{}/api/auth", test_port);
        let data = hashmap! {
            "email" => &email,
            "password" => &password,
        };
        debug!("login");
        let resp: LoggedUser = client
            .post(&url)
            .json(&data)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        debug!("logged in {:?}", resp);
        assert_eq!(resp.email.as_str(), email.as_str());

        debug!("get me");
        let resp: LoggedUser = client
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        debug!("I am: {:?}", resp);
        assert_eq!(resp.email.as_str(), email.as_str());

        std::env::remove_var("TESTENV");
        Ok(())
    }

    #[tokio::test]
    async fn test_create_user() -> Result<(), Error> {
        let _lock = AUTH_APP_MUTEX.lock();

        let mut secret_key = [0u8; KEY_LENGTH];
        secret_key.copy_from_slice(&get_random_key());

        let test_port = 12345;

        env::set_var("PORT", test_port.to_string());
        env::set_var("DOMAIN", "localhost");

        let config = Config::init_config()?;

        let pool = PgPool::new(&config.database_url);
        let email = format!("{}@localhost", get_random_string(32));
        let password = get_random_string(32);
        let invitation = Invitation::from_email(&email);
        invitation.insert(&pool).await?;

        SECRET_KEY.set(secret_key);
        JWT_SECRET.set(secret_key);

        tokio::task::spawn(async move { run_app(config).await.unwrap() });

        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

        let url = format!(
            "http://localhost:{}/api/register/{}",
            test_port, &invitation.id
        );
        let data = hashmap! {
            "password" => &password,
        };

        let client = reqwest::Client::builder().cookie_store(true).build()?;
        debug!("register");
        let resp: LoggedUser = client
            .post(&url)
            .json(&data)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        debug!("registered {:?}", resp);
        assert_eq!(resp.email.as_str(), email.as_str());

        assert!(Invitation::get_by_uuid(&invitation.id, &pool)
            .await?
            .is_none());

        let url = format!("http://localhost:{}/api/auth", test_port);
        let data = hashmap! {
            "email" => &email,
            "password" => &password,
        };
        debug!("login");
        let resp: LoggedUser = client
            .post(&url)
            .json(&data)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        debug!("logged in {:?}", resp);
        assert_eq!(resp.email.as_str(), email.as_str());

        debug!("get me");
        let resp: LoggedUser = client
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        debug!("I am: {:?}", resp);
        assert_eq!(resp.email.as_str(), email.as_str());

        let url = format!("http://localhost:{}/api/password_change", test_port);
        let new_password = get_random_string(32);
        let data = hashmap! {
            "email" => &email,
            "password" => &new_password,
        };
        debug!("change password");
        let text = client
            .post(&url)
            .json(&data)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        debug!("password changed {:?}", text);
        assert_eq!(text.as_str(), "password updated");

        let user = User::get_by_email(&email, &pool).await?.unwrap();
        assert!(user.verify_password(&new_password)?);

        user.delete(&pool).await?;
        assert_eq!(User::get_by_email(&email, &pool).await?, None);

        Ok(())
    }
}
