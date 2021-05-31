use anyhow::Error;
use log::debug;
use maplit::hashmap;
use rweb::{
    filters::BoxedFilter,
    http::{header::CONTENT_TYPE, status::StatusCode},
    openapi::{self, Spec},
    Filter, Reply,
};
use stack_string::StackString;
use std::{borrow::Cow, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{task::spawn, time::interval};

use arc_swap::ArcSwap;
use im::HashMap;
use serde_json::Value;
use uuid::Uuid;

use auth_server_ext::google_openid::GoogleClient;
use auth_server_lib::{config::Config, pgpool::PgPool, session::Session, user::User};
use authorized_users::{get_secrets, update_secret, AUTHORIZED_USERS, TRIGGER_DB_UPDATE};

use crate::{
    errors::error_response,
    routes::{
        auth_await, auth_url, callback, change_password, change_password_user, get_me, get_session,
        index_html, login, login_html, logout, main_css, main_js, post_session, register_email,
        register_html, register_user, status, test_login,
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
    pub session_cache: Arc<ArcSwap<HashMap<Uuid, Value>>>,
}

pub async fn start_app() -> Result<(), Error> {
    let config = Config::init_config()?;
    update_secrets(&config).await?;
    get_secrets(&config.secret_path, &config.jwt_secret_path).await?;
    run_app(config).await
}

fn get_api_scope(app: &AppState) -> BoxedFilter<(impl Reply,)> {
    let auth_path = login(app.clone()).or(logout(app.clone())).or(get_me());

    let invitation_path = register_email(app.clone());
    let register_path = register_user(app.clone());
    let password_change_path = change_password_user(app.clone());
    let auth_url_path = auth_url(app.clone());
    let auth_await_path = auth_await(app.clone());
    let callback_path = callback(app.clone());
    let status_path = status(app.clone());
    let session_path = get_session(app.clone())
        .or(post_session(app.clone()))
        .boxed();

    let index_html_path = index_html();
    let main_css_path = main_css();
    let main_js_path = main_js();
    let register_html_path = register_html();
    let login_html_path = login_html();
    let change_password_path = change_password();

    auth_path
        .or(invitation_path)
        .or(register_path)
        .or(password_change_path)
        .or(auth_url_path)
        .or(auth_await_path)
        .or(callback_path)
        .or(status_path)
        .or(session_path)
        .or(index_html_path)
        .or(main_css_path)
        .or(main_js_path)
        .or(register_html_path)
        .or(login_html_path)
        .or(change_password_path)
        .boxed()
}

fn modify_spec(spec: &mut Spec) {
    spec.info.title = "Rust Auth Server".into();
    spec.info.description = "Authorization Server written in rust using jwt/jws/jwe and featuring \
                             integration with Google OAuth"
        .into();
    spec.info.version = env!("CARGO_PKG_VERSION").into();

    let status_codes = hashmap! {
        ("/api/auth", "post") => (StatusCode::OK, StatusCode::CREATED),
        ("/api/auth", "delete") => (StatusCode::OK, StatusCode::CREATED),
        ("/api/invitation", "post") => (StatusCode::OK, StatusCode::CREATED),
        ("/api/register/{invitation_id}", "post") => (StatusCode::OK, StatusCode::CREATED),
        ("/api/password_change", "post") => (StatusCode::OK, StatusCode::CREATED),
    };

    let response_descriptions = hashmap! {
        ("/api/auth", "get", StatusCode::OK) => "Current users email",
        ("/api/auth", "post", StatusCode::CREATED) => "Current logged in username",
        ("/api/auth", "delete", StatusCode::CREATED) => "Email of logged in user",
        ("/api/invitation", "post", StatusCode::CREATED) => "Invitation Object",
        ("/api/register/{invitation_id}", "post", StatusCode::CREATED) => "Registered Email",
        ("/api/password_change", "post", StatusCode::CREATED) => "Success Message",
        ("/api/callback", "get", StatusCode::OK) => "Callback Response",
        ("/api/await", "get", StatusCode::OK) => "Finished",
    };

    for ((path, method), (old_code, new_code)) in status_codes {
        if let Some(path) = spec.paths.get_mut(path) {
            if let Some(method) = match method {
                "get" => path.get.as_mut(),
                "post" => path.post.as_mut(),
                "patch" => path.patch.as_mut(),
                "delete" => path.delete.as_mut(),
                _ => panic!("Unsupported"),
            } {
                let old_code: Cow<'static, str> = old_code.as_u16().to_string().into();
                let new_code = new_code.as_u16().to_string();
                if let Some(old) = method.responses.remove(&old_code) {
                    method.responses.insert(new_code.into(), old);
                }
            }
        }
    }

    for ((path, method, code), description) in response_descriptions {
        let code: Cow<'static, str> = code.as_u16().to_string().into();
        if let Some(path) = spec.paths.get_mut(path) {
            if let Some(method) = match method {
                "get" => path.get.as_mut(),
                "patch" => path.patch.as_mut(),
                "post" => path.post.as_mut(),
                "delete" => path.delete.as_mut(),
                _ => panic!("Unsupported"),
            } {
                if let Some(resp) = method.responses.get_mut(&code) {
                    resp.description = description.into();
                }
            }
        }
    }
}

async fn run_app(config: Config) -> Result<(), Error> {
    async fn _update_db(pool: PgPool, client: GoogleClient, expiration_seconds: i64) {
        let mut i = interval(Duration::from_secs(60));
        loop {
            let p = pool.clone();
            fill_auth_from_db(&p, expiration_seconds)
                .await
                .unwrap_or(());
            client.cleanup_token_map().await;
            i.tick().await;
        }
    }

    let google_client = GoogleClient::new(&config).await?;
    let pool = PgPool::new(&config.database_url);

    spawn(_update_db(
        pool.clone(),
        google_client.clone(),
        config.expiration_seconds,
    ));

    let app = AppState {
        config: config.clone(),
        pool: pool.clone(),
        google_client: google_client.clone(),
        session_cache: Arc::new(ArcSwap::new(Arc::new(HashMap::new()))),
    };

    let (mut spec, api_scope) = openapi::spec().build(|| get_api_scope(&app));
    modify_spec(&mut spec);
    let spec = Arc::new(spec);
    let spec_json_path = rweb::path!("api" / "openapi" / "json")
        .and(rweb::path::end())
        .map({
            let spec = spec.clone();
            move || warp::reply::json(spec.as_ref())
        });

    let spec_yaml = serde_yaml::to_string(spec.as_ref())?;
    let spec_yaml_path = rweb::path!("api" / "openapi" / "yaml")
        .and(rweb::path::end())
        .map(move || {
            let reply = rweb::reply::html(spec_yaml.clone());
            rweb::reply::with_header(reply, CONTENT_TYPE, "text/yaml")
        });

    let cors = rweb::cors()
        .allow_methods(vec!["GET", "POST", "DELETE"])
        .allow_header("content-type")
        .allow_header("jwt")
        .allow_any_origin()
        .build();

    let routes = api_scope
        .or(spec_json_path)
        .or(spec_yaml_path)
        .recover(error_response)
        .with(cors);
    let addr: SocketAddr = format!("127.0.0.1:{}", config.port).parse()?;
    debug!("{:?}", addr);
    rweb::serve(routes).bind(addr).await;

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
        session_cache: Arc::new(ArcSwap::new(Arc::new(HashMap::new()))),
    };

    let port = config.port;

    let auth_path = test_login(app.clone()).or(logout(app.clone())).or(get_me());

    let cors = rweb::cors()
        .allow_methods(vec!["GET", "POST", "DELETE"])
        .allow_header("content-type")
        .allow_header("authorization")
        .allow_any_origin()
        .build();

    let routes = auth_path.recover(error_response).with(cors);

    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse()?;
    rweb::serve(routes).bind(addr).await;

    Ok(())
}

pub async fn fill_auth_from_db(
    pool: &PgPool,
    expiration_seconds: i64,
) -> Result<(), anyhow::Error> {
    debug!("{:?}", *TRIGGER_DB_UPDATE);
    let users: Vec<StackString> = if TRIGGER_DB_UPDATE.check() {
        Session::cleanup(&pool, expiration_seconds).await?;
        User::get_authorized_users(pool)
            .await?
            .into_iter()
            .map(|user| user.email)
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
    use arc_swap::ArcSwap;
    use im::HashMap;
    use log::debug;
    use maplit::hashmap;
    use reqwest::header::HeaderValue;
    use rweb::openapi;
    use std::{env, sync::Arc};

    use auth_server_ext::{google_openid::GoogleClient, invitation::Invitation};
    use auth_server_lib::{
        config::Config, get_random_string, pgpool::PgPool, session::Session, user::User,
        AUTH_APP_MUTEX,
    };
    use authorized_users::{get_random_key, JWT_SECRET, KEY_LENGTH, SECRET_KEY};

    use crate::{
        app::{get_api_scope, modify_spec, run_app, run_test_app, AppState},
        logged_user::LoggedUser,
        routes::PasswordChangeOutput,
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
        let _lock = AUTH_APP_MUTEX.lock().await;

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
        let _lock = AUTH_APP_MUTEX.lock().await;

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
        let session = resp.session.unwrap();

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
        let output: PasswordChangeOutput = client
            .post(&url)
            .json(&data)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        debug!("password changed {:?}", output);
        assert_eq!(output.message.as_str(), "password updated");

        let url = format!("http://localhost:{}/api/session", test_port);
        let data = hashmap! {
            "key" => "value",
        };
        debug!("POST session");
        let value = HeaderValue::from_str(&session.to_string())?;
        let resp = client
            .post(&url)
            .json(&data)
            .header("session", value.clone())
            .send()
            .await?
            .error_for_status()?;
        debug!("{:?}", resp);
        debug!("GET session");
        let resp: std::collections::HashMap<String, String> = client
            .get(&url)
            .header("session", value)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        debug!("{:?}", resp);
        assert_eq!(resp.len(), 1);
        let url = format!("http://localhost:{}/api/auth", test_port);
        let resp: String = client
            .delete(&url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        assert_eq!(resp, format!(r#""{} has been logged out""#, email));

        let sessions = Session::get_by_email(&pool, &email).await?;
        for session in sessions {
            session.delete(&pool).await?;
        }

        let user = User::get_by_email(&email, &pool).await?.unwrap();
        assert!(user.verify_password(&new_password)?);

        user.delete(&pool).await?;
        assert_eq!(User::get_by_email(&email, &pool).await?, None);

        Ok(())
    }

    #[tokio::test]
    async fn test_api_spec() -> Result<(), Error> {
        let config = Config::init_config()?;
        let google_client = GoogleClient::new(&config).await?;
        let pool = PgPool::new(&config.database_url);

        let app = AppState {
            config: config.clone(),
            pool: pool.clone(),
            google_client: google_client.clone(),
            session_cache: Arc::new(ArcSwap::new(Arc::new(HashMap::new()))),
        };

        let (mut spec, _) = openapi::spec().build(|| get_api_scope(&app));
        modify_spec(&mut spec);
        let spec_yaml = serde_yaml::to_string(&spec)?;

        debug!("{}", spec_yaml);
        Ok(())
    }
}
