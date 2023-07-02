use anyhow::Error;
use futures::TryStreamExt;
use log::debug;
use rweb::{
    filters::BoxedFilter,
    http::header::CONTENT_TYPE,
    openapi::{self, Info},
    Filter, Reply,
};
use stack_string::format_sstr;
use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{task::spawn, time::interval};

use auth_server_ext::{google_openid::GoogleClient, ses_client::SesInstance};
use auth_server_lib::{config::Config, pgpool::PgPool, session::Session, user::User};
use authorized_users::{get_secrets, update_secret, AUTHORIZED_USERS, TRIGGER_DB_UPDATE};

use crate::{
    errors::error_response,
    routes::{
        auth_await, auth_url, callback, change_password, change_password_user, delete_session,
        delete_sessions, get_me, get_session, get_sessions, index_html, list_session_data,
        list_session_obj, list_sessions, login, login_html, logout, main_css, main_js,
        post_session, register_email, register_html, register_user, status, test_login,
    },
    session_data_cache::SessionDataCache,
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
    pub ses: SesInstance,
    pub session_cache: SessionDataCache,
}

/// # Errors
/// Returns error if config init fails or if `get_secrets` call fails
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
        .or(delete_session(app.clone()))
        .boxed();
    let list_session_obj_path = list_session_obj(app.clone()).boxed();
    let get_sessions_path = get_sessions(app.clone())
        .or(delete_sessions(app.clone()))
        .boxed();
    let list_sessions_path = list_sessions(app.clone()).boxed();
    let list_session_data_path = list_session_data(app.clone()).boxed();
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
        .or(list_session_obj_path)
        .or(get_sessions_path)
        .or(list_session_data_path)
        .or(list_sessions_path)
        .or(index_html_path)
        .or(main_css_path)
        .or(main_js_path)
        .or(register_html_path)
        .or(login_html_path)
        .or(change_password_path)
        .boxed()
}

async fn run_app(config: Config) -> Result<(), Error> {
    async fn _update_db(pool: PgPool, client: GoogleClient, expiration_seconds: i64) {
        let mut i = interval(Duration::from_secs(60));
        loop {
            fill_auth_from_db(&pool, expiration_seconds)
                .await
                .unwrap_or(());
            client.cleanup_token_map().await;
            i.tick().await;
        }
    }

    let google_client = GoogleClient::new(&config).await?;
    let ses = SesInstance::new(None);
    let pool = PgPool::new(&config.database_url);

    let update_handle = spawn(_update_db(
        pool.clone(),
        google_client.clone(),
        config.expiration_seconds,
    ));

    let app = AppState {
        config: config.clone(),
        pool,
        google_client,
        ses,
        session_cache: SessionDataCache::new(),
    };

    let (spec, api_scope) = openapi::spec()
        .info(Info {
            title: "Rust Auth Server".into(),
            description: "Authorization Server written in rust using jwt/jws/jwe and featuring \
                          integration with Google OAuth"
                .into(),
            version: env!("CARGO_PKG_VERSION").into(),
            ..Info::default()
        })
        .build(|| get_api_scope(&app));
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
    let addr: SocketAddr =
        format_sstr!("{host}:{port}", host = config.host, port = config.port).parse()?;
    debug!("{:?}", addr);
    rweb::serve(routes).bind(addr).await;
    update_handle.await.map_err(Into::into)
}

/// # Errors
/// Returns error if
///     * Google client init fails
///     * Url parsing fails for host:port
///     * Binding to socket fails
#[allow(clippy::similar_names)]
pub async fn run_test_app(config: Config) -> Result<(), Error> {
    let google_client = GoogleClient::new(&config).await?;
    let ses = SesInstance::new(None);
    let pool = PgPool::new(&config.database_url);

    let app = AppState {
        config: config.clone(),
        pool,
        google_client,
        ses,
        session_cache: SessionDataCache::new(),
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
    let addr: SocketAddr = format_sstr!("{host}:{port}", host = config.host).parse()?;
    rweb::serve(routes).bind(addr).await;
    Ok(())
}

/// # Errors
/// Returns error if
///     * `Session::cleanup` fails
///     * `User::get_authorized_users` fails
///     * `AUTHORIZED_USERS.merge_users` fails
pub async fn fill_auth_from_db(
    pool: &PgPool,
    expiration_seconds: i64,
) -> Result<(), anyhow::Error> {
    debug!("{:?}", *TRIGGER_DB_UPDATE);
    let users = if TRIGGER_DB_UPDATE.check() {
        Session::cleanup(pool, expiration_seconds).await?;
        let result: Result<HashSet<_>, _> = User::get_authorized_users(pool)
            .await?
            .map_ok(|user| user.email)
            .try_collect()
            .await;
        result?
    } else {
        AUTHORIZED_USERS.get_users()
    };
    AUTHORIZED_USERS.update_users(users);
    debug!("{:?}", *AUTHORIZED_USERS);
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Error;
    use http::StatusCode;
    use log::debug;
    use maplit::hashmap;
    use rweb::openapi;
    use stack_string::format_sstr;
    use std::{collections::HashMap, env};
    use tokio::{
        task::spawn,
        time::{sleep, Duration},
    };
    use url::Url;

    use auth_server_ext::{google_openid::GoogleClient, ses_client::SesInstance};
    use auth_server_lib::{
        config::Config, get_random_string, invitation::Invitation, pgpool::PgPool,
        session::Session, user::User, AUTH_APP_MUTEX,
    };
    use authorized_users::{get_random_key, AuthorizedUser, JWT_SECRET, KEY_LENGTH, SECRET_KEY};

    use crate::{
        app::{get_api_scope, run_app, run_test_app, AppState},
        logged_user::LoggedUser,
        routes::PasswordChangeOutput,
        session_data_cache::SessionDataCache,
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
        let email = format_sstr!("{}@localhost", get_random_string(32));
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
        let test_handle = spawn({
            env_logger::init();
            let config = config.clone();
            async move { run_test_app(config).await.unwrap() }
        });

        sleep(Duration::from_secs(10)).await;

        let client = reqwest::Client::builder().cookie_store(true).build()?;
        let url = format_sstr!("http://localhost:{test_port}/api/auth");
        let data = hashmap! {
            "email" => &email,
            "password" => &password,
        };
        debug!("login");
        let resp: LoggedUser = client
            .post(url.as_str())
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
            .get(url.as_str())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        debug!("I am: {:?}", resp);
        assert_eq!(resp.email.as_str(), email.as_str());

        std::env::remove_var("TESTENV");

        test_handle.abort();

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
        env::set_var("SECURE", "false");

        let config = Config::init_config()?;

        let pool = PgPool::new(&config.database_url);
        let email = format_sstr!("{}@localhost", get_random_string(32));
        let password = get_random_string(32);
        let invitation = Invitation::from_email(&email);
        invitation.insert(&pool).await?;

        SECRET_KEY.set(secret_key);
        JWT_SECRET.set(secret_key);

        let app_handle = spawn(async move { run_app(config).await.unwrap() });

        sleep(Duration::from_secs(10)).await;

        let url = format_sstr!(
            "http://localhost:{test_port}/api/register/{id}",
            id = invitation.id
        );
        let data = hashmap! {
            "password" => &password,
        };

        let client = reqwest::Client::builder().cookie_store(true).build()?;
        debug!("register");
        let resp: LoggedUser = client
            .post(url.as_str())
            .json(&data)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        debug!("registered {:?}", resp);
        assert_eq!(resp.email.as_str(), email.as_str());

        assert!(Invitation::get_by_uuid(invitation.id, &pool)
            .await?
            .is_none());

        let url = format_sstr!("http://localhost:{test_port}/api/auth");
        let data = hashmap! {
            "email" => &email,
            "password" => &password,
        };
        debug!("login");
        let resp: LoggedUser = client
            .post(url.as_str())
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
            .get(url.as_str())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        debug!("I am: {:?}", resp);
        assert_eq!(resp.email.as_str(), email.as_str());

        let url = format_sstr!("http://localhost:{test_port}/api/password_change");
        let new_password = get_random_string(32);
        let data = hashmap! {
            "email" => &email,
            "password" => &new_password,
        };
        debug!("change password");
        let output: PasswordChangeOutput = client
            .post(url.as_str())
            .json(&data)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        debug!("password changed {:?}", output);
        assert_eq!(output.message.as_str(), "password updated");

        let base_url: Url = format_sstr!("http://localhost:{test_port}").parse()?;
        let data = hashmap! {
            "key" => "value",
        };
        debug!("POST session");
        AuthorizedUser::set_session_data(
            &base_url,
            resp.session.into(),
            &resp.secret_key,
            &client,
            "test",
            &data,
        )
        .await?;
        debug!("GET session");
        let resp: HashMap<String, String> = AuthorizedUser::get_session_data(
            &base_url,
            resp.session.into(),
            &resp.secret_key,
            &client,
            "test",
        )
        .await?;
        debug!("{resp:?}");
        assert_eq!(resp.len(), 1);
        let url = format_sstr!("http://localhost:{test_port}/api/auth");
        let status: StatusCode = client
            .delete(url.as_str())
            .send()
            .await?
            .error_for_status()?
            .status();
        assert_eq!(status, StatusCode::NO_CONTENT);

        let sessions = Session::get_by_email(&pool, &email).await?;
        for session in sessions {
            session.delete(&pool).await?;
        }

        let user = User::get_by_email(&email, &pool).await?.unwrap();
        assert!(user.verify_password(&new_password)?);

        user.delete(&pool).await?;
        assert_eq!(User::get_by_email(&email, &pool).await?, None);
        app_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn test_api_spec() -> Result<(), Error> {
        let config = Config::init_config()?;
        let google_client = GoogleClient::new(&config).await?;
        let ses = SesInstance::new(None);
        let pool = PgPool::new(&config.database_url);

        let app = AppState {
            config: config.clone(),
            pool,
            google_client,
            ses,
            session_cache: SessionDataCache::new(),
        };

        let (spec, _) = openapi::spec().build(|| get_api_scope(&app));
        let spec_yaml = serde_yaml::to_string(&spec)?;

        debug!("{}", spec_yaml);
        Ok(())
    }
}
