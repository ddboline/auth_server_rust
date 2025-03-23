use futures::{TryStreamExt, try_join};
use http::Method;
use stack_string::{StackString, format_sstr};
use std::{collections::HashMap, convert::TryInto, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpListener, task::spawn, time::interval};
use tower_http::cors::{Any, CorsLayer};
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_rapidoc::RapiDoc;
use utoipa_redoc::{Redoc, Servable};
use utoipa_swagger_ui::SwaggerUi;

use auth_server_ext::{google_openid::GoogleClient, ses_client::SesInstance};
use auth_server_lib::{
    config::Config, errors::AuthServerError, pgpool::PgPool, session::Session, user::User,
};
use authorized_users::{
    AUTHORIZED_USERS, AuthorizedUser, errors::AuthUsersError, get_secrets, update_secret,
};

use crate::{
    EmailStatsWrapper,
    SesQuotasWrapper,
    SessionSummaryWrapper,
    errors::ServiceError as Error,
    logged_user::LoggedUser,
    // errors::error_response,
    routes::{get_api_scope, get_test_routes},
    session_data_cache::SessionDataCache,
};

async fn update_secrets(config: &Config) -> Result<(), AuthUsersError> {
    update_secret(&config.secret_path).await?;
    update_secret(&config.jwt_secret_path).await
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Rust Autorization Server",
        description = "Authorization Server written in rust using jwt/jws/jwe and featuring \
                       integration with Google OAuth",
    ),
    components(schemas(SessionSummaryWrapper, SesQuotasWrapper, EmailStatsWrapper, LoggedUser))
)]
struct ApiDoc;

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
    update_secrets(&config)
        .await
        .map_err(Into::<AuthServerError>::into)?;
    get_secrets(&config.secret_path, &config.jwt_secret_path)
        .await
        .map_err(Into::<AuthServerError>::into)?;
    run_app(config).await
}

async fn run_app(config: Config) -> Result<(), Error> {
    async fn update_db(pool: PgPool, client: GoogleClient, expiration_seconds: u32) {
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
    let sdk_config = aws_config::load_from_env().await;
    let ses = SesInstance::new(&sdk_config);
    let pool = PgPool::new(&config.database_url)?;

    let update_handle = spawn(update_db(
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
    let app = Arc::new(app);

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(["content-type".try_into()?, "jwt".try_into()?])
        .allow_origin(Any);

    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .merge(get_api_scope(&app))
        .layer(cors)
        .split_for_parts();

    let router = router
        .merge(SwaggerUi::new("/swaggerui").url("/api/openapi.json", api.clone()))
        .merge(Redoc::with_url("/api/redoc", api.clone()))
        .merge(RapiDoc::new("/api/openapi.json").path("/rapidoc"));

    let host = &config.host;
    let port = config.port;

    let addr: SocketAddr = format_sstr!("{host}:{port}").parse()?;
    println!("{addr:?}");
    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, router.into_make_service()).await?;

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
    let sdk_config = aws_config::load_from_env().await;
    let ses = SesInstance::new(&sdk_config);
    let pool = PgPool::new(&config.database_url)?;

    let app = AppState {
        config: config.clone(),
        pool,
        google_client,
        ses,
        session_cache: SessionDataCache::new(),
    };

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(["content-type".try_into()?, "jwt".try_into()?])
        .allow_origin(Any);

    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .merge(get_test_routes(&app))
        .layer(cors)
        .split_for_parts();

    let router = router
        .merge(SwaggerUi::new("/swaggerui").url("/api/openapi.json", api.clone()))
        .merge(Redoc::with_url("/api/redoc", api.clone()))
        .merge(RapiDoc::new("/api/openapi.json").path("/rapidoc"));

    let host = &config.host;
    let port = config.port;

    let addr: SocketAddr = format_sstr!("{host}:{port}").parse()?;
    println!("{addr:?}" );
    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, router.into_make_service())
        .await
        .map_err(Into::into)
}

/// # Errors
/// Returns error if
///     * `Session::cleanup` fails
///     * `User::get_authorized_users` fails
///     * `AUTHORIZED_USERS.merge_users` fails
pub async fn fill_auth_from_db(pool: &PgPool, expiration_seconds: u32) -> Result<(), Error> {
    let (cleanup_result, most_recent_user_db) = try_join!(
        Session::cleanup(pool, expiration_seconds),
        User::get_most_recent(pool),
    )?;
    let existing_users = AUTHORIZED_USERS.get_users();
    let most_recent_user = existing_users.values().map(|i| i.created_at).max();
    println!("most_recent_user_db {most_recent_user_db:?} most_recent_user {most_recent_user:?}");
    if cleanup_result == 0
        && most_recent_user_db.is_some()
        && most_recent_user.is_some()
        && most_recent_user_db <= most_recent_user
    {
        return Ok(());
    }
    let result: Result<HashMap<StackString, AuthorizedUser>, _> = User::get_authorized_users(pool)
        .await?
        .map_ok(|user| (user.email.clone(), user.into()))
        .try_collect()
        .await;
    let users = result.map_err(Into::<AuthServerError>::into)?;
    AUTHORIZED_USERS.update_users(users);
    println!("AUTHORIZED_USERS {:?}", *AUTHORIZED_USERS);
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Error;
    use http::StatusCode;
    use maplit::hashmap;
    use stack_string::format_sstr;
    use std::{collections::HashMap, env, sync::Arc};
    use tokio::{
        task::spawn,
        time::{Duration, sleep},
    };
    use url::Url;
    use utoipa::OpenApi;

    use auth_server_ext::{google_openid::GoogleClient, ses_client::SesInstance};
    use auth_server_lib::{
        AUTH_APP_MUTEX, config::Config, errors::AuthServerError, get_random_string,
        invitation::Invitation, pgpool::PgPool, session::Session, user::User,
    };
    use authorized_users::{AuthorizedUser, JWT_SECRET, KEY_LENGTH, SECRET_KEY, get_random_key};

    use crate::{
        app::{
            ApiDoc,
            AppState,
            // get_api_scope,
            run_app,
            run_test_app,
        },
        logged_user::LoggedUser,
        routes::{PasswordChangeOutput, get_api_scope},
        session_data_cache::SessionDataCache,
    };

    #[test]
    fn test_get_random_string() -> Result<(), Error> {
        let rs = get_random_string(32);
        println!("{}", rs);
        assert_eq!(rs.len(), 32);
        Ok(())
    }

    #[tokio::test]
    async fn test_test_app() -> Result<(), Error> {
        let _lock = AUTH_APP_MUTEX.lock().await;

        unsafe {
            env::set_var("TESTENV", "true");
        }
        let email = format_sstr!("{}@localhost", get_random_string(32));
        let password = get_random_string(32);

        let mut secret_key = [0u8; KEY_LENGTH];
        secret_key.copy_from_slice(&get_random_key());

        SECRET_KEY.set(secret_key);
        JWT_SECRET.set(secret_key);

        let test_port = 54321;

        unsafe {
            env::set_var("PORT", test_port.to_string());
            env::set_var("DOMAIN", "localhost");
        }
        let config = Config::init_config()?;

        println!("{} {}", config.port, config.domain);
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
        println!("login");
        let resp: LoggedUser = client
            .post(url.as_str())
            .json(&data)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        println!("logged in {:?}", resp);
        assert_eq!(resp.email.as_str(), email.as_str());

        println!("get me");
        let resp = client
            .get(url.as_str())
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        println!("resp {resp}");
        let resp: LoggedUser = client
            .get(url.as_str())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        println!("I am: {:?}", resp);
        assert_eq!(resp.email.as_str(), email.as_str());

        let url = format_sstr!("http://localhost:{test_port}/api/openapi.json");
        let result = client
            .get(url.as_str())
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        println!("{result}");

        unsafe {
            std::env::remove_var("TESTENV");
        }

        test_handle.abort();

        Ok(())
    }

    #[tokio::test]
    async fn test_create_user() -> Result<(), Error> {
        let _lock = AUTH_APP_MUTEX.lock().await;

        let mut secret_key = [0u8; KEY_LENGTH];
        secret_key.copy_from_slice(&get_random_key());

        let test_port = 12345;

        unsafe {
            env::set_var("PORT", test_port.to_string());
            env::set_var("DOMAIN", "localhost");
            env::set_var("SECURE", "false");
        }

        let config = Config::init_config()?;

        let pool = PgPool::new(&config.database_url)?;
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
        println!("register");
        let resp: LoggedUser = client
            .post(url.as_str())
            .json(&data)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        println!("registered {:?}", resp);
        assert_eq!(resp.email.as_str(), email.as_str());

        assert!(
            Invitation::get_by_uuid(invitation.id, &pool)
                .await?
                .is_none()
        );

        let url = format_sstr!("http://localhost:{test_port}/api/auth");
        let data = hashmap! {
            "email" => &email,
            "password" => &password,
        };
        println!("login");
        let resp: LoggedUser = client
            .post(url.as_str())
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
            .get(url.as_str())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        println!("I am: {:?}", resp);
        assert_eq!(resp.email.as_str(), email.as_str());

        let url = format_sstr!("http://localhost:{test_port}/api/password_change");
        let new_password = get_random_string(32);
        let data = hashmap! {
            "email" => &email,
            "password" => &new_password,
        };
        println!("change password");
        let output: PasswordChangeOutput = client
            .post(url.as_str())
            .json(&data)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        println!("password changed {:?}", output);
        assert_eq!(output.message.as_str(), "password updated");

        let base_url: Url = format_sstr!("http://localhost:{test_port}").parse()?;
        let data = hashmap! {
            "key" => "value",
        };
        println!("POST session");
        AuthorizedUser::set_session_data(
            &base_url,
            resp.session.into(),
            &resp.secret_key,
            &client,
            "test",
            &data,
        )
        .await
        .map_err(Into::<AuthServerError>::into)?;
        println!("GET session");
        let resp: HashMap<String, String> = AuthorizedUser::get_session_data(
            &base_url,
            resp.session.into(),
            &resp.secret_key,
            &client,
            "test",
        )
        .await
        .map_err(Into::<AuthServerError>::into)?;
        println!("{resp:?}");
        assert_eq!(resp.len(), 1);
        let url = format_sstr!("http://localhost:{test_port}/api/auth");
        let status = client
            .delete(url.as_str())
            .send()
            .await?
            .error_for_status()?
            .status();
        assert_eq!(status.as_u16(), StatusCode::NO_CONTENT.as_u16());

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
        let sdk_config = aws_config::load_from_env().await;
        let ses = SesInstance::new(&sdk_config);
        let pool = PgPool::new(&config.database_url)?;

        let app = AppState {
            config: config.clone(),
            pool,
            google_client,
            ses,
            session_cache: SessionDataCache::new(),
        };

        let app = Arc::new(app);

        let (_, spec) = utoipa_axum::router::OpenApiRouter::with_openapi(ApiDoc::openapi())
            .merge(get_api_scope(&app))
            .split_for_parts();
        let spec_yaml = serde_yml::to_string(&spec).map_err(Into::<AuthServerError>::into)?;

        std::fs::write("../scripts/openapi.yaml", &spec_yaml)?;

        Ok(())
    }
}
