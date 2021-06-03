use chrono::Utc;
use futures::try_join;
use log::debug;
use rweb::{delete, get, post, Json, Query, Rejection, Schema};
use serde::{Deserialize, Serialize};
use serde_json::{map::Map, Value};
use stack_string::StackString;
use std::sync::Arc;
use url::Url;
use uuid::Uuid;
use std::convert::Infallible;

use auth_server_ext::{
    datetime_wrapper::DateTimeWrapper,
    google_openid::GoogleClient,
    invitation::Invitation,
    ses_client::{EmailStats, SesInstance, SesQuotas},
};
use auth_server_lib::{config::Config, pgpool::PgPool, session::Session, user::User};
use authorized_users::{AuthorizedUser, AUTHORIZED_USERS};
use rweb_helper::{
    content_type_trait::{ContentTypeCss, ContentTypeHtml, ContentTypeJs},
    derive_response_description,
    html_response::HtmlResponse as HtmlBase,
    json_response::JsonResponse as JsonBase,
    status_code_trait::{StatusCodeCreated, StatusCodeOk},
};

use crate::{
    app::AppState, auth::AuthRequest, errors::ServiceError as Error, logged_user::LoggedUser,
};

pub type WarpResult<T> = Result<T, Rejection>;
pub type HttpResult<T> = Result<T, Error>;

struct AuthIndexDescription {}
derive_response_description!(AuthIndexDescription, "Main page");
type AuthIndexResponse =
    HtmlBase<&'static str, Infallible, StatusCodeOk, ContentTypeHtml, AuthIndexDescription>;

#[get("/auth/index.html")]
pub async fn index_html() -> WarpResult<AuthIndexResponse> {
    Ok(HtmlBase::new(include_str!("../../templates/index.html")))
}

struct CssDescription {}
derive_response_description!(CssDescription, "CSS");
type CssResponse = HtmlBase<&'static str, Infallible, StatusCodeOk, ContentTypeCss, CssDescription>;

#[get("/auth/main.css")]
pub async fn main_css() -> WarpResult<CssResponse> {
    Ok(HtmlBase::new(include_str!("../../templates/main.css")))
}

struct RegisterDescription {}
derive_response_description!(RegisterDescription, "Main page");
type RegisterResponse =
    HtmlBase<&'static str, Infallible, StatusCodeOk, ContentTypeHtml, RegisterDescription>;

#[get("/auth/register.html")]
pub async fn register_html() -> WarpResult<RegisterResponse> {
    Ok(HtmlBase::new(include_str!("../../templates/register.html")))
}

struct JsDescription {}
derive_response_description!(JsDescription, "Javascript");
type JsResponse = HtmlBase<&'static str, Infallible, StatusCodeOk, ContentTypeJs, JsDescription>;

#[get("/auth/main.js")]
pub async fn main_js() -> WarpResult<JsResponse> {
    Ok(HtmlBase::new(include_str!("../../templates/main.js")))
}

struct AuthLoginDescription {}
derive_response_description!(AuthLoginDescription, "Login Page");
type AuthLoginResponse =
    HtmlBase<&'static str, Infallible, StatusCodeOk, ContentTypeHtml, AuthLoginDescription>;

#[get("/auth/login.html")]
pub async fn login_html() -> WarpResult<AuthLoginResponse> {
    Ok(HtmlBase::new(include_str!("../../templates/login.html")))
}

struct PwChangeDescription {}
derive_response_description!(PwChangeDescription, "Change Password");
type PwChangeResponse =
    HtmlBase<&'static str, Infallible, StatusCodeOk, ContentTypeHtml, PwChangeDescription>;

#[get("/auth/change_password.html")]
pub async fn change_password() -> WarpResult<PwChangeResponse> {
    Ok(HtmlBase::new(include_str!(
        "../../templates/change_password.html"
    )))
}

struct ApiAuthPostDescription {}

derive_response_description!(ApiAuthPostDescription, "Current logged in username");

type ApiAuthResponse = JsonBase<LoggedUser, Error, StatusCodeCreated, ApiAuthPostDescription>;

#[post("/api/auth")]
#[openapi(description = "Login with username and password")]
pub async fn login(
    #[data] data: AppState,
    auth_data: Json<AuthRequest>,
) -> WarpResult<ApiAuthResponse> {
    let auth_data = auth_data.into_inner();
    let session = Session::new(auth_data.email.as_str());
    session
        .insert(&data.pool)
        .await
        .map_err(Into::<Error>::into)?;

    let mut session_map_cache = (*data.session_cache.load().clone()).clone();
    session_map_cache.insert(session.id, Value::Object(Map::new()));
    data.session_cache.store(Arc::new(session_map_cache));

    let (user, jwt) = login_user_jwt(auth_data, session.id, &data.pool, &data.config).await?;
    let resp = JsonBase::new(user).with_cookie(jwt);
    Ok(resp)
}

async fn login_user_jwt(
    auth_data: AuthRequest,
    session: Uuid,
    pool: &PgPool,
    config: &Config,
) -> HttpResult<(LoggedUser, String)> {
    let message = if let Some(user) = auth_data.authenticate(pool).await? {
        let user: AuthorizedUser = user.into();
        let mut user: LoggedUser = user.into();
        user.session = Some(session.into());
        match user.get_jwt_cookie(&config.domain, config.expiration_seconds) {
            Ok(jwt) => return Ok((user, jwt)),
            Err(e) => format!("Failed to create_token {}", e),
        }
    } else {
        "Username and Password don't match".into()
    };
    Err(Error::BadRequest(message))
}

struct ApiAuthDeleteDescription {}

derive_response_description!(ApiAuthDeleteDescription, "Status Message");

type ApiAuthDeleteResponse = JsonBase<String, Error, StatusCodeCreated, ApiAuthDeleteDescription>;

#[delete("/api/auth")]
#[openapi(description = "Log out")]
pub async fn logout(
    #[cookie = "jwt"] logged_user: LoggedUser,
    #[data] data: AppState,
) -> WarpResult<ApiAuthDeleteResponse> {
    if let Some(session) = logged_user.session.map(Into::into) {
        if let Some(session_obj) = Session::get_session(&data.pool, &session)
            .await
            .map_err(Into::<Error>::into)?
        {
            session_obj
                .delete(&data.pool)
                .await
                .map_err(Into::<Error>::into)?;
        }
        let mut session_map_cache = (*data.session_cache.load().clone()).clone();
        session_map_cache.remove(&session);
        data.session_cache.store(Arc::new(session_map_cache));
    }
    let resp =
        JsonBase::new(format!("{} has been logged out", logged_user.email)).with_cookie(format!(
            "jwt=; HttpOnly; Path=/; Domain={}; Max-Age={}",
            data.config.domain, data.config.expiration_seconds
        ));
    Ok(resp)
}

struct ApiAuthGetDescription {}

derive_response_description!(ApiAuthGetDescription, "Current users email");

type ApiAuthGetResponse = JsonBase<LoggedUser, Error, StatusCodeOk, ApiAuthGetDescription>;

#[get("/api/auth")]
#[openapi(description = "Get current username if logged in")]
pub async fn get_me(#[cookie = "jwt"] logged_user: LoggedUser) -> WarpResult<ApiAuthGetResponse> {
    Ok(JsonBase::new(logged_user))
}

struct GetSessionDescription {}
derive_response_description!(GetSessionDescription, "Get Session Object");

type GetSessionResponse = JsonBase<Value, Error, StatusCodeOk, GetSessionDescription>;

#[get("/api/session")]
#[openapi(description = "Get Session")]
pub async fn get_session(
    #[header = "session"] session: Uuid,
    #[data] data: AppState,
) -> WarpResult<GetSessionResponse> {
    if let Some(value) = data.session_cache.load().get(&session) {
        debug!("got cache");
        return Ok(JsonBase::new(value.clone()));
    }
    if let Some(session_obj) = Session::get_session(&data.pool, &session)
        .await
        .map_err(Into::<Error>::into)?
    {
        let mut session_map_cache = (*data.session_cache.load().clone()).clone();
        session_map_cache.insert(session, session_obj.session_data.clone());
        data.session_cache.store(Arc::new(session_map_cache));
        return Ok(JsonBase::new(session_obj.session_data));
    }
    Ok(JsonBase::new(Value::Null))
}

struct PostSessionDescription {}
derive_response_description!(PostSessionDescription, "Set Session Object");

type PostSessionResponse = JsonBase<Value, Error, StatusCodeCreated, PostSessionDescription>;

#[post("/api/session")]
#[openapi(description = "Set session value")]
pub async fn post_session(
    #[header = "session"] session: Uuid,
    #[data] data: AppState,
    payload: Json<Value>,
) -> WarpResult<PostSessionResponse> {
    let payload = payload.into_inner();
    debug!("payload {} {}", payload, session);
    debug!("session {}", session);
    if let Some(mut session_obj) = Session::get_session(&data.pool, &session)
        .await
        .map_err(Into::<Error>::into)?
    {
        debug!("session_obj {:?}", session_obj.session_data);
        session_obj.session_data = payload.clone();
        session_obj
            .update(&data.pool)
            .await
            .map_err(Into::<Error>::into)?;
        let mut session_map_cache = (*data.session_cache.load().clone()).clone();
        *session_map_cache.entry(session).or_default() = session_obj.session_data;
        data.session_cache.store(Arc::new(session_map_cache));
    }
    Ok(JsonBase::new(payload))
}

#[derive(Deserialize, Schema)]
pub struct CreateInvitation {
    #[schema(description = "Email to send invitation to")]
    pub email: StackString,
}

#[derive(Serialize, Schema)]
pub struct InvitationOutput {
    #[schema(description = "Invitation ID")]
    pub id: StackString,
    #[schema(description = "Email Address")]
    pub email: StackString,
    #[schema(description = "Expiration Datetime")]
    pub expires_at: DateTimeWrapper,
}

impl From<Invitation> for InvitationOutput {
    fn from(i: Invitation) -> Self {
        Self {
            id: i.id.to_string().into(),
            email: i.email,
            expires_at: i.expires_at.into(),
        }
    }
}

struct ApiInvitationDescription {}
derive_response_description!(ApiInvitationDescription, "Invitation Object");

type ApiInvitationResponse =
    JsonBase<InvitationOutput, Error, StatusCodeCreated, ApiInvitationDescription>;

#[post("/api/invitation")]
#[openapi(description = "Send invitation to specified email")]
pub async fn register_email(
    #[data] data: AppState,
    invitation: Json<CreateInvitation>,
) -> WarpResult<ApiInvitationResponse> {
    let invitation =
        register_email_invitation(invitation.into_inner(), &data.pool, &data.config).await?;
    let resp = JsonBase::new(invitation.into());
    Ok(resp)
}

async fn register_email_invitation(
    invitation: CreateInvitation,
    pool: &PgPool,
    config: &Config,
) -> HttpResult<Invitation> {
    let email = invitation.email;
    let invitation = Invitation::from_email(&email);
    invitation.insert(pool).await?;
    invitation
        .send_invitation(&config.sending_email_address, config.callback_url.as_str())
        .await?;
    Ok(invitation)
}

#[derive(Debug, Deserialize, Schema)]
pub struct UserData {
    pub password: StackString,
}

struct ApiRegisterDescription {}
derive_response_description!(ApiRegisterDescription, "Registered Email");

type ApiRegisterResponse = JsonBase<LoggedUser, Error, StatusCodeCreated, ApiRegisterDescription>;

#[post("/api/register/{invitation_id}")]
#[openapi(description = "Set password using link from email")]
pub async fn register_user(
    invitation_id: StackString,
    #[data] data: AppState,
    user_data: Json<UserData>,
) -> WarpResult<ApiRegisterResponse> {
    let user = register_user_object(
        invitation_id,
        user_data.into_inner(),
        &data.pool,
        &data.config,
    )
    .await?;
    let resp = JsonBase::new(user.into());
    Ok(resp)
}

async fn register_user_object(
    invitation_id: StackString,
    user_data: UserData,
    pool: &PgPool,
    config: &Config,
) -> HttpResult<AuthorizedUser> {
    let uuid = Uuid::parse_str(&invitation_id)?;
    if let Some(invitation) = Invitation::get_by_uuid(&uuid, pool).await? {
        if invitation.expires_at > Utc::now() {
            let user = User::from_details(&invitation.email, &user_data.password, &config);
            user.upsert(pool).await?;
            invitation.delete(pool).await?;
            let user: AuthorizedUser = user.into();
            AUTHORIZED_USERS.store_auth(user.clone(), true)?;
            return Ok(user);
        }
        invitation.delete(pool).await?;
    }
    Err(Error::BadRequest("Invalid invitation".into()))
}

#[derive(Serialize, Deserialize, Debug, Schema)]
pub struct PasswordChangeOutput {
    pub message: StackString,
}

struct ApiPasswordChangeDescription {}
derive_response_description!(ApiPasswordChangeDescription, "Success Message");

type ApiPasswordChangeResponse =
    JsonBase<PasswordChangeOutput, Error, StatusCodeCreated, ApiPasswordChangeDescription>;

#[post("/api/password_change")]
#[openapi(description = "Change password for currently logged in user")]
pub async fn change_password_user(
    #[cookie = "jwt"] logged_user: LoggedUser,
    #[data] data: AppState,
    user_data: Json<UserData>,
) -> WarpResult<ApiPasswordChangeResponse> {
    let message = change_password_user_body(
        logged_user,
        user_data.into_inner(),
        &data.pool,
        &data.config,
    )
    .await?
    .into();
    let resp = JsonBase::new(PasswordChangeOutput { message });
    Ok(resp)
}

async fn change_password_user_body(
    logged_user: LoggedUser,
    user_data: UserData,
    pool: &PgPool,
    config: &Config,
) -> HttpResult<&'static str> {
    if let Some(mut user) = User::get_by_email(&logged_user.email, pool).await? {
        user.set_password(&user_data.password, &config);
        user.update(pool).await?;
        Ok("password updated")
    } else {
        Err(Error::BadRequest("Invalid User".into()))
    }
}

#[derive(Deserialize, Schema)]
pub struct GetAuthUrlData {
    #[schema(description = "Url to redirect to after completion of authorization")]
    pub final_url: StackString,
}

#[derive(Serialize, Deserialize, Schema)]
pub struct AuthUrlOutput {
    pub csrf_state: StackString,
    pub auth_url: StackString,
}

struct ApiAuthUrlDescription {}
derive_response_description!(ApiAuthUrlDescription, "Authorization Url");

type ApiAuthUrlResponse = JsonBase<AuthUrlOutput, Error, StatusCodeOk, ApiAuthUrlDescription>;

#[post("/api/auth_url")]
#[openapi(description = "Get Oauth Url")]
pub async fn auth_url(
    #[data] data: AppState,
    query: Json<GetAuthUrlData>,
) -> WarpResult<ApiAuthUrlResponse> {
    let (csrf_state, authorize_url) =
        auth_url_body(query.into_inner(), &data.google_client).await?;
    let authorize_url: String = authorize_url.into();
    let resp = JsonBase::new(AuthUrlOutput {
        csrf_state,
        auth_url: authorize_url.into(),
    });
    Ok(resp)
}

async fn auth_url_body(
    payload: GetAuthUrlData,
    google_client: &GoogleClient,
) -> HttpResult<(StackString, Url)> {
    debug!("{:?}", payload.final_url);
    let (csrf_state, auth_url) = google_client.get_auth_url().await?;
    Ok((csrf_state, auth_url))
}

#[derive(Schema, Serialize, Deserialize)]
pub struct AuthAwait {
    pub state: StackString,
}

struct ApiAwaitDescription {}
derive_response_description!(ApiAwaitDescription, "Finished");

type ApiAwaitResponse =
    HtmlBase<&'static str, Infallible, StatusCodeOk, ContentTypeHtml, ApiAwaitDescription>;

#[get("/api/await")]
#[openapi(description = "Await completion of auth")]
pub async fn auth_await(
    #[data] data: AppState,
    query: Query<AuthAwait>,
) -> WarpResult<ApiAwaitResponse> {
    let state = query.into_inner().state;
    loop {
        if !data.google_client.check_csrf(&state).await {
            return Ok(HtmlBase::new(""));
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

#[derive(Deserialize, Schema)]
pub struct CallbackQuery {
    pub code: StackString,
    pub state: StackString,
}

struct ApiCallbackDescription {}
derive_response_description!(ApiCallbackDescription, "Callback Response");

type ApiCallbackResponse =
    HtmlBase<&'static str, Error, StatusCodeOk, ContentTypeHtml, ApiCallbackDescription>;

#[get("/api/callback")]
#[openapi(description = "Callback method for use in Oauth flow")]
pub async fn callback(
    #[data] data: AppState,
    query: Query<CallbackQuery>,
) -> WarpResult<ApiCallbackResponse> {
    let jwt = callback_body(
        query.into_inner(),
        &data.pool,
        &data.google_client,
        &data.config,
    )
    .await?;
    let body = r#"
        <title>Google Oauth Succeeded</title>
        This window can be closed.
        <script language="JavaScript" type="text/javascript">window.close()</script>
    "#;
    Ok(HtmlBase::new(body).with_cookie(&jwt))
}

async fn callback_body(
    query: CallbackQuery,
    pool: &PgPool,
    google_client: &GoogleClient,
    config: &Config,
) -> HttpResult<String> {
    if let Some(user) = google_client
        .run_callback(&query.code, &query.state, pool)
        .await?
    {
        let mut user: LoggedUser = user.into();

        let session = Session::new(user.email.as_str());
        session.insert(&pool).await?;

        user.session = Some(session.id.into());

        let jwt = user.get_jwt_cookie(&config.domain, config.expiration_seconds)?;
        Ok(jwt)
    } else {
        Err(Error::BadRequest("Callback Failed".into()))
    }
}

#[derive(Serialize, Schema)]
pub struct StatusOutput {
    number_of_users: i64,
    number_of_invitations: i64,
    quota: SesQuotas,
    stats: EmailStats,
}

struct StatusOutputDescription {}
derive_response_description!(StatusOutputDescription, "Status output");

type StatusResponse = JsonBase<StatusOutput, Error, StatusCodeOk, StatusOutputDescription>;

#[get("/api/status")]
#[openapi(description = "Status endpoint")]
pub async fn status(#[data] data: AppState) -> WarpResult<StatusResponse> {
    let result = status_body(&data.pool).await?;
    Ok(JsonBase::new(result))
}

async fn status_body(pool: &PgPool) -> HttpResult<StatusOutput> {
    let ses = SesInstance::new(None);
    let (number_users, number_invitations, (quota, stats)) = try_join!(
        User::get_number_users(pool),
        Invitation::get_number_invitations(pool),
        ses.get_statistics(),
    )?;
    let result = StatusOutput {
        number_of_users: number_users,
        number_of_invitations: number_invitations,
        quota,
        stats,
    };
    Ok(result)
}

#[post("/api/auth")]
pub async fn test_login(
    auth_data: Json<AuthRequest>,
    #[data] data: AppState,
) -> WarpResult<JsonBase<LoggedUser, Error, StatusCodeCreated>> {
    let auth_data = auth_data.into_inner();
    let session = Session::new(auth_data.email.as_str());
    let (user, jwt) = test_login_user_jwt(auth_data, session.id, &data.config).await?;
    let resp = JsonBase::new(user).with_cookie(jwt);
    Ok(resp)
}

async fn test_login_user_jwt(
    auth_data: AuthRequest,
    session: Uuid,
    config: &Config,
) -> HttpResult<(LoggedUser, String)> {
    if let Ok(s) = std::env::var("TESTENV") {
        if &s == "true" {
            let user = AuthorizedUser {
                email: auth_data.email.into(),
                session: Some(session),
            };
            AUTHORIZED_USERS.merge_users(&[user.email.clone()])?;
            let mut user: LoggedUser = user.into();
            user.session = Some(session.into());
            let jwt = user.get_jwt_cookie(&config.domain, config.expiration_seconds)?;
            return Ok((user, jwt));
        }
    }
    Err(Error::BadRequest(
        "Username and Password don't match".into(),
    ))
}
