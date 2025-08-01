use axum::{
    Json,
    extract::{Path, Query, State},
};
use derive_more::{From, Into};
use futures::{TryStreamExt, try_join};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stack_string::{StackString, format_sstr};
use std::{str, sync::Arc, time::Duration};
use time::OffsetDateTime;
use tokio::time::{sleep, timeout};
use utoipa::{IntoParams, OpenApi, PartialSchema, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use utoipa_helper::{
    UtoipaResponse, html_response::HtmlResponse as HtmlBase,
    json_response::JsonResponse as JsonBase,
};
use uuid::Uuid;

use auth_server_ext::{
    google_openid::GoogleClient,
    send_invitation,
    ses_client::{SesInstance, Statistics},
};
use auth_server_lib::{
    config::Config,
    date_time_wrapper::iso8601,
    errors::AuthServerError,
    invitation::Invitation,
    pgpool::PgPool,
    session::{Session, SessionSummary},
    session_data::SessionData,
    user::User,
};
use authorized_users::{AUTHORIZED_USERS, AuthorizedUser};

use crate::{
    EmailStatsWrapper, SesQuotasWrapper, SessionSummaryWrapper,
    app::AppState,
    auth::AuthRequest,
    elements::{
        change_password_body, index_body, login_body, register_body, session_body,
        session_data_body,
    },
    errors::ServiceError as Error,
    logged_user::{LoggedUser, SecretKey, SessionKey, UserCookies},
};

type AuthResult<T> = Result<T, Error>;

#[derive(Deserialize, ToSchema, IntoParams)]
struct FinalUrlData {
    #[param(example = r#""https://example.com""#, inline)]
    #[schema(example = r#""https://example.com""#, inline)]
    /// Url to redirect to after completion of authorization
    final_url: Option<StackString>,
}

#[derive(UtoipaResponse)]
#[response(description = "Main Page", content = "text/html")]
#[rustfmt::skip]
struct AuthIndexResponse(HtmlBase::<StackString>);

#[utoipa::path(
    get,
    path = "/auth/index.html",
    params(FinalUrlData),
    responses(AuthIndexResponse, Error)
)]
/// Main Page
// Main Page
async fn index_html(
    user: Option<LoggedUser>,
    data: State<Arc<AppState>>,
    query: Query<FinalUrlData>,
) -> AuthResult<AuthIndexResponse> {
    let Query(query) = query;

    let body = {
        let summaries = if user.is_some() {
            list_sessions_lines(&data).await?
        } else {
            Vec::new()
        };
        let data = if let Some(user) = &user {
            SessionData::get_session_summary(&data.pool, user.session).await?
        } else {
            Vec::new()
        };
        index_body(user, summaries, data, query.final_url)?
    };
    Ok(HtmlBase::new(body).into())
}

#[derive(UtoipaResponse)]
#[response(description = "CSS", content = "text/css")]
#[rustfmt::skip]
struct CssResponse(HtmlBase::<&'static str>);

#[utoipa::path(get, path = "/auth/main.css", responses(CssResponse))]
async fn main_css() -> CssResponse {
    HtmlBase::new(include_str!("../../templates/main.css")).into()
}

#[derive(Deserialize, ToSchema, IntoParams)]
struct RegisterQuery {
    #[schema(inline)]
    #[param(inline)]
    id: Uuid,
    #[schema(inline)]
    #[param(inline)]
    email: StackString,
}

#[derive(UtoipaResponse)]
#[response(description = "Registration", content = "text/html")]
#[rustfmt::skip]
struct RegisterResponse(HtmlBase::<StackString>);

#[utoipa::path(
    get,
    path = "/auth/register.html",
    params(RegisterQuery),
    responses(RegisterResponse, Error)
)]
/// Registration Page
async fn register_html(
    query: Query<RegisterQuery>,
    data: State<Arc<AppState>>,
) -> AuthResult<RegisterResponse> {
    let Query(query) = query;
    let invitation_id: Uuid = query.id;
    let email = query.email;
    let invitation = Invitation::get_by_uuid(invitation_id, &data.pool)
        .await?
        .ok_or_else(|| Error::BadRequest("Invitation Not Found"))?;

    if invitation.email == email {
        let body = register_body(invitation_id)?;
        Ok(HtmlBase::new(body).into())
    } else {
        Err(Error::BadRequest("Invalid invitation"))
    }
}

#[derive(UtoipaResponse)]
#[response(description = "Javascript", content = "text/javascript")]
#[rustfmt::skip]
struct JsResponse(HtmlBase::<&'static str>);

#[utoipa::path(get, path = "/auth/main.js", responses(JsResponse))]
async fn main_js() -> JsResponse {
    HtmlBase::new(include_str!("../../templates/main.js")).into()
}

#[derive(UtoipaResponse)]
#[response(description = "Login Page", content = "text/html")]
#[rustfmt::skip]
struct AuthLoginResponse(HtmlBase::<StackString>);

#[utoipa::path(
    get,
    path = "/auth/login.html",
    params(FinalUrlData),
    responses(AuthLoginResponse, Error)
)]
/// Login Page
async fn login_html(
    user: Option<LoggedUser>,
    query: Query<FinalUrlData>,
) -> AuthResult<AuthLoginResponse> {
    let Query(query) = query;
    let body = login_body(user, query.final_url)?;
    Ok(HtmlBase::new(body).into())
}

#[derive(UtoipaResponse)]
#[response(description = "Change Password", content = "text/html")]
#[rustfmt::skip]
struct PwChangeResponse(HtmlBase::<StackString>);

#[utoipa::path(
    get,
    path = "/auth/change_password.html",
    responses(PwChangeResponse, Error)
)]
/// Password Change Page
async fn change_password(user: LoggedUser) -> AuthResult<PwChangeResponse> {
    let body = change_password_body(user)?;
    Ok(HtmlBase::new(body).into())
}

#[derive(UtoipaResponse)]
#[response(description = "Current logged in username", status = "CREATED", content = "application/json")]
#[rustfmt::skip]
struct ApiAuthResponse(JsonBase::<LoggedUser>);

#[utoipa::path(post, path = "/api/auth", request_body = AuthRequest, responses(ApiAuthResponse, Error))]
/// Login with username and password
// Login with username and password
async fn login(
    data: State<Arc<AppState>>,
    auth_data: Json<AuthRequest>,
) -> AuthResult<ApiAuthResponse> {
    let Json(auth_data) = auth_data;

    let (user, session, cookies) = auth_data.login_user_jwt(&data.pool, &data.config).await?;

    let _ = data.session_cache.add_session(&session);

    let resp = JsonBase::new(user)
        .with_cookie(cookies.get_session_cookie_str())
        .with_cookie(cookies.get_jwt_cookie_str());
    Ok(resp.into())
}

#[derive(UtoipaResponse)]
#[response(description = "Status Message", status = "NO_CONTENT")]
#[rustfmt::skip]
struct ApiAuthDeleteResponse(HtmlBase::<StackString>);

#[utoipa::path(delete, path = "/api/auth", responses(ApiAuthDeleteResponse, Error))]
/// Log out
// Log out
async fn logout(user: LoggedUser, data: State<Arc<AppState>>) -> AuthResult<ApiAuthDeleteResponse> {
    let session_id = user.session;
    let _ = data.session_cache.remove_session(session_id);
    LoggedUser::delete_user_session(session_id, &data.pool).await?;
    let cookies = user.clear_jwt_cookie(
        &data.config.domain,
        data.config.expiration_seconds,
        data.config.secure,
    );
    let body = format_sstr!("{} has been logged out", user.email);
    let resp = HtmlBase::new(body)
        .with_cookie(cookies.get_session_cookie_str())
        .with_cookie(cookies.get_jwt_cookie_str());
    Ok(resp.into())
}

#[derive(UtoipaResponse)]
#[response(description = "Current users email", content = "application/json")]
#[rustfmt::skip]
struct ApiAuthGetResponse(JsonBase::<LoggedUser>);

#[utoipa::path(get, path = "/api/auth", responses(ApiAuthGetResponse, Error))]
/// Get current user if logged in
// Get current user
async fn get_user(user: LoggedUser, data: State<Arc<AppState>>) -> AuthResult<ApiAuthGetResponse> {
    let session_id = user.session;
    if !data.session_cache.has_session(session_id) {
        if let Some(session) = Session::get_session(&data.pool, session_id).await? {
            let _ = data.session_cache.add_session(&session);
        } else {
            return Err(Error::Unauthorized);
        }
    }
    Ok(JsonBase::new(user).into())
}

#[derive(UtoipaResponse)]
#[response(description = "Session Object", content = "application/json")]
#[rustfmt::skip]
struct GetSessionResponse(JsonBase::<Value>);

#[utoipa::path(
    get,
    path = "/api/session/{session_key}",
    params(
        ("session_key" = inline(StackString), description = "Session Key"),
        ("session" = inline(Uuid), Header, description = "Session Header"),
        ("secret-key" = inline(StackString), Header, description = "Secret Key Header"),
    ),
    responses(GetSessionResponse, Error)
)]
/// Get Session
async fn get_session(
    data: State<Arc<AppState>>,
    session_key: Path<StackString>,
    session: SessionKey,
    secret_key: SecretKey,
) -> AuthResult<GetSessionResponse> {
    let Path(session_key) = session_key;
    let session = session.into();
    let secret_key: StackString = secret_key.into();
    if let Some(value) = data
        .session_cache
        .get_data(session, &secret_key, &session_key)?
    {
        Ok(JsonBase::new(value).into())
    } else if let Some(session_data) =
        SessionData::get_session_from_cache(&data.pool, session, &secret_key, &session_key).await?
    {
        let value = session_data.get_session_value().clone();
        data.session_cache
            .set_data(session, secret_key, session_key, &value)?;
        Ok(JsonBase::new(value).into())
    } else {
        Ok(JsonBase::new(Value::Null).into())
    }
}

#[derive(UtoipaResponse)]
#[response(description = "Set Session Object", status = "CREATED", content = "application/json")]
#[rustfmt::skip]
struct PostSessionResponse(JsonBase::<Value>);

#[allow(dead_code)]
#[derive(ToSchema)]
struct SessionPayload(Value);

#[utoipa::path(
    post,
    path = "/api/session/{session_key}",
    request_body = inline(SessionPayload),
    params(("session_key" = inline(StackString), description = "Session Key")),
    responses(PostSessionResponse, Error)
)]
/// Set session value
async fn post_session(
    data: State<Arc<AppState>>,
    session_key: Path<StackString>,
    session: SessionKey,
    secret_key: SecretKey,
    payload: Json<Value>,
) -> AuthResult<PostSessionResponse> {
    let Path(session_key) = session_key;
    let session = session.into();
    let secret_key: StackString = secret_key.into();

    let Json(payload) = payload;
    debug!("payload {payload} {session}");
    debug!("session {session}");
    if let Some(session_data) = Session::set_session_from_cache(
        &data.pool,
        session,
        &secret_key,
        &session_key,
        payload.clone(),
    )
    .await?
    {
        data.session_cache.set_data(
            session,
            secret_key,
            session_key,
            session_data.get_session_value(),
        )?;
    }
    Ok(JsonBase::new(payload).into())
}

#[derive(ToSchema, Serialize, Deserialize, Into, From)]
struct DeleteSesssionInner(Option<Value>);

#[derive(UtoipaResponse)]
#[response(description = "Delete Session Object", status = "NO_CONTENT", content = "application/json")]
#[rustfmt::skip]
struct DeleteSessionResponse(JsonBase::<DeleteSesssionInner>);

#[utoipa::path(
    delete,
    path = "/api/session/{session_key}",
    params(("session_key" = inline(StackString), description = "Session Key")),
    responses(DeleteSessionResponse, Error)
)]
/// Delete session value
async fn delete_session(
    data: State<Arc<AppState>>,
    session_key: Path<StackString>,
    session: SessionKey,
    secret_key: SecretKey,
) -> AuthResult<DeleteSessionResponse> {
    let Path(session_key) = session_key;
    let session = session.into();
    let secret_key: StackString = secret_key.into();

    Session::delete_session_data_from_cache(&data.pool, session, &secret_key, &session_key).await?;
    let result = data
        .session_cache
        .remove_data(session, secret_key, session_key)?
        .into();
    Ok(JsonBase::new(result).into())
}

#[derive(ToSchema, Serialize, Deserialize)]
/// SessionData
struct SessionDataObj {
    /// Session ID
    #[schema(inline)]
    session_id: Uuid,
    /// Session Key
    #[schema(inline)]
    session_key: StackString,
    /// Session Data
    session_value: Value,
    /// Created At
    #[serde(with = "iso8601")]
    created_at: OffsetDateTime,
}

impl From<SessionData> for SessionDataObj {
    fn from(value: SessionData) -> Self {
        Self {
            session_id: value.get_session_id(),
            session_key: value.get_session_key().into(),
            session_value: value.get_session_value().clone(),
            created_at: value.get_created_at().to_offsetdatetime(),
        }
    }
}

#[derive(UtoipaResponse)]
#[response(description = "Session Data", content = "application/json")]
#[rustfmt::skip]
struct SessionDataObjResponse(JsonBase::<Vec<SessionDataObj>>);

#[utoipa::path(
    get,
    path = "/api/session-data",
    responses(SessionDataObjResponse, Error)
)]
/// Session Data
async fn list_session_obj(
    user: LoggedUser,
    data: State<Arc<AppState>>,
) -> AuthResult<SessionDataObjResponse> {
    let values = SessionData::get_by_session_id_streaming(&data.pool, user.session)
        .await?
        .map_ok(Into::into)
        .try_collect()
        .await
        .map_err(Into::<AuthServerError>::into)?;

    Ok(JsonBase::new(values).into())
}

#[derive(UtoipaResponse)]
#[response(description = "List Sessions")]
#[rustfmt::skip]
struct ListSessionsResponse(HtmlBase::<StackString>);

#[utoipa::path(
    get,
    path = "/api/list-sessions",
    responses(ListSessionsResponse, Error)
)]
/// List Sessions
async fn list_sessions(
    _: LoggedUser,
    data: State<Arc<AppState>>,
) -> AuthResult<ListSessionsResponse> {
    let summaries = list_sessions_lines(&data).await?;
    let body = session_body(summaries)?;
    Ok(HtmlBase::new(body).into())
}

async fn list_sessions_lines(data: &AppState) -> AuthResult<Vec<SessionSummary>> {
    Session::get_session_summary(&data.pool)
        .await
        .map_err(Into::into)
}

#[derive(UtoipaResponse)]
#[response(description = "List Session Data")]
#[rustfmt::skip]
struct ListSessionDataResponse(HtmlBase::<StackString>);

#[utoipa::path(
    get,
    path = "/api/list-session-data",
    responses(ListSessionDataResponse, Error)
)]
/// List Session Data
async fn list_session_data(
    user: LoggedUser,
    data: State<Arc<AppState>>,
) -> AuthResult<ListSessionDataResponse> {
    let data = SessionData::get_session_summary(&data.pool, user.session).await?;
    let body = session_data_body(data)?;
    Ok(HtmlBase::new(body).into())
}

#[derive(ToSchema, Serialize, Into, From)]
struct SessionsInner(Vec<SessionSummaryWrapper>);

#[derive(UtoipaResponse)]
#[response(description = "Sessions", content = "application/json")]
#[rustfmt::skip]
struct SessionsResponse(JsonBase::<SessionsInner>);

#[utoipa::path(get, path = "/api/sessions", responses(SessionsResponse, Error))]
/// Open Sessions
async fn get_sessions(_: LoggedUser, data: State<Arc<AppState>>) -> AuthResult<SessionsResponse> {
    let objects: Vec<SessionSummaryWrapper> = list_sessions_lines(&data)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(JsonBase::new(objects.into()).into())
}

#[derive(UtoipaResponse)]
#[response(description = "Delete Sessions", status = "NO_CONTENT")]
#[rustfmt::skip]
struct DeleteSessionsResponse(HtmlBase::<&'static str>);

#[derive(Deserialize, ToSchema, Debug, IntoParams)]
struct SessionQuery {
    /// Session Key
    #[param(inline)]
    #[schema(inline)]
    session_key: Option<StackString>,
    /// Session
    #[param(inline)]
    #[schema(inline)]
    session: Option<Uuid>,
}

#[utoipa::path(
    delete,
    path = "/api/sessions",
    params(SessionQuery),
    responses(DeleteSessionsResponse, Error)
)]
/// Delete Sessions
async fn delete_sessions(
    user: LoggedUser,
    data: State<Arc<AppState>>,
    session_query: Query<SessionQuery>,
) -> AuthResult<DeleteSessionsResponse> {
    let Query(session_query) = session_query;
    if let Some(session_key) = &session_query.session_key {
        let session_id = user.session;
        Session::delete_session_data_from_cache(
            &data.pool,
            session_id,
            &user.secret_key,
            session_key,
        )
        .await?;
        data.session_cache
            .remove_data(session_id, &user.secret_key, session_key)?;
    }
    if let Some(session) = session_query.session {
        LoggedUser::delete_user_session(session, &data.pool).await?;
        let _ = data.session_cache.remove_session(session);
    }
    Ok(HtmlBase::new("finished").into())
}

#[derive(Deserialize, ToSchema)]
/// CreateInvitation
struct CreateInvitation {
    /// Email to send invitation to
    #[schema(inline)]
    email: StackString,
}

#[derive(Serialize, ToSchema)]
/// Invitation
struct InvitationOutput {
    /// Invitation ID
    #[schema(inline)]
    id: StackString,
    /// Email Address
    #[schema(inline)]
    email: StackString,
    /// Expiration Datetime
    #[serde(with = "iso8601")]
    expires_at: OffsetDateTime,
}

impl From<Invitation> for InvitationOutput {
    fn from(i: Invitation) -> Self {
        let expires_at: OffsetDateTime = i.expires_at.into();
        Self {
            id: i.id.to_string().into(),
            email: i.email,
            expires_at,
        }
    }
}

#[derive(UtoipaResponse)]
#[response(description = "Invitation Object", status = "CREATED", content = "application/json")]
#[rustfmt::skip]
struct ApiInvitationResponse(JsonBase::<InvitationOutput>);

#[utoipa::path(
    post,
    path = "/api/invitation",
    request_body = CreateInvitation,
    responses(ApiInvitationResponse, Error)
)]
/// Send invitation to specified email
async fn register_email(
    data: State<Arc<AppState>>,
    invitation: Json<CreateInvitation>,
) -> AuthResult<ApiInvitationResponse> {
    let Json(invitation) = invitation;

    let email = invitation.email;
    let invitation = Invitation::from_email(email);
    invitation.insert(&data.pool).await?;
    send_invitation(
        &data.ses,
        &invitation,
        &data.config.sending_email_address,
        &data.config.callback_url,
    )
    .await?;

    let resp = JsonBase::new(invitation.into());
    Ok(resp.into())
}

#[derive(Debug, Deserialize, ToSchema)]
/// PasswordData
struct PasswordData {
    /// Password
    #[schema(inline)]
    password: StackString,
}

#[derive(UtoipaResponse)]
#[response(description = "Registered Email", status = "CREATED", content = "application/json")]
#[rustfmt::skip]
struct ApiRegisterResponse(JsonBase::<LoggedUser>);

#[utoipa::path(
    post,
    path = "/api/register/{invitation_id}",
    request_body = PasswordData,
    params(("invitation_id" = inline(Uuid), description = "Invitation ID")),
    responses(ApiRegisterResponse, Error)
)]
/// Set password using link from email
async fn register_user(
    data: State<Arc<AppState>>,
    invitation_id: Path<Uuid>,
    user_data: Json<PasswordData>,
) -> AuthResult<ApiRegisterResponse> {
    let Path(invitation_id) = invitation_id;
    let Json(user_data) = user_data;
    let invitation = Invitation::get_by_uuid(invitation_id, &data.pool)
        .await?
        .ok_or_else(|| Error::BadRequest("Invitation Not Found"))?;
    let expires_at: OffsetDateTime = invitation.expires_at.into();
    if expires_at > OffsetDateTime::now_utc() {
        let user = User::from_details(invitation.email.clone(), &user_data.password)?;
        user.upsert(&data.pool).await?;
        invitation.delete(&data.pool).await?;
        let user: AuthorizedUser = user.into();
        AUTHORIZED_USERS.store_auth(&user, true);
        let resp = JsonBase::new(user.into());
        Ok(resp.into())
    } else {
        invitation.delete(&data.pool).await?;
        Err(Error::BadRequest("Invalid invitation"))
    }
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
/// PasswordChange
pub struct PasswordChangeOutput {
    #[schema(inline)]
    pub message: StackString,
}

#[derive(UtoipaResponse)]
#[response(description = "Success Message", status = "CREATED", content = "application/json")]
#[rustfmt::skip]
struct ApiPasswordChangeResponse(JsonBase::<PasswordChangeOutput>);

#[utoipa::path(
    post,
    path = "/api/password_change",
    request_body = PasswordData,
    responses(ApiPasswordChangeResponse, Error)
)]
/// Change password for currently logged in user
async fn change_password_user(
    user: LoggedUser,
    data: State<Arc<AppState>>,
    user_data: Json<PasswordData>,
) -> AuthResult<ApiPasswordChangeResponse> {
    let Json(user_data) = user_data;
    let mut user = User::get_by_email(&user.email, &data.pool)
        .await?
        .ok_or_else(|| Error::BadRequest("User Not Found"))?;
    user.set_password(&user_data.password)?;
    user.update(&data.pool).await?;
    let message = "password updated".into();
    let resp = JsonBase::new(PasswordChangeOutput { message });
    Ok(resp.into())
}

#[derive(Serialize, Deserialize, ToSchema)]
/// AuthUrl
struct AuthUrlOutput {
    /// Auth URL
    #[schema(inline)]
    auth_url: StackString,
    /// CSRF State
    #[schema(inline)]
    csrf_state: StackString,
}

#[derive(UtoipaResponse)]
#[response(description = "Authorization Url", status = "CREATED", content = "application/json")]
#[rustfmt::skip]
struct ApiAuthUrlResponse(JsonBase::<AuthUrlOutput>);

#[utoipa::path(post, path = "/api/auth_url", request_body = FinalUrlData, responses(ApiAuthUrlResponse, Error))]
/// Get Oauth Url
async fn auth_url(
    data: State<Arc<AppState>>,
    query: Json<FinalUrlData>,
) -> AuthResult<ApiAuthUrlResponse> {
    let Json(query) = query;
    let (auth_url, csrf_state) = data
        .google_client
        .get_auth_url_csrf(query.final_url.as_ref().map(StackString::as_str))
        .await?;
    let auth_url: String = auth_url.into();
    let resp = JsonBase::new(AuthUrlOutput {
        auth_url: auth_url.into(),
        csrf_state,
    });
    Ok(resp.into())
}

#[derive(ToSchema, Serialize, Deserialize, IntoParams)]
struct AuthAwait {
    /// CSRF State
    #[param(inline)]
    state: StackString,
}

#[derive(UtoipaResponse)]
#[response(description = "Finished", content = "text/html")]
#[rustfmt::skip]
struct ApiAwaitResponse(HtmlBase::<StackString>);

#[utoipa::path(
    get,
    path = "/api/await",
    params(AuthAwait),
    responses(ApiAwaitResponse, Error)
)]
/// Await completion of auth
async fn auth_await(
    data: State<Arc<AppState>>,
    query: Query<AuthAwait>,
) -> AuthResult<ApiAwaitResponse> {
    let Query(AuthAwait { state }) = query;
    if timeout(
        Duration::from_secs(60),
        data.google_client.wait_csrf(&state),
    )
    .await
    .is_err()
    {
        error!("await timed out");
    }
    sleep(Duration::from_millis(10)).await;
    let final_url = data
        .google_client
        .decode(&state)
        .unwrap_or_else(|| "".into());
    Ok(HtmlBase::new(final_url).into())
}

#[derive(Deserialize, ToSchema, IntoParams)]
struct CallbackQuery {
    /// Authorization Code
    #[param(inline)]
    code: StackString,
    /// CSRF State
    #[param(inline)]
    state: StackString,
}

#[derive(UtoipaResponse)]
#[response(description = "Callback Response", content = "text/html")]
#[rustfmt::skip]
struct ApiCallbackResponse(HtmlBase::<&'static str>);

#[utoipa::path(
    get,
    path = "/api/callback",
    params(CallbackQuery),
    responses(ApiCallbackResponse, Error)
)]
/// Callback method for use in Oauth flow
async fn callback(
    data: State<Arc<AppState>>,
    query: Query<CallbackQuery>,
) -> AuthResult<ApiCallbackResponse> {
    let Query(query) = query;
    let cookies = callback_body(query, &data.pool, &data.google_client, &data.config).await?;
    let body = r#"
        <title>Google Oauth Succeeded</title>
        This window can be closed.
        <script language="JavaScript" type="text/javascript">window.close()</script>
    "#;
    Ok(HtmlBase::new(body)
        .with_cookie(cookies.get_session_cookie_str())
        .with_cookie(cookies.get_jwt_cookie_str())
        .into())
}

async fn callback_body(
    query: CallbackQuery,
    pool: &PgPool,
    google_client: &GoogleClient,
    config: &Config,
) -> AuthResult<UserCookies<'static>> {
    let user = google_client
        .run_callback(&query.code, &query.state, pool)
        .await?
        .ok_or_else(|| Error::BadRequest("Callback Failed"))?;
    let mut user: LoggedUser = user.into();

    let session = Session::new(user.email.as_str());
    session.insert(pool).await?;

    user.session = session.get_id();
    user.secret_key = session.get_secret_key().into();

    let cookies = user.get_jwt_cookie(&config.domain, config.expiration_seconds, config.secure)?;
    Ok(cookies)
}

#[derive(Serialize, ToSchema)]
/// Status
struct StatusOutput {
    /// Number of Users
    number_of_users: u64,
    /// Number of Invitations
    number_of_invitations: u64,
    /// Number of Sessions
    number_of_sessions: u64,
    /// Number of Data Entries
    number_of_entries: u64,
    quota: SesQuotasWrapper,
    stats: EmailStatsWrapper,
}

#[derive(UtoipaResponse)]
#[response(description = "Status output", content = "application/json")]
#[rustfmt::skip]
struct StatusResponse(JsonBase::<StatusOutput>);

#[utoipa::path(get, path = "/api/status", responses(StatusResponse, Error))]
/// Status endpoint
async fn status(data: State<Arc<AppState>>) -> AuthResult<StatusResponse> {
    let result = status_body(&data.pool).await?;
    Ok(JsonBase::new(result).into())
}

async fn status_body(pool: &PgPool) -> AuthResult<StatusOutput> {
    let sdk_config = aws_config::load_from_env().await;
    let ses = SesInstance::new(&sdk_config);
    let (
        number_users,
        number_invitations,
        number_sessions,
        number_entries,
        Statistics { quotas, stats },
    ) = try_join!(
        async move { User::get_number_users(pool).await.map_err(Into::into) },
        async move { Session::get_number_sessions(pool).await.map_err(Into::into) },
        async move {
            SessionData::get_number_entries(pool)
                .await
                .map_err(Into::into)
        },
        async move {
            Invitation::get_number_invitations(pool)
                .await
                .map_err(Into::into)
        },
        ses.get_statistics(),
    )?;
    Ok(StatusOutput {
        number_of_users: number_users,
        number_of_invitations: number_invitations,
        number_of_sessions: number_sessions,
        number_of_entries: number_entries,
        quota: quotas.into(),
        stats: stats.into(),
    })
}

#[derive(UtoipaResponse)]
#[response(description = "Login POST", status = "CREATED", content = "application/json")]
#[rustfmt::skip]
struct TestLoginResponse(JsonBase::<LoggedUser>);

#[utoipa::path(post, path = "/api/auth", request_body = AuthRequest, responses(TestLoginResponse, Error))]
async fn test_login(
    data: State<Arc<AppState>>,
    auth_data: Json<AuthRequest>,
) -> AuthResult<TestLoginResponse> {
    let Json(auth_data) = auth_data;
    let session = Session::new(auth_data.email.as_str());
    let (user, cookies) = test_login_user_jwt(auth_data, session, &data.config).await?;
    let resp = JsonBase::new(user)
        .with_cookie(cookies.get_session_cookie_str())
        .with_cookie(cookies.get_jwt_cookie_str());
    Ok(resp.into())
}

#[utoipa::path(get, path = "/api/auth", responses(ApiAuthGetResponse, Error))]
async fn test_get_user(user: LoggedUser) -> AuthResult<ApiAuthGetResponse> {
    Ok(JsonBase::new(user).into())
}

async fn test_login_user_jwt(
    auth_data: AuthRequest,
    session: Session,
    config: &Config,
) -> AuthResult<(LoggedUser, UserCookies<'static>)> {
    use maplit::hashmap;

    if let Ok(s) = std::env::var("TESTENV") {
        if &s == "true" {
            let email = auth_data.email;
            let user = AuthorizedUser::new(&email, session.get_id(), session.get_secret_key());
            AUTHORIZED_USERS.update_users(hashmap! {user.get_email().into() => user.clone()});
            let mut user: LoggedUser = user.into();
            user.session = session.get_id();
            let cookies = user.get_jwt_cookie(&config.domain, config.expiration_seconds, false)?;
            return Ok((user, cookies));
        }
    }
    Err(Error::BadRequest("Username and Password don't match"))
}

pub fn get_test_routes(app: &AppState) -> OpenApiRouter {
    let app = Arc::new(app.clone());

    OpenApiRouter::new()
        .routes(routes!(test_get_user))
        .routes(routes!(test_login))
        .with_state(app)
}

pub fn get_api_scope(app: &AppState) -> OpenApiRouter {
    let app = Arc::new(app.clone());

    OpenApiRouter::new()
        .routes(routes!(login, logout, get_user))
        .routes(routes!(register_email))
        .routes(routes!(register_user))
        .routes(routes!(change_password_user))
        .routes(routes!(auth_url))
        .routes(routes!(auth_await))
        .routes(routes!(callback))
        .routes(routes!(status))
        .routes(routes!(get_session, post_session, delete_session))
        .routes(routes!(list_session_obj))
        .routes(routes!(get_sessions, delete_sessions))
        .routes(routes!(list_sessions))
        .routes(routes!(list_session_data))
        .routes(routes!(index_html))
        .routes(routes!(main_css))
        .routes(routes!(main_js))
        .routes(routes!(register_html))
        .routes(routes!(login_html))
        .routes(routes!(change_password))
        .with_state(app)
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
pub struct ApiDoc;
