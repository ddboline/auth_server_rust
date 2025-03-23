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
use utoipa::{PartialSchema, ToSchema};
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

type WarpResult<T> = Result<T, Error>;
type HttpResult<T> = Result<T, Error>;

#[derive(Deserialize, ToSchema)]
struct FinalUrlData {
    #[schema(example = r#""https://example.com""#)]
    /// Url to redirect to after completion of authorization
    final_url: Option<StackString>,
}

#[derive(UtoipaResponse)]
#[response(description = "Main Page", content = "text/html")]
#[rustfmt::skip]
struct AuthIndexResponse(HtmlBase::<StackString>);

#[utoipa::path(get, path = "/auth/index.html", responses(AuthIndexResponse, Error))]
/// Main Page
async fn index_html(
    user: Option<LoggedUser>,
    data: State<Arc<AppState>>,
    query: Query<FinalUrlData>,
) -> WarpResult<AuthIndexResponse> {
    let Query(query) = query;

    let body = {
        let summaries = if user.is_some() {
            list_sessions_lines(&data).await?
        } else {
            Vec::new()
        };
        let data = if let Some(user) = &user {
            SessionData::get_session_summary(&data.pool, user.session.into())
                .await
                .map_err(Into::<Error>::into)?
        } else {
            Vec::new()
        };
        index_body(user, summaries, data, query.final_url).map_err(Into::<Error>::into)?
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

#[derive(Deserialize, ToSchema)]
struct RegisterQuery {
    id: Uuid,
    email: StackString,
}

#[derive(UtoipaResponse)]
#[response(description = "Registration", content = "text/html")]
#[rustfmt::skip]
struct RegisterResponse(HtmlBase::<StackString>);

#[utoipa::path(get, path = "/auth/register.html", responses(RegisterResponse, Error))]
/// Registration Page
async fn register_html(
    query: Query<RegisterQuery>,
    data: State<Arc<AppState>>,
) -> WarpResult<RegisterResponse> {
    let Query(query) = query;
    let invitation_id: Uuid = query.id.into();
    let email = query.email;

    if let Some(invitation) = Invitation::get_by_uuid(invitation_id, &data.pool)
        .await
        .map_err(Into::<Error>::into)?
    {
        if invitation.email == email {
            let body = register_body(invitation_id).map_err(Into::<Error>::into)?;
            return Ok(HtmlBase::new(body).into());
        }
    }
    Err(Error::BadRequest("Invalid invitation").into())
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

#[utoipa::path(get, path = "/auth/login.html", responses(AuthLoginResponse, Error))]
/// Login Page
async fn login_html(
    user: Option<LoggedUser>,
    query: Query<FinalUrlData>,
) -> WarpResult<AuthLoginResponse> {
    let Query(query) = query;
    let body = login_body(user, query.final_url).map_err(Into::<Error>::into)?;
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
async fn change_password(user: LoggedUser) -> WarpResult<PwChangeResponse> {
    let body = change_password_body(user).map_err(Into::<Error>::into)?;
    Ok(HtmlBase::new(body).into())
}

#[derive(UtoipaResponse)]
#[response(description = "Current logged in username", status = "CREATED", content = "application/json")]
#[rustfmt::skip]
struct ApiAuthResponse(JsonBase::<LoggedUser>);

#[utoipa::path(post, path = "/api/auth", responses(ApiAuthResponse, Error))]
/// Login with username and password
async fn login(
    data: State<Arc<AppState>>,
    auth_data: Json<AuthRequest>,
) -> WarpResult<ApiAuthResponse> {
    let Json(auth_data) = auth_data;

    let (user, session, cookies) = auth_data.login_user_jwt(&data.pool, &data.config).await?;

    let _ = data.session_cache.add_session(session);

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
async fn logout(user: LoggedUser, data: State<Arc<AppState>>) -> WarpResult<ApiAuthDeleteResponse> {
    let session_id = user.session.into();
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
/// Get current username if logged in
async fn get_user(user: LoggedUser, data: State<Arc<AppState>>) -> WarpResult<ApiAuthGetResponse> {
    let session_id = user.session.into();
    if !data.session_cache.has_session(session_id) {
        if let Some(session) = Session::get_session(&data.pool, session_id)
            .await
            .map_err(Into::<Error>::into)?
        {
            let _ = data.session_cache.add_session(session);
        } else {
            return Err(Error::Unauthorized.into());
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
    responses(GetSessionResponse, Error)
)]
/// Get Session
async fn get_session(
    data: State<Arc<AppState>>,
    session_key: Path<StackString>,
    session: SessionKey,
    secret_key: SecretKey,
) -> WarpResult<GetSessionResponse> {
    let Path(session_key) = session_key;
    let session = session.into();
    let secret_key: StackString = secret_key.into();
    let value = if let Some(value) =
        data.session_cache
            .get_data(session, &secret_key, &session_key)?
    {
        value
    } else if let Some(session_data) =
        SessionData::get_session_from_cache(&data.pool, session, &secret_key, &session_key)
            .await
            .map_err(Into::<Error>::into)?
    {
        data.session_cache.set_data(
            session,
            secret_key,
            session_key,
            &session_data.session_value,
        )?;
        session_data.session_value
    } else {
        Value::Null
    };
    Ok(JsonBase::new(value).into())
}

#[derive(UtoipaResponse)]
#[response(description = "Set Session Object", status = "CREATED", content = "application/json")]

#[rustfmt::skip]
struct PostSessionResponse(JsonBase::<Value>);

#[utoipa::path(
    post,
    path = "/api/session/{session_key}",
    responses(PostSessionResponse, Error)
)]
/// Set session value
async fn post_session(
    data: State<Arc<AppState>>,
    session_key: Path<StackString>,
    session: SessionKey,
    secret_key: SecretKey,
    payload: Json<Value>,
) -> WarpResult<PostSessionResponse> {
    let Path(session_key) = session_key;
    let session = session.into();
    let secret_key: StackString = secret_key.into();

    let Json(payload) = payload;
    debug!("payload {} {}", payload, session);
    debug!("session {}", session);
    if let Some(session_data) = Session::set_session_from_cache(
        &data.pool,
        session,
        &secret_key,
        &session_key,
        payload.clone(),
    )
    .await
    .map_err(Into::<Error>::into)?
    {
        data.session_cache.set_data(
            session,
            secret_key,
            session_key,
            &session_data.session_value,
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
    responses(DeleteSessionResponse, Error)
)]
/// Delete session value
async fn delete_session(
    data: State<Arc<AppState>>,
    session_key: Path<StackString>,
    session: SessionKey,
    secret_key: SecretKey,
) -> WarpResult<DeleteSessionResponse> {
    let Path(session_key) = session_key;
    let session = session.into();
    let secret_key: StackString = secret_key.into();

    Session::delete_session_data_from_cache(&data.pool, session, &secret_key, &session_key)
        .await
        .map_err(Into::<Error>::into)?;
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
    session_id: Uuid,
    /// Session Key
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
            session_id: value.session_id.into(),
            session_key: value.session_key,
            session_value: value.session_value,
            created_at: value.created_at.to_offsetdatetime().into(),
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
) -> WarpResult<SessionDataObjResponse> {
    let values = SessionData::get_by_session_id_streaming(&data.pool, user.session.into())
        .await
        .map_err(Into::<Error>::into)?
        .map_ok(Into::into)
        .try_collect()
        .await
        .map_err(Into::<AuthServerError>::into)
        .map_err(Into::<Error>::into)?;

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
) -> WarpResult<ListSessionsResponse> {
    let summaries = list_sessions_lines(&data).await?;
    let body = session_body(summaries).map_err(Into::<Error>::into)?;
    Ok(HtmlBase::new(body).into())
}

async fn list_sessions_lines(data: &AppState) -> HttpResult<Vec<SessionSummary>> {
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
) -> WarpResult<ListSessionDataResponse> {
    let data = SessionData::get_session_summary(&data.pool, user.session.into())
        .await
        .map_err(Into::<Error>::into)?;
    let body = session_data_body(data).map_err(Into::<Error>::into)?;
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
async fn get_sessions(_: LoggedUser, data: State<Arc<AppState>>) -> WarpResult<SessionsResponse> {
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

#[derive(Deserialize, ToSchema, Debug)]
struct SessionQuery {
    /// Session Key
    session_key: Option<StackString>,
    /// Session
    session: Option<Uuid>,
}

#[utoipa::path(
    delete,
    path = "/api/sessions",
    responses(DeleteSessionsResponse, Error)
)]
/// Delete Sessions
async fn delete_sessions(
    user: LoggedUser,
    data: State<Arc<AppState>>,
    session_query: Query<SessionQuery>,
) -> WarpResult<DeleteSessionsResponse> {
    let Query(session_query) = session_query;
    if let Some(session_key) = &session_query.session_key {
        let session_id = user.session.into();
        Session::delete_session_data_from_cache(
            &data.pool,
            session_id,
            &user.secret_key,
            session_key,
        )
        .await
        .map_err(Into::<Error>::into)?;
        data.session_cache
            .remove_data(session_id, &user.secret_key, session_key)?;
    }
    if let Some(session) = session_query.session {
        LoggedUser::delete_user_session(session.into(), &data.pool).await?;
        let _ = data.session_cache.remove_session(session.into());
    }
    Ok(HtmlBase::new("finished").into())
}

#[derive(Deserialize, ToSchema)]
/// CreateInvitation
struct CreateInvitation {
    /// Email to send invitation to
    email: StackString,
}

#[derive(Serialize, ToSchema)]
/// Invitation
struct InvitationOutput {
    /// Invitation ID
    id: StackString,
    /// Email Address
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
            expires_at: expires_at.into(),
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
    responses(ApiInvitationResponse, Error)
)]
/// Send invitation to specified email
async fn register_email(
    data: State<Arc<AppState>>,
    invitation: Json<CreateInvitation>,
) -> WarpResult<ApiInvitationResponse> {
    let Json(invitation) = invitation;

    let email = invitation.email;
    let invitation = Invitation::from_email(email);
    invitation
        .insert(&data.pool)
        .await
        .map_err(Into::<Error>::into)?;
    send_invitation(
        &data.ses,
        &invitation,
        &data.config.sending_email_address,
        &data.config.callback_url,
    )
    .await
    .map_err(Into::<Error>::into)?;

    let resp = JsonBase::new(invitation.into());
    Ok(resp.into())
}

#[derive(Debug, Deserialize, ToSchema)]
/// PasswordData
struct PasswordData {
    /// Password
    password: StackString,
}

#[derive(UtoipaResponse)]
#[response(description = "Registered Email", status = "CREATED", content = "application/json")]
#[rustfmt::skip]
struct ApiRegisterResponse(JsonBase::<LoggedUser>);

#[utoipa::path(
    post,
    path = "/api/register/{invitation_id}",
    responses(ApiRegisterResponse, Error)
)]
/// Set password using link from email
async fn register_user(
    data: State<Arc<AppState>>,
    invitation_id: Path<Uuid>,
    user_data: Json<PasswordData>,
) -> WarpResult<ApiRegisterResponse> {
    let Path(invitation_id) = invitation_id;
    let Json(user_data) = user_data;
    if let Some(invitation) = Invitation::get_by_uuid(invitation_id.into(), &data.pool)
        .await
        .map_err(Into::<Error>::into)?
    {
        let expires_at: OffsetDateTime = invitation.expires_at.into();
        if expires_at > OffsetDateTime::now_utc() {
            let user = User::from_details(invitation.email.clone(), &user_data.password)
                .map_err(Into::<Error>::into)?;
            user.upsert(&data.pool).await.map_err(Into::<Error>::into)?;
            invitation
                .delete(&data.pool)
                .await
                .map_err(Into::<Error>::into)?;
            let user: AuthorizedUser = user.into();
            AUTHORIZED_USERS.store_auth(user.clone(), true);
            let resp = JsonBase::new(user.into());
            return Ok(resp.into());
        }
        invitation
            .delete(&data.pool)
            .await
            .map_err(Into::<Error>::into)?;
    }
    Err(Error::BadRequest("Invalid invitation").into())
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
/// PasswordChange
pub struct PasswordChangeOutput {
    pub message: StackString,
}

#[derive(UtoipaResponse)]
#[response(description = "Success Message", status = "CREATED", content = "application/json")]
#[rustfmt::skip]
struct ApiPasswordChangeResponse(JsonBase::<PasswordChangeOutput>);

#[utoipa::path(
    post,
    path = "/api/password_change",
    responses(ApiPasswordChangeResponse, Error)
)]
/// Change password for currently logged in user")]
async fn change_password_user(
    user: LoggedUser,
    data: State<Arc<AppState>>,
    user_data: Json<PasswordData>,
) -> WarpResult<ApiPasswordChangeResponse> {
    let Json(user_data) = user_data;
    let message: StackString = if let Some(mut user) = User::get_by_email(&user.email, &data.pool)
        .await
        .map_err(Into::<Error>::into)?
    {
        user.set_password(&user_data.password)
            .map_err(Into::<Error>::into)?;
        user.update(&data.pool).await.map_err(Into::<Error>::into)?;
        "password updated".into()
    } else {
        return Err(Error::BadRequest("Invalid User").into());
    };
    let resp = JsonBase::new(PasswordChangeOutput { message });
    Ok(resp.into())
}

#[derive(Serialize, Deserialize, ToSchema)]
/// AuthUrl")]
struct AuthUrlOutput {
    /// Auth URL")]
    auth_url: StackString,
    /// CSRF State")]
    csrf_state: StackString,
}

#[derive(UtoipaResponse)]
#[response(description = "Authorization Url", status = "CREATED", content = "application/json")]
#[rustfmt::skip]
struct ApiAuthUrlResponse(JsonBase::<AuthUrlOutput>);

#[utoipa::path(post, path = "/api/auth_url", responses(ApiAuthUrlResponse, Error))]
/// Get Oauth Url")]
async fn auth_url(
    data: State<Arc<AppState>>,
    query: Json<FinalUrlData>,
) -> WarpResult<ApiAuthUrlResponse> {
    let Json(query) = query;
    let (auth_url, csrf_state) = data
        .google_client
        .get_auth_url_csrf(query.final_url.as_ref().map(StackString::as_str))
        .await
        .map_err(Into::<Error>::into)?;
    let auth_url: String = auth_url.into();
    let resp = JsonBase::new(AuthUrlOutput {
        auth_url: auth_url.into(),
        csrf_state,
    });
    Ok(resp.into())
}

#[derive(ToSchema, Serialize, Deserialize)]
struct AuthAwait {
    /// CSRF State")]
    state: StackString,
}

#[derive(UtoipaResponse)]
#[response(description = "Finished", content = "text/html")]
#[rustfmt::skip]
struct ApiAwaitResponse(HtmlBase::<StackString>);

#[utoipa::path(get, path = "/api/await", responses(ApiAwaitResponse, Error))]
/// Await completion of auth")]
async fn auth_await(
    data: State<Arc<AppState>>,
    query: Query<AuthAwait>,
) -> WarpResult<ApiAwaitResponse> {
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
    let final_url = if let Some(s) = data.google_client.decode(&state) {
        s
    } else {
        "".into()
    };
    Ok(HtmlBase::new(final_url).into())
}

#[derive(Deserialize, ToSchema)]
struct CallbackQuery {
    /// Authorization Code")]
    code: StackString,
    /// CSRF State")]
    state: StackString,
}

#[derive(UtoipaResponse)]
#[response(description = "Callback Response", content = "text/html")]
#[rustfmt::skip]
struct ApiCallbackResponse(HtmlBase::<&'static str>);

#[utoipa::path(get, path = "/api/callback", responses(ApiCallbackResponse, Error))]
/// Callback method for use in Oauth flow")]
async fn callback(
    data: State<Arc<AppState>>,
    query: Query<CallbackQuery>,
) -> WarpResult<ApiCallbackResponse> {
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
) -> HttpResult<UserCookies<'static>> {
    if let Some(user) = google_client
        .run_callback(&query.code, &query.state, pool)
        .await?
    {
        let mut user: LoggedUser = user.into();

        let session = Session::new(user.email.as_str());
        session.insert(pool).await?;

        user.session = session.id.into();
        user.secret_key = session.secret_key;

        let cookies =
            user.get_jwt_cookie(&config.domain, config.expiration_seconds, config.secure)?;
        Ok(cookies)
    } else {
        Err(Error::BadRequest("Callback Failed"))
    }
}

#[derive(Serialize, ToSchema)]
/// Status")]
struct StatusOutput {
    /// Number of Users")]
    number_of_users: u64,
    /// Number of Invitations")]
    number_of_invitations: u64,
    /// Number of Sessions")]
    number_of_sessions: u64,
    /// Number of Data Entries")]
    number_of_entries: u64,
    quota: SesQuotasWrapper,
    stats: EmailStatsWrapper,
}

#[derive(UtoipaResponse)]
#[response(description = "Status output", content = "application/json")]
#[rustfmt::skip]
struct StatusResponse(JsonBase::<StatusOutput>);

#[utoipa::path(get, path = "/api/status", responses(StatusResponse, Error))]
/// Status endpoint")]
async fn status(data: State<Arc<AppState>>) -> WarpResult<StatusResponse> {
    let result = status_body(&data.pool).await?;
    Ok(JsonBase::new(result).into())
}

async fn status_body(pool: &PgPool) -> HttpResult<StatusOutput> {
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

#[utoipa::path(post, path = "/api/auth", responses(TestLoginResponse, Error))]
async fn test_login(
    data: State<Arc<AppState>>,
    auth_data: Json<AuthRequest>,
) -> WarpResult<TestLoginResponse> {
    let Json(auth_data) = auth_data;
    let session = Session::new(auth_data.email.as_str());
    let (user, cookies) = test_login_user_jwt(auth_data, session, &data.config).await?;
    let resp = JsonBase::new(user)
        .with_cookie(cookies.get_session_cookie_str())
        .with_cookie(cookies.get_jwt_cookie_str());
    Ok(resp.into())
}

#[utoipa::path(get, path = "/api/auth", responses(ApiAuthGetResponse, Error))]
async fn test_get_user(user: LoggedUser) -> WarpResult<ApiAuthGetResponse> {
    Ok(JsonBase::new(user).into())
}

async fn test_login_user_jwt(
    auth_data: AuthRequest,
    session: Session,
    config: &Config,
) -> HttpResult<(LoggedUser, UserCookies<'static>)> {
    use maplit::hashmap;

    if let Ok(s) = std::env::var("TESTENV") {
        if &s == "true" {
            let email = auth_data.email;
            let user = AuthorizedUser::new(&email, session.id, &session.secret_key);
            AUTHORIZED_USERS.update_users(hashmap! {user.email.clone() => user.clone()});
            let mut user: LoggedUser = user.into();
            user.session = session.id.into();
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
