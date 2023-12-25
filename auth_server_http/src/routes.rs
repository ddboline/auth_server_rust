use futures::{try_join, TryStreamExt};
use log::{debug, error};
use rweb::{delete, get, post, Json, Query, Rejection, Schema};
use rweb_helper::{DateTimeType, UuidWrapper};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stack_string::{format_sstr, StackString};
use std::{convert::Infallible, str, time::Duration};
use time::OffsetDateTime;
use tokio::time::{sleep, timeout};
use uuid::Uuid;

use auth_server_ext::{
    google_openid::GoogleClient,
    send_invitation,
    ses_client::{SesInstance, Statistics},
};
use auth_server_lib::{
    config::Config,
    errors::AuthServerError,
    invitation::Invitation,
    pgpool::PgPool,
    session::{Session, SessionSummary},
    session_data::SessionData,
    user::User,
};
use authorized_users::{AuthorizedUser, AUTHORIZED_USERS};
use rweb_helper::{
    html_response::HtmlResponse as HtmlBase, json_response::JsonResponse as JsonBase, RwebResponse,
};

use crate::{
    app::AppState,
    auth::AuthRequest,
    elements::{
        change_password_body, index_body, login_body, register_body, session_body,
        session_data_body,
    },
    errors::ServiceError as Error,
    iso8601,
    logged_user::{LoggedUser, UserCookies},
    EmailStatsWrapper, SesQuotasWrapper, SessionSummaryWrapper,
};

pub type WarpResult<T> = Result<T, Rejection>;
pub type HttpResult<T> = Result<T, Error>;

#[derive(Deserialize, Schema)]
#[schema(component = "FinalUrl")]
pub struct FinalUrlData {
    #[schema(
        description = "Url to redirect to after completion of authorization",
        example = r#""https://example.com""#
    )]
    pub final_url: Option<StackString>,
}

#[derive(RwebResponse)]
#[response(description = "Main Page", content = "html")]
struct AuthIndexResponse(HtmlBase<StackString, Error>);

#[get("/auth/index.html")]
pub async fn index_html(
    user: Option<LoggedUser>,
    #[data] data: AppState,
    query: Query<FinalUrlData>,
) -> WarpResult<AuthIndexResponse> {
    let query = query.into_inner();

    let body = {
        let summaries = if user.is_some() {
            list_sessions_lines(&data).await?
        } else {
            Vec::new()
        };
        let data = if let Some(user) = &user {
            SessionData::get_by_session_id_streaming(&data.pool, user.session.into())
                .await
                .map_err(Into::<Error>::into)?
                .map_ok(|s| {
                    let js = serde_json::to_vec(&s.session_value).unwrap_or_else(|_| Vec::new());
                    let js = js.get(..100).unwrap_or_else(|| &js[..]);
                    let js = match str::from_utf8(js) {
                        Ok(s) => s,
                        Err(error) => str::from_utf8(&js[..error.valid_up_to()]).unwrap(),
                    };
                    (s, js.into())
                })
                .try_collect()
                .await
                .map_err(Into::<AuthServerError>::into)
                .map_err(Into::<Error>::into)?
        } else {
            Vec::new()
        };
        index_body(user, summaries, data, query.final_url)
    };
    Ok(HtmlBase::new(body.into()).into())
}

#[derive(RwebResponse)]
#[response(description = "CSS", content = "css")]
struct CssResponse(HtmlBase<&'static str, Infallible>);

#[get("/auth/main.css")]
pub async fn main_css() -> WarpResult<CssResponse> {
    Ok(HtmlBase::new(include_str!("../../templates/main.css")).into())
}

#[derive(Deserialize, Schema)]
struct RegisterQuery {
    id: UuidWrapper,
    email: StackString,
}

#[derive(RwebResponse)]
#[response(description = "Registration", content = "html")]
struct RegisterResponse(HtmlBase<StackString, Error>);

#[get("/auth/register.html")]
pub async fn register_html(
    query: Query<RegisterQuery>,
    #[data] data: AppState,
) -> WarpResult<RegisterResponse> {
    let query = query.into_inner();
    let invitation_id: Uuid = query.id.into();
    let email = query.email;

    if let Some(invitation) = Invitation::get_by_uuid(invitation_id, &data.pool)
        .await
        .map_err(Into::<Error>::into)?
    {
        if invitation.email == email {
            let body = register_body(invitation_id);
            return Ok(HtmlBase::new(body.into()).into());
        }
    }
    Err(Error::BadRequest("Invalid invitation").into())
}

#[derive(RwebResponse)]
#[response(description = "Javascript", content = "js")]
struct JsResponse(HtmlBase<&'static str, Infallible>);

#[get("/auth/main.js")]
pub async fn main_js() -> WarpResult<JsResponse> {
    Ok(HtmlBase::new(include_str!("../../templates/main.js")).into())
}

#[derive(RwebResponse)]
#[response(description = "Login Page", content = "html")]
struct AuthLoginResponse(HtmlBase<StackString, Error>);

#[get("/auth/login.html")]
pub async fn login_html(
    user: Option<LoggedUser>,
    query: Query<FinalUrlData>,
) -> WarpResult<AuthLoginResponse> {
    let query = query.into_inner();
    let body = login_body(user, query.final_url);
    Ok(HtmlBase::new(body.into()).into())
}

#[derive(RwebResponse)]
#[response(description = "Change Password", content = "html")]
struct PwChangeResponse(HtmlBase<StackString, Error>);

#[get("/auth/change_password.html")]
pub async fn change_password(user: LoggedUser) -> WarpResult<PwChangeResponse> {
    let body = change_password_body(user);
    Ok(HtmlBase::new(body.into()).into())
}

#[derive(RwebResponse)]
#[response(description = "Current logged in username", status = "CREATED")]
struct ApiAuthResponse(JsonBase<LoggedUser, Error>);

#[post("/api/auth")]
#[openapi(description = "Login with username and password")]
pub async fn login(
    #[data] data: AppState,
    auth_data: Json<AuthRequest>,
) -> WarpResult<ApiAuthResponse> {
    let auth_data = auth_data.into_inner();

    let (user, session, UserCookies { session_id, jwt }) =
        auth_data.login_user_jwt(&data.pool, &data.config).await?;

    data.session_cache.add_session(session);
    let session_str = format_sstr!("{}", session_id.encoded());
    let jwt_str = format_sstr!("{}", jwt.encoded());

    let resp = JsonBase::new(user)
        .with_cookie(&session_str)
        .with_cookie(&jwt_str);
    Ok(resp.into())
}

#[derive(RwebResponse)]
#[response(description = "Status Message", status = "NO_CONTENT")]
struct ApiAuthDeleteResponse(JsonBase<StackString, Error>);

#[delete("/api/auth")]
#[openapi(description = "Log out")]
pub async fn logout(user: LoggedUser, #[data] data: AppState) -> WarpResult<ApiAuthDeleteResponse> {
    LoggedUser::delete_user_session(user.session.into(), &data.pool).await?;
    data.session_cache.remove_session(user.session.into());
    let UserCookies { session_id, jwt } = user.clear_jwt_cookie(
        &data.config.domain,
        data.config.expiration_seconds,
        data.config.secure,
    );
    let body = format_sstr!("{} has been logged out", user.email);
    let resp = JsonBase::new(body)
        .with_cookie(session_id.encoded().to_string())
        .with_cookie(jwt.encoded().to_string());
    Ok(resp.into())
}

#[derive(RwebResponse)]
#[response(description = "Current users email")]
struct ApiAuthGetResponse(JsonBase<LoggedUser, Error>);

#[get("/api/auth")]
#[openapi(description = "Get current username if logged in")]
pub async fn get_me(user: LoggedUser) -> WarpResult<ApiAuthGetResponse> {
    Ok(JsonBase::new(user).into())
}

#[derive(RwebResponse)]
#[response(description = "Session Object")]
struct GetSessionResponse(JsonBase<Value, Error>);

#[get("/api/session/{session_key}")]
#[openapi(description = "Get Session")]
pub async fn get_session(
    #[header = "session"] session: Uuid,
    #[header = "secret-key"] secret_key: StackString,
    session_key: StackString,
    #[data] data: AppState,
) -> WarpResult<GetSessionResponse> {
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

#[derive(RwebResponse)]
#[response(description = "Set Session Object", status = "CREATED")]
struct PostSessionResponse(JsonBase<Value, Error>);

#[post("/api/session/{session_key}")]
#[openapi(description = "Set session value")]
pub async fn post_session(
    #[header = "session"] session: Uuid,
    #[header = "secret-key"] secret_key: StackString,
    #[data] data: AppState,
    session_key: StackString,
    payload: Json<Value>,
) -> WarpResult<PostSessionResponse> {
    let payload = payload.into_inner();
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

#[derive(RwebResponse)]
#[response(description = "Delete Session Object", status = "NO_CONTENT")]
struct DeleteSessionResponse(JsonBase<Option<Value>, Error>);

#[delete("/api/session/{session_key}")]
#[openapi(description = "Delete session value")]
pub async fn delete_session(
    #[header = "session"] session: Uuid,
    #[header = "secret-key"] secret_key: StackString,
    #[data] data: AppState,
    session_key: StackString,
) -> WarpResult<DeleteSessionResponse> {
    Session::delete_session_data_from_cache(&data.pool, session, &secret_key, &session_key)
        .await
        .map_err(Into::<Error>::into)?;
    let result = data
        .session_cache
        .remove_data(session, secret_key, session_key)?;
    Ok(JsonBase::new(result).into())
}

#[derive(Schema, Serialize, Deserialize)]
#[schema(component = "SessionData")]
struct SessionDataObj {
    #[schema(description = "Session ID")]
    session_id: UuidWrapper,
    #[schema(description = "Session Key")]
    session_key: StackString,
    #[schema(description = "Session Data")]
    session_value: Value,
    #[schema(description = "Created At")]
    #[serde(with = "iso8601")]
    created_at: DateTimeType,
}

#[derive(RwebResponse)]
#[response(description = "Session Data")]
struct SessionDataObjResponse(JsonBase<Vec<SessionDataObj>, Error>);

#[get("/api/session-data")]
#[openapi(description = "Session Data")]
pub async fn list_session_obj(
    user: LoggedUser,
    #[data] data: AppState,
) -> WarpResult<SessionDataObjResponse> {
    let values = SessionData::get_by_session_id_streaming(&data.pool, user.session.into())
        .await
        .map_err(Into::<Error>::into)?
        .map_ok(|s| SessionDataObj {
            session_id: user.session,
            session_key: s.session_key,
            session_value: s.session_value,
            created_at: s.created_at.to_offsetdatetime().into(),
        })
        .try_collect()
        .await
        .map_err(Into::<AuthServerError>::into)
        .map_err(Into::<Error>::into)?;

    Ok(JsonBase::new(values).into())
}

#[derive(RwebResponse)]
#[response(description = "List Sessions")]
struct ListSessionsResponse(HtmlBase<StackString, Error>);

#[get("/api/list-sessions")]
pub async fn list_sessions(
    _: LoggedUser,
    #[data] data: AppState,
) -> WarpResult<ListSessionsResponse> {
    let summaries = list_sessions_lines(&data).await?;
    let body = session_body(summaries);
    Ok(HtmlBase::new(body.into()).into())
}

async fn list_sessions_lines(data: &AppState) -> HttpResult<Vec<SessionSummary>> {
    Session::get_session_summary(&data.pool)
        .await
        .map_err(Into::into)
}

#[derive(RwebResponse)]
#[response(description = "List Session Data")]
struct ListSessionDataResponse(HtmlBase<StackString, Error>);

#[get("/api/list-session-data")]
pub async fn list_session_data(
    user: LoggedUser,
    #[data] data: AppState,
) -> WarpResult<ListSessionDataResponse> {
    let data: Vec<(SessionData, StackString)> =
        SessionData::get_by_session_id_streaming(&data.pool, user.session.into())
            .await
            .map_err(Into::<Error>::into)?
            .map_ok(|s| {
                let js = serde_json::to_vec(&s.session_value).unwrap_or_else(|_| Vec::new());
                let js = js.get(..100).unwrap_or_else(|| &js[..]);
                let js = match str::from_utf8(js) {
                    Ok(s) => s,
                    Err(error) => str::from_utf8(&js[..error.valid_up_to()]).unwrap(),
                };
                (s, js.into())
            })
            .try_collect()
            .await
            .map_err(Into::<AuthServerError>::into)
            .map_err(Into::<Error>::into)?;

    let body = session_data_body(data);
    Ok(HtmlBase::new(body.into()).into())
}

#[derive(RwebResponse)]
#[response(description = "Sessions")]
struct SessionsResponse(JsonBase<Vec<SessionSummaryWrapper>, Error>);

#[get("/api/sessions")]
#[openapi(description = "Open Sessions")]
pub async fn get_sessions(_: LoggedUser, #[data] data: AppState) -> WarpResult<SessionsResponse> {
    let objects = list_sessions_lines(&data)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(JsonBase::new(objects).into())
}

#[derive(RwebResponse)]
#[response(description = "Delete Sessions", status = "NO_CONTENT")]
struct DeleteSessionsResponse(HtmlBase<&'static str, Error>);

#[derive(Deserialize, Schema, Debug)]
pub struct SessionQuery {
    #[schema(description = "Session Key")]
    pub session_key: Option<StackString>,
    #[schema(description = "Session")]
    pub session: Option<UuidWrapper>,
}

#[delete("/api/sessions")]
#[openapi(description = "Delete Sessions")]
pub async fn delete_sessions(
    user: LoggedUser,
    #[data] data: AppState,
    session_query: Query<SessionQuery>,
) -> WarpResult<DeleteSessionsResponse> {
    let session_query = session_query.into_inner();
    if let Some(session_key) = &session_query.session_key {
        Session::delete_session_data_from_cache(
            &data.pool,
            user.session.into(),
            &user.secret_key,
            session_key,
        )
        .await
        .map_err(Into::<Error>::into)?;
        data.session_cache
            .remove_data(user.session.into(), &user.secret_key, session_key)?;
    }
    if let Some(session) = session_query.session {
        LoggedUser::delete_user_session(session.into(), &data.pool).await?;
        data.session_cache.remove_session(session.into());
    }
    Ok(HtmlBase::new("finished").into())
}

#[derive(Deserialize, Schema)]
#[schema(component = "CreateInvitation")]
pub struct CreateInvitation {
    #[schema(description = "Email to send invitation to")]
    pub email: StackString,
}

#[derive(Serialize, Schema)]
#[schema(component = "Invitation")]
pub struct InvitationOutput {
    #[schema(description = "Invitation ID")]
    pub id: StackString,
    #[schema(description = "Email Address")]
    pub email: StackString,
    #[schema(description = "Expiration Datetime")]
    #[serde(with = "iso8601")]
    pub expires_at: DateTimeType,
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

#[derive(RwebResponse)]
#[response(description = "Invitation Object", status = "CREATED")]
struct ApiInvitationResponse(JsonBase<InvitationOutput, Error>);

#[post("/api/invitation")]
#[openapi(description = "Send invitation to specified email")]
pub async fn register_email(
    #[data] data: AppState,
    invitation: Json<CreateInvitation>,
) -> WarpResult<ApiInvitationResponse> {
    let invitation = invitation.into_inner();

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

#[derive(Debug, Deserialize, Schema)]
#[schema(component = "PasswordData")]
pub struct PasswordData {
    #[schema(description = "Password")]
    pub password: StackString,
}

#[derive(RwebResponse)]
#[response(description = "Registered Email", status = "CREATED")]
struct ApiRegisterResponse(JsonBase<LoggedUser, Error>);

#[post("/api/register/{invitation_id}")]
#[openapi(description = "Set password using link from email")]
pub async fn register_user(
    invitation_id: UuidWrapper,
    #[data] data: AppState,
    user_data: Json<PasswordData>,
) -> WarpResult<ApiRegisterResponse> {
    let user_data: PasswordData = user_data.into_inner();
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

#[derive(Serialize, Deserialize, Debug, Schema)]
#[schema(component = "PasswordChange")]
pub struct PasswordChangeOutput {
    pub message: StackString,
}

#[derive(RwebResponse)]
#[response(description = "Success Message", status = "CREATED")]
struct ApiPasswordChangeResponse(JsonBase<PasswordChangeOutput, Error>);

#[post("/api/password_change")]
#[openapi(description = "Change password for currently logged in user")]
pub async fn change_password_user(
    user: LoggedUser,
    #[data] data: AppState,
    user_data: Json<PasswordData>,
) -> WarpResult<ApiPasswordChangeResponse> {
    let user_data = user_data.into_inner();
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

#[derive(Serialize, Deserialize, Schema)]
#[schema(component = "AuthUrl")]
pub struct AuthUrlOutput {
    #[schema(description = "CSRF State")]
    pub csrf_state: StackString,
    #[schema(description = "Auth URL")]
    pub auth_url: StackString,
}

#[derive(RwebResponse)]
#[response(description = "Authorization Url", status = "CREATED")]
struct ApiAuthUrlResponse(JsonBase<AuthUrlOutput, Error>);

#[post("/api/auth_url")]
#[openapi(description = "Get Oauth Url")]
pub async fn auth_url(
    #[data] data: AppState,
    query: Json<FinalUrlData>,
) -> WarpResult<ApiAuthUrlResponse> {
    let query = query.into_inner();
    let (csrf_state, authorize_url) = data
        .google_client
        .get_auth_url(query.final_url.as_ref().map(StackString::as_str))
        .await
        .map_err(Into::<Error>::into)?;
    let authorize_url: String = authorize_url.into();
    let resp = JsonBase::new(AuthUrlOutput {
        csrf_state,
        auth_url: authorize_url.into(),
    });
    Ok(resp.into())
}

#[derive(Schema, Serialize, Deserialize)]
pub struct AuthAwait {
    #[schema(description = "CSRF State")]
    pub state: StackString,
}

#[derive(RwebResponse)]
#[response(description = "Finished", content = "html")]
struct ApiAwaitResponse(HtmlBase<StackString, Infallible>);

#[get("/api/await")]
#[openapi(description = "Await completion of auth")]
pub async fn auth_await(
    #[data] data: AppState,
    query: Query<AuthAwait>,
) -> WarpResult<ApiAwaitResponse> {
    let state = query.into_inner().state;
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

#[derive(Deserialize, Schema)]
pub struct CallbackQuery {
    #[schema(description = "Authorization Code")]
    pub code: StackString,
    #[schema(description = "CSRF State")]
    pub state: StackString,
}

#[derive(RwebResponse)]
#[response(description = "Callback Response", content = "html")]
struct ApiCallbackResponse(HtmlBase<&'static str, Error>);

#[get("/api/callback")]
#[openapi(description = "Callback method for use in Oauth flow")]
pub async fn callback(
    #[data] data: AppState,
    query: Query<CallbackQuery>,
) -> WarpResult<ApiCallbackResponse> {
    let UserCookies { session_id, jwt } = callback_body(
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
    Ok(HtmlBase::new(body)
        .with_cookie(&session_id.encoded().to_string())
        .with_cookie(&jwt.encoded().to_string())
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

#[derive(Serialize, Schema)]
#[schema(component = "Status")]
pub struct StatusOutput {
    #[schema(description = "Number of Users")]
    number_of_users: i64,
    #[schema(description = "Number of Invitations")]
    number_of_invitations: i64,
    #[schema(description = "Number of Sessions")]
    number_of_sessions: i64,
    #[schema(description = "Number of Data Entries")]
    number_of_entries: i64,
    quota: SesQuotasWrapper,
    stats: EmailStatsWrapper,
}

#[derive(RwebResponse)]
#[response(description = "Status output")]
struct StatusResponse(JsonBase<StatusOutput, Error>);

#[get("/api/status")]
#[openapi(description = "Status endpoint")]
pub async fn status(#[data] data: AppState) -> WarpResult<StatusResponse> {
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
    let result = StatusOutput {
        number_of_users: number_users,
        number_of_invitations: number_invitations,
        number_of_sessions: number_sessions,
        number_of_entries: number_entries,
        quota: quotas.into(),
        stats: stats.into(),
    };
    Ok(result)
}

#[derive(RwebResponse)]
#[response(description = "Login POST", status = "CREATED")]
struct TestLoginResponse(JsonBase<LoggedUser, Error>);

#[post("/api/auth")]
pub async fn test_login(
    auth_data: Json<AuthRequest>,
    #[data] data: AppState,
) -> WarpResult<TestLoginResponse> {
    let auth_data = auth_data.into_inner();
    let session = Session::new(auth_data.email.as_str());
    let (user, UserCookies { session_id, jwt }) =
        test_login_user_jwt(auth_data, session, &data.config).await?;
    let resp = JsonBase::new(user)
        .with_cookie(session_id.encoded().to_string())
        .with_cookie(jwt.encoded().to_string());
    Ok(resp.into())
}

async fn test_login_user_jwt(
    auth_data: AuthRequest,
    session: Session,
    config: &Config,
) -> HttpResult<(LoggedUser, UserCookies<'static>)> {
    use maplit::hashset;

    if let Ok(s) = std::env::var("TESTENV") {
        if &s == "true" {
            let email = auth_data.email;
            let user = AuthorizedUser {
                email,
                session: session.id,
                secret_key: session.secret_key.clone(),
            };
            AUTHORIZED_USERS.update_users(hashset! {user.email.clone()});
            let mut user: LoggedUser = user.into();
            user.session = session.id.into();
            let cookies = user.get_jwt_cookie(&config.domain, config.expiration_seconds, false)?;
            return Ok((user, cookies));
        }
    }
    Err(Error::BadRequest("Username and Password don't match"))
}
