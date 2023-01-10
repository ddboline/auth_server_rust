use dioxus::prelude::{dioxus_elements, rsx, Element, GlobalAttributes, Scope, VirtualDom};
use futures::{try_join, TryStreamExt};
use log::{debug, error};
use rweb::{delete, get, post, Json, Query, Rejection, Schema};
use rweb_helper::{DateTimeType, UuidWrapper};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stack_string::{format_sstr, StackString};
use std::{convert::Infallible, str, time::Duration};
use time::{macros::format_description, OffsetDateTime};
use tokio::time::{sleep, timeout};
use url::Url;
use uuid::Uuid;

use auth_server_ext::{
    google_openid::GoogleClient,
    send_invitation,
    ses_client::{SesInstance, Statistics},
};
use auth_server_lib::{
    config::Config,
    invitation::Invitation,
    pgpool::{PgPool, PgTransaction},
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
    errors::ServiceError as Error,
    iso8601,
    logged_user::{LoggedUser, UserCookies},
    EmailStatsWrapper, SesQuotasWrapper, SessionSummaryWrapper,
};

pub type WarpResult<T> = Result<T, Rejection>;
pub type HttpResult<T> = Result<T, Error>;

#[derive(RwebResponse)]
#[response(description = "Main Page", content = "html")]
struct AuthIndexResponse(HtmlBase<&'static str, Infallible>);

#[get("/auth/index.html")]
pub async fn index_html() -> WarpResult<AuthIndexResponse> {
    Ok(HtmlBase::new(include_str!("../../templates/index.html")).into())
}

#[derive(RwebResponse)]
#[response(description = "CSS", content = "css")]
struct CssResponse(HtmlBase<&'static str, Infallible>);

#[get("/auth/main.css")]
pub async fn main_css() -> WarpResult<CssResponse> {
    Ok(HtmlBase::new(include_str!("../../templates/main.css")).into())
}

#[derive(RwebResponse)]
#[response(description = "Registration", content = "html")]
struct RegisterResponse(HtmlBase<&'static str, Infallible>);

#[get("/auth/register.html")]
pub async fn register_html() -> WarpResult<RegisterResponse> {
    Ok(HtmlBase::new(include_str!("../../templates/register.html")).into())
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
struct AuthLoginResponse(HtmlBase<&'static str, Infallible>);

#[get("/auth/login.html")]
pub async fn login_html() -> WarpResult<AuthLoginResponse> {
    Ok(HtmlBase::new(include_str!("../../templates/login.html")).into())
}

#[derive(RwebResponse)]
#[response(description = "Change Password", content = "html")]
struct PwChangeResponse(HtmlBase<&'static str, Infallible>);

#[get("/auth/change_password.html")]
pub async fn change_password() -> WarpResult<PwChangeResponse> {
    Ok(HtmlBase::new(include_str!("../../templates/change_password.html")).into())
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
        login_user_jwt(auth_data, &data.pool, &data.config).await?;

    data.session_cache.add_session(session);
    let session_str = StackString::from_display(session_id.encoded());
    let jwt_str = StackString::from_display(jwt.encoded());

    let resp = JsonBase::new(user)
        .with_cookie(&session_str)
        .with_cookie(&jwt_str);
    Ok(resp.into())
}

async fn login_user_jwt(
    auth_data: AuthRequest,
    pool: &PgPool,
    config: &Config,
) -> HttpResult<(LoggedUser, Session, UserCookies<'static>)> {
    let session = Session::new(auth_data.email.as_str());
    session.insert(pool).await.map_err(|e| {
        error!("error on session insert {e}");
        e
    })?;

    let user = auth_data.authenticate(pool).await?;
    let user: AuthorizedUser = user.into();
    let mut user: LoggedUser = user.into();
    user.session = session.id.into();
    user.secret_key = session.secret_key.clone();
    let cookies = user
        .get_jwt_cookie(&config.domain, config.expiration_seconds, config.secure)
        .map_err(|e| {
            error!("Failed to create_token {e}");
            Error::BadRequest("Failed to create_token")
        })?;
    Ok((user, session, cookies))
}

#[derive(RwebResponse)]
#[response(description = "Status Message", status = "CREATED")]
struct ApiAuthDeleteResponse(JsonBase<StackString, Error>);

#[delete("/api/auth")]
#[openapi(description = "Log out")]
pub async fn logout(user: LoggedUser, #[data] data: AppState) -> WarpResult<ApiAuthDeleteResponse> {
    delete_user_session(user.session.into(), &data.pool).await?;
    data.session_cache.remove_session(user.session.into());
    let UserCookies { session_id, jwt } = user.clear_jwt_cookie(
        &data.config.domain,
        data.config.expiration_seconds,
        data.config.secure,
    );
    let body = format_sstr!("{} has been logged out", user.email);
    let resp = JsonBase::new(body)
        .with_cookie(&session_id.encoded().to_string())
        .with_cookie(&jwt.encoded().to_string());
    Ok(resp.into())
}

async fn delete_user_session(session: Uuid, pool: &PgPool) -> HttpResult<()> {
    if let Some(session_obj) = Session::get_session(pool, session).await? {
        for session_data in session_obj.get_all_session_data(pool).await? {
            session_data.delete(pool).await?;
        }
        session_obj.delete(pool).await?;
    }
    Ok(())
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
    if let Some(value) = data
        .session_cache
        .get_data(session, &secret_key, &session_key)?
    {
        return Ok(JsonBase::new(value).into());
    }
    if let Some(session_data) =
        get_session_from_cache(&data, session, secret_key, session_key).await?
    {
        return Ok(JsonBase::new(session_data.session_value).into());
    }
    Ok(JsonBase::new(Value::Null).into())
}

async fn get_session_from_cache(
    data: &AppState,
    session: Uuid,
    secret_key: StackString,
    session_key: StackString,
) -> HttpResult<Option<SessionData>> {
    if let Some(session_obj) = Session::get_session(&data.pool, session).await? {
        if session_obj.secret_key != secret_key {
            return Err(Error::BadRequest("Bad Secret"));
        }
        if let Some(session_data) = session_obj
            .get_session_data(&data.pool, &session_key)
            .await?
        {
            data.session_cache.set_data(
                session,
                secret_key,
                session_key,
                &session_data.session_value,
            )?;
            return Ok(Some(session_data));
        }
    }
    Ok(None)
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
    set_session_from_cache(&data, session, secret_key, session_key, payload.clone()).await?;
    Ok(JsonBase::new(payload).into())
}

async fn set_session_from_cache(
    data: &AppState,
    session: Uuid,
    secret_key: StackString,
    session_key: StackString,
    payload: Value,
) -> HttpResult<()> {
    let mut conn = data.pool.get().await?;
    let tran = conn.transaction().await?;
    let conn: &PgTransaction = &tran;

    if let Some(session_obj) = Session::get_session_conn(conn, session).await? {
        if session_obj.secret_key != secret_key {
            return Err(Error::BadRequest("Bad Secret"));
        }
        let session_data = session_obj
            .set_session_data_conn(conn, &session_key, payload.clone())
            .await?;
        debug!("session_data {:?}", session_data);
        tran.commit().await?;
        data.session_cache.set_data(
            session,
            secret_key,
            session_key,
            &session_data.session_value,
        )?;
    }
    Ok(())
}

#[derive(RwebResponse)]
#[response(description = "Delete Session Object", status = "CREATED")]
struct DeleteSessionResponse(HtmlBase<&'static str, Error>);

#[delete("/api/session/{session_key}")]
#[openapi(description = "Delete session value")]
pub async fn delete_session(
    #[header = "session"] session: Uuid,
    #[header = "secret-key"] secret_key: StackString,
    #[data] data: AppState,
    session_key: StackString,
) -> WarpResult<DeleteSessionResponse> {
    delete_session_data_from_cache(&data, session, &secret_key, &session_key).await?;
    data.session_cache
        .remove_data(session, secret_key, session_key)?;
    Ok(HtmlBase::new("done").into())
}

async fn delete_session_data_from_cache(
    data: &AppState,
    session: Uuid,
    secret_key: impl AsRef<str>,
    session_key: impl AsRef<str>,
) -> HttpResult<()> {
    if let Some(session_obj) = Session::get_session(&data.pool, session).await? {
        if session_obj.secret_key != secret_key.as_ref() {
            return Err(Error::BadRequest("Bad Secret"));
        }
        if let Some(session_data) = session_obj
            .get_session_data(&data.pool, session_key)
            .await?
        {
            session_data.delete(&data.pool).await?;
        }
    }
    Ok(())
}

#[derive(Schema, Serialize, Deserialize)]
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
    let values = list_session_objs(&data, &user).await?;
    Ok(JsonBase::new(values).into())
}

async fn list_session_objs(data: &AppState, user: &LoggedUser) -> HttpResult<Vec<SessionDataObj>> {
    SessionData::get_by_session_id_streaming(&data.pool, user.session.into())
        .await?
        .map_ok(|s| SessionDataObj {
            session_id: user.session,
            session_key: s.session_key,
            session_value: s.session_value,
            created_at: s.created_at.to_offsetdatetime().into(),
        })
        .try_collect()
        .await
        .map_err(Into::into)
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
    let body = {
        let mut app = VirtualDom::new_with_props(session_element, SessionProps { summaries });
        drop(app.rebuild());
        dioxus_ssr::render(&app)
    };
    Ok(HtmlBase::new(body.into()).into())
}

struct SessionProps {
    summaries: Vec<SessionSummary>,
}

fn session_element(cx: Scope<SessionProps>) -> Element {
    cx.render(rsx! {
         table {
            "border": "1",
            class: "dataframe",
            style: "text-align: center",
            thead {
                tr {
                    th {"Session ID"},
                    th {"Email Address"},
                    th {"Created At"},
                    th {"Number of Data Objects"},
                },
            },
            tbody {
                cx.props.summaries.iter().enumerate().map(|(idx, s)| {
                    let id = s.session_id;
                    let email = &s.email_address;
                    let created_at = s.created_at.format(format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z")).unwrap_or_else(|_| String::new());
                    let n_obj = s.number_of_data_objects;
                    rsx! {
                        tr {
                            key: "list-session-row-{idx}",
                            style: "text-align: center",
                            td {"{id}"},
                            td {"{email}"},
                            td {"{created_at}"},
                            td {"{n_obj}"},
                            td {
                                input {
                                    "type": "button",
                                    name: "delete",
                                    value: "Delete",
                                    "onclick": "delete_session('{id}')",
                                }
                            }
                        }
                    }
                }),
            }
         },
    })
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
    let data = list_session_data_lines(&data, &user).await?;
    let body = {
        let mut app = VirtualDom::new_with_props(session_data_element, SessionDataProps { data });
        drop(app.rebuild());
        dioxus_ssr::render(&app)
    };
    Ok(HtmlBase::new(body.into()).into())
}

struct SessionDataProps {
    data: Vec<(SessionData, StackString)>,
}

fn session_data_element(cx: Scope<SessionDataProps>) -> Element {
    cx.render(rsx! {
        table {
            "border": "1",
            class: "dataframe",
            thead {
                tr {
                    th {"Session ID"},
                    th {"Session Key"},
                    th {"Created At"},
                    th {"Session Value"},
                }
            },
            tbody {
                cx.props.data.iter().enumerate().map(|(idx, (s, js))| {
                    let id = s.session_id;
                    let key = &s.session_key;
                    let created_at = s.created_at.format(format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z")).unwrap_or_else(|_| String::new());
                    rsx! {
                        tr {
                            key: "list-session-data-row-{idx}",
                            style: "text-align",
                            td {"{id}"},
                            td {"{key}"},
                            td {"{created_at}"},
                            td {"{js}"},
                            td {
                                input {
                                    "type": "button",
                                    name: "delete",
                                    value: "Delete",
                                    "onclick": "delete_session_data('{key}')",
                                }
                            }
                        }
                    }
                }),
            }
        }
    })
}

async fn list_session_data_lines(
    data: &AppState,
    user: &LoggedUser,
) -> HttpResult<Vec<(SessionData, StackString)>> {
    SessionData::get_by_session_id_streaming(&data.pool, user.session.into())
        .await?
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
        .map_err(Into::into)
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
#[response(description = "Delete Sessions")]
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
        delete_session_data_from_cache(&data, user.session.into(), &user.secret_key, session_key)
            .await?;
        data.session_cache
            .remove_data(user.session.into(), &user.secret_key, session_key)?;
    }
    if let Some(session) = session_query.session {
        delete_user_session(session.into(), &data.pool).await?;
        data.session_cache.remove_session(session.into());
    }
    Ok(HtmlBase::new("finished").into())
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
    let invitation = register_email_invitation(invitation, &data).await?;
    let resp = JsonBase::new(invitation.into());
    Ok(resp.into())
}

async fn register_email_invitation(
    invitation: CreateInvitation,
    data: &AppState,
) -> HttpResult<Invitation> {
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
    Ok(invitation)
}

#[derive(Debug, Deserialize, Schema)]
pub struct UserData {
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
    user_data: Json<UserData>,
) -> WarpResult<ApiRegisterResponse> {
    let user =
        register_user_object(invitation_id.into(), user_data.into_inner(), &data.pool).await?;
    let resp = JsonBase::new(user.into());
    Ok(resp.into())
}

async fn register_user_object(
    invitation_id: Uuid,
    user_data: UserData,
    pool: &PgPool,
) -> HttpResult<AuthorizedUser> {
    if let Some(invitation) = Invitation::get_by_uuid(invitation_id, pool).await? {
        let expires_at: OffsetDateTime = invitation.expires_at.into();
        if expires_at > OffsetDateTime::now_utc() {
            let user = User::from_details(invitation.email.clone(), &user_data.password);
            user.upsert(pool).await?;
            invitation.delete(pool).await?;
            let user: AuthorizedUser = user.into();
            AUTHORIZED_USERS.store_auth(user.clone(), true);
            return Ok(user);
        }
        invitation.delete(pool).await?;
    }
    Err(Error::BadRequest("Invalid invitation"))
}

#[derive(Serialize, Deserialize, Debug, Schema)]
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
    user_data: Json<UserData>,
) -> WarpResult<ApiPasswordChangeResponse> {
    let message = change_password_user_body(user, user_data.into_inner(), &data.pool)
        .await?
        .into();
    let resp = JsonBase::new(PasswordChangeOutput { message });
    Ok(resp.into())
}

async fn change_password_user_body(
    logged_user: LoggedUser,
    user_data: UserData,
    pool: &PgPool,
) -> HttpResult<&'static str> {
    if let Some(mut user) = User::get_by_email(&logged_user.email, pool).await? {
        user.set_password(&user_data.password);
        user.update(pool).await?;
        Ok("password updated")
    } else {
        Err(Error::BadRequest("Invalid User"))
    }
}

#[derive(Deserialize, Schema)]
pub struct GetAuthUrlData {
    #[schema(description = "Url to redirect to after completion of authorization")]
    pub final_url: StackString,
}

#[derive(Serialize, Deserialize, Schema)]
pub struct AuthUrlOutput {
    #[schema(description = "CSRF State")]
    pub csrf_state: StackString,
    #[schema(description = "Auth URL")]
    pub auth_url: StackString,
}

#[derive(RwebResponse)]
#[response(description = "Authorization Url")]
struct ApiAuthUrlResponse(JsonBase<AuthUrlOutput, Error>);

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
    Ok(resp.into())
}

async fn auth_url_body(
    payload: GetAuthUrlData,
    google_client: &GoogleClient,
) -> HttpResult<(StackString, Url)> {
    debug!("{:?}", payload.final_url);
    let (csrf_state, auth_url) = google_client.get_auth_url().await;
    Ok((csrf_state, auth_url))
}

#[derive(Schema, Serialize, Deserialize)]
pub struct AuthAwait {
    #[schema(description = "CSRF State")]
    pub state: StackString,
}

#[derive(RwebResponse)]
#[response(description = "Finished", content = "html")]
struct ApiAwaitResponse(HtmlBase<&'static str, Infallible>);

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
    Ok(HtmlBase::new("").into())
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
    let ses = SesInstance::new(None);
    let (
        number_users,
        number_invitations,
        number_sessions,
        number_entries,
        Statistics { quotas, stats },
    ) = try_join!(
        User::get_number_users(pool),
        Session::get_number_sessions(pool),
        SessionData::get_number_entries(pool),
        Invitation::get_number_invitations(pool),
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
#[response(status = "CREATED")]
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
        .with_cookie(&session_id.encoded().to_string())
        .with_cookie(&jwt.encoded().to_string());
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
