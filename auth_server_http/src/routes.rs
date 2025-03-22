use futures::{try_join, TryStreamExt};
use http::{HeaderMap, HeaderValue};
use http::{StatusCode, header::SET_COOKIE};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stack_string::{format_sstr, StackString};
use std::{convert::{Infallible, TryInto}, str, time::Duration};
use time::OffsetDateTime;
use tokio::time::{sleep, timeout};
use uuid::Uuid;
use axum::extract::{State, Query};
use utoipa::ToSchema;
use axum::Json;
use axum::response::{Response, IntoResponse, AppendHeaders, IntoResponseParts};
use std::sync::Arc;
use utoipa::IntoResponses;

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
    SesQuotasWrapper, EmailStatsWrapper
};

#[derive(Deserialize, ToSchema)]
// #[schema(component = "FinalUrl")]
pub struct FinalUrlData {
    /// Url to redirect to after completion of authorization
    #[schema(example = r#""https://example.com""#)]
    pub final_url: Option<StackString>,
}

#[derive(Serialize, ToSchema, Clone)]
pub struct StatusOutput {
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

// #[derive(RwebResponse)]
// #[response(description = "Status output")]
// struct StatusResponse(JsonBase<StatusOutput, Error>);

// #[get("/api/status")]
// #[openapi(description = "Status endpoint")]
pub async fn status(data: State<Arc<AppState>>) -> Result<Json<StatusOutput>, Error> {
    let result = status_body(&data.pool).await?;
    Ok(Json(result))
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

// pub type WarpResult<T> = Result<T, Rejection>;
pub type HttpResult<T> = Result<T, Error>;

// #[derive(RwebResponse)]
// #[response(description = "Main Page", content = "html")]
// struct AuthIndexResponse(HtmlBase<StackString, Error>);

// #[get("/auth/index.html")]
// #[openapi(description = "Main Page")]
// pub async fn index_html(
//     user: Option<LoggedUser>,
//     #[data] data: AppState,
//     query: Query<FinalUrlData>,
// ) -> WarpResult<AuthIndexResponse> {
//     let query = query.into_inner();

//     let body = {
//         let summaries = if user.is_some() {
//             list_sessions_lines(&data).await?
//         } else {
//             Vec::new()
//         };
//         let data = if let Some(user) = &user {
//             SessionData::get_session_summary(&data.pool, user.session.into())
//                 .await
//                 .map_err(Into::<Error>::into)?
//         } else {
//             Vec::new()
//         };
//         index_body(user, summaries, data, query.final_url).map_err(Into::<Error>::into)?
//     };
//     Ok(HtmlBase::new(body).into())
// }

// #[derive(RwebResponse)]
// #[response(description = "CSS", content = "css")]
// struct CssResponse(HtmlBase<&'static str, Infallible>);

// #[get("/auth/main.css")]
// pub async fn main_css() -> WarpResult<CssResponse> {
//     Ok(HtmlBase::new(include_str!("../../templates/main.css")).into())
// }

#[derive(Deserialize)]
struct RegisterQuery {
    id: Uuid,
    email: StackString,
}

// #[derive(RwebResponse)]
// #[response(description = "Registration", content = "html")]
// struct RegisterResponse(HtmlBase<StackString, Error>);

// #[get("/auth/register.html")]
// #[openapi(description = "Registration Page")]
// pub async fn register_html(
//     query: Query<RegisterQuery>,
//     #[data] data: AppState,
// ) -> WarpResult<RegisterResponse> {
//     let query = query.into_inner();
//     let invitation_id: Uuid = query.id.into();
//     let email = query.email;

//     if let Some(invitation) = Invitation::get_by_uuid(invitation_id, &data.pool)
//         .await
//         .map_err(Into::<Error>::into)?
//     {
//         if invitation.email == email {
//             let body = register_body(invitation_id).map_err(Into::<Error>::into)?;
//             return Ok(HtmlBase::new(body).into());
//         }
//     }
//     Err(Error::BadRequest("Invalid invitation").into())
// }

// #[derive(RwebResponse)]
// #[response(description = "Javascript", content = "js")]
// struct JsResponse(HtmlBase<&'static str, Infallible>);

// #[get("/auth/main.js")]
// pub async fn main_js() -> WarpResult<JsResponse> {
//     Ok(HtmlBase::new(include_str!("../../templates/main.js")).into())
// }

// #[derive(RwebResponse)]
// #[response(description = "Login Page", content = "html")]
// struct AuthLoginResponse(HtmlBase<StackString, Error>);

#[utoipa::path(get, path="/auth/login.html", responses((status = OK, description = "Login Page")))]
/// Login Page
pub async fn login_html(
    user: Option<LoggedUser>,
    query: Query<FinalUrlData>,
) -> Result<impl IntoResponse, Error> {
    let Query(query) = query;
    let body = login_body(user, query.final_url).map_err(Into::<Error>::into)?;
    Ok(body)
}

// #[derive(RwebResponse)]
// #[response(description = "Change Password", content = "html")]
// struct PwChangeResponse(HtmlBase<StackString, Error>);

// #[get("/auth/change_password.html")]
// #[openapi(description = "Password Change Page")]
// pub async fn change_password(user: LoggedUser) -> WarpResult<PwChangeResponse> {
//     let body = change_password_body(user).map_err(Into::<Error>::into)?;
//     Ok(HtmlBase::new(body).into())
// }

// #[post("/api/auth")]
// #[openapi(description = "Login with username and password")]
#[utoipa::path(post, path="/api/auth", responses((status = CREATED, description = "Current logged in username", body = LoggedUser)))]
pub async fn login(
    data: State<Arc<AppState>>,
    auth_data: Json<AuthRequest>,
) -> Result<Response, Error> {
    let Json(auth_data) = auth_data;

    let (user, session, cookies) = auth_data.login_user_jwt(&data.pool, &data.config).await?;

    let _ = data.session_cache.add_session(session);

    Ok(
        (StatusCode::CREATED, cookies.get_headers()?, Json(user)).into_response()
    )
}

// #[derive(RwebResponse)]
// #[response(description = "Status Message", status = "NO_CONTENT")]
// struct ApiAuthDeleteResponse(JsonBase<StackString, Error>);

/// Log out
#[utoipa::path(delete, path="/api/auth", responses((status = NO_CONTENT, description = "Log Out")))]
pub async fn logout(
    user: LoggedUser,
    data: State<Arc<AppState>>
) -> Result<Response, Error> {
    let session_id = user.session.into();
    let _ = data.session_cache.remove_session(session_id);
    LoggedUser::delete_user_session(session_id, &data.pool).await?;
    let cookies = user.clear_jwt_cookie(
        &data.config.domain,
        data.config.expiration_seconds,
        data.config.secure,
    );
    let body = format_sstr!("{} has been logged out", user.email);

    Ok(
        (StatusCode::NO_CONTENT, cookies.get_headers()?, body).into_response()
    )
}

// #[derive(RwebResponse)]
// #[response(description = "Current users email")]
// struct ApiAuthGetResponse(JsonBase<LoggedUser, Error>);

// #[get("/api/auth")]
// #[openapi(description = "Get current username if logged in")]
#[utoipa::path(get, path="/api/auth", responses((status = OK, body = LoggedUser, description = "Get current username if logged in")))]
pub async fn get_user(
    user: LoggedUser,
    data: State<Arc<AppState>>
) -> Result<Json<LoggedUser>, Error> {
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
    Ok(Json(user))
}

// #[derive(RwebResponse)]
// #[response(description = "Session Object")]
// struct GetSessionResponse(JsonBase<Value, Error>);

// #[get("/api/session/{session_key}")]
// #[openapi(description = "Get Session")]
// pub async fn get_session(
//     #[header = "session"] session: Uuid,
//     #[header = "secret-key"] secret_key: StackString,
//     session_key: StackString,
//     #[data] data: AppState,
// ) -> WarpResult<GetSessionResponse> {
//     let value = if let Some(value) =
//         data.session_cache
//             .get_data(session, &secret_key, &session_key)?
//     {
//         value
//     } else if let Some(session_data) =
//         SessionData::get_session_from_cache(&data.pool, session, &secret_key, &session_key)
//             .await
//             .map_err(Into::<Error>::into)?
//     {
//         data.session_cache.set_data(
//             session,
//             secret_key,
//             session_key,
//             &session_data.session_value,
//         )?;
//         session_data.session_value
//     } else {
//         Value::Null
//     };
//     Ok(JsonBase::new(value).into())
// }

// #[derive(RwebResponse)]
// #[response(description = "Set Session Object", status = "CREATED")]
// struct PostSessionResponse(JsonBase<Value, Error>);

// #[post("/api/session/{session_key}")]
// #[openapi(description = "Set session value")]
// pub async fn post_session(
//     #[header = "session"] session: Uuid,
//     #[header = "secret-key"] secret_key: StackString,
//     #[data] data: AppState,
//     session_key: StackString,
//     payload: Json<Value>,
// ) -> WarpResult<PostSessionResponse> {
//     let payload = payload.into_inner();
//     debug!("payload {} {}", payload, session);
//     debug!("session {}", session);
//     if let Some(session_data) = Session::set_session_from_cache(
//         &data.pool,
//         session,
//         &secret_key,
//         &session_key,
//         payload.clone(),
//     )
//     .await
//     .map_err(Into::<Error>::into)?
//     {
//         data.session_cache.set_data(
//             session,
//             secret_key,
//             session_key,
//             &session_data.session_value,
//         )?;
//     }
//     Ok(JsonBase::new(payload).into())
// }

// #[derive(RwebResponse)]
// #[response(description = "Delete Session Object", status = "NO_CONTENT")]
// struct DeleteSessionResponse(JsonBase<Option<Value>, Error>);

// #[delete("/api/session/{session_key}")]
// #[openapi(description = "Delete session value")]
// pub async fn delete_session(
//     #[header = "session"] session: Uuid,
//     #[header = "secret-key"] secret_key: StackString,
//     #[data] data: AppState,
//     session_key: StackString,
// ) -> WarpResult<DeleteSessionResponse> {
//     Session::delete_session_data_from_cache(&data.pool, session, &secret_key, &session_key)
//         .await
//         .map_err(Into::<Error>::into)?;
//     let result = data
//         .session_cache
//         .remove_data(session, secret_key, session_key)?;
//     Ok(JsonBase::new(result).into())
// }

// #[derive(Schema, Serialize, Deserialize)]
// #[schema(component = "SessionData")]
// struct SessionDataObj {
//     #[schema(description = "Session ID")]
//     session_id: UuidWrapper,
//     #[schema(description = "Session Key")]
//     session_key: StackString,
//     #[schema(description = "Session Data")]
//     session_value: Value,
//     #[schema(description = "Created At")]
//     #[serde(with = "iso8601")]
//     created_at: DateTimeType,
// }

// impl From<SessionData> for SessionDataObj {
//     fn from(value: SessionData) -> Self {
//         Self {
//             session_id: value.session_id.into(),
//             session_key: value.session_key,
//             session_value: value.session_value,
//             created_at: value.created_at.to_offsetdatetime().into(),
//         }
//     }
// }

// #[derive(RwebResponse)]
// #[response(description = "Session Data")]
// struct SessionDataObjResponse(JsonBase<Vec<SessionDataObj>, Error>);

// #[get("/api/session-data")]
// #[openapi(description = "Session Data")]
// pub async fn list_session_obj(
//     user: LoggedUser,
//     #[data] data: AppState,
// ) -> WarpResult<SessionDataObjResponse> {
//     let values = SessionData::get_by_session_id_streaming(&data.pool, user.session.into())
//         .await
//         .map_err(Into::<Error>::into)?
//         .map_ok(Into::into)
//         .try_collect()
//         .await
//         .map_err(Into::<AuthServerError>::into)
//         .map_err(Into::<Error>::into)?;

//     Ok(JsonBase::new(values).into())
// }

// #[derive(RwebResponse)]
// #[response(description = "List Sessions")]
// struct ListSessionsResponse(HtmlBase<StackString, Error>);

// #[get("/api/list-sessions")]
// #[openapi(description = "List Sessions")]
// pub async fn list_sessions(
//     _: LoggedUser,
//     #[data] data: AppState,
// ) -> WarpResult<ListSessionsResponse> {
//     let summaries = list_sessions_lines(&data).await?;
//     let body = session_body(summaries).map_err(Into::<Error>::into)?;
//     Ok(HtmlBase::new(body).into())
// }

async fn list_sessions_lines(data: &AppState) -> HttpResult<Vec<SessionSummary>> {
    Session::get_session_summary(&data.pool)
        .await
        .map_err(Into::into)
}

// #[derive(RwebResponse)]
// #[response(description = "List Session Data")]
// struct ListSessionDataResponse(HtmlBase<StackString, Error>);

// #[get("/api/list-session-data")]
// #[openapi(description = "List Session Data")]
// pub async fn list_session_data(
//     user: LoggedUser,
//     #[data] data: AppState,
// ) -> WarpResult<ListSessionDataResponse> {
//     let data = SessionData::get_session_summary(&data.pool, user.session.into())
//         .await
//         .map_err(Into::<Error>::into)?;
//     let body = session_data_body(data).map_err(Into::<Error>::into)?;
//     Ok(HtmlBase::new(body).into())
// }

// #[derive(RwebResponse)]
// #[response(description = "Sessions")]
// struct SessionsResponse(JsonBase<Vec<SessionSummaryWrapper>, Error>);

// #[get("/api/sessions")]
// #[openapi(description = "Open Sessions")]
// pub async fn get_sessions(_: LoggedUser, #[data] data: AppState) -> WarpResult<SessionsResponse> {
//     let objects = list_sessions_lines(&data)
//         .await?
//         .into_iter()
//         .map(Into::into)
//         .collect();
//     Ok(JsonBase::new(objects).into())
// }

// #[derive(RwebResponse)]
// #[response(description = "Delete Sessions", status = "NO_CONTENT")]
// struct DeleteSessionsResponse(HtmlBase<&'static str, Error>);

// #[derive(Deserialize, Schema, Debug)]
// pub struct SessionQuery {
//     #[schema(description = "Session Key")]
//     pub session_key: Option<StackString>,
//     #[schema(description = "Session")]
//     pub session: Option<UuidWrapper>,
// }

// #[delete("/api/sessions")]
// #[openapi(description = "Delete Sessions")]
// pub async fn delete_sessions(
//     user: LoggedUser,
//     #[data] data: AppState,
//     session_query: Query<SessionQuery>,
// ) -> WarpResult<DeleteSessionsResponse> {
//     let session_query = session_query.into_inner();
//     if let Some(session_key) = &session_query.session_key {
//         let session_id = user.session.into();
//         Session::delete_session_data_from_cache(
//             &data.pool,
//             session_id,
//             &user.secret_key,
//             session_key,
//         )
//         .await
//         .map_err(Into::<Error>::into)?;
//         data.session_cache
//             .remove_data(session_id, &user.secret_key, session_key)?;
//     }
//     if let Some(session) = session_query.session {
//         LoggedUser::delete_user_session(session.into(), &data.pool).await?;
//         let _ = data.session_cache.remove_session(session.into());
//     }
//     Ok(HtmlBase::new("finished").into())
// }

// #[derive(Deserialize, Schema)]
// #[schema(component = "CreateInvitation")]
// pub struct CreateInvitation {
//     #[schema(description = "Email to send invitation to")]
//     pub email: StackString,
// }

// #[derive(Serialize, Schema)]
// #[schema(component = "Invitation")]
// pub struct InvitationOutput {
//     #[schema(description = "Invitation ID")]
//     pub id: StackString,
//     #[schema(description = "Email Address")]
//     pub email: StackString,
//     #[schema(description = "Expiration Datetime")]
//     #[serde(with = "iso8601")]
//     pub expires_at: DateTimeType,
// }

// impl From<Invitation> for InvitationOutput {
//     fn from(i: Invitation) -> Self {
//         let expires_at: OffsetDateTime = i.expires_at.into();
//         Self {
//             id: i.id.to_string().into(),
//             email: i.email,
//             expires_at: expires_at.into(),
//         }
//     }
// }

// #[derive(RwebResponse)]
// #[response(description = "Invitation Object", status = "CREATED")]
// struct ApiInvitationResponse(JsonBase<InvitationOutput, Error>);

// #[post("/api/invitation")]
// #[openapi(description = "Send invitation to specified email")]
// pub async fn register_email(
//     #[data] data: AppState,
//     invitation: Json<CreateInvitation>,
// ) -> WarpResult<ApiInvitationResponse> {
//     let invitation = invitation.into_inner();

//     let email = invitation.email;
//     let invitation = Invitation::from_email(email);
//     invitation
//         .insert(&data.pool)
//         .await
//         .map_err(Into::<Error>::into)?;
//     send_invitation(
//         &data.ses,
//         &invitation,
//         &data.config.sending_email_address,
//         &data.config.callback_url,
//     )
//     .await
//     .map_err(Into::<Error>::into)?;

//     let resp = JsonBase::new(invitation.into());
//     Ok(resp.into())
// }

// #[derive(Debug, Deserialize, Schema)]
// #[schema(component = "PasswordData")]
// pub struct PasswordData {
//     #[schema(description = "Password")]
//     pub password: StackString,
// }

// #[derive(RwebResponse)]
// #[response(description = "Registered Email", status = "CREATED")]
// struct ApiRegisterResponse(JsonBase<LoggedUser, Error>);

// #[post("/api/register/{invitation_id}")]
// #[openapi(description = "Set password using link from email")]
// pub async fn register_user(
//     invitation_id: UuidWrapper,
//     #[data] data: AppState,
//     user_data: Json<PasswordData>,
// ) -> WarpResult<ApiRegisterResponse> {
//     let user_data: PasswordData = user_data.into_inner();
//     if let Some(invitation) = Invitation::get_by_uuid(invitation_id.into(), &data.pool)
//         .await
//         .map_err(Into::<Error>::into)?
//     {
//         let expires_at: OffsetDateTime = invitation.expires_at.into();
//         if expires_at > OffsetDateTime::now_utc() {
//             let user = User::from_details(invitation.email.clone(), &user_data.password)
//                 .map_err(Into::<Error>::into)?;
//             user.upsert(&data.pool).await.map_err(Into::<Error>::into)?;
//             invitation
//                 .delete(&data.pool)
//                 .await
//                 .map_err(Into::<Error>::into)?;
//             let user: AuthorizedUser = user.into();
//             AUTHORIZED_USERS.store_auth(user.clone(), true);
//             let resp = JsonBase::new(user.into());
//             return Ok(resp.into());
//         }
//         invitation
//             .delete(&data.pool)
//             .await
//             .map_err(Into::<Error>::into)?;
//     }
//     Err(Error::BadRequest("Invalid invitation").into())
// }

#[derive(Serialize, Deserialize, Debug, ToSchema)]
// #[schema(component = "PasswordChange")]
pub struct PasswordChangeOutput {
    pub message: StackString,
}

// #[derive(RwebResponse)]
// #[response(description = "Success Message", status = "CREATED")]
// struct ApiPasswordChangeResponse(JsonBase<PasswordChangeOutput, Error>);

// #[post("/api/password_change")]
// #[openapi(description = "Change password for currently logged in user")]
// pub async fn change_password_user(
//     user: LoggedUser,
//     #[data] data: AppState,
//     user_data: Json<PasswordData>,
// ) -> WarpResult<ApiPasswordChangeResponse> {
//     let user_data = user_data.into_inner();
//     let message: StackString = if let Some(mut user) = User::get_by_email(&user.email, &data.pool)
//         .await
//         .map_err(Into::<Error>::into)?
//     {
//         user.set_password(&user_data.password)
//             .map_err(Into::<Error>::into)?;
//         user.update(&data.pool).await.map_err(Into::<Error>::into)?;
//         "password updated".into()
//     } else {
//         return Err(Error::BadRequest("Invalid User").into());
//     };
//     let resp = JsonBase::new(PasswordChangeOutput { message });
//     Ok(resp.into())
// }

// #[derive(Serialize, Deserialize, Schema)]
// #[schema(component = "AuthUrl")]
// pub struct AuthUrlOutput {
//     #[schema(description = "Auth URL")]
//     pub auth_url: StackString,
//     #[schema(description = "CSRF State")]
//     pub csrf_state: StackString,
// }

// #[derive(RwebResponse)]
// #[response(description = "Authorization Url", status = "CREATED")]
// struct ApiAuthUrlResponse(JsonBase<AuthUrlOutput, Error>);

// #[post("/api/auth_url")]
// #[openapi(description = "Get Oauth Url")]
// pub async fn auth_url(
//     #[data] data: AppState,
//     query: Json<FinalUrlData>,
// ) -> WarpResult<ApiAuthUrlResponse> {
//     let query = query.into_inner();
//     let (auth_url, csrf_state) = data
//         .google_client
//         .get_auth_url_csrf(query.final_url.as_ref().map(StackString::as_str))
//         .await
//         .map_err(Into::<Error>::into)?;
//     let auth_url: String = auth_url.into();
//     let resp = JsonBase::new(AuthUrlOutput {
//         auth_url: auth_url.into(),
//         csrf_state,
//     });
//     Ok(resp.into())
// }

// #[derive(Schema, Serialize, Deserialize)]
// pub struct AuthAwait {
//     #[schema(description = "CSRF State")]
//     pub state: StackString,
// }

// #[derive(RwebResponse)]
// #[response(description = "Finished", content = "html")]
// struct ApiAwaitResponse(HtmlBase<StackString, Infallible>);

// #[get("/api/await")]
// #[openapi(description = "Await completion of auth")]
// pub async fn auth_await(
//     #[data] data: AppState,
//     query: Query<AuthAwait>,
// ) -> WarpResult<ApiAwaitResponse> {
//     let state = query.into_inner().state;
//     if timeout(
//         Duration::from_secs(60),
//         data.google_client.wait_csrf(&state),
//     )
//     .await
//     .is_err()
//     {
//         error!("await timed out");
//     }
//     sleep(Duration::from_millis(10)).await;
//     let final_url = if let Some(s) = data.google_client.decode(&state) {
//         s
//     } else {
//         "".into()
//     };
//     Ok(HtmlBase::new(final_url).into())
// }

#[derive(Deserialize, ToSchema)]
pub struct CallbackQuery {
    /// Authorization Code
    pub code: StackString,
    /// CSRF State
    pub state: StackString,
}

// #[derive(RwebResponse)]
// #[response(description = "Callback Response", content = "html")]
// struct ApiCallbackResponse(HtmlBase<&'static str, Error>);

// #[get("/api/callback")]
// #[openapi(description = "Callback method for use in Oauth flow")]
// pub async fn callback(
//     #[data] data: AppState,
//     query: Query<CallbackQuery>,
// ) -> WarpResult<ApiCallbackResponse> {
//     let cookies = callback_body(
//         query.into_inner(),
//         &data.pool,
//         &data.google_client,
//         &data.config,
//     )
//     .await?;
//     let body = r#"
//         <title>Google Oauth Succeeded</title>
//         This window can be closed.
//         <script language="JavaScript" type="text/javascript">window.close()</script>
//     "#;
//     Ok(HtmlBase::new(body)
//         .with_cookie(cookies.get_session_cookie_str())
//         .with_cookie(cookies.get_jwt_cookie_str())
//         .into())
// }

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

// #[derive(RwebResponse)]
// #[response(description = "Login POST", status = "CREATED")]
// struct TestLoginResponse(JsonBase<LoggedUser, Error>);

#[utoipa::path(post, path="/api/auth")]
pub async fn test_login(
    data: State<Arc<AppState>>,
    auth_data: Json<AuthRequest>,
) -> Result<Response, Error> {
    let Json(auth_data) = auth_data;
    let session = Session::new(auth_data.email.as_str());
    println!("auth_data {auth_data:?}");
    let (user, cookies) = test_login_user_jwt(auth_data, session, &data.config).await?;
    println!("user {user:?} cookies {cookies:?}");
    Ok(
        (StatusCode::CREATED, cookies.get_headers()?, Json(user)).into_response()
    )
}

#[utoipa::path(get, path="/api/auth", responses((status = OK, body = LoggedUser)))]
pub async fn test_get_user(user: LoggedUser) -> Result<Json<LoggedUser>, Error> {
    Ok(Json(user))
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
