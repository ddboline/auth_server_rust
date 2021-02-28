use chrono::Utc;
use futures::try_join;
use http::header::SET_COOKIE;
use indexmap::IndexMap;
use log::debug;
use rweb::{
    delete, get,
    openapi::{self, Entity, MediaType, ObjectOrReference, Response, ResponseEntity, Responses},
    post, Json, Schema, Query,
};
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use std::borrow::Cow;
use url::Url;
use uuid::Uuid;
use warp::{Rejection, Reply, http::Uri};

use auth_server_ext::{
    google_openid::GoogleClient, invitation::Invitation, ses_client::SesInstance,
};
use auth_server_lib::{config::Config, pgpool::PgPool, user::User};
use authorized_users::{AuthorizedUser, AUTHORIZED_USERS};

use crate::{
    app::AppState, auth::AuthRequest, errors::ServiceError as Error, logged_user::LoggedUser,
};

pub type WarpResult<T> = Result<T, Rejection>;
pub type HttpResult<T> = Result<T, Error>;

pub struct JsonResponse<T: Serialize + Entity + Send> {
    data: T,
    cookie: Option<String>,
}

impl<T> JsonResponse<T>
where
    T: Serialize + Entity + Send,
{
    pub fn new(data: T) -> Self {
        Self { data, cookie: None }
    }
    pub fn with_cookie(mut self, cookie: String) -> Self {
        self.cookie = Some(cookie);
        self
    }
}

impl<T> Reply for JsonResponse<T>
where
    T: Serialize + Entity + Send,
{
    fn into_response(self) -> warp::hyper::Response<warp::hyper::Body> {
        let reply = warp::reply::json(&self.data);
        if let Some(header) = self.cookie {
            let reply = warp::reply::with_header(reply, SET_COOKIE, header);
            reply.into_response()
        } else {
            reply.into_response()
        }
    }
}

impl<T> Entity for JsonResponse<T>
where
    T: Serialize + Entity + Send,
{
    fn describe() -> openapi::Schema {
        T::describe()
    }
}

impl<T> ResponseEntity for JsonResponse<T>
where
    T: Serialize + Entity + Send,
{
    fn describe_responses() -> Responses {
        let schema = Self::describe();
        let mut content = IndexMap::new();
        content.insert(
            Cow::Borrowed("application/json"),
            MediaType {
                schema: Some(ObjectOrReference::Object(schema)),
                examples: None,
                encoding: Default::default(),
            },
        );
        let mut map = Responses::new();
        map.insert(
            Cow::Borrowed("200"),
            Response {
                content,
                ..Default::default()
            },
        );
        map
    }
}

#[post("/api/auth")]
#[openapi(description = "Login with username and password")]
pub async fn login(
    #[data] data: AppState,
    auth_data: Json<AuthRequest>,
) -> WarpResult<JsonResponse<LoggedUser>> {
    let (user, jwt) = login_user_jwt(auth_data.into_inner(), &data.pool, &data.config).await?;
    Ok(JsonResponse {
        data: user,
        cookie: Some(jwt),
    })
}

async fn login_user_jwt(
    auth_data: AuthRequest,
    pool: &PgPool,
    config: &Config,
) -> HttpResult<(LoggedUser, String)> {
    let message = if let Some(user) = auth_data.authenticate(pool).await? {
        let user: AuthorizedUser = user.into();
        let user: LoggedUser = user.into();
        match user.get_jwt_cookie(&config.domain, config.expiration_seconds) {
            Ok(jwt) => return Ok((user, jwt)),
            Err(e) => format!("Failed to create_token {}", e),
        }
    } else {
        "Username and Password don't match".into()
    };
    Err(Error::BadRequest(message))
}

#[delete("/api/auth")]
#[openapi(description = "Log out")]
pub async fn logout(
    #[cookie = "jwt"] logged_user: LoggedUser,
    #[data] data: AppState,
) -> WarpResult<JsonResponse<String>> {
    Ok(
        JsonResponse::new(format!("{} has been logged out", logged_user.email)).with_cookie(
            format!(
                "jwt=; HttpOnly; Path=/; Domain={}; Max-Age={}",
                data.config.domain, data.config.expiration_seconds
            ),
        ),
    )
}

#[get("/api/auth")]
#[openapi(description = "Get current username if logged in")]
pub async fn get_me(
    #[cookie = "jwt"] logged_user: LoggedUser,
) -> WarpResult<JsonResponse<LoggedUser>> {
    Ok(JsonResponse::new(logged_user))
}

#[derive(Deserialize, Schema)]
pub struct CreateInvitation {
    #[schema(description = "Email to send invitation to")]
    pub email: StackString,
}

#[post("/api/invitation")]
#[openapi(description = "Send invitation to specified email")]
pub async fn register_email(
    #[data] data: AppState,
    invitation: Json<CreateInvitation>,
) -> WarpResult<JsonResponse<String>> {
    let invitation =
        register_email_invitation(invitation.into_inner(), &data.pool, &data.config).await?;
    Ok(JsonResponse::new(invitation.id.to_string()))
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

#[post("/api/register/{invitation_id}")]
#[openapi(description = "Set password using link from email")]
pub async fn register_user(
    invitation_id: StackString,
    #[data] data: AppState,
    user_data: Json<UserData>,
) -> WarpResult<JsonResponse<LoggedUser>> {
    let user = register_user_object(
        invitation_id,
        user_data.into_inner(),
        &data.pool,
        &data.config,
    )
    .await?;
    Ok(JsonResponse::new(user.into()))
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
        } else {
            invitation.delete(pool).await?;
        }
    }
    Err(Error::BadRequest("Invalid invitation".into()))
}

#[post("/api/password_change")]
#[openapi(description = "Change password for currently logged in user")]
pub async fn change_password_user(
    #[cookie = "jwt"] logged_user: LoggedUser,
    #[data] data: AppState,
    user_data: Json<UserData>,
) -> WarpResult<String> {
    let body = change_password_user_body(
        logged_user,
        user_data.into_inner(),
        &data.pool,
        &data.config,
    )
    .await?;
    Ok(body.into())
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
    #[schema(description="Url to redirect to after completion of authorization")]
    pub final_url: StackString,
}

#[post("/api/auth_url")]
#[openapi(description = "Get Oauth Url")]
pub async fn auth_url(#[data] data: AppState, payload: Json<GetAuthUrlData>) -> WarpResult<String> {
    let authorize_url = auth_url_body(payload.into_inner(), &data.google_client).await?;
    Ok(authorize_url.into_string())
}

async fn auth_url_body(payload: GetAuthUrlData, google_client: &GoogleClient) -> HttpResult<Url> {
    debug!("{:?}", payload.final_url);
    Ok(google_client.get_auth_url(&payload.final_url).await?)
}

#[derive(Deserialize, Schema)]
pub struct CallbackQuery {
    pub code: StackString,
    pub state: StackString,
}

#[get("/api/callback")]
#[openapi(description = "Callback method for use in Oauth flow")]
pub async fn callback(
    #[data] data: AppState,
    query: Query<CallbackQuery>,
) -> WarpResult<impl Reply> {
    let (jwt, body) = callback_body(
        query.into_inner(),
        &data.pool,
        &data.google_client,
        &data.config,
    )
    .await?;
    println!("redirecting {:?}", body);
    let redirect = warp::redirect(body);
    let reply = warp::reply::with_header(redirect, SET_COOKIE, jwt);
    Ok(reply)
}

async fn callback_body(
    query: CallbackQuery,
    pool: &PgPool,
    google_client: &GoogleClient,
    config: &Config,
) -> HttpResult<(String, Uri)> {
    if let Some((user, body)) = google_client
        .run_callback(&query.code, &query.state, pool)
        .await?
    {
        let user: LoggedUser = user.into();
        let jwt = user.get_jwt_cookie(&config.domain, config.expiration_seconds)?;
        Ok((jwt, body.as_str().parse()?))
    } else {
        Err(Error::BadRequest("Callback Failed".into()))
    }
}

#[get("/api/status")]
#[openapi(description = "Status endpoint")]
pub async fn status(#[data] data: AppState) -> WarpResult<String> {
    let body = status_body(&data.pool).await?;
    Ok(body)
}

async fn status_body(pool: &PgPool) -> HttpResult<String> {
    let ses = SesInstance::new(None);
    let (number_users, number_invitations, (quota, stats)) = try_join!(
        User::get_number_users(pool),
        Invitation::get_number_invitations(pool),
        ses.get_statistics(),
    )?;
    let body = format!(
        "Users: {}<br>Invitations: {}<br>{:#?}<br>{:#?}<br>",
        number_users, number_invitations, quota, stats,
    );
    Ok(body)
}

#[post("/api/auth")]
pub async fn test_login(
    auth_data: Json<AuthRequest>,
    #[data] data: AppState,
) -> WarpResult<JsonResponse<LoggedUser>> {
    let (user, jwt) = test_login_user_jwt(auth_data.into_inner(), &data.config).await?;
    Ok(JsonResponse::new(user).with_cookie(jwt))
}

async fn test_login_user_jwt(
    auth_data: AuthRequest,
    config: &Config,
) -> HttpResult<(LoggedUser, String)> {
    if let Ok(s) = std::env::var("TESTENV") {
        if &s == "true" {
            let user = AuthorizedUser {
                email: auth_data.email.into(),
            };
            AUTHORIZED_USERS.merge_users(&[user.clone()])?;
            let user: LoggedUser = user.into();
            let jwt = user.get_jwt_cookie(&config.domain, config.expiration_seconds)?;
            return Ok((user, jwt));
        }
    }
    Err(Error::BadRequest(
        "Username and Password don't match".into(),
    ))
}
