use chrono::Utc;
use futures::try_join;
use http::{
    header::{CONTENT_TYPE, SET_COOKIE},
    StatusCode,
};
use log::debug;
use rweb::{delete, get, post, Json, Schema};
use serde::Deserialize;
use stack_string::StackString;
use url::Url;
use uuid::Uuid;
use warp::{Rejection, Reply};

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

#[post("/api/auth")]
pub async fn login(#[data] data: AppState, auth_data: Json<AuthRequest>) -> WarpResult<impl Reply> {
    let (user, jwt) = login_user_jwt(auth_data.into_inner(), &data.pool, &data.config).await?;
    let reply = warp::reply::json(&user);
    let reply = warp::reply::with_header(reply, SET_COOKIE, jwt);
    Ok(reply)
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
pub async fn logout(
    #[cookie = "jwt"] logged_user: LoggedUser,
    #[data] data: AppState,
) -> WarpResult<impl Reply> {
    let reply = warp::reply::html(format!("{} has been logged out", logged_user.email));
    let reply = warp::reply::with_header(
        reply,
        SET_COOKIE,
        format!(
            "jwt=; HttpOnly; Path=/; Domain={}; Max-Age={}",
            data.config.domain, data.config.expiration_seconds
        ),
    );
    Ok(reply)
}

#[get("/api/auth")]
pub async fn get_me(#[cookie = "jwt"] logged_user: LoggedUser) -> WarpResult<impl Reply> {
    Ok(warp::reply::json(&logged_user))
}

#[derive(Deserialize, Schema)]
pub struct CreateInvitation {
    pub email: StackString,
}

#[post("/api/invitation")]
pub async fn register_email(
    #[data] data: AppState,
    invitation: Json<CreateInvitation>,
) -> WarpResult<impl Reply> {
    let invitation =
        register_email_invitation(invitation.into_inner(), &data.pool, &data.config).await?;
    Ok(warp::reply::json(&invitation))
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
pub async fn register_user(
    invitation_id: StackString,
    #[data] data: AppState,
    user_data: Json<UserData>,
) -> WarpResult<impl Reply> {
    let user = register_user_object(
        invitation_id,
        user_data.into_inner(),
        &data.pool,
        &data.config,
    )
    .await?;
    Ok(warp::reply::json(&user))
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
pub async fn change_password_user(
    #[cookie = "jwt"] logged_user: LoggedUser,
    #[data] data: AppState,
    user_data: Json<UserData>,
) -> WarpResult<impl Reply> {
    let body = change_password_user_body(
        logged_user,
        user_data.into_inner(),
        &data.pool,
        &data.config,
    )
    .await?;
    Ok(warp::reply::html(body))
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
    pub final_url: StackString,
}

#[post("/api/auth_url")]
pub async fn auth_url(
    #[data] data: AppState,
    payload: Json<GetAuthUrlData>,
) -> WarpResult<impl Reply> {
    let authorize_url = auth_url_body(payload.into_inner(), &data.google_client).await?;
    Ok(warp::reply::html(authorize_url.into_string()))
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
pub async fn callback(
    #[data] data: AppState,
    query: Json<CallbackQuery>,
) -> WarpResult<impl Reply> {
    let (jwt, body) = callback_body(
        query.into_inner(),
        &data.pool,
        &data.google_client,
        &data.config,
    )
    .await?;
    let reply = warp::reply::html(body);
    let reply = warp::reply::with_header(reply, SET_COOKIE, jwt);
    Ok(reply)
}

async fn callback_body(
    query: CallbackQuery,
    pool: &PgPool,
    google_client: &GoogleClient,
    config: &Config,
) -> HttpResult<(String, String)> {
    if let Some((user, body)) = google_client
        .run_callback(&query.code, &query.state, pool)
        .await?
    {
        let user: LoggedUser = user.into();
        let jwt = user.get_jwt_cookie(&config.domain, config.expiration_seconds)?;
        Ok((jwt, body))
    } else {
        Err(Error::BadRequest("Callback Failed".into()))
    }
}

#[get("/api/status")]
pub async fn status(#[data] data: AppState) -> WarpResult<impl Reply> {
    let body = status_body(&data.pool).await?;
    Ok(warp::reply::html(body))
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
) -> WarpResult<impl Reply> {
    let (user, jwt) = test_login_user_jwt(auth_data.into_inner(), &data.config).await?;
    let reply = warp::reply::json(&user);
    let reply = warp::reply::with_status(reply, StatusCode::OK);
    let reply = warp::reply::with_header(reply, CONTENT_TYPE, "application/json");
    let reply = warp::reply::with_header(reply, SET_COOKIE, jwt);
    return Ok(reply);
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
