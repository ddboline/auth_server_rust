use chrono::Utc;
use futures::try_join;
use http::{
    header::{CONTENT_TYPE, SET_COOKIE},
    StatusCode,
};
use log::debug;
use serde::{Deserialize};
use stack_string::StackString;
use uuid::Uuid;
use warp::{Reply, reply::Html, reply::Json};

use auth_server_ext::{
    google_openid::{CallbackQuery, GetAuthUrlData, GoogleClient},
    invitation::Invitation,
    ses_client::SesInstance,
};
use auth_server_lib::{auth::AuthRequest, config::Config, pgpool::PgPool, user::User};
use authorized_users::{token::Token, AuthorizedUser, AUTHORIZED_USERS};

use crate::{errors::ServiceError as Error, logged_user::LoggedUser};

pub type WarpResult<T> = Result<T, Error>;
pub type HttpResult = WarpResult<Html<String>>;
pub type JsonResult = WarpResult<Json>;

pub async fn login(
    auth_data: AuthRequest,
    pool: &PgPool,
    config: &Config,
) -> WarpResult<impl Reply> {
    if let Some(user) = auth_data.authenticate(pool).await? {
        let user: AuthorizedUser = user.into();
        let token = Token::create_token(&user, &config.domain, config.expiration_seconds)
            .map_err(|e| Error::BadRequest(format!("Failed to create_token {}", e)))?;
        let reply = warp::reply::json(&user);
        let reply = warp::reply::with_status(reply, StatusCode::OK);
        let reply = warp::reply::with_header(reply, CONTENT_TYPE, "application/json");
        let reply = warp::reply::with_header(
            reply,
            SET_COOKIE,
            format!(
                "jwt={}; HttpOnly; Path=/; Domain={}; Max-Age={}",
                token, config.domain, config.expiration_seconds
            ),
        );
        Ok(reply)
    } else {
        Err(Error::BadRequest(
            "Username and Password don't match".into(),
        ))
    }
}

pub async fn logout(logged_user: LoggedUser, config: &Config) -> WarpResult<impl Reply> {
    let reply = warp::reply::html(format!("{} has been logged out", logged_user.email));
    let reply = warp::reply::with_header(
        reply,
        SET_COOKIE,
        format!(
            "jwt=; HttpOnly; Path=/; Domain={}; Max-Age={}",
            config.domain, config.expiration_seconds
        ),
    );
    Ok(reply)
}

pub async fn get_me(logged_user: LoggedUser) -> JsonResult {
    let reply = warp::reply::json(&logged_user);
    Ok(reply)
}

#[derive(Deserialize)]
pub struct CreateInvitation {
    pub email: StackString,
}

pub async fn register_email(
    invitation: CreateInvitation,
    pool: &PgPool,
    config: &Config,
) -> JsonResult {
    let email = invitation.email;
    let invitation = Invitation::from_email(&email);
    invitation.insert(pool).await?;
    invitation
        .send_invitation(&config.sending_email_address, config.callback_url.as_str())
        .await?;
    let reply = warp::reply::json(&invitation);
    Ok(reply)
}

#[derive(Debug, Deserialize)]
pub struct UserData {
    pub password: StackString,
}

pub async fn register_user(
    invitation_id: StackString,
    user_data: UserData,
    pool: &PgPool,
    config: &Config,
) -> JsonResult {
    let uuid = Uuid::parse_str(&invitation_id)?;
    if let Some(invitation) = Invitation::get_by_uuid(&uuid, pool).await? {
        if invitation.expires_at > Utc::now() {
            let user = User::from_details(&invitation.email, &user_data.password, &config);
            user.upsert(pool).await?;
            invitation.delete(pool).await?;
            let user: AuthorizedUser = user.into();
            AUTHORIZED_USERS.store_auth(user.clone(), true)?;
            let reply = warp::reply::json(&user);
            return Ok(reply);
        } else {
            invitation.delete(pool).await?;
        }
    }
    Err(Error::BadRequest("Invalid invitation".into()))
}

pub async fn change_password_user(
    logged_user: LoggedUser,
    user_data: UserData,
    pool: &PgPool,
    config: &Config,
) -> HttpResult {
    if let Some(mut user) = User::get_by_email(&logged_user.email, pool).await? {
        user.set_password(&user_data.password, &config);
        user.update(pool).await?;
        let reply = warp::reply::html("password updated".into());
        Ok(reply)
    } else {
        Err(Error::BadRequest("Invalid User".into()))
    }
}

pub async fn auth_url(payload: GetAuthUrlData, google_client: &GoogleClient) -> HttpResult {
    debug!("{:?}", payload.final_url);
    let authorize_url = google_client.get_auth_url(payload).await?;
    let reply = warp::reply::html(authorize_url.into_string());
    Ok(reply)
}

pub async fn callback(
    query: CallbackQuery,
    pool: &PgPool,
    google_client: &GoogleClient,
    config: &Config,
) -> WarpResult<impl Reply> {
    if let Some((token, body)) = google_client.run_callback(&query, pool, &config).await? {
        let body: String = body.into();
        let reply = warp::reply::html(body);
        let reply = warp::reply::with_status(reply, StatusCode::OK);
        let reply = warp::reply::with_header(reply, CONTENT_TYPE, "application/json");
        let reply = warp::reply::with_header(
            reply,
            SET_COOKIE,
            format!(
                "jwt={}; HttpOnly; Path=/; Domain={}; Max-Age={}",
                token.to_string(),
                config.domain,
                config.expiration_seconds
            ),
        );
        Ok(reply)
    } else {
        Err(Error::BadRequest("Callback Failed".into()))
    }
}

pub async fn status(pool: &PgPool) -> HttpResult {
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
    let reply = warp::reply::html(body);
    Ok(reply)
}

pub async fn test_login(auth_data: AuthRequest, config: &Config) -> WarpResult<impl Reply> {
    if let Ok(s) = std::env::var("TESTENV") {
        if &s == "true" {
            let user = AuthorizedUser {
                email: auth_data.email.into(),
            };
            let token = Token::create_token(&user, &config.domain, config.expiration_seconds)?;
            let reply = warp::reply::json(&user);
            let reply = warp::reply::with_status(reply, StatusCode::OK);
            let reply = warp::reply::with_header(reply, CONTENT_TYPE, "application/json");
            let reply = warp::reply::with_header(
                reply,
                SET_COOKIE,
                format!(
                    "jwt={}; HttpOnly; Path=/; Domain={}; Max-Age={}",
                    token, config.domain, config.expiration_seconds
                ),
            );
            AUTHORIZED_USERS.merge_users(&[user])?;
            return Ok(reply);
        }
    }
    Err(Error::BadRequest(
        "Username and Password don't match".into(),
    ))
}
