use actix_identity::Identity;
use actix_web::{
    http::StatusCode,
    web::{Data, Json, Path, Query},
    HttpResponse,
};
use chrono::Utc;
use futures::try_join;
use log::debug;
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use uuid::Uuid;

use auth_server_ext::{
    google_openid::{CallbackQuery, GetAuthUrlData, GoogleClient},
    invitation::Invitation,
    ses_client::SesInstance,
};
use auth_server_lib::{auth::AuthRequest, user::User};
use authorized_users::{token::Token, AuthorizedUser, AUTHORIZED_USERS};

use crate::{
    app::{AppState, CONFIG},
    errors::ServiceError as Error,
    logged_user::LoggedUser,
};

pub type HttpResult = Result<HttpResponse, Error>;

fn form_http_response(body: String) -> HttpResult {
    Ok(HttpResponse::build(StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body(body))
}

fn to_json<T>(js: T) -> HttpResult
where
    T: Serialize,
{
    Ok(HttpResponse::Ok().json(js))
}

pub async fn login(auth_data: Json<AuthRequest>, id: Identity, data: Data<AppState>) -> HttpResult {
    if let Some(user) = auth_data.authenticate(&data.pool).await? {
        let user: AuthorizedUser = user.into();
        let token = Token::create_token(&user, &CONFIG.domain, CONFIG.expiration_seconds)
            .map_err(|e| Error::BadRequest(format!("Failed to create_token {}", e)))?;
        id.remember(token.into());
        to_json(user)
    } else {
        Err(Error::BadRequest(
            "Username and Password don't match".into(),
        ))
    }
}

pub async fn logout(id: Identity) -> HttpResult {
    id.forget();
    if let Some(id) = id.identity() {
        form_http_response(format!("{} has been logged out", id))
    } else {
        form_http_response("".to_string())
    }
}

pub async fn get_me(logged_user: LoggedUser, id: Identity, data: Data<AppState>) -> HttpResult {
    if let Some(user) = User::get_by_email(&logged_user.email, &data.pool).await? {
        let user: AuthorizedUser = user.into();
        let token = Token::create_token(&user, &CONFIG.domain, CONFIG.expiration_seconds)
            .map_err(|e| Error::BadRequest(format!("Failed to create_token {}", e)))?;
        id.remember(token.into());
        to_json(logged_user)
    } else {
        if let Some(id) = id.identity() {
            form_http_response(format!("{} has been logged out", id))
        } else {
            form_http_response("".to_string())
        }
    }
}

#[derive(Deserialize)]
pub struct CreateInvitation {
    pub email: StackString,
}

pub async fn register_email(
    invitation: Json<CreateInvitation>,
    data: Data<AppState>,
) -> HttpResult {
    let email = invitation.into_inner().email;
    let invitation = Invitation::from_email(&email);
    invitation.insert(&data.pool).await?;
    invitation
        .send_invitation(&CONFIG.sending_email_address, CONFIG.callback_url.as_str())
        .await?;
    to_json(invitation)
}

#[derive(Debug, Deserialize)]
pub struct UserData {
    pub password: StackString,
}

pub async fn register_user(
    invitation_id: Path<StackString>,
    user_data: Json<UserData>,
    data: Data<AppState>,
) -> HttpResult {
    let uuid = Uuid::parse_str(&invitation_id)?;
    if let Some(invitation) = Invitation::get_by_uuid(&uuid, &data.pool).await? {
        if invitation.expires_at > Utc::now() {
            let user = User::from_details(&invitation.email, &user_data.password, &CONFIG);
            user.upsert(&data.pool).await?;
            invitation.delete(&data.pool).await?;
            let user: AuthorizedUser = user.into();
            AUTHORIZED_USERS.store_auth(user.clone(), true)?;
            return to_json(user);
        } else {
            invitation.delete(&data.pool).await?;
        }
    }
    Err(Error::BadRequest("Invalid invitation".into()))
}

pub async fn change_password_user(
    logged_user: LoggedUser,
    user_data: Json<UserData>,
    data: Data<AppState>,
) -> HttpResult {
    if let Some(mut user) = User::get_by_email(&logged_user.email, &data.pool).await? {
        user.set_password(&user_data.password, &CONFIG);
        user.update(&data.pool).await?;
        form_http_response("password updated".to_string())
    } else {
        Err(Error::BadRequest("Invalid User".into()))
    }
}

pub async fn auth_url(payload: Json<GetAuthUrlData>, client: Data<GoogleClient>) -> HttpResult {
    let payload = payload.into_inner();
    debug!("{:?}", payload.final_url);

    let authorize_url = client.get_auth_url(payload).await?;
    form_http_response(authorize_url.into_string())
}

pub async fn callback(
    query: Query<CallbackQuery>,
    data: Data<AppState>,
    client: Data<GoogleClient>,
    id: Identity,
) -> HttpResult {
    if let Some((token, body)) = client.run_callback(&query, &data.pool, &CONFIG).await? {
        id.remember(token.into());
        form_http_response(body.into())
    } else {
        Err(Error::BadRequest("Callback Failed".into()))
    }
}

pub async fn status(data: Data<AppState>) -> HttpResult {
    let ses = SesInstance::new(None);
    let (number_users, number_invitations, (quota, stats)) = try_join!(
        User::get_number_users(&data.pool),
        Invitation::get_number_invitations(&data.pool),
        ses.get_statistics(),
    )?;
    let body = format!(
        "Users: {}<br>Invitations: {}<br>{:#?}<br>{:#?}<br>",
        number_users, number_invitations, quota, stats,
    );
    form_http_response(body)
}

pub async fn test_login(auth_data: Json<AuthRequest>, id: Identity) -> HttpResult {
    if let Ok(s) = std::env::var("TESTENV") {
        if &s == "true" {
            let auth_data = auth_data.into_inner();
            let user = AuthorizedUser {
                email: auth_data.email.into(),
            };
            let token = Token::create_token(&user, &CONFIG.domain, CONFIG.expiration_seconds)?;
            id.remember(token.into());
            return to_json(user);
        }
    }
    Err(Error::BadRequest(
        "Username and Password don't match".into(),
    ))
}

pub async fn test_logout(id: Identity) -> HttpResult {
    id.forget();
    if let Some(id) = id.identity() {
        form_http_response(format!("{} has been logged out", id))
    } else {
        form_http_response("".to_string())
    }
}

pub async fn test_get_me(logged_user: LoggedUser) -> HttpResult {
    to_json(logged_user)
}
