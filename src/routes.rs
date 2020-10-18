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

use crate::{
    app::{AppState, CONFIG},
    auth::AuthRequest,
    errors::ServiceError as Error,
    google_openid::{CallbackQuery, GetAuthUrlData, GoogleClient},
    invitation::Invitation,
    logged_user::{LoggedUser, AUTHORIZED_USERS},
    ses_client::SesInstance,
    token::Token,
    user::User,
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
        let user: LoggedUser = user.into();
        let token = Token::create_token(&user)?;
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

pub async fn get_me(logged_user: LoggedUser) -> HttpResult {
    to_json(logged_user)
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
        .send_invitation(CONFIG.callback_url.as_str())
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
            let user = User::from_details(&invitation.email, &user_data.password);
            user.upsert(&data.pool).await?;
            invitation.delete(&data.pool).await?;
            let user: LoggedUser = user.into();
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
        user.set_password(&user_data.password);
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
    if let Some((token, body)) = client.run_callback(&query, &data.pool).await? {
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
            let user = LoggedUser {
                email: auth_data.email.into(),
            };
            let token = Token::create_token(&user)?;
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
