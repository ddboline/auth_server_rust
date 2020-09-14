use actix_identity::Identity;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json, Path, Query};
use actix_web::HttpResponse;
use bcrypt::{hash, verify};
use chrono::{Duration, Utc};
use log::debug;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use url::Url;
use uuid::Uuid;

use crate::app::{AppState, CONFIG};
use crate::email_service::send_invitation;
use crate::errors::ServiceError as Error;
use crate::google_openid::{
    get_auth_url, get_google_client, request_userinfo, CallbackQuery, CrsfTokenCache,
    GetAuthUrlData, GoogleClient, CSRF_TOKENS,
};
use crate::invitation::Invitation;
use crate::logged_user::LoggedUser;
use crate::token::Token;
use crate::user::User;

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

pub fn hash_password(plain: &str) -> Result<String, Error> {
    // get the hashing cost from the env variable or use default
    hash(plain, CONFIG.hash_rounds).map_err(|_| Error::InternalServerError)
}

#[derive(Debug, Deserialize)]
pub struct AuthData {
    pub email: String,
    pub password: String,
}

pub async fn login(auth_data: Json<AuthData>, id: Identity, data: Data<AppState>) -> HttpResult {
    if let Some(user) = User::get_by_email(&auth_data.email, &data.pool).await? {
        if verify(&auth_data.password, &user.password)? {
            let user: LoggedUser = user.into();
            let token = Token::create_token(&user)?;
            id.remember(token.into());
            return to_json(user);
        }
    }
    Err(Error::BadRequest(
        "Username and Password don't match".into(),
    ))
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
    pub email: String,
}

pub async fn register_email(
    invitation: Json<CreateInvitation>,
    data: Data<AppState>,
) -> HttpResult {
    let email = invitation.into_inner().email;
    if let Some(user) = User::get_by_email(&email, &data.pool).await? {
        let logged_user: LoggedUser = user.into();
        to_json(logged_user)
    } else {
        let new_invitation = Invitation {
            id: Uuid::new_v4(),
            email,
            expires_at: Utc::now() + Duration::hours(24),
        };
        new_invitation.insert(&data.pool).await?;
        send_invitation(&new_invitation, CONFIG.callback_url.as_str()).await?;
        to_json(new_invitation)
    }
}

#[derive(Debug, Deserialize)]
pub struct UserData {
    pub password: String,
}

pub async fn register_user(
    invitation_id: Path<String>,
    user_data: Json<UserData>,
    data: Data<AppState>,
) -> HttpResult {
    let invitation_id = Uuid::parse_str(&invitation_id.into_inner())?;
    if let Some(invitation) = Invitation::get_by_uuid(&invitation_id, &data.pool).await? {
        if invitation.expires_at > Utc::now() {
            let password = hash_password(&user_data.password)?;
            let user = User::from_details(&invitation.email, &password);
            user.insert(&data.pool).await?;
            invitation.delete(&data.pool).await?;
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
        user.password = hash_password(&user_data.password)?.into();
        user.update(&data.pool).await?;
        form_http_response("password updated".to_string())
    } else {
        Err(Error::BadRequest("Invalid User".into()))
    }
}

pub async fn auth_url(payload: Json<GetAuthUrlData>, client: Data<GoogleClient>) -> HttpResult {
    let payload = payload.into_inner();
    debug!("{:?}", payload.final_url);
    let final_url: Url = payload
        .final_url
        .parse()
        .map_err(|err| Error::BlockingError(format!("Failed to parse url {:?}", err)))?;
    let client = client.read().await.clone();
    let (authorize_url, options) = get_auth_url(&client);

    let csrf_state = options.state.clone().expect("No CSRF state");
    let nonce = options.nonce.clone().expect("No nonce");

    CSRF_TOKENS.write().await.insert(
        csrf_state,
        CrsfTokenCache {
            nonce,
            final_url,
            timestamp: Utc::now(),
        },
    );
    Ok(HttpResponse::Ok().body(authorize_url.into_string()))
}

pub async fn callback(
    query: Query<CallbackQuery>,
    data: Data<AppState>,
    client: Data<GoogleClient>,
    id: Identity,
) -> HttpResult {
    let query = query.into_inner();
    let code = query.code.clone();

    let value = CSRF_TOKENS.write().await.remove(&query.state);
    if let Some(CrsfTokenCache {
        nonce, final_url, ..
    }) = value
    {
        debug!("Nonce {:?}", nonce);

        let userinfo = match request_userinfo(&client.read().await.clone(), &code, &nonce).await {
            Ok(userinfo) => userinfo,
            Err(e) => {
                let new_client = get_google_client().await?;
                *client.write().await = Arc::new(new_client);
                return Err(e);
            }
        };

        if let Some(user_email) = &userinfo.email {
            if let Some(user) = User::get_by_email(user_email, &data.pool).await? {
                let user: LoggedUser = user.into();

                let token = Token::create_token(&user)?;
                id.remember(token.into());
                let body = format!(
                    "{}'{}'{}",
                    r#"<script>!function(){let url = "#,
                    final_url,
                    r#";location.replace(url);}();</script>"#
                );
                return Ok(HttpResponse::Ok().body(body));
            }
        }
        Err(Error::BadRequest("Oauth failed".into()))
    } else {
        Ok(HttpResponse::Ok().body("Csrf Token invalid"))
    }
}
