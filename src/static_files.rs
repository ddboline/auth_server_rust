use warp::{
    http::{header::CONTENT_TYPE, Error as HttpError, Response as HttpResponse},
    reply::Response,
};

pub fn index_html() -> Result<Response, HttpError> {
    HttpResponse::builder()
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(include_str!("../templates/index.html").into())
}

pub fn main_css() -> Result<Response, HttpError> {
    HttpResponse::builder()
        .header(CONTENT_TYPE, "text/css; charset=utf-8")
        .body(include_str!("../templates/main.css").into())
        .map_err(Into::into)
}

pub fn register_html() -> Result<Response, HttpError> {
    HttpResponse::builder()
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(include_str!("../templates/register.html").into())
        .map_err(Into::into)
}

pub fn main_js() -> Result<Response, HttpError> {
    HttpResponse::builder()
        .header(CONTENT_TYPE, "text/javascript; charset=utf-8")
        .body(include_str!("../templates/main.js").into())
        .map_err(Into::into)
}

pub fn login_html() -> Result<Response, HttpError> {
    HttpResponse::builder()
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(include_str!("../templates/login.html").into())
        .map_err(Into::into)
}

pub fn change_password() -> Result<Response, HttpError> {
    HttpResponse::builder()
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(include_str!("../templates/change_password.html").into())
        .map_err(Into::into)
}
