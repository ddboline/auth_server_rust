use http::{header::CONTENT_TYPE, Error, Response, StatusCode};

type HttpResponse = Result<Response<&'static str>, Error>;

pub fn index_html() -> HttpResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(include_str!("../../templates/index.html"))
}

pub fn main_css() -> HttpResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/css; charset=utf-8")
        .body(include_str!("../../templates/main.css"))
}

pub fn register_html() -> HttpResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(include_str!("../../templates/register.html"))
}

pub fn main_js() -> HttpResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/javascript; charset=utf-8")
        .body(include_str!("../../templates/main.js"))
}

pub fn login_html() -> HttpResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(include_str!("../../templates/login.html"))
}

pub fn change_password() -> HttpResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(include_str!("../../templates/change_password.html"))
}
