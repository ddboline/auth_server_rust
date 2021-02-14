use http::{header::CONTENT_TYPE, Error, Response, StatusCode};

type HttpResult = Result<Response<&'static str>, Error>;

#[inline]
fn get_response(c: &'static str, s: &'static str) -> HttpResult {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, c)
        .body(s)
}

pub fn index_html() -> HttpResult {
    get_response(
        "text/html; charset=utf-8",
        include_str!("../../templates/index.html"),
    )
}

pub fn main_css() -> HttpResult {
    get_response(
        "text/css; charset=utf-8",
        include_str!("../../templates/main.css"),
    )
}

pub fn register_html() -> HttpResult {
    get_response(
        "text/html; charset=utf-8",
        include_str!("../../templates/register.html"),
    )
}

pub fn main_js() -> HttpResult {
    get_response(
        "text/javascript; charset=utf-8",
        include_str!("../../templates/main.js"),
    )
}

pub fn login_html() -> HttpResult {
    get_response(
        "text/html; charset=utf-8",
        include_str!("../../templates/login.html"),
    )
}

pub fn change_password() -> HttpResult {
    get_response(
        "text/html; charset=utf-8",
        include_str!("../../templates/change_password.html"),
    )
}
