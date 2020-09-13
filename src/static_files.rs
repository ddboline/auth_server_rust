use actix_web::HttpResponse;

pub fn index_html() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../templates/index.html"))
}

pub fn main_css() -> HttpResponse {
    HttpResponse::Ok()
        .header(CONTENT_TYPE, "text/css; charset=utf-8")
        .body(include_str!("../templates/main.css"))
        .map_err(Into::into)
}

pub fn register_html() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../templates/register.html"))
        .map_err(Into::into)
}

pub fn main_js() -> HttpResponse {
    HttpResponse::Ok()
        .header(CONTENT_TYPE, "text/javascript; charset=utf-8")
        .body(include_str!("../templates/main.js"))
        .map_err(Into::into)
}

pub fn login_html() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../templates/login.html"))
        .map_err(Into::into)
}

pub fn change_password() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../templates/change_password.html"))
        .map_err(Into::into)
}
