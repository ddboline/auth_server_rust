use anyhow::Error;
use actix_identity::{CookieIdentityPolicy, IdentityService};
use actix_web::{middleware::Logger, web, App, HttpServer};

use crate::pgpool::PgPool;
use crate::config::Config;
use crate::static_files::{
    change_password, index_html, login_html, main_css, main_js, register_html,
};

pub async fn start_app() -> Result<(), Error> {


    let index = warp::path!("auth" / "index.html").map(index_html);
    let main_css = warp::path!("auth" / "main.css").map(main_css);
    let main_js = warp::path!("auth" / "main.js").map(main_js);
    let register_html = warp::path!("auth" / "register.html").map(register_html);
    let login_html = warp::path!("auth" / "login.html").map(login_html);
    let change_password = warp::path!("auth" / "change_password").map(change_password);

    let routes = index
        .or(main_css)
        .or(main_js)
        .or(register_html)
        .or(login_html)
        .or(change_password);

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
    Ok(())
}
