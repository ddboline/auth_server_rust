use auth_server_http::app::start_app;

#[actix_web::main]
#[cfg(not(tarpaulin_include))]
async fn main() {
    env_logger::init();
    start_app().await.unwrap();
}
