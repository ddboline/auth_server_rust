use auth_server_rust::app::start_app;

#[actix_web::main]
async fn main() {
    env_logger::init();
    start_app().await.unwrap();
}
