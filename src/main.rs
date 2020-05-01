use auth_server_rust::app::start_app;

#[tokio::main]
async fn main() {
    start_app().await.unwrap();
}
