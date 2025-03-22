use auth_server_http::app::start_app;
use auth_server_http::errors::ServiceError as Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    tokio::spawn(async move { start_app().await }).await?
}
