use auth_server_ext::errors::AuthServerExtError as Error;
use auth_server_http::app::start_app;

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    tokio::spawn(async move { start_app().await }).await?
}
