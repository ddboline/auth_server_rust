use anyhow::Error;

use auth_server_http::app::start_app;

#[tokio::main]
#[cfg(not(tarpaulin_include))]
async fn main() -> Result<(), Error> {
    env_logger::init();
    tokio::spawn(async move { start_app().await })
        .await
        .unwrap()
}
