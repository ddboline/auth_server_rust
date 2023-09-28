use auth_server_admin::run_cli;

use auth_server_ext::errors::AuthServerExtError as Error;

#[tokio::main]
#[cfg(not(tarpaulin_include))]
async fn main() -> Result<(), Error> {
    env_logger::init();
    tokio::spawn(async move { run_cli().await }).await.unwrap()
}
