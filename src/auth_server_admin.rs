use anyhow::Error;

use auth_server_lib::auth_server_admin::run_cli;

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    run_cli().await?;
    Ok(())
}
