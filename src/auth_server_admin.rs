use anyhow::Error;

use auth_server_admin::run_cli;

#[tokio::main]
#[cfg(not(tarpaulin_include))]
async fn main() -> Result<(), Error> {
    env_logger::init();
    run_cli().await?;
    Ok(())
}
