use auth_server_http::app::start_app;

#[cfg(feature = "dhap-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[tokio::main]
#[cfg(not(tarpaulin_include))]
async fn main() {

    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    env_logger::init();
    start_app().await.unwrap();
}
