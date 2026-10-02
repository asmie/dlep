#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dlep_router::run_from(std::env::args_os()).await
}
