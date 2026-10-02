#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dlep_modem::run_from(std::env::args_os()).await
}
