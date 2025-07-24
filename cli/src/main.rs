use rex::cli;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::ERROR)
        .init();

    if let Err(err) = cli::start().await {
        println!("\x1b[31;1mError:\x1b[0m execution failed: {err:?}");
        std::process::exit(1);
    }
}
