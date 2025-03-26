use rex::cli;

#[tokio::main]
async fn main() {
    match cli::start().await {
        Ok(_) => {}
        Err(err) => {
            tracing::error!("{err:?}");
            std::process::exit(1);
        }
    }
}
