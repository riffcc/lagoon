use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    if std::env::var("LAGOON_EMBEDDED").is_ok() {
        info!("lagoon-web — embedded gateway mode (IRC server + web)");
        lagoon_web::run_with_irc().await
    } else {
        info!("lagoon-web — standalone web gateway");
        lagoon_web::run().await
    }
}
