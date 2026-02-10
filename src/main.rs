use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("lagoon — Lagun's Lagoon");
    info!("where you call home.");

    lagoon::irc::server::run("0.0.0.0:6667").await
}
