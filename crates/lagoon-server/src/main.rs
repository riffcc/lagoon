use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("lagoon — Lagun's Lagoon");
    info!("where you call home.");

    // Bind addresses: configurable via LAGOON_IRC_BIND, or localhost only.
    // Direct IRC client access over the internet is disabled — use the web gateway.
    let bind_addr =
        std::env::var("LAGOON_IRC_BIND").unwrap_or_else(|_| "127.0.0.1:6667".to_string());
    let bind_static: &'static str = Box::leak(bind_addr.into_boxed_str());
    let mut addrs: Vec<&str> = vec![bind_static];

    // Check for Yggdrasil interface.
    if let Some(ygg_addr) = lagoon_server::irc::transport::detect_yggdrasil_addr() {
        info!("detected Yggdrasil address: {ygg_addr}");
        // Leak the string so we get a &'static str — this runs once at startup.
        let addr: &'static str = Box::leak(format!("[{ygg_addr}]:6667").into_boxed_str());
        addrs.push(addr);
    }

    lagoon_server::irc::server::run(&addrs).await
}
