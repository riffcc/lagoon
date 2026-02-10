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

    // Bind addresses: TCP for local, Yggdrasil IPv6 when available.
    // Yggdrasil addresses (200::/7) are added automatically if detected.
    let mut addrs: Vec<&str> = vec!["0.0.0.0:6667"];

    // Check for Yggdrasil interface.
    if let Some(ygg_addr) = detect_yggdrasil_addr() {
        info!("detected Yggdrasil address: {ygg_addr}");
        // Leak the string so we get a &'static str — this runs once at startup.
        let addr: &'static str = Box::leak(format!("[{ygg_addr}]:6667").into_boxed_str());
        addrs.push(addr);
    }

    lagoon::irc::server::run(&addrs).await
}

/// Detect the local Yggdrasil IPv6 address (200::/7 range).
///
/// Reads `/proc/net/if_inet6` directly — no dependency on `ip` or `iproute2`.
/// Falls back to the `ip` command if `/proc` isn't available.
fn detect_yggdrasil_addr() -> Option<String> {
    // Try /proc/net/if_inet6 first (works in containers without iproute2).
    // Format: hex_addr iface_idx prefix_len scope flags iface_name
    // Yggdrasil addresses start with 02 (200::/7).
    if let Ok(content) = std::fs::read_to_string("/proc/net/if_inet6") {
        for line in content.lines() {
            let hex = line.split_whitespace().next().unwrap_or("");
            if hex.len() == 32 && hex.starts_with("02") {
                // Convert 32-char hex to colon-separated IPv6.
                let groups: Vec<&str> = (0..8)
                    .map(|i| &hex[i * 4..(i + 1) * 4])
                    .collect();
                let addr = groups.join(":");
                return Some(addr);
            }
        }
    }

    // Fallback: try `ip` command.
    use std::process::Command;
    let output = Command::new("ip")
        .args(["-6", "addr", "show", "scope", "global"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("inet6 ") {
            let addr = line
                .strip_prefix("inet6 ")?
                .split('/')
                .next()?
                .to_string();
            if addr.starts_with("200:") || addr.starts_with("201:")
                || addr.starts_with("300:") || addr.starts_with("301:")
            {
                return Some(addr);
            }
        }
    }
    None
}
