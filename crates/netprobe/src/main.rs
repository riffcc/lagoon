use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

fn is_yggdrasil(addr: &Ipv6Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 0x02 || (octets[0] == 0x03 && octets[1] & 0xf0 == 0x00)
}

fn routability(addr: &IpAddr) -> &'static str {
    match addr {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                "LOOPBACK"
            } else if v4.octets()[0] == 10 {
                "PRIVATE (10.x — RFC1918)"
            } else if v4.octets()[0] == 172 && (v4.octets()[1] & 0xf0) == 16 {
                "PRIVATE (172.16-31.x — RFC1918)"
            } else if v4.octets()[0] == 192 && v4.octets()[1] == 168 {
                "PRIVATE (192.168.x — RFC1918)"
            } else if v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64 {
                "CGNAT (100.64-127.x — RFC6598)"
            } else if v4.octets()[0] == 169 && v4.octets()[1] == 254 {
                "LINK-LOCAL (169.254.x — APIPA)"
            } else {
                "PUBLIC (globally routable)"
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                "LOOPBACK (::1)"
            } else if is_yggdrasil(v6) {
                "YGGDRASIL OVERLAY (200:/300: — crypto-routed)"
            } else {
                let segs = v6.segments();
                if segs[0] == 0xfe80 {
                    "LINK-LOCAL (fe80::)"
                } else if segs[0] & 0xfe00 == 0xfc00 {
                    "ULA (fc00::/fd00:: — RFC4193)"
                } else if segs[0] == 0xfdaa {
                    "FLY 6PN (fdaa:: — Fly.io private)"
                } else if segs[0] & 0xe000 == 0x2000 {
                    "PUBLIC (globally routable)"
                } else {
                    "UNKNOWN"
                }
            }
        }
    }
}

fn guess_routable(addr: &IpAddr) -> bool {
    matches!(
        routability(addr),
        "PUBLIC (globally routable)" | "YGGDRASIL OVERLAY (200:/300: — crypto-routed)"
    )
}

struct IfAddr {
    iface: String,
    addr: IpAddr,
    prefix_len: u8,
    scope: String,
}

fn read_ipv6_addrs() -> Vec<IfAddr> {
    let mut result = Vec::new();
    if let Ok(content) = fs::read_to_string("/proc/net/if_inet6") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let hex = parts[0];
                let prefix: u8 = parts[2].parse().unwrap_or(0);
                let scope_id: u8 = parts[3].parse().unwrap_or(0);
                let iface = parts[5];
                if let Ok(bytes) = hex::decode(hex) {
                    if bytes.len() == 16 {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&bytes);
                        let addr = IpAddr::V6(Ipv6Addr::from(octets));
                        let scope = match scope_id {
                            0x00 => "global",
                            0x20 => "link",
                            0x40 => "site",
                            0x80 => "compat",
                            _ => "unknown",
                        };
                        result.push(IfAddr {
                            iface: iface.to_string(),
                            addr,
                            prefix_len: prefix,
                            scope: scope.to_string(),
                        });
                    }
                }
            }
        }
    }
    result
}

fn read_ipv4_addrs() -> Vec<IfAddr> {
    let mut result = Vec::new();
    if let Ok(content) = fs::read_to_string("/proc/net/fib_trie") {
        // Quick parse: look for LOCAL lines with IPs
        let mut current_prefix = 0u8;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('/') {
                current_prefix = trimmed.trim_start_matches('/').parse().unwrap_or(0);
            }
            if trimmed.contains("/32 host LOCAL") {
                if let Some(ip_str) = trimmed.split_whitespace().next() {
                    if let Ok(addr) = ip_str.trim_start_matches("- ").parse::<Ipv4Addr>() {
                        result.push(IfAddr {
                            iface: "?".to_string(),
                            addr: IpAddr::V4(addr),
                            prefix_len: current_prefix,
                            scope: "n/a".to_string(),
                        });
                    }
                }
            }
        }
    }
    // Fallback: parse all interfaces from /sys/class/net
    if result.is_empty() {
        if let Ok(entries) = fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let iface = entry.file_name().to_string_lossy().to_string();
                // Read addresses from /proc/net/fib_trie isn't reliable, use getifaddrs approach
                // Just report we couldn't find v4 this way
                let _ = iface;
            }
        }
    }
    result
}

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}

fn get_all_addrs() -> Vec<IfAddr> {
    // Use nix/libc getifaddrs for reliable cross-platform results
    let mut addrs = Vec::new();

    // Parse /proc/net/if_inet6 for IPv6
    addrs.extend(read_ipv6_addrs());

    // For IPv4, parse interface addresses from /sys + /proc
    // Most reliable: just read from the system
    if let Ok(output) = std::process::Command::new("ip")
        .args(["-j", "addr", "show"])
        .output()
    {
        if let Ok(text) = String::from_utf8(output.stdout) {
            // Quick JSON parse — look for addr_info entries
            // Format: [{"ifname":"eth0","addr_info":[{"local":"10.x.x.x","prefixlen":24}]}]
            for iface_block in text.split("\"ifname\"") {
                let iface_name = iface_block
                    .split('"')
                    .nth(1)
                    .unwrap_or("?")
                    .to_string();
                for addr_block in iface_block.split("\"local\"") {
                    if let Some(ip_str) = addr_block.split('"').nth(1) {
                        if let Ok(addr) = ip_str.parse::<IpAddr>() {
                            if addr.is_ipv4() {
                                let prefix = addr_block
                                    .split("\"prefixlen\"")
                                    .nth(1)
                                    .and_then(|s| {
                                        s.trim()
                                            .trim_start_matches(':')
                                            .trim()
                                            .split(|c: char| !c.is_ascii_digit())
                                            .next()
                                            .and_then(|n| n.parse::<u8>().ok())
                                    })
                                    .unwrap_or(0);
                                // Don't duplicate IPv6 addrs we already have
                                if !addrs.iter().any(|a| a.addr == addr) {
                                    addrs.push(IfAddr {
                                        iface: iface_name.clone(),
                                        addr,
                                        prefix_len: prefix,
                                        scope: "n/a".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    addrs
}

fn report() -> String {
    let mut out = String::new();
    out.push_str("╔══════════════════════════════════════════════════════════════════╗\n");
    out.push_str("║                    NETPROBE — Network Diagnostic               ║\n");
    out.push_str("╚══════════════════════════════════════════════════════════════════╝\n\n");

    // Hostname
    if let Ok(hostname) = fs::read_to_string("/etc/hostname") {
        out.push_str(&format!("Hostname: {}\n", hostname.trim()));
    }

    // Environment hints
    for var in &[
        "FLY_REGION",
        "FLY_ALLOC_ID",
        "FLY_PRIVATE_IP",
        "BUNNY_REGION",
        "HOSTNAME",
        "SERVER_NAME",
    ] {
        if let Ok(val) = std::env::var(var) {
            out.push_str(&format!("  {var} = {val}\n"));
        }
    }
    out.push('\n');

    let addrs = get_all_addrs();

    out.push_str(&format!(
        "Found {} addresses:\n\n",
        addrs.len()
    ));

    out.push_str(&format!(
        "{:<12} {:<45} {:<6} {:<8} {:<8} {}\n",
        "INTERFACE", "ADDRESS", "PREFIX", "SCOPE", "ROUTE?", "CLASSIFICATION"
    ));
    out.push_str(&format!("{}\n", "─".repeat(110)));

    for a in &addrs {
        let routable = if guess_routable(&a.addr) {
            "YES"
        } else {
            "no"
        };
        out.push_str(&format!(
            "{:<12} {:<45} /{:<5} {:<8} {:<8} {}\n",
            a.iface,
            a.addr.to_string(),
            a.prefix_len,
            a.scope,
            routable,
            routability(&a.addr)
        ));
    }

    out.push_str(&format!("\n{}\n", "─".repeat(110)));

    // Best guess
    let best = addrs
        .iter()
        .filter(|a| guess_routable(&a.addr))
        .collect::<Vec<_>>();
    if best.is_empty() {
        out.push_str("\nBEST GUESS: No globally routable addresses found.\n");
        out.push_str("  Ygg peering via private IPs will FAIL across regions.\n");
        out.push_str("  Need LAGOON_SWITCHBOARD_ADDR or public IP for cross-region peering.\n");
    } else {
        out.push_str("\nBEST GUESS for Ygg peering:\n");
        for b in &best {
            out.push_str(&format!(
                "  {} on {} — {}\n",
                b.addr,
                b.iface,
                routability(&b.addr)
            ));
        }
    }

    out
}

#[tokio::main]
async fn main() {
    let report_text = report();
    println!("{report_text}");

    let listener = TcpListener::bind("0.0.0.0:58888")
        .await
        .expect("Failed to bind 0.0.0.0:58888");
    println!("Listening on 0.0.0.0:58888 — connect to see this report\n");

    loop {
        if let Ok((mut stream, peer)) = listener.accept().await {
            println!("Connection from {peer}");
            let text = report();
            let _ = stream.write_all(text.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    }
}
