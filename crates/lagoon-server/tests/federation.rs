/// Integration tests for channel federation across the 4-node Docker mesh.
///
/// These tests connect real IRC clients to the running Docker containers
/// and verify that `#room:server` federation works correctly:
///
/// - Local rooms (`#channel`) show ONLY local users + local LagoonBot
/// - Federated rooms (`#channel:server`) show the remote server's users
/// - Visitors from other servers appear with `nick@server` suffix
/// - Remote LagoonBots do NOT leak into rooms they didn't join
///
/// Run with: `cargo test --test federation` (requires `docker compose up`)
use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Server ports (mapped from Docker containers to localhost).
const LAGOON_PORT: u16 = 6667;
const LON_PORT: u16 = 16667;
const PER_PORT: u16 = 26667;
const NYC_PORT: u16 = 36667;

/// Simple blocking IRC client for testing.
struct TestClient {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    nick: String,
    lines: Vec<String>,
}

impl TestClient {
    fn connect(port: u16, nick: &str) -> io::Result<Self> {
        let stream = TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_secs(5),
        )?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        let writer = stream.try_clone()?;
        let reader = BufReader::new(stream);

        let mut client = Self {
            reader,
            writer,
            nick: nick.to_string(),
            lines: Vec::new(),
        };

        // Register.
        client.send(&format!("NICK {nick}"))?;
        client.send(&format!("USER {nick} 0 * :{nick}"))?;

        // Read until MOTD ends (376) or timeout.
        client.read_until("376")?;

        Ok(client)
    }

    fn send(&mut self, line: &str) -> io::Result<()> {
        writeln!(self.writer, "{line}\r")?;
        self.writer.flush()
    }

    /// Read lines until one contains the given substring, or timeout.
    fn read_until(&mut self, marker: &str) -> io::Result<()> {
        loop {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed")),
                Ok(_) => {
                    let trimmed = line.trim_end().to_string();
                    self.lines.push(trimmed.clone());
                    if trimmed.contains(marker) {
                        return Ok(());
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, format!("timeout waiting for '{marker}'")));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Drain all available lines (non-blocking read until timeout).
    fn drain(&mut self) {
        loop {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => self.lines.push(line.trim_end().to_string()),
                Err(_) => break,
            }
        }
    }

    /// Join a channel and read until NAMES end (366).
    fn join(&mut self, channel: &str) -> io::Result<()> {
        self.send(&format!("JOIN {channel}"))?;
        self.read_until("366")
    }

    /// Request NAMES for a channel, read until 366, return the names set.
    fn names(&mut self, channel: &str) -> io::Result<HashSet<String>> {
        // Clear buffer.
        self.lines.clear();
        self.drain();
        self.lines.clear();

        self.send(&format!("NAMES {channel}"))?;
        self.read_until("366")?;

        // Parse 353 lines to extract names.
        let mut names = HashSet::new();
        for line in &self.lines {
            // :server 353 nick = #channel :name1 name2 name3
            if line.contains(" 353 ") {
                if let Some(names_part) = line.rsplit_once(':') {
                    for name in names_part.1.split_whitespace() {
                        // Strip prefix symbols (~&@%+).
                        let clean = name.trim_start_matches(['~', '&', '@', '%', '+']);
                        names.insert(clean.to_string());
                    }
                }
            }
        }
        Ok(names)
    }

    fn part(&mut self, channel: &str) -> io::Result<()> {
        self.send(&format!("PART {channel}"))?;
        // Read the PART echo.
        self.drain();
        Ok(())
    }

    fn quit(mut self) -> io::Result<()> {
        self.send("QUIT :test done")?;
        Ok(())
    }
}

fn docker_available() -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{LAGOON_PORT}").parse().unwrap(),
        Duration::from_secs(1),
    )
    .is_ok()
}

/// Local `#channel` should only contain local users and local LagoonBot.
/// No remote users, no remote LagoonBots.
#[test]
fn local_room_has_only_local_users() {
    if !docker_available() {
        eprintln!("skipping: Docker containers not running");
        return;
    }

    let mut alice = TestClient::connect(LAGOON_PORT, "t_alice_local").unwrap();
    alice.join("#test-local").unwrap();

    let names = alice.names("#test-local").unwrap();

    // Should contain our nick and LagoonBot (if it auto-joins, otherwise just us).
    assert!(names.contains("t_alice_local"), "should contain our nick, got: {names:?}");

    // Should NOT contain any @server nicks.
    for name in &names {
        assert!(
            !name.contains('@'),
            "local room should not have remote users, found: {name}"
        );
    }

    alice.quit().unwrap();
}

/// When users from multiple servers visit `#room:lagoon.lagun.co`,
/// all visitors should appear in the NAMES list with `nick@server` suffix.
#[test]
fn federated_room_shows_all_visitors() {
    if !docker_available() {
        eprintln!("skipping: Docker containers not running");
        return;
    }

    // Connect a user to each server.
    let mut on_lagoon = TestClient::connect(LAGOON_PORT, "t_fed_lagoon").unwrap();
    let mut on_lon = TestClient::connect(LON_PORT, "t_fed_lon").unwrap();
    let mut on_per = TestClient::connect(PER_PORT, "t_fed_per").unwrap();
    let mut on_nyc = TestClient::connect(NYC_PORT, "t_fed_nyc").unwrap();

    // The user on lagoon joins their local #test-fed (this is lagoon's room).
    on_lagoon.join("#test-fed").unwrap();

    // Users on other servers visit lagoon's room via federation.
    on_lon.join("#test-fed:lagoon.lagun.co").unwrap();
    on_per.join("#test-fed:lagoon.lagun.co").unwrap();
    on_nyc.join("#test-fed:lagoon.lagun.co").unwrap();

    // Give federation relays a moment to connect and propagate NAMES.
    // (We re-request NAMES after a brief drain to pick up relay updates.)
    on_lon.drain();
    on_per.drain();
    on_nyc.drain();

    // Check NAMES from lagoon (the host server).
    let lagoon_names = on_lagoon.names("#test-fed").unwrap();

    // lagoon's local room should have the local user.
    assert!(
        lagoon_names.contains("t_fed_lagoon"),
        "lagoon's #test-fed should contain local user t_fed_lagoon, got: {lagoon_names:?}"
    );

    // Visitors from other servers should appear with @server suffix.
    assert!(
        lagoon_names.contains("t_fed_lon@lon.lagun.co"),
        "lagoon's #test-fed should contain visitor t_fed_lon@lon.lagun.co, got: {lagoon_names:?}"
    );
    assert!(
        lagoon_names.contains("t_fed_per@per.lagun.co"),
        "lagoon's #test-fed should contain visitor t_fed_per@per.lagun.co, got: {lagoon_names:?}"
    );
    assert!(
        lagoon_names.contains("t_fed_nyc@nyc.lagun.co"),
        "lagoon's #test-fed should contain visitor t_fed_nyc@nyc.lagun.co, got: {lagoon_names:?}"
    );

    // Cleanup.
    on_lagoon.part("#test-fed").ok();
    on_lon.part("#test-fed:lagoon.lagun.co").ok();
    on_per.part("#test-fed:lagoon.lagun.co").ok();
    on_nyc.part("#test-fed:lagoon.lagun.co").ok();

    on_lagoon.quit().ok();
    on_lon.quit().ok();
    on_per.quit().ok();
    on_nyc.quit().ok();
}

/// Remote LagoonBots must NOT leak into rooms on other servers.
/// Only the host server's LagoonBot should be present.
#[test]
fn no_remote_lagoonbot_leak() {
    if !docker_available() {
        eprintln!("skipping: Docker containers not running");
        return;
    }

    // Connect users and have them visit lagoon's room.
    let mut on_lagoon = TestClient::connect(LAGOON_PORT, "t_noleak_lagoon").unwrap();
    let mut on_lon = TestClient::connect(LON_PORT, "t_noleak_lon").unwrap();

    on_lagoon.join("#test-noleak").unwrap();
    on_lon.join("#test-noleak:lagoon.lagun.co").unwrap();

    on_lon.drain();

    let lagoon_names = on_lagoon.names("#test-noleak").unwrap();

    // lagoon's own LagoonBot may or may not be in #test-noleak (it only auto-joins #lagoon).
    // But LagoonBot from OTHER servers must NEVER appear.
    for name in &lagoon_names {
        if name.starts_with("LagoonBot@") {
            panic!(
                "remote LagoonBot leaked into lagoon's room: {name}. Full NAMES: {lagoon_names:?}"
            );
        }
    }

    on_lagoon.part("#test-noleak").ok();
    on_lon.part("#test-noleak:lagoon.lagun.co").ok();
    on_lagoon.quit().ok();
    on_lon.quit().ok();
}

/// The host server's NAMES for a local room should NOT change just because
/// a visitor from another server joined `#room:thisserver`. The local room
/// is the local room. Visitors appear in it (with @server suffix) but
/// no remote infrastructure leaks.
#[test]
fn visitor_does_not_pollute_local_room_with_infrastructure() {
    if !docker_available() {
        eprintln!("skipping: Docker containers not running");
        return;
    }

    let mut on_lagoon = TestClient::connect(LAGOON_PORT, "t_infra_lagoon").unwrap();
    let mut on_lon = TestClient::connect(LON_PORT, "t_infra_lon").unwrap();

    on_lagoon.join("#test-infra").unwrap();

    // Snapshot NAMES before visitor.
    let names_before = on_lagoon.names("#test-infra").unwrap();

    // Visitor arrives from lon.
    on_lon.join("#test-infra:lagoon.lagun.co").unwrap();
    on_lon.drain();

    let names_after = on_lagoon.names("#test-infra").unwrap();

    // The only new entry should be the visitor themselves.
    let new_entries: HashSet<_> = names_after.difference(&names_before).collect();

    for entry in &new_entries {
        assert!(
            !entry.contains("~relay") && !entry.starts_with("LagoonBot"),
            "infrastructure leaked into local room when visitor joined: {entry}. \
             Before: {names_before:?}, After: {names_after:?}"
        );
    }

    on_lagoon.part("#test-infra").ok();
    on_lon.part("#test-infra:lagoon.lagun.co").ok();
    on_lagoon.quit().ok();
    on_lon.quit().ok();
}

/// The #lagoon channel exists on every server with LagoonBot.
/// Auto-federation must NOT cause remote LagoonBots to appear in the
/// local #lagoon. This is the real-world scenario that exposes the bug.
#[test]
fn lagoon_channel_no_remote_lagoonbot() {
    if !docker_available() {
        eprintln!("skipping: Docker containers not running");
        return;
    }

    let mut on_lagoon = TestClient::connect(LAGOON_PORT, "t_lagoon_bot").unwrap();
    on_lagoon.join("#lagoon").unwrap();

    let names = on_lagoon.names("#lagoon").unwrap();

    // LagoonBot (local) should be present.
    assert!(
        names.contains("LagoonBot"),
        "local LagoonBot should be in #lagoon, got: {names:?}"
    );

    // NO remote LagoonBots should be present.
    let remote_bots: Vec<_> = names
        .iter()
        .filter(|n| n.starts_with("LagoonBot@"))
        .collect();
    assert!(
        remote_bots.is_empty(),
        "remote LagoonBots leaked into local #lagoon: {remote_bots:?}. Full NAMES: {names:?}"
    );

    // NO relay nicks should be visible.
    let relay_nicks: Vec<_> = names.iter().filter(|n| n.contains("~relay")).collect();
    assert!(
        relay_nicks.is_empty(),
        "relay nicks visible in local #lagoon: {relay_nicks:?}. Full NAMES: {names:?}"
    );

    on_lagoon.part("#lagoon").ok();
    on_lagoon.quit().ok();
}

/// When visiting #lagoon:lagoon.lagun.co from lon, the NAMES list should
/// show lagoon's actual users (with @lagoon.lagun.co suffix) plus any
/// other visitors. Remote LagoonBots from lon/per/nyc must NOT appear.
#[test]
fn visiting_lagoon_room_correct_names() {
    if !docker_available() {
        eprintln!("skipping: Docker containers not running");
        return;
    }

    // Put a user on lagoon's #lagoon.
    let mut on_lagoon = TestClient::connect(LAGOON_PORT, "t_visit_host").unwrap();
    on_lagoon.join("#lagoon").unwrap();

    // Visit from lon.
    let mut on_lon = TestClient::connect(LON_PORT, "t_visit_lon").unwrap();
    on_lon.join("#lagoon:lagoon.lagun.co").unwrap();

    // Read updated NAMES (relay may take a moment).
    on_lon.drain();
    let names = on_lon.names("#lagoon:lagoon.lagun.co").unwrap();

    // Should see lagoon's local users.
    assert!(
        names.contains("t_visit_host@lagoon.lagun.co")
            || names.contains("t_visit_host"),
        "should see lagoon's local user t_visit_host, got: {names:?}"
    );

    // Should see lagoon's LagoonBot.
    assert!(
        names.contains("LagoonBot@lagoon.lagun.co")
            || names.contains("LagoonBot"),
        "should see lagoon's LagoonBot, got: {names:?}"
    );

    // Must NOT see LagoonBot from lon, per, or nyc.
    for name in &names {
        if name.starts_with("LagoonBot@") && !name.ends_with("lagoon.lagun.co") {
            panic!(
                "remote LagoonBot from non-host server in federated view: {name}. Full: {names:?}"
            );
        }
    }

    on_lagoon.part("#lagoon").ok();
    on_lon.part("#lagoon:lagoon.lagun.co").ok();
    on_lagoon.quit().ok();
    on_lon.quit().ok();
}
