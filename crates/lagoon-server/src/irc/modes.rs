/// IRC channel modes — data structures and pure functions for mode parsing,
/// hostmask matching, and WHOWAS history.

/// Per-channel mode flags.
#[derive(Debug, Clone)]
pub struct ChannelModes {
    /// +i — invite only
    pub invite_only: bool,
    /// +m — moderated (only Voice+ can speak)
    pub moderated: bool,
    /// +n — no external messages (must be in channel to send)
    pub no_external: bool,
    /// +t — only ops can set topic
    pub topic_locked: bool,
    /// +k — channel key (password)
    pub key: Option<String>,
    /// +l — user limit
    pub limit: Option<usize>,
    /// +s — secret (hidden from LIST and WHOIS)
    pub secret: bool,
}

impl Default for ChannelModes {
    fn default() -> Self {
        Self {
            invite_only: false,
            moderated: false,
            no_external: true, // +n on by default per IRC convention
            topic_locked: false,
            key: None,
            limit: None,
            secret: false,
        }
    }
}

impl ChannelModes {
    /// Render current modes as an IRC mode string, e.g. "+ntk secret".
    pub fn to_mode_string(&self) -> String {
        let mut flags = String::from("+");
        let mut params = Vec::new();

        if self.invite_only {
            flags.push('i');
        }
        if self.moderated {
            flags.push('m');
        }
        if self.no_external {
            flags.push('n');
        }
        if self.secret {
            flags.push('s');
        }
        if self.topic_locked {
            flags.push('t');
        }
        if let Some(ref key) = self.key {
            flags.push('k');
            params.push(key.clone());
        }
        if let Some(limit) = self.limit {
            flags.push('l');
            params.push(limit.to_string());
        }

        if flags == "+" {
            return "+".into();
        }

        if params.is_empty() {
            flags
        } else {
            format!("{flags} {}", params.join(" "))
        }
    }
}

/// A single ban list entry.
#[derive(Debug, Clone)]
pub struct BanEntry {
    /// Wildcard hostmask pattern (e.g. `*!*@bad.host`).
    pub mask: String,
    /// Nick of the user who set the ban.
    pub set_by: String,
    /// Unix timestamp when the ban was set.
    pub set_at: u64,
}

/// A record of a disconnected user for WHOWAS.
#[derive(Debug, Clone)]
pub struct WhowasEntry {
    pub nick: String,
    pub user: String,
    pub host: String,
    pub realname: String,
    pub disconnect_time: u64,
}

/// Ring buffer of WHOWAS entries (fixed capacity).
#[derive(Debug)]
pub struct WhowasBuffer {
    entries: Vec<WhowasEntry>,
    capacity: usize,
}

impl WhowasBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            capacity,
        }
    }

    /// Push an entry. If at capacity, the oldest entry is evicted.
    pub fn push(&mut self, entry: WhowasEntry) {
        if self.entries.len() >= self.capacity {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    /// Look up entries by nick (case-insensitive), most recent first.
    pub fn lookup(&self, nick: &str) -> Vec<&WhowasEntry> {
        let lower = nick.to_ascii_lowercase();
        self.entries
            .iter()
            .rev()
            .filter(|e| e.nick.to_ascii_lowercase() == lower)
            .collect()
    }
}

/// A parsed mode change: `+n`, `-m`, `+k secret`, etc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeChange {
    /// true = setting (+), false = unsetting (-)
    pub setting: bool,
    /// The mode character
    pub mode: char,
    /// Optional parameter (key, limit, nick for membership modes, ban mask)
    pub param: Option<String>,
}

/// Parse an IRC mode string with its parameters into individual mode changes.
///
/// CHANMODES classification:
/// - Type A (list, always takes param): `b`
/// - Type B (always takes param): `k`
/// - Type C (param on set, no param on unset): `l`
/// - Type D (never takes param): `i, m, n, s, t`
/// - Membership (always takes param): `q, a, o, v`
pub fn parse_mode_string(mode_str: &str, params: &[String]) -> Vec<ModeChange> {
    let mut changes = Vec::new();
    let mut setting = true;
    let mut param_idx = 0;

    for ch in mode_str.chars() {
        match ch {
            '+' => setting = true,
            '-' => setting = false,
            // Type A: list mode, always takes a param
            'b' => {
                let param = if param_idx < params.len() {
                    let p = params[param_idx].clone();
                    param_idx += 1;
                    Some(p)
                } else if setting {
                    // +b with no param = list bans (no change to push)
                    None
                } else {
                    None
                };
                changes.push(ModeChange {
                    setting,
                    mode: 'b',
                    param,
                });
            }
            // Type B: always takes a param
            'k' => {
                let param = if param_idx < params.len() {
                    let p = params[param_idx].clone();
                    param_idx += 1;
                    Some(p)
                } else {
                    None
                };
                changes.push(ModeChange {
                    setting,
                    mode: 'k',
                    param,
                });
            }
            // Type C: param on set, no param on unset
            'l' => {
                let param = if setting && param_idx < params.len() {
                    let p = params[param_idx].clone();
                    param_idx += 1;
                    Some(p)
                } else {
                    None
                };
                changes.push(ModeChange {
                    setting,
                    mode: 'l',
                    param,
                });
            }
            // Type D: no param
            'i' | 'm' | 'n' | 's' | 't' => {
                changes.push(ModeChange {
                    setting,
                    mode: ch,
                    param: None,
                });
            }
            // Membership modes: always take a param (nick)
            'q' | 'a' | 'o' | 'v' => {
                let param = if param_idx < params.len() {
                    let p = params[param_idx].clone();
                    param_idx += 1;
                    Some(p)
                } else {
                    None
                };
                changes.push(ModeChange {
                    setting,
                    mode: ch,
                    param,
                });
            }
            // Unknown — still emit it so the caller can send 472
            _ => {
                changes.push(ModeChange {
                    setting,
                    mode: ch,
                    param: None,
                });
            }
        }
    }

    changes
}

/// Match a wildcard hostmask pattern against a full hostmask.
///
/// Supports `*` (zero or more characters) and `?` (exactly one character).
/// Case-insensitive comparison (IRC convention).
pub fn match_hostmask(mask: &str, full_hostmask: &str) -> bool {
    let mask = mask.to_ascii_lowercase();
    let full = full_hostmask.to_ascii_lowercase();
    wildcard_match(mask.as_bytes(), full.as_bytes())
}

/// Recursive wildcard matcher for `*` and `?`.
fn wildcard_match(pattern: &[u8], text: &[u8]) -> bool {
    // Iterative implementation to avoid stack overflow on long patterns.
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi = usize::MAX;
    let mut star_ti = 0;

    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    // Consume trailing *'s in pattern.
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }

    pi == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ChannelModes ────────────────────────────────────────────────

    #[test]
    fn default_modes_have_no_external() {
        let modes = ChannelModes::default();
        assert!(modes.no_external);
        assert!(!modes.invite_only);
        assert!(!modes.moderated);
        assert!(!modes.topic_locked);
        assert!(!modes.secret);
        assert!(modes.key.is_none());
        assert!(modes.limit.is_none());
    }

    #[test]
    fn mode_string_default() {
        let modes = ChannelModes::default();
        assert_eq!(modes.to_mode_string(), "+n");
    }

    #[test]
    fn mode_string_multiple_flags() {
        let modes = ChannelModes {
            invite_only: true,
            moderated: true,
            no_external: true,
            topic_locked: true,
            secret: false,
            key: None,
            limit: None,
        };
        assert_eq!(modes.to_mode_string(), "+imnt");
    }

    #[test]
    fn mode_string_with_key_and_limit() {
        let modes = ChannelModes {
            invite_only: false,
            moderated: false,
            no_external: true,
            topic_locked: true,
            secret: true,
            key: Some("secret".into()),
            limit: Some(42),
        };
        assert_eq!(modes.to_mode_string(), "+nstkl secret 42");
    }

    #[test]
    fn mode_string_with_limit_only() {
        let modes = ChannelModes {
            no_external: true,
            limit: Some(10),
            ..ChannelModes::default()
        };
        assert_eq!(modes.to_mode_string(), "+nl 10");
    }

    #[test]
    fn mode_string_empty() {
        let modes = ChannelModes {
            invite_only: false,
            moderated: false,
            no_external: false,
            topic_locked: false,
            secret: false,
            key: None,
            limit: None,
        };
        assert_eq!(modes.to_mode_string(), "+");
    }

    // ── parse_mode_string ───────────────────────────────────────────

    #[test]
    fn parse_simple_flags() {
        let changes = parse_mode_string("+nt", &[]);
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0], ModeChange { setting: true, mode: 'n', param: None });
        assert_eq!(changes[1], ModeChange { setting: true, mode: 't', param: None });
    }

    #[test]
    fn parse_mixed_set_unset() {
        let changes = parse_mode_string("+nt-m", &[]);
        assert_eq!(changes.len(), 3);
        assert!(changes[0].setting);
        assert!(changes[1].setting);
        assert!(!changes[2].setting);
        assert_eq!(changes[2].mode, 'm');
    }

    #[test]
    fn parse_key_mode() {
        let changes = parse_mode_string("+k", &["secret".into()]);
        assert_eq!(changes.len(), 1);
        assert_eq!(
            changes[0],
            ModeChange { setting: true, mode: 'k', param: Some("secret".into()) }
        );
    }

    #[test]
    fn parse_unset_key() {
        let changes = parse_mode_string("-k", &["oldkey".into()]);
        assert_eq!(changes.len(), 1);
        assert_eq!(
            changes[0],
            ModeChange { setting: false, mode: 'k', param: Some("oldkey".into()) }
        );
    }

    #[test]
    fn parse_limit_set() {
        let changes = parse_mode_string("+l", &["50".into()]);
        assert_eq!(changes.len(), 1);
        assert_eq!(
            changes[0],
            ModeChange { setting: true, mode: 'l', param: Some("50".into()) }
        );
    }

    #[test]
    fn parse_limit_unset_no_param() {
        let changes = parse_mode_string("-l", &[]);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0], ModeChange { setting: false, mode: 'l', param: None });
    }

    #[test]
    fn parse_membership_modes() {
        let changes = parse_mode_string("+o-v", &["alice".into(), "bob".into()]);
        assert_eq!(changes.len(), 2);
        assert_eq!(
            changes[0],
            ModeChange { setting: true, mode: 'o', param: Some("alice".into()) }
        );
        assert_eq!(
            changes[1],
            ModeChange { setting: false, mode: 'v', param: Some("bob".into()) }
        );
    }

    #[test]
    fn parse_ban_mode_with_mask() {
        let changes = parse_mode_string("+b", &["*!*@bad.host".into()]);
        assert_eq!(changes.len(), 1);
        assert_eq!(
            changes[0],
            ModeChange { setting: true, mode: 'b', param: Some("*!*@bad.host".into()) }
        );
    }

    #[test]
    fn parse_ban_list_query() {
        let changes = parse_mode_string("+b", &[]);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0], ModeChange { setting: true, mode: 'b', param: None });
    }

    #[test]
    fn parse_complex_mode_string() {
        let changes = parse_mode_string("+ntk-m+l", &["secret".into(), "25".into()]);
        assert_eq!(changes.len(), 5);
        assert_eq!(changes[0], ModeChange { setting: true, mode: 'n', param: None });
        assert_eq!(changes[1], ModeChange { setting: true, mode: 't', param: None });
        assert_eq!(
            changes[2],
            ModeChange { setting: true, mode: 'k', param: Some("secret".into()) }
        );
        assert_eq!(changes[3], ModeChange { setting: false, mode: 'm', param: None });
        assert_eq!(
            changes[4],
            ModeChange { setting: true, mode: 'l', param: Some("25".into()) }
        );
    }

    #[test]
    fn parse_unknown_mode() {
        let changes = parse_mode_string("+x", &[]);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0], ModeChange { setting: true, mode: 'x', param: None });
    }

    // ── match_hostmask ──────────────────────────────────────────────

    #[test]
    fn exact_match() {
        assert!(match_hostmask("nick!user@host", "nick!user@host"));
    }

    #[test]
    fn case_insensitive() {
        assert!(match_hostmask("NICK!USER@HOST", "nick!user@host"));
        assert!(match_hostmask("nick!user@host", "NICK!USER@HOST"));
    }

    #[test]
    fn star_wildcard() {
        assert!(match_hostmask("*!*@bad.host", "anyone!anything@bad.host"));
        assert!(!match_hostmask("*!*@bad.host", "anyone!anything@good.host"));
    }

    #[test]
    fn question_wildcard() {
        assert!(match_hostmask("n?ck!user@host", "nick!user@host"));
        assert!(!match_hostmask("n?ck!user@host", "niiick!user@host"));
    }

    #[test]
    fn star_in_host() {
        assert!(match_hostmask("*!*@*.bad.net", "user!ident@sub.bad.net"));
        assert!(!match_hostmask("*!*@*.bad.net", "user!ident@bad.net"));
    }

    #[test]
    fn all_wildcard() {
        assert!(match_hostmask("*", "anything!goes@here"));
        assert!(match_hostmask("*!*@*", "anything!goes@here"));
    }

    #[test]
    fn no_match() {
        assert!(!match_hostmask("specific!user@host", "other!user@host"));
    }

    #[test]
    fn empty_pattern() {
        assert!(!match_hostmask("", "nick!user@host"));
        assert!(match_hostmask("", ""));
    }

    // ── WhowasBuffer ────────────────────────────────────────────────

    #[test]
    fn whowas_push_and_lookup() {
        let mut buf = WhowasBuffer::new(3);
        buf.push(WhowasEntry {
            nick: "Alice".into(),
            user: "alice".into(),
            host: "host.com".into(),
            realname: "Alice A".into(),
            disconnect_time: 100,
        });
        buf.push(WhowasEntry {
            nick: "Bob".into(),
            user: "bob".into(),
            host: "host.com".into(),
            realname: "Bob B".into(),
            disconnect_time: 200,
        });

        let results = buf.lookup("alice");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].nick, "Alice");

        let results = buf.lookup("ALICE");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn whowas_eviction() {
        let mut buf = WhowasBuffer::new(2);
        buf.push(WhowasEntry {
            nick: "A".into(),
            user: "a".into(),
            host: "h".into(),
            realname: "".into(),
            disconnect_time: 1,
        });
        buf.push(WhowasEntry {
            nick: "B".into(),
            user: "b".into(),
            host: "h".into(),
            realname: "".into(),
            disconnect_time: 2,
        });
        buf.push(WhowasEntry {
            nick: "C".into(),
            user: "c".into(),
            host: "h".into(),
            realname: "".into(),
            disconnect_time: 3,
        });

        // "A" should have been evicted.
        assert!(buf.lookup("A").is_empty());
        assert_eq!(buf.lookup("B").len(), 1);
        assert_eq!(buf.lookup("C").len(), 1);
    }

    #[test]
    fn whowas_most_recent_first() {
        let mut buf = WhowasBuffer::new(10);
        buf.push(WhowasEntry {
            nick: "Same".into(),
            user: "old".into(),
            host: "h".into(),
            realname: "".into(),
            disconnect_time: 1,
        });
        buf.push(WhowasEntry {
            nick: "Same".into(),
            user: "new".into(),
            host: "h".into(),
            realname: "".into(),
            disconnect_time: 2,
        });

        let results = buf.lookup("Same");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].user, "new"); // most recent first
        assert_eq!(results[1].user, "old");
    }
}
