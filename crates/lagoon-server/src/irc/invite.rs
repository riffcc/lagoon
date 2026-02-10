/// Invite code system — generate, validate, and manage invite codes
/// for community links and server peering.
use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// The kind of invite code.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InviteKind {
    /// Invite to join a channel on a (possibly remote) server.
    CommunityLink,
    /// Invite for server-to-server peering.
    ServerPeering,
}

/// Privilege level granted by an invite.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Privilege {
    Read,
    Write,
    Moderate,
    Admin,
}

impl std::fmt::Display for Privilege {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
            Self::Moderate => write!(f, "moderate"),
            Self::Admin => write!(f, "admin"),
        }
    }
}

impl std::str::FromStr for Privilege {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "moderate" => Ok(Self::Moderate),
            "admin" => Ok(Self::Admin),
            _ => Err(format!("unknown privilege: {s}")),
        }
    }
}

/// A single invite code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteCode {
    /// The invite code string (base58, 12 chars).
    pub code: String,
    /// What kind of invite this is.
    pub kind: InviteKind,
    /// LensID of the creator.
    pub created_by: String,
    /// Target: channel name (CommunityLink) or LensID/server name (ServerPeering).
    pub target: String,
    /// Privileges granted by this invite.
    pub privileges: Vec<Privilege>,
    /// Maximum number of uses (None = unlimited).
    pub max_uses: Option<u32>,
    /// Current use count.
    pub uses: u32,
    /// Expiration time (None = never).
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether the invite is active.
    pub active: bool,
    /// When the invite was created.
    pub created_at: DateTime<Utc>,
}

/// Base58 alphabet (Bitcoin-style, no 0OIl).
const BASE58_CHARS: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Generate a random base58 code of the given length.
fn generate_code(len: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..BASE58_CHARS.len());
            BASE58_CHARS[idx] as char
        })
        .collect()
}

/// In-memory invite store with JSON file persistence.
#[derive(Debug)]
pub struct InviteStore {
    invites: HashMap<String, InviteCode>,
    persist_path: Option<std::path::PathBuf>,
}

impl InviteStore {
    /// Create a new empty store (no persistence).
    pub fn new() -> Self {
        Self {
            invites: HashMap::new(),
            persist_path: None,
        }
    }

    /// Load from `{data_dir}/invites.json` or create empty.
    pub fn load_or_create(data_dir: &Path) -> Self {
        let path = data_dir.join("invites.json");
        let mut store = Self {
            invites: HashMap::new(),
            persist_path: Some(path.clone()),
        };

        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(json) => match serde_json::from_str::<Vec<InviteCode>>(&json) {
                    Ok(codes) => {
                        for code in codes {
                            store.invites.insert(code.code.clone(), code);
                        }
                        info!(count = store.invites.len(), "loaded invite codes");
                    }
                    Err(e) => warn!("failed to parse invites.json: {e}"),
                },
                Err(e) => warn!("failed to read invites.json: {e}"),
            }
        }

        store
    }

    /// Persist to disk (atomic write via tmp+rename).
    fn persist(&self) {
        let Some(path) = &self.persist_path else {
            return;
        };
        let codes: Vec<&InviteCode> = self.invites.values().collect();
        match serde_json::to_string_pretty(&codes) {
            Ok(json) => {
                let tmp = path.with_extension("json.tmp");
                if std::fs::write(&tmp, &json).is_ok() {
                    let _ = std::fs::rename(&tmp, path);
                }
            }
            Err(e) => warn!("failed to serialize invites: {e}"),
        }
    }

    /// Create a new invite code.
    pub fn create(
        &mut self,
        kind: InviteKind,
        created_by: String,
        target: String,
        privileges: Vec<Privilege>,
        max_uses: Option<u32>,
        expires_at: Option<DateTime<Utc>>,
    ) -> &InviteCode {
        let code = generate_code(12);
        let invite = InviteCode {
            code: code.clone(),
            kind,
            created_by,
            target,
            privileges,
            max_uses,
            uses: 0,
            expires_at,
            active: true,
            created_at: Utc::now(),
        };
        self.invites.insert(code.clone(), invite);
        self.persist();
        self.invites.get(&code).unwrap()
    }

    /// Validate an invite code — check active, not expired, not exhausted.
    pub fn validate(&self, code: &str) -> Result<&InviteCode, String> {
        let invite = self
            .invites
            .get(code)
            .ok_or_else(|| "unknown invite code".to_string())?;

        if !invite.active {
            return Err("invite code is no longer active".to_string());
        }

        if let Some(expires) = invite.expires_at {
            if Utc::now() > expires {
                return Err("invite code has expired".to_string());
            }
        }

        if let Some(max) = invite.max_uses {
            if invite.uses >= max {
                return Err("invite code has been used the maximum number of times".to_string());
            }
        }

        Ok(invite)
    }

    /// Use an invite code — validates, increments use count, auto-deactivates if maxed.
    pub fn use_code(&mut self, code: &str) -> Result<InviteCode, String> {
        // Validate first.
        self.validate(code)?;

        let invite = self.invites.get_mut(code).unwrap();
        invite.uses += 1;

        // Auto-deactivate if max uses reached.
        if let Some(max) = invite.max_uses {
            if invite.uses >= max {
                invite.active = false;
            }
        }

        let result = invite.clone();
        self.persist();
        Ok(result)
    }

    /// Revoke an invite code.
    pub fn revoke(&mut self, code: &str) -> Result<(), String> {
        let invite = self
            .invites
            .get_mut(code)
            .ok_or_else(|| "unknown invite code".to_string())?;
        invite.active = false;
        self.persist();
        Ok(())
    }

    /// Modify an invite code's mutable fields.
    pub fn modify(
        &mut self,
        code: &str,
        new_privileges: Option<Vec<Privilege>>,
        new_max_uses: Option<Option<u32>>,
        new_expires: Option<Option<DateTime<Utc>>>,
    ) -> Result<&InviteCode, String> {
        let invite = self
            .invites
            .get_mut(code)
            .ok_or_else(|| "unknown invite code".to_string())?;

        if let Some(privs) = new_privileges {
            invite.privileges = privs;
        }
        if let Some(max) = new_max_uses {
            invite.max_uses = max;
        }
        if let Some(exp) = new_expires {
            invite.expires_at = exp;
        }

        self.persist();
        Ok(self.invites.get(code).unwrap())
    }

    /// List invite codes, optionally filtered by target.
    pub fn list(&self, filter_target: Option<&str>) -> Vec<&InviteCode> {
        self.invites
            .values()
            .filter(|inv| {
                filter_target
                    .map(|t| inv.target == t)
                    .unwrap_or(true)
            })
            .collect()
    }

    /// Get info about a specific invite code.
    pub fn get(&self, code: &str) -> Option<&InviteCode> {
        self.invites.get(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_code_length() {
        let code = generate_code(12);
        assert_eq!(code.len(), 12);
    }

    #[test]
    fn generate_code_base58() {
        let code = generate_code(100);
        for ch in code.chars() {
            assert!(
                BASE58_CHARS.contains(&(ch as u8)),
                "char {ch} not in base58"
            );
        }
    }

    #[test]
    fn generate_code_unique() {
        let c1 = generate_code(12);
        let c2 = generate_code(12);
        assert_ne!(c1, c2);
    }

    #[test]
    fn invite_create_and_validate() {
        let mut store = InviteStore::new();
        let code = store
            .create(
                InviteKind::CommunityLink,
                "b3b3/abc".into(),
                "#lagoon".into(),
                vec![Privilege::Read, Privilege::Write],
                None,
                None,
            )
            .code
            .clone();
        assert_eq!(code.len(), 12);
        assert!(store.validate(&code).is_ok());
    }

    #[test]
    fn invite_use_increments() {
        let mut store = InviteStore::new();
        let code = store
            .create(
                InviteKind::CommunityLink,
                "b3b3/abc".into(),
                "#lagoon".into(),
                vec![Privilege::Read],
                Some(2),
                None,
            )
            .code
            .clone();

        let used = store.use_code(&code).unwrap();
        assert_eq!(used.uses, 1);
        assert!(used.active);

        let used = store.use_code(&code).unwrap();
        assert_eq!(used.uses, 2);
        assert!(!used.active); // Auto-deactivated.

        assert!(store.use_code(&code).is_err()); // Exhausted.
    }

    #[test]
    fn invite_revoke() {
        let mut store = InviteStore::new();
        let code = store
            .create(
                InviteKind::ServerPeering,
                "b3b3/abc".into(),
                "per.lagun.co".into(),
                vec![],
                None,
                None,
            )
            .code
            .clone();

        assert!(store.validate(&code).is_ok());
        store.revoke(&code).unwrap();
        assert!(store.validate(&code).is_err());
    }

    #[test]
    fn invite_modify() {
        let mut store = InviteStore::new();
        let code = store
            .create(
                InviteKind::CommunityLink,
                "b3b3/abc".into(),
                "#dev".into(),
                vec![Privilege::Read],
                None,
                None,
            )
            .code
            .clone();

        let modified = store
            .modify(
                &code,
                Some(vec![Privilege::Read, Privilege::Write, Privilege::Admin]),
                Some(Some(10)),
                None,
            )
            .unwrap();
        assert_eq!(modified.privileges.len(), 3);
        assert_eq!(modified.max_uses, Some(10));
    }

    #[test]
    fn invite_list_filter() {
        let mut store = InviteStore::new();
        store.create(
            InviteKind::CommunityLink,
            "b3b3/abc".into(),
            "#lagoon".into(),
            vec![],
            None,
            None,
        );
        store.create(
            InviteKind::CommunityLink,
            "b3b3/abc".into(),
            "#dev".into(),
            vec![],
            None,
            None,
        );
        store.create(
            InviteKind::CommunityLink,
            "b3b3/abc".into(),
            "#lagoon".into(),
            vec![],
            None,
            None,
        );

        assert_eq!(store.list(None).len(), 3);
        assert_eq!(store.list(Some("#lagoon")).len(), 2);
        assert_eq!(store.list(Some("#dev")).len(), 1);
    }

    #[test]
    fn invite_expiry() {
        let mut store = InviteStore::new();
        let code = store
            .create(
                InviteKind::CommunityLink,
                "b3b3/abc".into(),
                "#lagoon".into(),
                vec![],
                None,
                Some(Utc::now() - chrono::Duration::hours(1)), // Already expired.
            )
            .code
            .clone();

        assert!(store.validate(&code).is_err());
    }

    #[test]
    fn invite_persistence_roundtrip() {
        let tmp = std::env::temp_dir().join(format!(
            "lagoon-test-invite-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        let code = {
            let mut store = InviteStore::load_or_create(&tmp);
            store
                .create(
                    InviteKind::CommunityLink,
                    "b3b3/abc".into(),
                    "#lagoon".into(),
                    vec![Privilege::Read],
                    None,
                    None,
                )
                .code
                .clone()
        };

        // Reload and verify.
        let store = InviteStore::load_or_create(&tmp);
        assert!(store.validate(&code).is_ok());

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
