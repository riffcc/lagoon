/// Circle/community system — server-managed groups of channels with membership and roles.
///
/// Each community (circle) lives on a single server and groups channels together.
/// Users join circles to see their channels. Circles are the organizational unit
/// that appears in the web UI sidebar.
use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

/// Role within a community.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CommunityRole {
    Owner,
    Moderator,
    Member,
}

impl std::fmt::Display for CommunityRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Owner => write!(f, "owner"),
            Self::Moderator => write!(f, "moderator"),
            Self::Member => write!(f, "member"),
        }
    }
}

impl std::str::FromStr for CommunityRole {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "owner" => Ok(Self::Owner),
            "moderator" | "mod" => Ok(Self::Moderator),
            "member" => Ok(Self::Member),
            _ => Err(format!("unknown community role: {s}")),
        }
    }
}

/// A single community (circle).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Community {
    /// Unique identifier.
    pub id: Uuid,
    /// Display name.
    pub name: String,
    /// Short description.
    pub description: String,
    /// Username of the creator/owner.
    pub owner: String,
    /// Members: username → role.
    pub members: HashMap<String, CommunityRole>,
    /// IRC channel names belonging to this community.
    pub channels: Vec<String>,
    /// When the community was created.
    pub created_at: DateTime<Utc>,
}

/// In-memory community store with JSON file persistence.
#[derive(Debug)]
pub struct CommunityStore {
    communities: HashMap<Uuid, Community>,
    persist_path: Option<std::path::PathBuf>,
}

impl CommunityStore {
    /// Create a new empty store (no persistence).
    pub fn new() -> Self {
        Self {
            communities: HashMap::new(),
            persist_path: None,
        }
    }

    /// Load from `{data_dir}/communities.json` or create with a default community.
    pub fn load_or_create(data_dir: &Path) -> Self {
        let path = data_dir.join("communities.json");
        let mut store = Self {
            communities: HashMap::new(),
            persist_path: Some(path.clone()),
        };

        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(json) => match serde_json::from_str::<Vec<Community>>(&json) {
                    Ok(list) => {
                        for c in list {
                            store.communities.insert(c.id, c);
                        }
                        info!(count = store.communities.len(), "loaded communities");
                    }
                    Err(e) => warn!("failed to parse communities.json: {e}"),
                },
                Err(e) => warn!("failed to read communities.json: {e}"),
            }
        }

        // Bootstrap: if no communities exist, create the default one.
        if store.communities.is_empty() {
            store.create_default();
        }

        store
    }

    /// Create the default community named after the server hostname.
    fn create_default(&mut self) {
        use super::server::SERVER_NAME;
        let id = Uuid::new_v4();
        let name = SERVER_NAME.clone();
        let community = Community {
            id,
            name: name.clone(),
            description: String::new(),
            owner: String::new(),
            members: HashMap::new(),
            channels: vec!["#lagoon".into()],
            created_at: Utc::now(),
        };
        info!(id = %id, name = %name, "created default community");
        self.communities.insert(id, community);
        self.persist();
    }

    /// Get the default community (first one with no owner, or just the first one).
    pub fn default_community(&self) -> Option<&Community> {
        self.communities
            .values()
            .find(|c| c.owner.is_empty())
            .or_else(|| self.communities.values().next())
    }

    /// Auto-join a user to the default community if they're not already in any.
    pub fn auto_join_default(&mut self, username: &str) {
        // Already in at least one community — skip.
        if self.communities.values().any(|c| c.members.contains_key(username)) {
            return;
        }
        let Some(id) = self.default_community().map(|c| c.id) else {
            return;
        };
        let community = self.communities.get_mut(&id).unwrap();
        let name = community.name.clone();
        community.members.insert(username.to_string(), CommunityRole::Member);
        self.persist();
        info!(username, community = %name, "auto-joined user to default community");
    }

    /// Persist to disk (atomic write via tmp+rename).
    fn persist(&self) {
        let Some(path) = &self.persist_path else {
            return;
        };
        let list: Vec<&Community> = self.communities.values().collect();
        match serde_json::to_string_pretty(&list) {
            Ok(json) => {
                let tmp = path.with_extension("json.tmp");
                if std::fs::write(&tmp, &json).is_ok() {
                    let _ = std::fs::rename(&tmp, path);
                }
            }
            Err(e) => warn!("failed to serialize communities: {e}"),
        }
    }

    /// Create a new community. Owner is added as Owner role.
    /// A default channel `#<name>` is created automatically.
    pub fn create(&mut self, name: String, description: String, owner: String) -> &Community {
        let id = Uuid::new_v4();
        let default_channel = format!("#{}", name.to_ascii_lowercase().replace(' ', "-"));

        let mut members = HashMap::new();
        members.insert(owner.clone(), CommunityRole::Owner);

        let community = Community {
            id,
            name,
            description,
            owner,
            members,
            channels: vec![default_channel],
            created_at: Utc::now(),
        };

        self.communities.insert(id, community);
        self.persist();
        self.communities.get(&id).unwrap()
    }

    /// Get a community by ID.
    pub fn get(&self, id: Uuid) -> Option<&Community> {
        self.communities.get(&id)
    }

    /// List all communities a user belongs to.
    pub fn list_for_user(&self, username: &str) -> Vec<&Community> {
        self.communities
            .values()
            .filter(|c| c.members.contains_key(username))
            .collect()
    }

    /// List all communities on this server.
    pub fn list_all(&self) -> Vec<&Community> {
        self.communities.values().collect()
    }

    /// Join a community as Member. Returns error if already a member.
    pub fn join(&mut self, id: Uuid, username: &str) -> Result<&Community, String> {
        let community = self
            .communities
            .get_mut(&id)
            .ok_or_else(|| "community not found".to_string())?;

        if community.members.contains_key(username) {
            return Err("already a member".to_string());
        }

        community.members.insert(username.to_string(), CommunityRole::Member);
        self.persist();
        Ok(self.communities.get(&id).unwrap())
    }

    /// Leave a community. Owner cannot leave (must delete or transfer).
    pub fn leave(&mut self, id: Uuid, username: &str) -> Result<(), String> {
        let community = self
            .communities
            .get_mut(&id)
            .ok_or_else(|| "community not found".to_string())?;

        if community.owner == username {
            return Err("owner cannot leave — delete the community or transfer ownership".to_string());
        }

        if community.members.remove(username).is_none() {
            return Err("not a member".to_string());
        }

        self.persist();
        Ok(())
    }

    /// Add a channel to a community.
    pub fn add_channel(&mut self, id: Uuid, channel: String) -> Result<&Community, String> {
        let community = self
            .communities
            .get_mut(&id)
            .ok_or_else(|| "community not found".to_string())?;

        if community.channels.contains(&channel) {
            return Err("channel already in community".to_string());
        }

        community.channels.push(channel);
        self.persist();
        Ok(self.communities.get(&id).unwrap())
    }

    /// Remove a channel from a community.
    pub fn remove_channel(&mut self, id: Uuid, channel: &str) -> Result<&Community, String> {
        let community = self
            .communities
            .get_mut(&id)
            .ok_or_else(|| "community not found".to_string())?;

        let before = community.channels.len();
        community.channels.retain(|ch| ch != channel);

        if community.channels.len() == before {
            return Err("channel not in community".to_string());
        }

        self.persist();
        Ok(self.communities.get(&id).unwrap())
    }

    /// Update community metadata (name and/or description).
    pub fn update(
        &mut self,
        id: Uuid,
        new_name: Option<String>,
        new_description: Option<String>,
    ) -> Result<&Community, String> {
        let community = self
            .communities
            .get_mut(&id)
            .ok_or_else(|| "community not found".to_string())?;

        if let Some(name) = new_name {
            community.name = name;
        }
        if let Some(desc) = new_description {
            community.description = desc;
        }

        self.persist();
        Ok(self.communities.get(&id).unwrap())
    }

    /// Set a member's role. Only works on existing members.
    pub fn set_role(
        &mut self,
        id: Uuid,
        username: &str,
        role: CommunityRole,
    ) -> Result<(), String> {
        let community = self
            .communities
            .get_mut(&id)
            .ok_or_else(|| "community not found".to_string())?;

        if !community.members.contains_key(username) {
            return Err("not a member".to_string());
        }

        community.members.insert(username.to_string(), role);
        self.persist();
        Ok(())
    }

    /// Delete a community. Only the owner can do this.
    pub fn delete(&mut self, id: Uuid, requesting_user: &str) -> Result<Community, String> {
        let community = self
            .communities
            .get(&id)
            .ok_or_else(|| "community not found".to_string())?;

        if community.owner != requesting_user {
            return Err("only the owner can delete a community".to_string());
        }

        let removed = self.communities.remove(&id).unwrap();
        self.persist();
        Ok(removed)
    }

    /// Check if a user has at least the given role in a community.
    pub fn has_role(&self, id: Uuid, username: &str, minimum: CommunityRole) -> bool {
        let Some(community) = self.communities.get(&id) else {
            return false;
        };
        let Some(role) = community.members.get(username) else {
            return false;
        };
        role_level(*role) >= role_level(minimum)
    }

    /// Check if a user is a member of a community.
    pub fn is_member(&self, id: Uuid, username: &str) -> bool {
        self.communities
            .get(&id)
            .is_some_and(|c| c.members.contains_key(username))
    }
}

/// Numeric role level for comparison (higher = more privilege).
fn role_level(role: CommunityRole) -> u8 {
    match role {
        CommunityRole::Member => 0,
        CommunityRole::Moderator => 1,
        CommunityRole::Owner => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_community() {
        let mut store = CommunityStore::new();
        let c = store.create("General".into(), "Main hangout".into(), "alice".into());
        assert_eq!(c.name, "General");
        assert_eq!(c.owner, "alice");
        assert_eq!(c.channels, vec!["#general"]);
        assert_eq!(c.members.len(), 1);
        assert_eq!(c.members["alice"], CommunityRole::Owner);
    }

    #[test]
    fn join_and_leave() {
        let mut store = CommunityStore::new();
        let id = store.create("Dev".into(), "Developers".into(), "alice".into()).id;

        store.join(id, "bob").unwrap();
        assert!(store.is_member(id, "bob"));
        assert_eq!(store.get(id).unwrap().members["bob"], CommunityRole::Member);

        store.leave(id, "bob").unwrap();
        assert!(!store.is_member(id, "bob"));
    }

    #[test]
    fn owner_cannot_leave() {
        let mut store = CommunityStore::new();
        let id = store.create("Test".into(), "".into(), "alice".into()).id;
        assert!(store.leave(id, "alice").is_err());
    }

    #[test]
    fn duplicate_join_rejected() {
        let mut store = CommunityStore::new();
        let id = store.create("Test".into(), "".into(), "alice".into()).id;
        store.join(id, "bob").unwrap();
        assert!(store.join(id, "bob").is_err());
    }

    #[test]
    fn list_for_user() {
        let mut store = CommunityStore::new();
        let id1 = store.create("Circle A".into(), "".into(), "alice".into()).id;
        let _id2 = store.create("Circle B".into(), "".into(), "bob".into()).id;
        store.create("Circle C".into(), "".into(), "alice".into());

        store.join(id1, "bob").unwrap();

        let alice_circles = store.list_for_user("alice");
        assert_eq!(alice_circles.len(), 2);

        let bob_circles = store.list_for_user("bob");
        assert_eq!(bob_circles.len(), 2); // Circle B (owner) + Circle A (joined)

        let charlie_circles = store.list_for_user("charlie");
        assert_eq!(charlie_circles.len(), 0);
    }

    #[test]
    fn add_and_remove_channel() {
        let mut store = CommunityStore::new();
        let id = store.create("Dev".into(), "".into(), "alice".into()).id;

        store.add_channel(id, "#dev-ops".into()).unwrap();
        let c = store.get(id).unwrap();
        assert_eq!(c.channels.len(), 2);
        assert!(c.channels.contains(&"#dev".to_string()));
        assert!(c.channels.contains(&"#dev-ops".to_string()));

        // Duplicate channel rejected.
        assert!(store.add_channel(id, "#dev-ops".into()).is_err());

        store.remove_channel(id, "#dev-ops").unwrap();
        let c = store.get(id).unwrap();
        assert_eq!(c.channels.len(), 1);

        // Non-existent channel removal rejected.
        assert!(store.remove_channel(id, "#nonexistent").is_err());
    }

    #[test]
    fn update_metadata() {
        let mut store = CommunityStore::new();
        let id = store.create("Old Name".into(), "old desc".into(), "alice".into()).id;

        store.update(id, Some("New Name".into()), None).unwrap();
        assert_eq!(store.get(id).unwrap().name, "New Name");
        assert_eq!(store.get(id).unwrap().description, "old desc");

        store.update(id, None, Some("new desc".into())).unwrap();
        assert_eq!(store.get(id).unwrap().description, "new desc");
    }

    #[test]
    fn role_management() {
        let mut store = CommunityStore::new();
        let id = store.create("Test".into(), "".into(), "alice".into()).id;
        store.join(id, "bob").unwrap();

        assert!(store.has_role(id, "alice", CommunityRole::Owner));
        assert!(store.has_role(id, "alice", CommunityRole::Moderator));
        assert!(store.has_role(id, "alice", CommunityRole::Member));

        assert!(!store.has_role(id, "bob", CommunityRole::Owner));
        assert!(!store.has_role(id, "bob", CommunityRole::Moderator));
        assert!(store.has_role(id, "bob", CommunityRole::Member));

        store.set_role(id, "bob", CommunityRole::Moderator).unwrap();
        assert!(store.has_role(id, "bob", CommunityRole::Moderator));
        assert!(!store.has_role(id, "bob", CommunityRole::Owner));
    }

    #[test]
    fn delete_community() {
        let mut store = CommunityStore::new();
        let id = store.create("Doomed".into(), "".into(), "alice".into()).id;
        store.join(id, "bob").unwrap();

        // Non-owner can't delete.
        assert!(store.delete(id, "bob").is_err());

        // Owner can delete.
        let removed = store.delete(id, "alice").unwrap();
        assert_eq!(removed.name, "Doomed");
        assert!(store.get(id).is_none());
    }

    #[test]
    fn persistence_roundtrip() {
        let tmp = std::env::temp_dir().join(format!(
            "lagoon-test-community-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        let id = {
            let mut store = CommunityStore::load_or_create(&tmp);
            let c = store.create("Persistent".into(), "survives restart".into(), "alice".into());
            c.id
        };

        // Reload and verify.
        let store = CommunityStore::load_or_create(&tmp);
        let c = store.get(id).unwrap();
        assert_eq!(c.name, "Persistent");
        assert_eq!(c.owner, "alice");
        assert!(c.members.contains_key("alice"));

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
