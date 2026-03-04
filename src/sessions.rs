use std::collections::HashMap;
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use tracing::{info, warn};

use crate::tokens::TokenMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub domain: String,
    pub captured_at: String,
    pub last_used: String,
    pub status: SessionStatus,
    pub cookies: Vec<Cookie>,
    #[serde(default)]
    pub local_storage: HashMap<String, HashMap<String, String>>,
    #[serde(default)]
    pub session_storage: HashMap<String, HashMap<String, String>>,
    /// Names of cookies that are auth cookies (captured during login).
    /// These get swapped (fake↔real) on every request/response.
    #[serde(default)]
    pub auth_cookie_names: Vec<String>,
    /// JSON field names that contain tokens (e.g., "access_token").
    #[serde(default)]
    pub token_fields: Vec<String>,
    /// Bidirectional real↔fake token mapping.
    #[serde(default)]
    pub token_map: TokenMap,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    Active,
    Expired,
    Capturing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    #[serde(default)]
    pub expires: Option<u64>,
    #[serde(default)]
    pub secure: bool,
    #[serde(default)]
    pub http_only: bool,
    #[serde(default)]
    pub same_site: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageData {
    pub local_storage: HashMap<String, String>,
    pub session_storage: HashMap<String, String>,
}

pub struct SessionStore {
    sessions: HashMap<String, Session>,
    sessions_dir: PathBuf,
}

impl SessionStore {
    /// Create a new store, loading sessions from ~/.warden/sessions/
    pub fn new() -> Self {
        let sessions_dir = crate::config::config_dir().join("sessions");
        let mut store = Self {
            sessions: HashMap::new(),
            sessions_dir,
        };
        store.load_all();
        store
    }

    /// Create a store with pre-loaded sessions (for testing).
    pub fn with_sessions(sessions: HashMap<String, Session>) -> Self {
        Self {
            sessions,
            sessions_dir: PathBuf::from("/tmp/warden-test-sessions"),
        }
    }

    /// Load all session files from the sessions directory.
    pub fn load_all(&mut self) {
        if !self.sessions_dir.exists() {
            std::fs::create_dir_all(&self.sessions_dir).ok();
            return;
        }
        if let Ok(entries) = std::fs::read_dir(&self.sessions_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "json") {
                    match std::fs::read_to_string(&path) {
                        Ok(data) => match serde_json::from_str::<Session>(&data) {
                            Ok(session) => {
                                info!("Loaded session: {}", session.domain);
                                self.sessions.insert(session.domain.clone(), session);
                            }
                            Err(e) => warn!("Failed to parse session file {:?}: {}", path, e),
                        },
                        Err(e) => warn!("Failed to read session file {:?}: {}", path, e),
                    }
                }
            }
        }
    }

    /// Save a session to disk.
    pub fn save(&self, session: &Session) -> Result<(), Box<dyn std::error::Error>> {
        std::fs::create_dir_all(&self.sessions_dir)?;
        let path = self.sessions_dir.join(format!("{}.json", session.domain));
        let json = serde_json::to_string_pretty(session)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Get a session by exact domain.
    pub fn get(&self, domain: &str) -> Option<&Session> {
        self.sessions.get(domain)
    }

    /// Get a mutable reference to a session by exact domain.
    pub fn get_mut(&mut self, domain: &str) -> Option<&mut Session> {
        self.sessions.get_mut(domain)
    }

    /// Insert or update a session.
    pub fn insert(&mut self, session: Session) {
        self.save(&session).ok();
        self.sessions.insert(session.domain.clone(), session);
    }

    /// Remove a session and delete its file.
    pub fn remove(&mut self, domain: &str) -> Option<Session> {
        let path = self.sessions_dir.join(format!("{}.json", domain));
        std::fs::remove_file(path).ok();
        self.sessions.remove(domain)
    }

    /// List all sessions.
    pub fn list(&self) -> Vec<&Session> {
        self.sessions.values().collect()
    }

    /// Find a session matching a request domain.
    /// "mail.yahoo.com" matches session for "yahoo.com".
    pub fn find_for_domain(&self, request_domain: &str) -> Option<&Session> {
        for session in self.sessions.values() {
            if domain_matches(request_domain, &session.domain) {
                return Some(session);
            }
        }
        None
    }

    /// Find a mutable session matching a request domain.
    pub fn find_for_domain_mut(&mut self, request_domain: &str) -> Option<&mut Session> {
        // Need to find the key first, then do a mutable lookup
        let key = self.sessions.keys()
            .find(|k| domain_matches(request_domain, k))
            .cloned();
        key.and_then(move |k| self.sessions.get_mut(&k))
    }

    /// Save a session by domain name (convenience for proxy code).
    pub fn save_domain(&self, domain: &str) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(session) = self.find_for_domain(domain) {
            self.save(session)
        } else {
            Ok(())
        }
    }

    /// Get cookies that should be injected for a given request URL.
    pub fn cookies_for_request(&self, url: &str) -> Vec<&Cookie> {
        let (is_secure, request_domain, request_path) = match parse_url(url) {
            Some(parts) => parts,
            None => return vec![],
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let session = match self.find_for_domain(&request_domain) {
            Some(s) if s.status == SessionStatus::Active => s,
            _ => return vec![],
        };

        session.cookies.iter().filter(|cookie| {
            // Domain matching
            if !cookie_domain_matches(&request_domain, &cookie.domain) {
                return false;
            }
            // Path matching
            if !request_path.starts_with(&cookie.path) {
                return false;
            }
            // Secure flag
            if cookie.secure && !is_secure {
                return false;
            }
            // Expiry
            if let Some(expires) = cookie.expires {
                if expires < now {
                    return false;
                }
            }
            true
        }).collect()
    }

    /// Get storage (localStorage/sessionStorage) for a given origin.
    pub fn storage_for_origin(&self, origin: &str) -> Option<StorageData> {
        let (_is_secure, domain, _path) = parse_url(origin)?;

        let session = self.find_for_domain(&domain)?;
        if session.status != SessionStatus::Active {
            return None;
        }

        Some(StorageData {
            local_storage: session.local_storage.get(origin).cloned().unwrap_or_default(),
            session_storage: session.session_storage.get(origin).cloned().unwrap_or_default(),
        })
    }
}

/// Parse a URL into (is_https, domain, path).
pub fn parse_url(url: &str) -> Option<(bool, String, String)> {
    let is_https = url.starts_with("https://");
    let rest = url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let host = match host_port.find(':') {
        Some(i) => &host_port[..i],
        None => host_port,
    };
    Some((is_https, host.to_lowercase(), path))
}

/// Check if a request domain matches a session domain.
/// "mail.yahoo.com" matches "yahoo.com" but "notyahoo.com" does not.
pub fn domain_matches(request_domain: &str, session_domain: &str) -> bool {
    let req = request_domain.to_lowercase();
    let sess = session_domain.to_lowercase();

    if req == sess {
        return true;
    }

    // request_domain must be a subdomain of session_domain
    req.ends_with(&format!(".{}", sess))
}

/// Cookie domain matching per RFC 6265.
/// Cookie domain ".yahoo.com" matches "mail.yahoo.com" and "yahoo.com".
/// Cookie domain "mail.yahoo.com" does NOT match "finance.yahoo.com".
pub fn cookie_domain_matches(request_domain: &str, cookie_domain: &str) -> bool {
    let req = request_domain.to_lowercase();
    let cookie = cookie_domain.to_lowercase();
    let cookie = cookie.strip_prefix('.').unwrap_or(&cookie);

    if req == cookie {
        return true;
    }

    req.ends_with(&format!(".{}", cookie))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── domain_matches ──

    #[test]
    fn exact_domain_matches() {
        assert!(domain_matches("yahoo.com", "yahoo.com"));
    }

    #[test]
    fn subdomain_matches_parent() {
        assert!(domain_matches("mail.yahoo.com", "yahoo.com"));
        assert!(domain_matches("calendar.yahoo.com", "yahoo.com"));
    }

    #[test]
    fn deep_subdomain_matches() {
        assert!(domain_matches("a.b.yahoo.com", "yahoo.com"));
    }

    #[test]
    fn similar_domain_does_not_match() {
        assert!(!domain_matches("notyahoo.com", "yahoo.com"));
        assert!(!domain_matches("fakeyahoo.com", "yahoo.com"));
    }

    #[test]
    fn parent_does_not_match_subdomain() {
        assert!(!domain_matches("yahoo.com", "mail.yahoo.com"));
    }

    #[test]
    fn case_insensitive_matching() {
        assert!(domain_matches("Mail.Yahoo.COM", "yahoo.com"));
    }

    // ── cookie_domain_matches ──

    #[test]
    fn dotted_cookie_domain_matches_subdomain() {
        assert!(cookie_domain_matches("mail.yahoo.com", ".yahoo.com"));
        assert!(cookie_domain_matches("calendar.yahoo.com", ".yahoo.com"));
    }

    #[test]
    fn dotted_cookie_domain_matches_exact() {
        assert!(cookie_domain_matches("yahoo.com", ".yahoo.com"));
    }

    #[test]
    fn subdomain_cookie_does_not_match_sibling() {
        assert!(!cookie_domain_matches("finance.yahoo.com", "mail.yahoo.com"));
    }

    #[test]
    fn exact_cookie_domain_matches() {
        assert!(cookie_domain_matches("mail.yahoo.com", "mail.yahoo.com"));
    }

    #[test]
    fn unrelated_domain_no_match() {
        assert!(!cookie_domain_matches("evil.com", ".yahoo.com"));
        assert!(!cookie_domain_matches("notyahoo.com", ".yahoo.com"));
    }

    // ── parse_url ──

    #[test]
    fn parse_https_url() {
        let (secure, domain, path) = parse_url("https://mail.yahoo.com/inbox").unwrap();
        assert!(secure);
        assert_eq!(domain, "mail.yahoo.com");
        assert_eq!(path, "/inbox");
    }

    #[test]
    fn parse_http_url() {
        let (secure, domain, path) = parse_url("http://localhost:3000/api").unwrap();
        assert!(!secure);
        assert_eq!(domain, "localhost");
        assert_eq!(path, "/api");
    }

    #[test]
    fn parse_url_no_path() {
        let (_, domain, path) = parse_url("https://example.com").unwrap();
        assert_eq!(domain, "example.com");
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_invalid_url() {
        assert!(parse_url("not-a-url").is_none());
    }

    // ── cookies_for_request ──

    #[test]
    fn secure_cookie_not_injected_on_http() {
        let session = Session {
            domain: "example.com".into(),
            captured_at: "2026-01-01T00:00:00Z".into(),
            last_used: "2026-01-01T00:00:00Z".into(),
            status: SessionStatus::Active,
            cookies: vec![Cookie {
                name: "secure_sess".into(),
                value: "abc".into(),
                domain: ".example.com".into(),
                path: "/".into(),
                expires: None,
                secure: true,
                http_only: false,
                same_site: None,
            }],
            local_storage: HashMap::new(),
            session_storage: HashMap::new(),
            auth_cookie_names: vec![],
            token_fields: vec![],
            token_map: Default::default(),
        };
        let mut sessions = HashMap::new();
        sessions.insert("example.com".into(), session);
        let store = SessionStore::with_sessions(sessions);

        let cookies = store.cookies_for_request("http://example.com/page");
        assert!(cookies.is_empty(), "secure cookie must not be injected on HTTP");
    }

    #[test]
    fn secure_cookie_injected_on_https() {
        let session = Session {
            domain: "example.com".into(),
            captured_at: "2026-01-01T00:00:00Z".into(),
            last_used: "2026-01-01T00:00:00Z".into(),
            status: SessionStatus::Active,
            cookies: vec![Cookie {
                name: "secure_sess".into(),
                value: "abc".into(),
                domain: ".example.com".into(),
                path: "/".into(),
                expires: None,
                secure: true,
                http_only: false,
                same_site: None,
            }],
            local_storage: HashMap::new(),
            session_storage: HashMap::new(),
            auth_cookie_names: vec![],
            token_fields: vec![],
            token_map: Default::default(),
        };
        let mut sessions = HashMap::new();
        sessions.insert("example.com".into(), session);
        let store = SessionStore::with_sessions(sessions);

        let cookies = store.cookies_for_request("https://example.com/page");
        assert_eq!(cookies.len(), 1);
    }

    #[test]
    fn expired_cookie_not_injected() {
        let session = Session {
            domain: "example.com".into(),
            captured_at: "2026-01-01T00:00:00Z".into(),
            last_used: "2026-01-01T00:00:00Z".into(),
            status: SessionStatus::Active,
            cookies: vec![Cookie {
                name: "old".into(),
                value: "expired".into(),
                domain: ".example.com".into(),
                path: "/".into(),
                expires: Some(1), // expired in 1970
                secure: false,
                http_only: false,
                same_site: None,
            }],
            local_storage: HashMap::new(),
            session_storage: HashMap::new(),
            auth_cookie_names: vec![],
            token_fields: vec![],
            token_map: Default::default(),
        };
        let mut sessions = HashMap::new();
        sessions.insert("example.com".into(), session);
        let store = SessionStore::with_sessions(sessions);

        let cookies = store.cookies_for_request("https://example.com/");
        assert!(cookies.is_empty(), "expired cookies must not be injected");
    }

    #[test]
    fn path_matching() {
        let session = Session {
            domain: "example.com".into(),
            captured_at: "2026-01-01T00:00:00Z".into(),
            last_used: "2026-01-01T00:00:00Z".into(),
            status: SessionStatus::Active,
            cookies: vec![
                Cookie {
                    name: "root".into(),
                    value: "a".into(),
                    domain: ".example.com".into(),
                    path: "/".into(),
                    expires: None,
                    secure: false,
                    http_only: false,
                    same_site: None,
                },
                Cookie {
                    name: "api_only".into(),
                    value: "b".into(),
                    domain: ".example.com".into(),
                    path: "/api".into(),
                    expires: None,
                    secure: false,
                    http_only: false,
                    same_site: None,
                },
            ],
            local_storage: HashMap::new(),
            session_storage: HashMap::new(),
            auth_cookie_names: vec![],
            token_fields: vec![],
            token_map: Default::default(),
        };
        let mut sessions = HashMap::new();
        sessions.insert("example.com".into(), session);
        let store = SessionStore::with_sessions(sessions);

        // Root path gets root cookie only
        let root_cookies = store.cookies_for_request("https://example.com/other");
        assert_eq!(root_cookies.len(), 1);
        assert_eq!(root_cookies[0].name, "root");

        // /api path gets both
        let api_cookies = store.cookies_for_request("https://example.com/api/data");
        assert_eq!(api_cookies.len(), 2);
    }

    #[test]
    fn expired_session_returns_no_cookies() {
        let session = Session {
            domain: "example.com".into(),
            captured_at: "2026-01-01T00:00:00Z".into(),
            last_used: "2026-01-01T00:00:00Z".into(),
            status: SessionStatus::Expired,
            cookies: vec![Cookie {
                name: "sess".into(),
                value: "val".into(),
                domain: ".example.com".into(),
                path: "/".into(),
                expires: None,
                secure: false,
                http_only: false,
                same_site: None,
            }],
            local_storage: HashMap::new(),
            session_storage: HashMap::new(),
            auth_cookie_names: vec![],
            token_fields: vec![],
            token_map: Default::default(),
        };
        let mut sessions = HashMap::new();
        sessions.insert("example.com".into(), session);
        let store = SessionStore::with_sessions(sessions);

        let cookies = store.cookies_for_request("https://example.com/");
        assert!(cookies.is_empty());
    }

    // ── storage_for_origin ──

    #[test]
    fn storage_returned_for_matching_origin() {
        let mut local = HashMap::new();
        let mut origin_storage = HashMap::new();
        origin_storage.insert("token".into(), "jwt123".into());
        local.insert("https://mail.yahoo.com".into(), origin_storage);

        let session = Session {
            domain: "yahoo.com".into(),
            captured_at: "2026-01-01T00:00:00Z".into(),
            last_used: "2026-01-01T00:00:00Z".into(),
            status: SessionStatus::Active,
            cookies: vec![],
            local_storage: local,
            session_storage: HashMap::new(),
            auth_cookie_names: vec![],
            token_fields: vec![],
            token_map: Default::default(),
        };
        let mut sessions = HashMap::new();
        sessions.insert("yahoo.com".into(), session);
        let store = SessionStore::with_sessions(sessions);

        let data = store.storage_for_origin("https://mail.yahoo.com").unwrap();
        assert_eq!(data.local_storage.get("token").unwrap(), "jwt123");
    }

    #[test]
    fn no_storage_for_revoked_session() {
        let session = Session {
            domain: "yahoo.com".into(),
            captured_at: "2026-01-01T00:00:00Z".into(),
            last_used: "2026-01-01T00:00:00Z".into(),
            status: SessionStatus::Expired,
            cookies: vec![],
            local_storage: HashMap::new(),
            session_storage: HashMap::new(),
            auth_cookie_names: vec![],
            token_fields: vec![],
            token_map: Default::default(),
        };
        let mut sessions = HashMap::new();
        sessions.insert("yahoo.com".into(), session);
        let store = SessionStore::with_sessions(sessions);

        assert!(store.storage_for_origin("https://mail.yahoo.com").is_none());
    }

    #[test]
    fn no_storage_for_unmatched_origin() {
        let store = SessionStore::with_sessions(HashMap::new());
        assert!(store.storage_for_origin("https://unknown.com").is_none());
    }
}
