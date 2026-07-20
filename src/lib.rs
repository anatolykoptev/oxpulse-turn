//! Short-lived TURN/STUN credentials for WebRTC ICE, compatible with the
//! [coturn](https://github.com/coturn/coturn) REST-API time-limited credential
//! scheme (`use-auth-secret` / `static-auth-secret`).
//!
//! A caller holding a secret shared with the TURN server mints an ephemeral
//! `username` / `credential` pair that any coturn instance configured with the
//! same secret accepts — no per-user state on the TURN server, no database
//! round-trip. The credential is `base64(HMAC-SHA1(secret, "<expiry>:<user>"))`,
//! exactly the format coturn's `--use-auth-secret` validates.
//!
//! # Example
//!
//! ```
//! use std::time::Duration;
//! use oxpulse_turn::generate_credentials;
//!
//! let creds = generate_credentials(
//!     "shared-secret-configured-on-coturn",
//!     "alice",
//!     Duration::from_secs(3600),
//!     &["turn:turn.example.com:3478?transport=udp".to_string()],
//!     &["stun:stun.example.com:3478".to_string()],
//! );
//!
//! assert!(creds.username.ends_with(":alice"));
//! assert_eq!(creds.ttl, 3600);
//! assert_eq!(creds.ice_servers.len(), 2);
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// TURN/STUN server entry for ICE negotiation.
#[derive(Debug, Clone, Serialize)]
pub struct IceServer {
    pub urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

/// Temporary TURN credentials (coturn REST API compatible).
#[derive(Debug, Clone, Serialize)]
pub struct TurnCredentials {
    pub username: String,
    pub credential: String,
    pub ttl: u64,
    pub ice_servers: Vec<IceServer>,
    /// WebRTC `RTCPeerConnection` `iceTransportPolicy`. Server decides whether
    /// the client should use all candidates (`"all"`) or force TURN relay only
    /// (`"relay"`) to hide client IPs. Task 4.3.
    #[serde(rename = "iceTransportPolicy")]
    pub ice_transport_policy: &'static str,
}

/// Generate temporary TURN credentials using HMAC-SHA1.
///
/// Username format: `{unix_expiry}:{user_id}`
/// Credential: `base64(HMAC-SHA1(secret, username))`
///
/// `ice_transport_policy` defaults to `"all"`. Callers (see
/// `server/router.rs`) may override it after construction using struct update
/// syntax when they want to force relay.
pub fn generate_credentials(
    secret: &str,
    user_id: &str,
    ttl: Duration,
    turn_urls: &[String],
    stun_urls: &[String],
) -> TurnCredentials {
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
        + ttl.as_secs();

    let username = format!("{expiry}:{user_id}");

    let mut mac = HmacSha1::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(username.as_bytes());
    let credential = BASE64.encode(mac.finalize().into_bytes());

    let mut ice_servers = Vec::new();

    if !stun_urls.is_empty() {
        ice_servers.push(IceServer {
            urls: stun_urls.to_vec(),
            username: None,
            credential: None,
        });
    }

    if !turn_urls.is_empty() {
        ice_servers.push(IceServer {
            urls: turn_urls.to_vec(),
            username: Some(username.clone()),
            credential: Some(credential.clone()),
        });
    }

    TurnCredentials {
        username,
        credential,
        ttl: ttl.as_secs(),
        ice_servers,
        ice_transport_policy: "all",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn credentials_have_correct_format() {
        let creds = generate_credentials(
            "test-secret",
            "user1",
            Duration::from_secs(3600),
            &["turn:example.com:3478".to_string()],
            &["stun:stun.l.google.com:19302".to_string()],
        );
        assert!(creds.username.contains(':'));
        assert!(!creds.credential.is_empty());
        assert_eq!(creds.ttl, 3600);
        assert_eq!(creds.ice_servers.len(), 2);
    }

    #[test]
    fn empty_urls_produce_no_ice_servers() {
        let creds = generate_credentials("secret", "user", Duration::from_secs(60), &[], &[]);
        assert!(creds.ice_servers.is_empty());
    }

    #[test]
    fn stun_server_has_no_credentials() {
        let creds = generate_credentials(
            "secret",
            "user",
            Duration::from_secs(60),
            &[],
            &["stun:example.com:3478".to_string()],
        );
        assert_eq!(creds.ice_servers.len(), 1);
        assert!(creds.ice_servers[0].username.is_none());
        assert!(creds.ice_servers[0].credential.is_none());
    }

    #[test]
    fn default_ice_transport_policy_is_all() {
        let creds = generate_credentials("secret", "user", Duration::from_secs(60), &[], &[]);
        assert_eq!(creds.ice_transport_policy, "all");
    }
}
