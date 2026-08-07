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
//! # Clock synchronisation
//!
//! The credential expiry is derived from [`std::time::SystemTime::now`]. The
//! caller's system clock must be synchronised with the TURN server's clock
//! (e.g. via NTP). Clock skew causes credentials to expire early or late.
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

/// ICE transport policy for WebRTC `RTCPeerConnection`.
///
/// `"all"` allows all candidates (host, server-reflexive, relay);
/// `"relay"` forces TURN relay only, hiding client IPs from peers.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum IceTransportPolicy {
    /// Use all ICE candidates (default).
    #[default]
    All,
    /// Force TURN relay only — hides client IPs from peers.
    Relay,
}

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
    /// WebRTC `RTCPeerConnection` `iceTransportPolicy`. The server decides
    /// whether the client should use all candidates ([`IceTransportPolicy::All`])
    /// or force TURN relay only ([`IceTransportPolicy::Relay`]) to hide client
    /// IPs from peers.
    #[serde(rename = "iceTransportPolicy")]
    pub ice_transport_policy: IceTransportPolicy,
}

fn validate_user_id(user_id: &str) {
    assert!(!user_id.is_empty(), "user_id must be non-empty");
    assert!(
        !user_id.contains(':'),
        "user_id must not contain ':' (reserved as the coturn username separator)"
    );
    assert!(
        !user_id.chars().any(|c| c.is_control()),
        "user_id must not contain control characters"
    );
}

fn validate_urls(urls: &[String], expected_schemes: &[&str]) {
    for url in urls {
        let scheme = expected_schemes.iter().find(|s| url.starts_with(*s));
        assert!(
            scheme.is_some(),
            "URL must start with one of {:?}: got {:?}",
            expected_schemes,
            url
        );
        // After the scheme prefix there must be a non-empty host
        // (at least one char before '?', '#', or end of string).
        let rest = &url[scheme.unwrap().len()..];
        let host = rest.split(['?', '#']).next().unwrap_or("");
        assert!(
            !host.is_empty(),
            "URL must have a non-empty host after the scheme: got {:?}",
            url
        );
    }
}

/// Generate temporary TURN credentials using HMAC-SHA1.
///
/// Username format: `{unix_expiry}:{user_id}`
/// Credential: `base64(HMAC-SHA1(secret, username))`
///
/// `ice_transport_policy` defaults to [`IceTransportPolicy::All`]. Use
/// [`generate_credentials_with_policy`] to specify a different policy (e.g.
/// [`IceTransportPolicy::Relay`] to force relay and hide client IPs).
///
/// # Panics
///
/// - If `ttl` is zero.
/// - If `ttl` is so large that `now + ttl` overflows `u64`.
/// - If `user_id` is empty, contains `':'`, or contains control characters.
/// - If any URL in `turn_urls` or `stun_urls` does not start with the
///   expected scheme (`turn:`, `turns:` for TURN; `stun:`, `stuns:` for STUN)
///   or has an empty host.
/// - If the system clock is before the Unix epoch (1970-01-01 UTC).
///
/// # Clock synchronisation
///
/// The credential expiry is derived from [`std::time::SystemTime::now`]. The
/// caller's system clock must be synchronised with the TURN server's clock
/// (e.g. via NTP). Clock skew causes credentials to expire early or late.
pub fn generate_credentials(
    secret: &str,
    user_id: &str,
    ttl: Duration,
    turn_urls: &[String],
    stun_urls: &[String],
) -> TurnCredentials {
    generate_credentials_with_policy(
        secret,
        user_id,
        ttl,
        turn_urls,
        stun_urls,
        IceTransportPolicy::All,
    )
}

/// Generate temporary TURN credentials with a specified [`IceTransportPolicy`].
///
/// See [`generate_credentials`] for the credential format and validation rules.
pub fn generate_credentials_with_policy(
    secret: &str,
    user_id: &str,
    ttl: Duration,
    turn_urls: &[String],
    stun_urls: &[String],
    policy: IceTransportPolicy,
) -> TurnCredentials {
    assert!(!ttl.is_zero(), "ttl must be greater than zero");

    validate_user_id(user_id);
    validate_urls(turn_urls, &["turn:", "turns:"]);
    validate_urls(stun_urls, &["stun:", "stuns:"]);

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs();

    let expiry = now_secs
        .checked_add(ttl.as_secs())
        .expect("ttl overflow: expiry would exceed u64::MAX");

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
        ice_transport_policy: policy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // --- Existing tests (updated for new API) ---

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
        assert_eq!(creds.ice_transport_policy, IceTransportPolicy::All);
    }

    // --- HMAC correctness (test gap from breakit hunter) ---

    #[test]
    fn credential_matches_independently_computed_hmac() {
        // Verify the credential is HMAC-SHA1(secret, username), not
        // HMAC-SHA1(secret, user_id) or any other message. If someone
        // changes mac.update(username.as_bytes()) to mac.update(user_id),
        // this test catches it.
        let secret = "test-secret";
        let user_id = "user1";
        let creds = generate_credentials(secret, user_id, Duration::from_secs(3600), &[], &[]);

        let mut expected_mac = HmacSha1::new_from_slice(secret.as_bytes()).unwrap();
        expected_mac.update(creds.username.as_bytes());
        let expected = BASE64.encode(expected_mac.finalize().into_bytes());

        assert_eq!(
            creds.credential, expected,
            "credential must be HMAC-SHA1(secret, username)"
        );
    }

    #[test]
    fn credential_matches_known_coturn_vector() {
        // Known vector: HMAC-SHA1("test-secret", "1234567890:user1")
        // computed via Python hashlib.hmac — external to the hmac crate.
        let secret = "test-secret";
        let username = "1234567890:user1";

        let mut mac = HmacSha1::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(username.as_bytes());
        let credential = BASE64.encode(mac.finalize().into_bytes());

        assert_eq!(credential, "Lp3V9X/F/funWfBsr+tLbLcoWiE=");
    }

    #[test]
    fn hmac_matches_rfc2202_test_case_2() {
        // RFC 2202 test case 2 — verifies the hmac/sha1 crates produce
        // the correct HMAC-SHA1 for a known (key, data, digest) triple.
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";

        let mut mac = HmacSha1::new_from_slice(key).unwrap();
        mac.update(data);
        let result = mac.finalize().into_bytes();

        let expected: [u8; 20] = [
            0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84,
            0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79,
        ];
        assert_eq!(result.as_slice(), expected);
    }

    // --- Boundary / validation tests (test gap from breakit hunter) ---

    #[test]
    #[should_panic(expected = "ttl must be greater than zero")]
    fn ttl_zero_panics() {
        generate_credentials("secret", "user", Duration::from_secs(0), &[], &[]);
    }

    #[test]
    #[should_panic(expected = "ttl overflow")]
    fn ttl_overflow_panics() {
        // checked_add prevents silent wrap — overflow panics rather than
        // creating a credential that never expires (time-bounding is a
        // security guarantee per SECURITY.md).
        generate_credentials("secret", "user", Duration::from_secs(u64::MAX), &[], &[]);
    }

    #[test]
    #[should_panic(expected = "user_id must be non-empty")]
    fn empty_user_id_panics() {
        generate_credentials("secret", "", Duration::from_secs(60), &[], &[]);
    }

    #[test]
    #[should_panic(expected = "user_id must not contain ':'")]
    fn user_id_with_colon_panics() {
        generate_credentials("secret", "alice:bob", Duration::from_secs(60), &[], &[]);
    }

    #[test]
    #[should_panic(expected = "user_id must not contain control characters")]
    fn user_id_with_newline_panics() {
        generate_credentials("secret", "user\ninject", Duration::from_secs(60), &[], &[]);
    }

    #[test]
    #[should_panic(expected = "URL must start with")]
    fn invalid_turn_url_panics() {
        generate_credentials(
            "secret",
            "user",
            Duration::from_secs(60),
            &["not-a-url".to_string()],
            &[],
        );
    }

    #[test]
    #[should_panic(expected = "URL must start with")]
    fn invalid_stun_url_panics() {
        generate_credentials(
            "secret",
            "user",
            Duration::from_secs(60),
            &[],
            &["not-a-url".to_string()],
        );
    }

    #[test]
    fn valid_url_schemes_accepted() {
        let creds = generate_credentials(
            "secret",
            "user",
            Duration::from_secs(60),
            &[
                "turn:example.com:3478".to_string(),
                "turns:example.com:5349".to_string(),
            ],
            &[
                "stun:example.com:3478".to_string(),
                "stuns:example.com:5349".to_string(),
            ],
        );
        assert_eq!(creds.ice_servers.len(), 2);
    }

    #[test]
    #[should_panic(expected = "non-empty host")]
    fn empty_host_turn_url_panics() {
        generate_credentials(
            "secret",
            "user",
            Duration::from_secs(60),
            &["turn:".to_string()],
            &[],
        );
    }

    // --- IceTransportPolicy tests (Task 7) ---

    #[test]
    fn relay_policy_via_constructor() {
        let creds = generate_credentials_with_policy(
            "secret",
            "user",
            Duration::from_secs(60),
            &["turn:example.com:3478".to_string()],
            &[],
            IceTransportPolicy::Relay,
        );
        assert_eq!(creds.ice_transport_policy, IceTransportPolicy::Relay);
    }

    #[test]
    fn relay_policy_via_struct_update() {
        // Verify the struct-update pattern works with the enum type
        let creds = TurnCredentials {
            ice_transport_policy: IceTransportPolicy::Relay,
            ..generate_credentials("secret", "user", Duration::from_secs(60), &[], &[])
        };
        assert_eq!(creds.ice_transport_policy, IceTransportPolicy::Relay);
    }

    #[test]
    fn policy_serializes_to_lowercase_string() {
        let all = generate_credentials("secret", "user", Duration::from_secs(60), &[], &[]);
        let json = serde_json::to_string(&all).unwrap();
        assert!(json.contains("\"iceTransportPolicy\":\"all\""));

        let relay = generate_credentials_with_policy(
            "secret",
            "user",
            Duration::from_secs(60),
            &[],
            &[],
            IceTransportPolicy::Relay,
        );
        let json = serde_json::to_string(&relay).unwrap();
        assert!(json.contains("\"iceTransportPolicy\":\"relay\""));
    }
}
