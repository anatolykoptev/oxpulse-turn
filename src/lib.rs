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
//! # API layers
//!
//! | Layer | Function | When to use |
//! |---|---|---|
//! | **Issuer** | [`TurnCredentialIssuer`] | Server: validate config once at startup, `.issue()` per request |
//! | **Pure mint** | [`mint_credentials`] + [`compute_expiry`] | Deterministic minting with caller-supplied expiry (testable, no `SystemTime`) |
//! | **Try** | [`try_generate_credentials`] | One-shot mint returning `Result` (no panic) |
//! | **Panic** | [`generate_credentials`] | Simple use cases (panics on invalid input) |
//!
//! # Example
//!
//! ```
//! use std::time::Duration;
//! use oxpulse_turn::TurnCredentialIssuer;
//!
//! let issuer = TurnCredentialIssuer::new(
//!     "shared-secret-configured-on-coturn",
//!     Duration::from_secs(3600),
//!     &["turn:turn.example.com:3478?transport=udp".to_string()],
//!     &["stun:stun.example.com:3478".to_string()],
//! ).unwrap();
//!
//! let creds = issuer.issue("alice").unwrap();
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

/// Errors that can occur during TURN credential generation.
#[derive(Debug, thiserror::Error)]
pub enum TurnError {
    #[error("ttl must be greater than zero")]
    TtlZero,
    #[error("ttl overflow: expiry would exceed u64::MAX")]
    TtlOverflow,
    #[error("user_id must be non-empty")]
    EmptyUserId,
    #[error("user_id must not contain ':' (reserved as the coturn username separator)")]
    UserIdColon,
    #[error("user_id must not contain control characters")]
    UserIdControlChar,
    #[error("URL must start with one of {expected:?}: got {url:?}")]
    InvalidUrlScheme {
        expected: &'static [&'static str],
        url: String,
    },
    #[error("URL must have a non-empty host after the scheme: got {url:?}")]
    EmptyHost { url: String },
    #[error("system clock before unix epoch")]
    ClockBeforeEpoch,
}

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

/// Pre-validated TURN credential issuer for server use cases.
///
/// Validates configuration (secret, URLs, TTL) **once** at construction,
/// then mints credentials per-request without repeating validation. This is
/// the recommended API for servers that mint credentials on a hot path.
///
/// # Example
///
/// ```
/// use std::time::Duration;
/// use oxpulse_turn::{TurnCredentialIssuer, IceTransportPolicy};
///
/// let issuer = TurnCredentialIssuer::new(
///     "secret",
///     Duration::from_secs(3600),
///     &["turn:turn.example.com:3478".to_string()],
///     &["stun:stun.example.com:3478".to_string()],
/// ).unwrap();
///
/// // Per-request: only user_id is validated (config already checked)
/// let creds = issuer.issue("alice").unwrap();
/// let relay = issuer.issue_with_policy("bob", IceTransportPolicy::Relay).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct TurnCredentialIssuer {
    secret: String,
    ttl: Duration,
    turn_urls: Vec<String>,
    stun_urls: Vec<String>,
}

impl TurnCredentialIssuer {
    /// Create a new issuer, validating configuration once.
    ///
    /// # Errors
    ///
    /// Returns [`TurnError`] if URLs are invalid or TTL is zero.
    pub fn new(
        secret: &str,
        ttl: Duration,
        turn_urls: &[String],
        stun_urls: &[String],
    ) -> Result<Self, TurnError> {
        validate_urls(turn_urls, TURN_SCHEMES)?;
        validate_urls(stun_urls, STUN_SCHEMES)?;
        if ttl.is_zero() {
            return Err(TurnError::TtlZero);
        }
        if secret.len() < MIN_SECRET_LEN {
            log::warn!(
                "TURN secret is only {} bytes — recommend >= {} for HMAC-SHA1 security",
                secret.len(),
                MIN_SECRET_LEN
            );
        }
        if ttl > MAX_TTL {
            log::warn!(
                "TURN TTL {:?} exceeds recommended max of {:?} — long-lived credentials weaken time-bounding",
                ttl,
                MAX_TTL
            );
        }
        Ok(Self {
            secret: secret.to_string(),
            ttl,
            turn_urls: turn_urls.to_vec(),
            stun_urls: stun_urls.to_vec(),
        })
    }

    /// Issue credentials with the default policy ([`IceTransportPolicy::All`]).
    ///
    /// Only `user_id` is validated — configuration was checked at [`new`].
    ///
    /// # Errors
    ///
    /// Returns [`TurnError`] if `user_id` is invalid, the clock is before
    /// the Unix epoch, or TTL overflows.
    pub fn issue(&self, user_id: &str) -> Result<TurnCredentials, TurnError> {
        self.issue_with_policy(user_id, IceTransportPolicy::All)
    }

    /// Issue credentials with a specified [`IceTransportPolicy`].
    ///
    /// # Errors
    ///
    /// Returns [`TurnError`] if `user_id` is invalid, the clock is before
    /// the Unix epoch, or TTL overflows.
    pub fn issue_with_policy(
        &self,
        user_id: &str,
        policy: IceTransportPolicy,
    ) -> Result<TurnCredentials, TurnError> {
        validate_user_id(user_id)?;
        let now = now_unix()?;
        let expiry = compute_expiry(now, self.ttl)?;
        let mut creds = mint_credentials(
            &self.secret,
            user_id,
            expiry,
            &self.turn_urls,
            &self.stun_urls,
            policy,
        )?;
        creds.ttl = self.ttl.as_secs();
        Ok(creds)
    }
}

const TURN_SCHEMES: &[&str] = &["turn:", "turns:"];
const STUN_SCHEMES: &[&str] = &["stun:", "stuns:"];

/// Recommended maximum TTL for TURN credentials (1 hour).
///
/// Long-lived credentials increase the window for credential theft/replay.
/// `oxpulse-chat` already reduced from 24h to 1h. This constant lets callers
/// validate against the recommended upper bound.
pub const MAX_TTL: Duration = Duration::from_secs(3600);

/// Minimum recommended secret length for HMAC-SHA1 (16 bytes).
///
/// Shorter secrets weaken the HMAC — an attacker who brute-forces the secret
/// can forge credentials. `TurnCredentialIssuer::new` warns on shorter secrets.
pub const MIN_SECRET_LEN: usize = 16;

/// Derive STUN URLs from TURN URLs by swapping the scheme.
///
/// `turn:example.com:3478?transport=udp` → `stun:example.com:3478`
/// `turns:example.com:5349` → `stuns:example.com:5349`
///
/// Deduplicates and sorts the result. URLs with empty hosts are skipped.
/// This eliminates the need to configure STUN separately when it's the same
/// host as TURN (the common case).
pub fn stun_urls_from_turn(turn_urls: &[String]) -> Vec<String> {
    let mut urls: Vec<String> = turn_urls
        .iter()
        .filter_map(|url| {
            // Find which TURN scheme this URL uses
            let scheme = TURN_SCHEMES.iter().find(|s| url.starts_with(*s))?;
            let rest = &url[scheme.len()..];
            let authority = rest.split(['?', '#']).next()?;
            if authority.is_empty() {
                return None;
            }
            // Map turn: → stun:, turns: → stuns:
            let stun_scheme = if *scheme == "turns:" {
                "stuns:"
            } else {
                "stun:"
            };
            Some(format!("{stun_scheme}{authority}"))
        })
        .collect();
    urls.sort();
    urls.dedup();
    urls
}

fn validate_user_id(user_id: &str) -> Result<(), TurnError> {
    if user_id.is_empty() {
        return Err(TurnError::EmptyUserId);
    }
    if user_id.contains(':') {
        return Err(TurnError::UserIdColon);
    }
    if user_id.chars().any(|c| c.is_control()) {
        return Err(TurnError::UserIdControlChar);
    }
    Ok(())
}

fn validate_urls(
    urls: &[String],
    expected_schemes: &'static [&'static str],
) -> Result<(), TurnError> {
    for url in urls {
        let scheme = expected_schemes.iter().find(|s| url.starts_with(*s));
        let scheme = scheme.ok_or_else(|| TurnError::InvalidUrlScheme {
            expected: expected_schemes,
            url: url.clone(),
        })?;
        let rest = &url[scheme.len()..];
        let host = rest.split(['?', '#']).next().unwrap_or("");
        if host.is_empty() {
            return Err(TurnError::EmptyHost { url: url.clone() });
        }
    }
    Ok(())
}

fn now_unix() -> Result<u64, TurnError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TurnError::ClockBeforeEpoch)
        .map(|d| d.as_secs())
}

/// Compute the expiry timestamp `now_unix + ttl`, returning an error on overflow.
///
/// Separated from [`mint_credentials`] so the pure minting function stays
/// deterministic and testable without a time source.
///
/// # Errors
///
/// Returns [`TurnError::TtlZero`] if `ttl` is zero, or [`TurnError::TtlOverflow`]
/// if `now + ttl` overflows `u64`.
pub fn compute_expiry(now_unix: u64, ttl: Duration) -> Result<u64, TurnError> {
    if ttl.is_zero() {
        return Err(TurnError::TtlZero);
    }
    now_unix
        .checked_add(ttl.as_secs())
        .ok_or(TurnError::TtlOverflow)
}

/// Mint TURN credentials from a pre-computed expiry timestamp.
///
/// This is the **pure** building block: no `SystemTime`, no I/O — the caller
/// supplies `expiry_unix` (e.g. via [`compute_expiry`]). The same
/// `(secret, user_id, expiry_unix, urls, policy)` always yields the same
/// result, making this function deterministic and vector-testable.
///
/// # Errors
///
/// Returns [`TurnError`] if `user_id` or URLs are invalid.
pub fn mint_credentials(
    secret: &str,
    user_id: &str,
    expiry_unix: u64,
    turn_urls: &[String],
    stun_urls: &[String],
    policy: IceTransportPolicy,
) -> Result<TurnCredentials, TurnError> {
    validate_user_id(user_id)?;
    validate_urls(turn_urls, TURN_SCHEMES)?;
    validate_urls(stun_urls, STUN_SCHEMES)?;

    let username = format!("{expiry_unix}:{user_id}");

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

    Ok(TurnCredentials {
        username,
        credential,
        ttl: 0,
        ice_servers,
        ice_transport_policy: policy,
    })
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
/// Panics if any input is invalid. Use [`try_generate_credentials`] for a
/// `Result`-returning variant.
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
/// See [`generate_credentials`] for the credential format. Panics on invalid
/// input — use [`try_generate_credentials_with_policy`] for a `Result` variant.
pub fn generate_credentials_with_policy(
    secret: &str,
    user_id: &str,
    ttl: Duration,
    turn_urls: &[String],
    stun_urls: &[String],
    policy: IceTransportPolicy,
) -> TurnCredentials {
    try_generate_credentials_with_policy(secret, user_id, ttl, turn_urls, stun_urls, policy)
        .unwrap_or_else(|e| panic!("{e}"))
}

/// Same as [`generate_credentials`] but returns [`Result`] instead of panicking.
///
/// # Errors
///
/// Returns [`TurnError`] on any validation failure or clock error.
pub fn try_generate_credentials(
    secret: &str,
    user_id: &str,
    ttl: Duration,
    turn_urls: &[String],
    stun_urls: &[String],
) -> Result<TurnCredentials, TurnError> {
    try_generate_credentials_with_policy(
        secret,
        user_id,
        ttl,
        turn_urls,
        stun_urls,
        IceTransportPolicy::All,
    )
}

/// Same as [`generate_credentials_with_policy`] but returns [`Result`].
///
/// # Errors
///
/// Returns [`TurnError`] on any validation failure or clock error.
pub fn try_generate_credentials_with_policy(
    secret: &str,
    user_id: &str,
    ttl: Duration,
    turn_urls: &[String],
    stun_urls: &[String],
    policy: IceTransportPolicy,
) -> Result<TurnCredentials, TurnError> {
    validate_user_id(user_id)?;
    validate_urls(turn_urls, TURN_SCHEMES)?;
    validate_urls(stun_urls, STUN_SCHEMES)?;

    let now = now_unix()?;
    let expiry = compute_expiry(now, ttl)?;
    let mut creds = mint_credentials(secret, user_id, expiry, turn_urls, stun_urls, policy)?;
    creds.ttl = ttl.as_secs();
    Ok(creds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // --- Panicking API (backward compat with 0.2.0) ---

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

    // --- HMAC correctness ---

    #[test]
    fn credential_matches_independently_computed_hmac() {
        let secret = "test-secret";
        let user_id = "user1";
        let creds = generate_credentials(secret, user_id, Duration::from_secs(3600), &[], &[]);

        let mut expected_mac = HmacSha1::new_from_slice(secret.as_bytes()).unwrap();
        expected_mac.update(creds.username.as_bytes());
        let expected = BASE64.encode(expected_mac.finalize().into_bytes());

        assert_eq!(creds.credential, expected);
    }

    #[test]
    fn credential_matches_known_coturn_vector() {
        let secret = "test-secret";
        let username = "1234567890:user1";

        let mut mac = HmacSha1::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(username.as_bytes());
        let credential = BASE64.encode(mac.finalize().into_bytes());

        assert_eq!(credential, "Lp3V9X/F/funWfBsr+tLbLcoWiE=");
    }

    #[test]
    fn hmac_matches_rfc2202_test_case_2() {
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

    // --- Panic tests (backward compat) ---

    #[test]
    #[should_panic(expected = "ttl must be greater than zero")]
    fn ttl_zero_panics() {
        generate_credentials("secret", "user", Duration::from_secs(0), &[], &[]);
    }

    #[test]
    #[should_panic(expected = "ttl overflow")]
    fn ttl_overflow_panics() {
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

    // --- IceTransportPolicy tests ---

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

    // --- try_ API (Result-returning) ---

    #[test]
    fn try_generate_succeeds() {
        let creds = try_generate_credentials(
            "secret",
            "user",
            Duration::from_secs(60),
            &["turn:example.com:3478".to_string()],
            &[],
        )
        .unwrap();
        assert!(creds.username.contains(":user"));
        assert_eq!(creds.ttl, 60);
    }

    #[test]
    fn try_generate_ttl_zero() {
        let err = try_generate_credentials("secret", "user", Duration::from_secs(0), &[], &[]);
        assert!(matches!(err, Err(TurnError::TtlZero)));
    }

    #[test]
    fn try_generate_ttl_overflow() {
        let err =
            try_generate_credentials("secret", "user", Duration::from_secs(u64::MAX), &[], &[]);
        assert!(matches!(err, Err(TurnError::TtlOverflow)));
    }

    #[test]
    fn try_generate_empty_user_id() {
        let err = try_generate_credentials("secret", "", Duration::from_secs(60), &[], &[]);
        assert!(matches!(err, Err(TurnError::EmptyUserId)));
    }

    #[test]
    fn try_generate_colon_user_id() {
        let err = try_generate_credentials("secret", "a:b", Duration::from_secs(60), &[], &[]);
        assert!(matches!(err, Err(TurnError::UserIdColon)));
    }

    #[test]
    fn try_generate_control_char_user_id() {
        let err = try_generate_credentials("secret", "a\nb", Duration::from_secs(60), &[], &[]);
        assert!(matches!(err, Err(TurnError::UserIdControlChar)));
    }

    #[test]
    fn try_generate_invalid_url() {
        let err = try_generate_credentials(
            "secret",
            "user",
            Duration::from_secs(60),
            &["bad".to_string()],
            &[],
        );
        assert!(matches!(err, Err(TurnError::InvalidUrlScheme { .. })));
    }

    #[test]
    fn try_generate_empty_host() {
        let err = try_generate_credentials(
            "secret",
            "user",
            Duration::from_secs(60),
            &["turn:".to_string()],
            &[],
        );
        assert!(matches!(err, Err(TurnError::EmptyHost { .. })));
    }

    // --- Pure mint_credentials ---

    #[test]
    fn mint_is_deterministic() {
        let a = mint_credentials(
            "secret",
            "user",
            1_700_000_000,
            &[],
            &[],
            IceTransportPolicy::All,
        )
        .unwrap();
        let b = mint_credentials(
            "secret",
            "user",
            1_700_000_000,
            &[],
            &[],
            IceTransportPolicy::All,
        )
        .unwrap();
        assert_eq!(a.username, b.username);
        assert_eq!(a.credential, b.credential);
    }

    #[test]
    fn mint_username_format() {
        let creds = mint_credentials(
            "secret",
            "alice",
            1234567890,
            &[],
            &[],
            IceTransportPolicy::All,
        )
        .unwrap();
        assert_eq!(creds.username, "1234567890:alice");
    }

    #[test]
    fn mint_different_user_different_credential() {
        let a = mint_credentials(
            "secret",
            "alice",
            1234567890,
            &[],
            &[],
            IceTransportPolicy::All,
        )
        .unwrap();
        let b = mint_credentials(
            "secret",
            "bob",
            1234567890,
            &[],
            &[],
            IceTransportPolicy::All,
        )
        .unwrap();
        assert_ne!(a.username, b.username);
        assert_ne!(a.credential, b.credential);
    }

    #[test]
    fn mint_different_secret_same_username_different_credential() {
        let a = mint_credentials(
            "secret-a",
            "alice",
            1234567890,
            &[],
            &[],
            IceTransportPolicy::All,
        )
        .unwrap();
        let b = mint_credentials(
            "secret-b",
            "alice",
            1234567890,
            &[],
            &[],
            IceTransportPolicy::All,
        )
        .unwrap();
        assert_eq!(a.username, b.username);
        assert_ne!(a.credential, b.credential);
    }

    #[test]
    fn mint_matches_known_vector() {
        // HMAC-SHA1("test-secret", "1234567890:user1") = "Lp3V9X/F/funWfBsr+tLbLcoWiE="
        let creds = mint_credentials(
            "test-secret",
            "user1",
            1234567890,
            &[],
            &[],
            IceTransportPolicy::All,
        )
        .unwrap();
        assert_eq!(creds.username, "1234567890:user1");
        assert_eq!(creds.credential, "Lp3V9X/F/funWfBsr+tLbLcoWiE=");
    }

    #[test]
    fn mint_ttl_is_zero_for_pure_mint() {
        // mint_credentials doesn't set ttl (no Duration param) — caller sets it
        let creds = mint_credentials(
            "secret",
            "user",
            1234567890,
            &[],
            &[],
            IceTransportPolicy::All,
        )
        .unwrap();
        assert_eq!(creds.ttl, 0);
    }

    // --- compute_expiry ---

    #[test]
    fn compute_expiry_basic() {
        assert_eq!(compute_expiry(1000, Duration::from_secs(60)).unwrap(), 1060);
    }

    #[test]
    fn compute_expiry_zero_ttl() {
        let err = compute_expiry(1000, Duration::from_secs(0));
        assert!(matches!(err, Err(TurnError::TtlZero)));
    }

    #[test]
    fn compute_expiry_overflow() {
        let err = compute_expiry(u64::MAX - 10, Duration::from_secs(100));
        assert!(matches!(err, Err(TurnError::TtlOverflow)));
    }

    // --- TurnCredentialIssuer ---

    #[test]
    fn issuer_validates_config_once() {
        let issuer = TurnCredentialIssuer::new(
            "secret",
            Duration::from_secs(3600),
            &["turn:example.com:3478".to_string()],
            &["stun:example.com:3478".to_string()],
        )
        .unwrap();
        let creds = issuer.issue("alice").unwrap();
        assert!(creds.username.ends_with(":alice"));
        assert_eq!(creds.ttl, 3600);
    }

    #[test]
    fn issuer_rejects_invalid_urls_at_construction() {
        let err =
            TurnCredentialIssuer::new("secret", Duration::from_secs(60), &["bad".to_string()], &[]);
        assert!(matches!(err, Err(TurnError::InvalidUrlScheme { .. })));
    }

    #[test]
    fn issuer_rejects_zero_ttl_at_construction() {
        let err = TurnCredentialIssuer::new("secret", Duration::from_secs(0), &[], &[]);
        assert!(matches!(err, Err(TurnError::TtlZero)));
    }

    #[test]
    fn issuer_issue_validates_user_id() {
        let issuer =
            TurnCredentialIssuer::new("secret", Duration::from_secs(60), &[], &[]).unwrap();
        let err = issuer.issue("");
        assert!(matches!(err, Err(TurnError::EmptyUserId)));
    }

    #[test]
    fn issuer_issue_with_policy() {
        let issuer = TurnCredentialIssuer::new(
            "secret",
            Duration::from_secs(60),
            &["turn:example.com:3478".to_string()],
            &[],
        )
        .unwrap();
        let creds = issuer
            .issue_with_policy("bob", IceTransportPolicy::Relay)
            .unwrap();
        assert_eq!(creds.ice_transport_policy, IceTransportPolicy::Relay);
    }

    #[test]
    fn issuer_issue_does_not_revalidate_urls() {
        // Config validated once — issue() only checks user_id
        let issuer = TurnCredentialIssuer::new(
            "secret",
            Duration::from_secs(60),
            &["turn:example.com:3478".to_string()],
            &[],
        )
        .unwrap();
        // This should succeed — URLs were validated at new()
        let creds = issuer.issue("alice").unwrap();
        assert!(!creds.username.is_empty());
    }

    // --- stun_urls_from_turn (#19) ---

    #[test]
    fn stun_urls_from_turn_basic() {
        let turn = vec![
            "turn:example.com:3478?transport=udp".to_string(),
            "turn:example.com:3478?transport=tcp".to_string(),
        ];
        let stun = stun_urls_from_turn(&turn);
        // Both produce stun:example.com:3478 — deduplicated
        assert_eq!(stun, vec!["stun:example.com:3478"]);
    }

    #[test]
    fn stun_urls_from_turns_scheme() {
        let turn = vec!["turns:example.com:5349".to_string()];
        let stun = stun_urls_from_turn(&turn);
        assert_eq!(stun, vec!["stuns:example.com:5349"]);
    }

    #[test]
    fn stun_urls_from_turn_sorted_dedup() {
        let turn = vec![
            "turn:b.com:3478".to_string(),
            "turn:a.com:3478".to_string(),
            "turn:a.com:3478".to_string(),
        ];
        let stun = stun_urls_from_turn(&turn);
        assert_eq!(stun, vec!["stun:a.com:3478", "stun:b.com:3478"]);
    }

    #[test]
    fn stun_urls_from_turn_empty_input() {
        assert!(stun_urls_from_turn(&[]).is_empty());
    }

    #[test]
    fn stun_urls_from_turn_skips_empty_host() {
        let turn = vec!["turn:".to_string(), "turn:example.com:3478".to_string()];
        let stun = stun_urls_from_turn(&turn);
        assert_eq!(stun, vec!["stun:example.com:3478"]);
    }

    // --- MAX_TTL + MIN_SECRET_LEN constants (#20, #21) ---

    #[test]
    fn max_ttl_is_one_hour() {
        assert_eq!(MAX_TTL, Duration::from_secs(3600));
    }

    #[test]
    fn min_secret_len_is_16() {
        assert_eq!(MIN_SECRET_LEN, 16);
    }

    #[test]
    fn issuer_accepts_short_secret_with_warn() {
        // Short secret doesn't fail — just warns (backward compat)
        let issuer = TurnCredentialIssuer::new("short", Duration::from_secs(60), &[], &[]);
        assert!(issuer.is_ok());
    }

    #[test]
    fn issuer_accepts_long_ttl_with_warn() {
        // TTL > MAX_TTL doesn't fail — just warns (backward compat)
        let issuer =
            TurnCredentialIssuer::new("long-enough-secret", Duration::from_secs(7200), &[], &[]);
        assert!(issuer.is_ok());
    }
}
