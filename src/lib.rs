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
//! | **Issuer (strict)** | [`TurnCredentialIssuer::new_strict`] | Same, but rejects short secrets / long TTLs instead of warning |
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

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::Sha1;
use zeroize::Zeroizing;

type HmacSha1 = Hmac<Sha1>;

/// Errors that can occur during TURN credential generation.
///
/// `#[non_exhaustive]` — new variants may be added in minor releases without a
/// breaking change. Callers should not match exhaustively without a `_` arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
    #[error("user_id must not exceed {0} chars")]
    UserIdTooLong(usize),
    #[error("URL must start with one of {expected:?}: got {url:?}")]
    InvalidUrlScheme {
        expected: &'static [&'static str],
        url: String,
    },
    #[error("URL must have a non-empty host after the scheme: got {url:?}")]
    EmptyHost { url: String },
    #[error("system clock before unix epoch")]
    ClockBeforeEpoch,
    #[error("secrets must be non-empty")]
    EmptySecrets,
    #[error("secret must be at least {0} bytes for HMAC-SHA1 security")]
    SecretTooShort(usize),
    #[error("ttl {0:?} exceeds recommended max of {MAX_TTL:?} — long-lived credentials weaken time-bounding")]
    TtlTooLong(Duration),
    #[error("expiry {0} is out of range for chrono::DateTime conversion")]
    ExpiryOutOfRange(u64),
    #[error("unknown ice transport policy: {0:?} (expected \"all\" or \"relay\")")]
    UnknownIceTransportPolicy(String),
}

/// ICE transport policy for WebRTC `RTCPeerConnection`.
///
/// `"all"` allows all candidates (host, server-reflexive, relay);
/// `"relay"` forces TURN relay only, hiding client IPs from peers.
///
/// Convert from a string with [`FromStr`][std::str::FromStr] and back with
/// [`as_str`]. **Do not** hand-roll a `match` with a `_ => All` default —
/// `All` exposes the client's IP to the peer, so a silent fallback is a
/// security downgrade, not a cosmetic one.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum IceTransportPolicy {
    /// Use all ICE candidates (default).
    #[default]
    All,
    /// Force TURN relay only — hides client IPs from peers.
    Relay,
}

impl IceTransportPolicy {
    /// Return the wire string (`"all"` or `"relay"`) for this policy.
    ///
    /// Useful for feeding a metrics label or log field without going through
    /// `serde_json::to_string` and trimming quotes.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Relay => "relay",
        }
    }
}

impl std::str::FromStr for IceTransportPolicy {
    type Err = TurnError;

    /// Parse `"all"` or `"relay"` (case-sensitive) into [`IceTransportPolicy`].
    ///
    /// Returns [`TurnError::UnknownIceTransportPolicy`] for any other string.
    /// This forces the caller to handle the unknown case explicitly instead of
    /// silently defaulting to `All` (which would expose client IPs).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "all" => Ok(Self::All),
            "relay" => Ok(Self::Relay),
            other => Err(TurnError::UnknownIceTransportPolicy(other.to_string())),
        }
    }
}

/// TURN/STUN server entry for ICE negotiation.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Clone, Serialize)]
pub struct IceServer {
    pub urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

/// Temporary TURN credentials (coturn REST API compatible).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Clone, Serialize)]
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
    /// Human-readable expiry timestamp (RFC 3339). Only present when the
    /// `chrono` feature is enabled.
    #[cfg(feature = "chrono")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Pre-validated TURN credential issuer for server use cases.
///
/// Validates configuration (secret, URLs, TTL) **once** at construction,
/// then mints credentials per-request without repeating validation. This is
/// the recommended API for servers that mint credentials on a hot path.
///
/// Supports rolling key rotation: [`TurnCredentialIssuer::new_multi`] accepts
/// multiple secrets (active + alternates). [`TurnCredentialIssuer::rotate`]
/// inserts a new active secret; [`TurnCredentialIssuer::drop_oldest`] removes
/// the oldest after the rotation window expires.
///
/// **Strict mode:** [`new_strict`] / [`new_multi_strict`] reject short secrets
/// (< [`MIN_SECRET_LEN`]) and long TTLs (> [`MAX_TTL`]) with errors instead of
/// log warnings. Use these in security-conscious deployments.
///
/// **Secret hygiene:** secrets are stored as [`Zeroizing<String>`] and
/// overwritten on drop — see the `zeroize` crate.
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
#[derive(Clone)]
pub struct TurnCredentialIssuer {
    /// `[0]` = active (mint), `[1..]` = alternates (accepted by coturn during rotation overlap).
    /// Wrapped in [`Zeroizing`] so secret bytes are overwritten on drop.
    secrets: Vec<Zeroizing<String>>,
    ttl: Duration,
    turn_urls: Vec<String>,
    stun_urls: Vec<String>,
}

impl TurnCredentialIssuer {
    /// Create a new issuer with a single secret, validating configuration once.
    ///
    /// Short secrets (< [`MIN_SECRET_LEN`]) and long TTLs (> [`MAX_TTL`]) are
    /// accepted with a log warning. Use [`new_strict`] to reject them.
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
        Self::new_multi(vec![secret.to_string()], ttl, turn_urls, stun_urls)
    }

    /// Create a new issuer with multiple secrets for rolling rotation.
    ///
    /// `secrets[0]` is the active secret (used for minting). `secrets[1..]`
    /// are alternates — coturn accepts credentials minted with any of them
    /// during the rotation overlap window.
    ///
    /// Short secrets (< [`MIN_SECRET_LEN`]) and long TTLs (> [`MAX_TTL`]) are
    /// accepted with a log warning. Use [`new_multi_strict`] to reject them.
    ///
    /// # Errors
    ///
    /// Returns [`TurnError`] if `secrets` is empty, URLs are invalid, or TTL is zero.
    pub fn new_multi(
        secrets: Vec<String>,
        ttl: Duration,
        turn_urls: &[String],
        stun_urls: &[String],
    ) -> Result<Self, TurnError> {
        Self::build(secrets, ttl, turn_urls, stun_urls, false)
    }

    /// Like [`new`] but rejects short secrets (< [`MIN_SECRET_LEN`]) and long
    /// TTLs (> [`MAX_TTL`]) with [`TurnError::SecretTooShort`] /
    /// [`TurnError::TtlTooLong`] instead of warning.
    ///
    /// # Errors
    ///
    /// Returns [`TurnError`] if the secret is too short, TTL is too long,
    /// URLs are invalid, or TTL is zero.
    pub fn new_strict(
        secret: &str,
        ttl: Duration,
        turn_urls: &[String],
        stun_urls: &[String],
    ) -> Result<Self, TurnError> {
        Self::new_multi_strict(vec![secret.to_string()], ttl, turn_urls, stun_urls)
    }

    /// Like [`new_multi`] but rejects short secrets and long TTLs instead of
    /// warning. See [`new_strict`].
    ///
    /// # Errors
    ///
    /// Returns [`TurnError`] if any secret is too short, TTL is too long,
    /// `secrets` is empty, URLs are invalid, or TTL is zero.
    pub fn new_multi_strict(
        secrets: Vec<String>,
        ttl: Duration,
        turn_urls: &[String],
        stun_urls: &[String],
    ) -> Result<Self, TurnError> {
        Self::build(secrets, ttl, turn_urls, stun_urls, true)
    }

    /// Shared constructor core for both lenient and strict modes.
    fn build(
        secrets: Vec<String>,
        ttl: Duration,
        turn_urls: &[String],
        stun_urls: &[String],
        strict: bool,
    ) -> Result<Self, TurnError> {
        if secrets.is_empty() {
            return Err(TurnError::EmptySecrets);
        }
        validate_urls(turn_urls, TURN_SCHEMES)?;
        validate_urls(stun_urls, STUN_SCHEMES)?;
        if ttl.is_zero() {
            return Err(TurnError::TtlZero);
        }
        for secret in &secrets {
            if secret.len() < MIN_SECRET_LEN {
                if strict {
                    return Err(TurnError::SecretTooShort(MIN_SECRET_LEN));
                }
                log::warn!(
                    "TURN secret is only {} bytes — recommend >= {} for HMAC-SHA1 security",
                    secret.len(),
                    MIN_SECRET_LEN
                );
            }
        }
        if ttl > MAX_TTL {
            if strict {
                return Err(TurnError::TtlTooLong(ttl));
            }
            log::warn!(
                "TURN TTL {:?} exceeds recommended max of {:?} — long-lived credentials weaken time-bounding",
                ttl,
                MAX_TTL
            );
        }
        Ok(Self {
            secrets: secrets.into_iter().map(Zeroizing::new).collect(),
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
            &self.secrets[0],
            user_id,
            expiry,
            &self.turn_urls,
            &self.stun_urls,
            policy,
        )?;
        // Zeroizing<String> derefs to String → &str, so &self.secrets[0] works.
        creds.ttl = self.ttl.as_secs();
        Ok(creds)
    }

    /// Rotate: insert a new active secret, pushing the current one to alternate.
    ///
    /// After rotation, `secrets[0]` is the new active (mint), `secrets[1]` is
    /// the previous active (still accepted by coturn during overlap).
    pub fn rotate(&mut self, new_secret: String) {
        self.secrets.insert(0, Zeroizing::new(new_secret));
    }

    /// Drop the oldest secret after the rotation window expires.
    ///
    /// Keeps at least one secret (the active). Call this after all credentials
    /// minted with the old secret have expired.
    pub fn drop_oldest(&mut self) {
        if self.secrets.len() > 1 {
            self.secrets.pop();
        }
    }

    /// Number of secrets currently held (active + alternates).
    #[must_use]
    pub fn secret_count(&self) -> usize {
        self.secrets.len()
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

/// Maximum allowed `user_id` length (384 chars).
///
/// Generous: UUID is 36, email ~50, opaque ID ~64. A pathologically long
/// `user_id` bloats the username/credential and coturn's parsing. Reference:
/// flow-turn's 384-char limit.
pub const MAX_USER_ID_LEN: usize = 384;

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
    if user_id.len() > MAX_USER_ID_LEN {
        return Err(TurnError::UserIdTooLong(MAX_USER_ID_LEN));
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
        #[cfg(feature = "chrono")]
        expires_at: i64::try_from(expiry_unix)
            .ok()
            .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0)),
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

// Manual `Debug` impls: secrets and credentials must never reach logs via `{:?}`.
// (`Zeroizing<String>` derives `Debug` that prints the value in zeroize <= 1.9.0.)

impl fmt::Debug for IceServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IceServer")
            .field("urls", &self.urls)
            .field("username", &self.username)
            .field(
                "credential",
                &self.credential.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl fmt::Debug for TurnCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("TurnCredentials");
        d.field("username", &self.username)
            .field("credential", &"[REDACTED]")
            .field("ttl", &self.ttl)
            .field("ice_servers", &self.ice_servers)
            .field("ice_transport_policy", &self.ice_transport_policy);
        #[cfg(feature = "chrono")]
        d.field("expires_at", &self.expires_at);
        d.finish()
    }
}

impl fmt::Debug for TurnCredentialIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnCredentialIssuer")
            .field(
                "secrets",
                &format_args!("[REDACTED; {}]", self.secrets.len()),
            )
            .field("ttl", &self.ttl)
            .field("turn_urls", &self.turn_urls)
            .field("stun_urls", &self.stun_urls)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // --- Debug redaction ---

    #[test]
    fn issuer_debug_redacts_secrets() {
        let issuer = TurnCredentialIssuer::new_multi(
            vec![
                "CANARY_one_not_a_secret_0123456789abcdef".to_string(),
                "CANARY_two_not_a_secret_0123456789abcdef".to_string(),
            ],
            Duration::from_secs(3600),
            &["turn:turn.example.com:3478".to_string()],
            &["stun:stun.example.com:3478".to_string()],
        )
        .unwrap();
        let dbg = format!("{:?}", issuer);
        assert!(!dbg.contains("CANARY_one"), "secret leaked in Debug: {dbg}");
        assert!(!dbg.contains("CANARY_two"), "secret leaked in Debug: {dbg}");
        assert!(
            dbg.contains("secrets: [REDACTED; 2]"),
            "unexpected Debug: {dbg}"
        );
        assert!(dbg.contains("turn:turn.example.com:3478"));
    }

    #[test]
    fn credentials_debug_redacts_credential_but_serde_keeps_it() {
        let creds = generate_credentials(
            "test-secret",
            "user1",
            Duration::from_secs(3600),
            &["turn:example.com:3478".to_string()],
            &[],
        );
        let cred = creds.credential.clone();
        let ice_cred = creds.ice_servers[0].credential.clone().unwrap();
        let dbg = format!("{:?}", creds);
        assert!(!dbg.contains(&cred), "credential leaked in Debug: {dbg}");
        assert!(
            !dbg.contains(&ice_cred),
            "ice credential leaked in Debug: {dbg}"
        );
        assert!(
            dbg.contains("credential: \"[REDACTED]\""),
            "unexpected Debug: {dbg}"
        );
        assert!(dbg.contains("user1"));
        let json = serde_json::to_string(&creds).unwrap();
        assert!(json.contains(&cred));
        assert!(json.contains(&ice_cred));
    }

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

    // --- user_id length limit (#24) ---

    #[test]
    fn max_user_id_len_is_384() {
        assert_eq!(MAX_USER_ID_LEN, 384);
    }

    #[test]
    fn try_generate_user_id_too_long() {
        let long_id = "a".repeat(MAX_USER_ID_LEN + 1);
        let err = try_generate_credentials("secret", &long_id, Duration::from_secs(60), &[], &[]);
        assert!(matches!(err, Err(TurnError::UserIdTooLong(384))));
    }

    #[test]
    fn try_generate_user_id_exactly_at_limit() {
        let id = "a".repeat(MAX_USER_ID_LEN);
        let result = try_generate_credentials("secret", &id, Duration::from_secs(60), &[], &[]);
        assert!(result.is_ok());
    }

    #[test]
    #[should_panic(expected = "user_id must not exceed")]
    fn long_user_id_panics() {
        let long_id = "a".repeat(MAX_USER_ID_LEN + 1);
        generate_credentials("secret", &long_id, Duration::from_secs(60), &[], &[]);
    }

    // --- Multi-secret rotation (#25) ---

    #[test]
    fn new_multi_creates_issuer_with_multiple_secrets() {
        let issuer = TurnCredentialIssuer::new_multi(
            vec![
                "active-secret-12345".to_string(),
                "old-secret-123456".to_string(),
            ],
            Duration::from_secs(60),
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(issuer.secret_count(), 2);
    }

    #[test]
    fn new_multi_rejects_empty_secrets() {
        let err = TurnCredentialIssuer::new_multi(vec![], Duration::from_secs(60), &[], &[]);
        assert!(matches!(err, Err(TurnError::EmptySecrets)));
    }

    #[test]
    fn rotate_inserts_new_active_secret() {
        let mut issuer =
            TurnCredentialIssuer::new("first-secret-12345", Duration::from_secs(60), &[], &[])
                .unwrap();
        assert_eq!(issuer.secret_count(), 1);

        issuer.rotate("second-secret-1234".to_string());
        assert_eq!(issuer.secret_count(), 2);
    }

    #[test]
    fn drop_oldest_removes_old_secret() {
        let mut issuer = TurnCredentialIssuer::new_multi(
            vec![
                "active-secret-12345".to_string(),
                "old-secret-123456".to_string(),
            ],
            Duration::from_secs(60),
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(issuer.secret_count(), 2);

        issuer.drop_oldest();
        assert_eq!(issuer.secret_count(), 1);
    }

    #[test]
    fn drop_oldest_keeps_at_least_one() {
        let mut issuer =
            TurnCredentialIssuer::new("only-secret-12345", Duration::from_secs(60), &[], &[])
                .unwrap();
        assert_eq!(issuer.secret_count(), 1);

        issuer.drop_oldest();
        assert_eq!(issuer.secret_count(), 1);
    }

    #[test]
    fn rotation_mints_with_new_active_secret() {
        let mut issuer =
            TurnCredentialIssuer::new("first-secret-12345", Duration::from_secs(60), &[], &[])
                .unwrap();
        let creds_before = issuer.issue("alice").unwrap();

        issuer.rotate("second-secret-1234".to_string());
        let creds_after = issuer.issue("alice").unwrap();

        // Same user, same time window → username may match, but credential
        // differs because the active secret changed
        assert_ne!(creds_before.credential, creds_after.credential);
    }

    // --- Strict mode (#33, #34) ---

    #[test]
    fn strict_rejects_short_secret() {
        let err = TurnCredentialIssuer::new_strict("short", Duration::from_secs(60), &[], &[]);
        assert!(matches!(
            err,
            Err(TurnError::SecretTooShort(MIN_SECRET_LEN))
        ));
    }

    #[test]
    fn strict_accepts_long_enough_secret() {
        let issuer = TurnCredentialIssuer::new_strict(
            "long-enough-secret",
            Duration::from_secs(60),
            &[],
            &[],
        );
        assert!(issuer.is_ok());
    }

    #[test]
    fn strict_rejects_long_ttl() {
        let err = TurnCredentialIssuer::new_strict(
            "long-enough-secret",
            Duration::from_secs(7200),
            &[],
            &[],
        );
        assert!(matches!(err, Err(TurnError::TtlTooLong(_))));
    }

    #[test]
    fn strict_accepts_max_ttl() {
        let issuer = TurnCredentialIssuer::new_strict("long-enough-secret", MAX_TTL, &[], &[]);
        assert!(issuer.is_ok());
    }

    #[test]
    fn strict_multi_rejects_any_short_secret() {
        let err = TurnCredentialIssuer::new_multi_strict(
            vec!["long-enough-secret".to_string(), "short".to_string()],
            Duration::from_secs(60),
            &[],
            &[],
        );
        assert!(matches!(err, Err(TurnError::SecretTooShort(_))));
    }

    #[test]
    fn lenient_still_accepts_short_secret_and_long_ttl() {
        // Backward compat: new() still warns instead of rejecting
        let issuer = TurnCredentialIssuer::new("short", Duration::from_secs(7200), &[], &[]);
        assert!(issuer.is_ok());
    }

    // --- IceTransportPolicy FromStr + as_str (#30) ---

    #[test]
    fn policy_from_str_all() {
        let policy: IceTransportPolicy = "all".parse().unwrap();
        assert_eq!(policy, IceTransportPolicy::All);
    }

    #[test]
    fn policy_from_str_relay() {
        let policy: IceTransportPolicy = "relay".parse().unwrap();
        assert_eq!(policy, IceTransportPolicy::Relay);
    }

    #[test]
    fn policy_from_str_unknown_rejects() {
        let err: Result<IceTransportPolicy, _> = "unknown".parse();
        assert!(matches!(err, Err(TurnError::UnknownIceTransportPolicy(_))));
    }

    #[test]
    fn policy_from_str_case_sensitive() {
        let err: Result<IceTransportPolicy, _> = "All".parse();
        assert!(err.is_err(), "from_str should be case-sensitive");
    }

    #[test]
    fn policy_as_str_roundtrip() {
        for policy in [IceTransportPolicy::All, IceTransportPolicy::Relay] {
            let s = policy.as_str();
            let back: IceTransportPolicy = s.parse().unwrap();
            assert_eq!(policy, back, "as_str → from_str roundtrip failed for {s}");
        }
    }

    #[test]
    fn policy_as_str_matches_serde_output() {
        let all = generate_credentials("secret", "user", Duration::from_secs(60), &[], &[]);
        assert_eq!(all.ice_transport_policy.as_str(), "all");

        let relay = generate_credentials_with_policy(
            "secret",
            "user",
            Duration::from_secs(60),
            &[],
            &[],
            IceTransportPolicy::Relay,
        );
        assert_eq!(relay.ice_transport_policy.as_str(), "relay");
    }

    // --- chrono overflow (#35) ---

    #[cfg(feature = "chrono")]
    #[test]
    fn chrono_expires_at_none_on_overflow() {
        // u64::MAX cannot be converted to i64 — expires_at should be None
        // rather than silently wrapping to a negative timestamp.
        let creds = mint_credentials(
            "secret",
            "user",
            u64::MAX,
            &[],
            &[],
            IceTransportPolicy::All,
        )
        .unwrap();
        assert!(
            creds.expires_at.is_none(),
            "expires_at should be None for u64::MAX"
        );
        // username and credential are still valid
        assert!(creds.username.contains("18446744073709551615"));
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn chrono_expires_at_some_for_normal_value() {
        let creds = mint_credentials(
            "secret",
            "user",
            1_700_000_000,
            &[],
            &[],
            IceTransportPolicy::All,
        )
        .unwrap();
        assert!(creds.expires_at.is_some());
    }
}
