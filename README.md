# oxpulse-turn

[![crates.io](https://img.shields.io/crates/v/oxpulse-turn.svg)](https://crates.io/crates/oxpulse-turn)
[![docs.rs](https://img.shields.io/docsrs/oxpulse-turn)](https://docs.rs/oxpulse-turn)
[![license: AGPL-3.0-or-later](https://img.shields.io/crates/l/oxpulse-turn.svg)](#license)

Short-lived **TURN/STUN credentials** for WebRTC ICE, compatible with the
[coturn](https://github.com/coturn/coturn) REST-API time-limited credential
scheme (`use-auth-secret` / `static-auth-secret`).

Given a secret shared with your TURN server, this crate mints an ephemeral
`username` / `credential` pair that any coturn instance configured with the same
secret accepts — **no per-user state on the TURN server, no database round-trip.**
The credential is `base64(HMAC-SHA1(secret, "<expiry>:<user>"))`, exactly the
format coturn's `--use-auth-secret` validates.

## Features

- coturn REST-API-compatible time-limited credentials (`HMAC-SHA1`).
- Builds a ready-to-serialize `iceServers` array (STUN + TURN) for an
  `RTCPeerConnection` config — `serde::Serialize`, camelCase-correct.
- `iceTransportPolicy` control via `IceTransportPolicy` enum (`All` vs `Relay`)
  to optionally force relay and hide client IPs. Parse from a string with
  `FromStr` and convert back with `as_str()` — no hand-rolled `match` with a
  silent `_ => All` default (that would leak client IPs on unknown input).
- Input validation: rejects empty `user_id`, `:` in `user_id`, control
  characters, `user_id` over 384 chars, invalid URL schemes, and zero TTL.
- `TurnCredentialIssuer` for server use: validate config once at startup,
  `.issue()` per request. Supports rolling key rotation (`new_multi`, `rotate`,
  `drop_oldest`) and a strict mode that rejects short secrets / long TTLs
  (`new_strict`, `new_multi_strict`).
- `stun_urls_from_turn` helper: derive STUN URLs from your TURN pool by
  swapping the scheme — no need to configure STUN separately when it's the same
  host (the common case).
- Secrets are zeroized from memory on drop (`zeroize` crate).
- Pure function: no async, no I/O, no TURN-server dependency, zero server state.
- MSRV: 1.70.

## Install

```toml
[dependencies]
oxpulse-turn = "0.2"
```

### Feature flags

| Feature | Default | What it enables |
|---|---|---|
| `chrono` | off | `expires_at: Option<chrono::DateTime<Utc>>` field on `TurnCredentials` (RFC 3339 timestamp). Without it, only the numeric expiry in `username` is available. |
| `openapi` | off | `utoipa::ToSchema` derives on `TurnCredentials`, `IceServer`, `IceTransportPolicy` — for embedding in an OpenAPI document. |

```toml
# Enable both:
oxpulse-turn = { version = "0.2", features = ["chrono", "openapi"] }
```

## API layers

| Layer | Function | When to use |
|---|---|---|
| **Issuer** | `TurnCredentialIssuer::new` / `new_multi` | Server: validate config once at startup, `.issue()` per request |
| **Issuer (strict)** | `TurnCredentialIssuer::new_strict` / `new_multi_strict` | Same, but rejects short secrets / long TTLs instead of warning |
| **Pure mint** | `mint_credentials` + `compute_expiry` | Deterministic minting with caller-supplied expiry (testable, no `SystemTime`) |
| **Try** | `try_generate_credentials` | One-shot mint returning `Result` (no panic) |
| **Panic** | `generate_credentials` | Simple use cases (panics on invalid input) |

## Usage

### One-shot (simple)

```rust
use std::time::Duration;
use oxpulse_turn::generate_credentials;

let creds = generate_credentials(
    "shared-secret-configured-on-coturn",
    "alice",                                    // opaque user id
    Duration::from_secs(3600),                  // credential TTL
    &["turn:turn.example.com:3478?transport=udp".to_string()],
    &["stun:stun.example.com:3478".to_string()],
);

assert!(creds.username.ends_with(":alice"));
assert_eq!(creds.ttl, 3600);

// `creds` serializes straight into an RTCPeerConnection config:
// { "username", "credential", "ttl", "iceServers": [...], "iceTransportPolicy": "all" }
let json = serde_json::to_string(&creds).unwrap();
```

For a `Result`-returning variant (no panic), use `try_generate_credentials`.

### Server (recommended)

`TurnCredentialIssuer` validates configuration once at construction, then mints
credentials per-request without repeating validation — the right choice for a
hot path:

```rust
use std::time::Duration;
use oxpulse_turn::TurnCredentialIssuer;

let issuer = TurnCredentialIssuer::new(
    "shared-secret-configured-on-coturn",
    Duration::from_secs(3600),
    &["turn:turn.example.com:3478".to_string()],
    &["stun:stun.example.com:3478".to_string()],
)?;

// Per-request: only user_id is validated (config already checked)
let creds = issuer.issue("alice")?;
```

Use `new_strict` / `new_multi_strict` to reject short secrets (< 16 bytes) and
long TTLs (> 1 hour) with errors instead of log warnings:

```rust
let issuer = TurnCredentialIssuer::new_strict(
    "a- sufficiently-long-secret",
    Duration::from_secs(3600),
    &["turn:turn.example.com:3478".to_string()],
    &[],
)?;
```

### Relay-only (hide client IPs)

To force TURN relay and hide client IPs from peers, use
`generate_credentials_with_policy` or `issue_with_policy`:

```rust
use std::time::Duration;
use oxpulse_turn::{generate_credentials_with_policy, IceTransportPolicy};

let creds = generate_credentials_with_policy(
    "secret",
    "bob",
    Duration::from_secs(300),
    &["turn:turn.example.com:3478".to_string()],
    &[],
    IceTransportPolicy::Relay,
);
```

### Deriving STUN URLs from TURN

`stun_urls_from_turn` swaps the scheme (`turn:` → `stun:`, `turns:` → `stuns:`),
strips query strings, deduplicates, and sorts — no need to configure STUN
separately when it's the same host:

```rust
use oxpulse_turn::stun_urls_from_turn;

let turn_urls = vec![
    "turn:turn.example.com:3478?transport=udp".to_string(),
    "turn:turn.example.com:3478?transport=tcp".to_string(),
];
let stun_urls = stun_urls_from_turn(&turn_urls);
assert_eq!(stun_urls, vec!["stun:turn.example.com:3478"]);
```

### Key rotation

`new_multi` accepts multiple secrets (active + alternates). `rotate` inserts a
new active secret; `drop_oldest` removes the oldest after the rotation overlap
window expires:

```rust
use std::time::Duration;
use oxpulse_turn::TurnCredentialIssuer;

let mut issuer = TurnCredentialIssuer::new_multi(
    vec!["old-secret-configured-on-coturn".to_string()],
    Duration::from_secs(3600),
    &["turn:turn.example.com:3478".to_string()],
    &[],
)?;

// Deploy new secret on coturn, then rotate:
issuer.rotate("new-secret-configured-on-coturn".to_string());
// coturn now accepts credentials minted with either secret.
// After all old credentials expire:
issuer.drop_oldest();
```

## Point coturn at the same secret

```ini
# turnserver.conf
use-auth-secret
static-auth-secret=shared-secret-configured-on-coturn
```

coturn recomputes the same HMAC from its `static-auth-secret` and accepts the
credential until `unix_expiry` passes — so credentials are self-expiring and the
TURN server never needs to know about individual users.

## Migrating from 0.1.x

The only breaking change in 0.2.0 is the `ice_transport_policy` field type:
`&'static str` → `IceTransportPolicy` enum. The serde JSON output is unchanged
(`"all"`/`"relay"`), so the wire format is identical.

If your decision function returns `&str` (e.g. because the same value feeds a
Prometheus label), bridge at the single construction site instead of converting
your whole call chain:

```rust
use std::str::FromStr;
use oxpulse_turn::IceTransportPolicy;

// Your existing function returns &str — keep it.
fn decide_policy(user: &User) -> &'static str { /* ... */ "relay" }

// Bridge at the call site — FromStr forces you to handle the unknown case.
let policy = IceTransportPolicy::from_str(decide_policy(&user))?;
```

**Do not** hand-roll `match s { "relay" => Relay, _ => All }` — the `_ => All`
arm is a **security** default, not a cosmetic one. `All` exposes the client's IP
to the peer; `Relay` hides it. A typo or a future third variant silently
becomes `All` and de-anonymises a user with no error and no log. `FromStr`
returns `TurnError::UnknownIceTransportPolicy` on unknown input, forcing you to
handle it.

For the reverse direction (enum → `&str` for a metrics label), use
`IceTransportPolicy::as_str()`.

## Validation

`generate_credentials` panics on invalid inputs (programmer errors).
`try_generate_credentials` returns `Result` instead — use it when inputs come
from untrusted sources.

- `ttl` is zero or so large that `now + ttl` overflows `u64`.
- `user_id` is empty, contains `':'` (reserved as the coturn separator),
  contains control characters, or exceeds 384 chars (`MAX_USER_ID_LEN`).
- URLs don't start with the expected scheme (`turn:`/`turns:` for TURN,
  `stun:`/`stuns:` for STUN) or have an empty host.

In strict mode (`new_strict` / `new_multi_strict`), short secrets
(< `MIN_SECRET_LEN` = 16 bytes) and long TTLs (> `MAX_TTL` = 1 hour) are also
rejected. In lenient mode (the default), they are accepted with a log warning.

## Clock synchronisation

The credential expiry is derived from `SystemTime::now()`. Ensure the caller's
system clock is synchronised with the TURN server (e.g. via NTP). Clock skew
causes credentials to expire early or late.

## How it works

`username = "<unix_expiry>:<user_id>"` where `unix_expiry = now + ttl`.
`credential = base64(HMAC-SHA1(secret, username))`.

## License

Licensed under **AGPL-3.0-or-later**. See [LICENSE](LICENSE).

Part of [oxpulse](https://oxpulse.chat) — an end-to-end-encrypted group-calling stack.
