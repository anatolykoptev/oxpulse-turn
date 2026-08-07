# oxpulse-turn

[![crates.io](https://img.shields.io/crates/v/oxpulse-turn.svg)](https://crates.io/crates/oxpulse-turn)
|[![docs.rs](https://img.shields.io/docsrs/oxpulse-turn)](https://docs.rs/oxpulse-turn)
|[![license: AGPL-3.0-or-later](https://img.shields.io/crates/l/oxpulse-turn.svg)](#license)

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
  to optionally force relay and hide client IPs.
- Input validation: rejects empty `user_id`, `:` in `user_id`, control
  characters, invalid URL schemes, and zero TTL.
- Pure function: no async, no I/O, no TURN-server dependency, zero server state.

## Install

```toml
[dependencies]
oxpulse-turn = "0.2"
```

## Usage

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

Point coturn at the same secret:

```ini
# turnserver.conf
use-auth-secret
static-auth-secret=shared-secret-configured-on-coturn
```

To force relay-only (hide client IPs from peers), use `generate_credentials_with_policy`:

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

## Validation

`generate_credentials` panics on invalid inputs (programmer errors):

- `ttl` is zero or so large that `now + ttl` overflows `u64`.
- `user_id` is empty, contains `':'` (reserved as the coturn separator), or
  contains control characters.
- URLs don't start with the expected scheme (`turn:`/`turns:` for TURN,
  `stun:`/`stuns:` for STUN) or have an empty host.

## Clock synchronisation

The credential expiry is derived from `SystemTime::now()`. Ensure the caller's
system clock is synchronised with the TURN server (e.g. via NTP). Clock skew
causes credentials to expire early or late.

## How it works

`username = "<unix_expiry>:<user_id>"` where `unix_expiry = now + ttl`.
`credential = base64(HMAC-SHA1(secret, username))`.

coturn recomputes the same HMAC from its `static-auth-secret` and accepts the
credential until `unix_expiry` passes — so credentials are self-expiring and the
TURN server never needs to know about individual users.

## License

Licensed under **AGPL-3.0-or-later**. See [LICENSE](LICENSE).

Part of [oxpulse](https://oxpulse.chat) — an end-to-end-encrypted group-calling stack.
