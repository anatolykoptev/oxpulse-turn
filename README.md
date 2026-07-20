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
- `iceTransportPolicy` control (`"all"` vs `"relay"`) to optionally force relay
  and hide client IPs.
- Pure function: no async, no I/O, no TURN-server dependency, zero server state.

## Install

```toml
[dependencies]
oxpulse-turn = "0.1"
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

To force relay-only (hide client IPs from peers), override after construction:

```rust
use std::time::Duration;
use oxpulse_turn::{generate_credentials, TurnCredentials};

let creds = TurnCredentials {
    ice_transport_policy: "relay",
    ..generate_credentials("secret", "bob", Duration::from_secs(300), &[], &[])
};
```

## How it works

`username = "<unix_expiry>:<user_id>"` where `unix_expiry = now + ttl`.
`credential = base64(HMAC-SHA1(secret, username))`.

coturn recomputes the same HMAC from its `static-auth-secret` and accepts the
credential until `unix_expiry` passes — so credentials are self-expiring and the
TURN server never needs to know about individual users.

## License

Licensed under **AGPL-3.0-or-later**. See [LICENSE](LICENSE).

Part of [oxpulse](https://oxpulse.chat) — an end-to-end-encrypted group-calling stack.
