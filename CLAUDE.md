# CLAUDE.md

Notes for coding agents working in oxpulse-turn: a small Rust library that mints coturn
REST-API (`use-auth-secret`) time-limited TURN/STUN credentials and describes them as WebRTC
`iceServers`. Every document is indexed in [docs/INDEX.md](docs/INDEX.md).

## Layout

The whole crate is `src/lib.rs` (types, validation, minting, issuer, unit tests and doctests in
one file). Optional features: `chrono` (an `expires_at` field) and `openapi` (`utoipa::ToSchema`
derives). `Cargo.lock` is committed on purpose, because CI builds with `--locked`.

## Gate

CI (`.github/workflows/preflight.yml`, job `clippy + tests`) runs exactly:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --locked --release
```

A docs-only PR (Markdown, `docs/`, licence, issue and PR templates) skips that job through the
`docs-scope` job in the same workflow. That block is canonical across the fleet and is compared
byte for byte, so do not edit it here.

## Invariants that are easy to break

- **The credential format is a wire contract.** `username = "<unix_expiry>:<user_id>"`,
  `credential = base64(HMAC-SHA1(secret, username))`. A deployed coturn validates exactly this;
  changing it invalidates every live credential. Anything that changes the format or the public
  API needs an issue first.
- **Unknown input must never fall back to `IceTransportPolicy::All`.** `All` exposes the client's IP
  to the peer. Parsing goes through `FromStr` and returns `TurnError::UnknownIceTransportPolicy`;
  do not add a `_ => All` arm anywhere.
- **`:` is the separator.** `user_id` must stay free of `:` and control characters and within
  `MAX_USER_ID_LEN`; TURN/STUN URL schemes and non-empty hosts are validated.
- **Secrets are held in `Zeroizing` and must never be logged, formatted into errors or put in tests'
  panic messages.** Lenient mode only warns about short secrets and long TTLs; strict mode
  (`new_strict`, `new_multi_strict`) rejects them. Keep both behaviours.
- **The crate is a pure function of its inputs.** No async, no I/O, no TURN-server dependency. The
  `*_credentials` functions read the clock; `mint_credentials` + `compute_expiry` take it as an
  argument and are what tests should use.
- **Versions come from release-please**, which reads Conventional Commits (`feat`, `fix`, `docs`,
  `chore`, `refactor`). Never tag or edit the version, `CHANGELOG.md` or
  `.release-please-manifest.json` by hand.
- **The licence is AGPL-3.0-or-later and contributions need the CLA** in [CLA.md](CLA.md). Do not
  change `LICENSE` or the `license` field in `Cargo.toml`.
- **This repository is public.** No hostnames, operator paths, account names, tokens or personal
  data in any tracked file, tests and fixtures included.
