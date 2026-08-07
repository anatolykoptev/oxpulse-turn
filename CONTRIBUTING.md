# Contributing

This crate was extracted from the OxPulse monorepo so that a published AGPL
artifact has browsable source, an issue tracker, and a way to receive a patch.
Contributions are welcome on that basis.

## Before you start

Small and obvious fixes — open a PR directly. Anything that changes the public
API or the credential format, open an issue first: this crate has a downstream
consumer whose deployments depend on the credentials remaining valid.

## Scope of the crate

It does one thing: generate coturn `use-auth-secret` REST credentials
(HMAC-SHA1) and describe them as ICE servers. Please keep it that way. Transport
selection, relay health, and anything that reaches the network belong elsewhere.

## Development

```sh
cargo test                    # unit tests + doctests
cargo clippy -- -D warnings   # the CI gate; warnings are errors
cargo fmt
```

CI runs exactly `cargo clippy -- -D warnings` and `cargo test` on
`ubuntu-24.04-arm`. If those pass locally they will pass there.

## Commits

Conventional commits — `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`. The
release pipeline reads them: `feat:` produces a minor bump, `fix:` a patch, and
`feat!:` or a `BREAKING CHANGE:` footer a major one. A commit that does not parse
is silently excluded from the release, so keep the subject clean and put code
fragments in the body rather than the subject line.

Explain **why** in the body. The diff already shows what changed.

## Releases

Automated. Merging to `main` updates a release PR; merging that PR tags the
release and publishes to crates.io. Never tag by hand — it desynchronises the
release manifest.

## Licence and CLA

AGPL-3.0-or-later. Contributions require the CLA in [`CLA.md`](CLA.md); see that
file for how to sign. Code of conduct: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Security

Do not open a public issue for a suspected vulnerability — see
[`SECURITY.md`](SECURITY.md).
