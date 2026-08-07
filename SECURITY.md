# Security policy

This crate generates coturn-compatible TURN credentials. It is small and it sits
on a credential path, so we treat reports against it seriously.

## Scope

In scope:

- The source in this repository — HMAC-SHA1 credential generation, the
  `TurnCredentials` / `IceServer` types, and the public API surface.
- Anything that would let a caller derive a valid credential without the shared
  secret, or that weakens the credential's time-bounding.

Out of scope:

- coturn itself. Report those upstream to the coturn project.
- The operator's choice of shared secret, its rotation, or its storage — those
  are the deployer's responsibility. This crate takes the secret as a parameter
  and never persists it.
- Weaknesses inherent to the coturn `use-auth-secret` REST scheme itself, which
  is a published standard this crate implements rather than designs. A finding
  that the scheme is weaker than an alternative is interesting but is not a
  vulnerability in this crate.

## How to report

Email `security@oxpulse.chat`.

Include:

- A description of the issue and its impact.
- Steps to reproduce, or a proof-of-concept where applicable.
- Affected versions or commits if known.

Please do not open a public issue for a suspected vulnerability before we have
had a chance to respond.

## What to expect

- Acknowledgement within a few days.
- An assessment of severity and scope, shared with you.
- Coordinated disclosure: we will agree a timeline with you rather than impose
  one, and we will credit you unless you prefer otherwise.

## Supported versions

The latest published version on [crates.io](https://crates.io/crates/oxpulse-turn)
is supported. Older versions are not patched; upgrade instead.
