# Changelog

## [0.2.0](https://github.com/anatolykoptev/oxpulse-turn/compare/v0.1.2...v0.2.0) (2026-08-07)


### ⚠ BREAKING CHANGES

* ice_transport_policy field type changes from &'static str to IceTransportPolicy enum. The serde JSON output is unchanged ("all"/"relay"), but consumers constructing TurnCredentials directly must use the enum.

### Features

* expires_at, ToSchema, user_id limit, key rotation (closes [#22](https://github.com/anatolykoptev/oxpulse-turn/issues/22), [#23](https://github.com/anatolykoptev/oxpulse-turn/issues/23), [#24](https://github.com/anatolykoptev/oxpulse-turn/issues/24), [#25](https://github.com/anatolykoptev/oxpulse-turn/issues/25)) ([#28](https://github.com/anatolykoptev/oxpulse-turn/issues/28)) ([1e01db1](https://github.com/anatolykoptev/oxpulse-turn/commit/1e01db1aba4fa61f17c1518483093426a5b0e88d))
* input validation, IceTransportPolicy enum, doc fixes (closes [#7](https://github.com/anatolykoptev/oxpulse-turn/issues/7)-[#13](https://github.com/anatolykoptev/oxpulse-turn/issues/13)) ([#14](https://github.com/anatolykoptev/oxpulse-turn/issues/14)) ([7fbfd08](https://github.com/anatolykoptev/oxpulse-turn/commit/7fbfd08d153e7a5121e3850f326c9f2af0daa775))
* stun_urls_from_turn, MAX_TTL, MIN_SECRET_LEN (closes [#19](https://github.com/anatolykoptev/oxpulse-turn/issues/19), [#20](https://github.com/anatolykoptev/oxpulse-turn/issues/20), [#21](https://github.com/anatolykoptev/oxpulse-turn/issues/21)) ([#27](https://github.com/anatolykoptev/oxpulse-turn/issues/27)) ([d542120](https://github.com/anatolykoptev/oxpulse-turn/commit/d5421209f22076b79150b51d5f617071e37e64af))
* TurnError, pure mint_credentials, TurnCredentialIssuer (closes [#16](https://github.com/anatolykoptev/oxpulse-turn/issues/16), [#17](https://github.com/anatolykoptev/oxpulse-turn/issues/17), [#18](https://github.com/anatolykoptev/oxpulse-turn/issues/18)) ([#26](https://github.com/anatolykoptev/oxpulse-turn/issues/26)) ([558cf6a](https://github.com/anatolykoptev/oxpulse-turn/commit/558cf6aabbad7a953ad201ea8bf693d3b9d943f5))

## [0.1.2](https://github.com/anatolykoptev/oxpulse-turn/compare/v0.1.1...v0.1.2) (2026-08-07)


### Bug Fixes

* **release:** bootstrap release-please at the extraction point ([#3](https://github.com/anatolykoptev/oxpulse-turn/issues/3)) ([b2fd97f](https://github.com/anatolykoptev/oxpulse-turn/commit/b2fd97f7d562df1b10b6732a64adec7107caf530))
* **release:** open the release PR with the App token, not GITHUB_TOKEN ([#5](https://github.com/anatolykoptev/oxpulse-turn/issues/5)) ([83eead2](https://github.com/anatolykoptev/oxpulse-turn/commit/83eead2b4892eca7649603a1a0385cc10a498757))
