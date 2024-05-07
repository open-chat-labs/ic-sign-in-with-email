# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [unreleased]

### Added

- Add `canister_upgrader` to simplify upgrading the canister ([#23](https://github.com/open-chat-labs/ic-sign-in-with-email/pull/23))

### Changed

- Start collecting basic stats per account ([#10](https://github.com/open-chat-labs/ic-sign-in-with-email/pull/10))
- Pass up session key when generating verification code ([#12](https://github.com/open-chat-labs/ic-sign-in-with-email/pull/12))
- Allow specifying the RNG salt for tests ([#14](https://github.com/open-chat-labs/ic-sign-in-with-email/pull/14))
- Use magic links rather than verification codes ([#13](https://github.com/open-chat-labs/ic-sign-in-with-email/pull/13))
- Keep track of active magic links ([#16](https://github.com/open-chat-labs/ic-sign-in-with-email/pull/16))
- Include `identity_canister_id` when pushing magic links ([#19](https://github.com/open-chat-labs/ic-sign-in-with-email/pull/19))
- Move `EmailSenderConfig` into `api` package so that it is public ([#22](https://github.com/open-chat-labs/ic-sign-in-with-email/pull/22))

## [[0.4.0](https://github.com/open-chat-labs/ic-sign-in-with-email/releases/tag/v0.4.0)] - 2024-04-19

### Changed

- Avoid storing any email addresses ([#6](https://github.com/open-chat-labs/ic-sign-in-with-email/pull/6))
- Return `blocked_duration` rather than `blocked_until` ([#7](https://github.com/open-chat-labs/ic-sign-in-with-email/pull/7))

### Fixed

- Remove verification code after successful attempt ([#8](https://github.com/open-chat-labs/ic-sign-in-with-email/pull/8))

## [[0.3.0](https://github.com/open-chat-labs/ic-sign-in-with-email/releases/tag/v0.3.0)] - 2024-04-19

### Changed

- Introduce `ValidatedEmail` type to force validation in all cases ([#3](https://github.com/open-chat-labs/ic-sign-in-with-email/pull/3))
- Mark codes with any failed attempts as failed when removed ([#4](https://github.com/open-chat-labs/ic-sign-in-with-email/pull/4))

## [[0.2.0](https://github.com/open-chat-labs/ic-sign-in-with-email/releases/tag/v0.2.0)] - 2024-04-17

### Added

- Add email verification

### Changed

- Generate verification codes with 6 digits

## [[0.1.0](https://github.com/open-chat-labs/ic-sign-in-with-email/releases/tag/v0.1.0)] - 2024-04-15

- Initial release
