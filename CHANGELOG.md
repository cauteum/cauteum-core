# Changelog

## [Unreleased]

## [v0.0.2-alpha.1] - 2026-09-28

### Security

- Deny requests with unknown executable identity when a binary restriction applies.
- Reject unsupported deny-gate expressions instead of silently ignoring them.
- Canonicalize TOFU paths and serialize store updates with a persistent lock and durable writes.
- Require full suffix matches for recursive L7 path globs.

### Fixed

- Parse bracketed IPv6 endpoints and validate filesystem/binary paths by segments.
