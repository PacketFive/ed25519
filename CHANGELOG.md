# Changelog

All notable changes to pyrixos-ed25519 are listed here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-11-02

### Changed

- The package metadata names Weqaar Janjua as the author, with PacketFive
  as the maintainer.
- The quality gates run with coldframe from PyPI, the new name of
  pybootstrap, and read their settings from `[tool.coldframe]`.

## [1.0.0] - 2026-11-01

### Added

- `SigningKey`, `VerifyingKey` and `BadSignatureError`: Ed25519 key
  generation, signing and verification of RFC 8032 section 5.1, checked
  against the RFC's test vectors.
