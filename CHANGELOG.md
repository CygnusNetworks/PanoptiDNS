# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-30

First release. A Rust reimplementation of
[AllKnowingDNS](https://metacpan.org/dist/AllKnowingDNS) v1.7 (Perl, 2013,
unmaintained) that reads the same configuration file.

### Added

- Synthesized PTR and AAAA records for IPv6 networks, computed per query in both
  directions — no zone file for a /64.
- AllKnowingDNS v1.7 configuration format, with the acceptance vectors from its
  five Perl test files ported as regression tests.
- Strict, fail-fast configuration validation with rustc-style line-numbered
  diagnostics; every problem in a file is reported in one pass. `--check-config`
  validates without starting.
- Apex SOA and NS records, and a SOA in the authority section of negative answers
  so resolvers can cache them (RFC 2308). Optional, via `primary`/`hostmaster`.
- Response rate limiting, on by default, with separate budgets for answers and
  negative responses, per-client-prefix aggregation and BIND-style `slip`.
- EDNS(0), TCP, and BADVERS for unsupported EDNS versions.
- Hardened `with upstream`: asynchronous with a hard deadline, bounded
  concurrency, a circuit breaker, and a strict allowlist on relayed records.
- SIGHUP configuration reload; a parse error keeps the running configuration.
- `--healthcheck` subcommand, so the distroless image can health-check itself
  without a shell.
- Multi-arch container image (~5 MB, static musl, distroless, non-root), compose
  files for host and bridge networking, and a hardened systemd unit.

### Security

Six defects in AllKnowingDNS v1.7 are structurally absent here rather than
patched; each has a named regression test. Most seriously, the original could be
terminated by a single unauthenticated UDP packet, because it built resource
records by interpolating the query name into a DNS master-file presentation
string. See [SECURITY.md](SECURITY.md) and
[docs/MIGRATION-from-AllKnowingDNS.md](docs/MIGRATION-from-AllKnowingDNS.md).

### Compatibility notes

Behaviour differs from AllKnowingDNS in a few deliberate ways: prefix lengths may
be any multiple of 4 (not only 16), out-of-zone queries are REFUSED by default,
uppercase hex in queries is accepted, and malformed `network` lines, unknown
directives and `resolves to` without exactly one `%DIGITS%` are now fatal.
Full list in the migration guide.

[Unreleased]: https://github.com/CygnusNetworks/PanoptiDNS/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/CygnusNetworks/PanoptiDNS/releases/tag/v0.1.0
