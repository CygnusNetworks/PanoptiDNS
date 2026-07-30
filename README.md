# PanoptiDNS

[![CI](https://github.com/CygnusNetworks/PanoptiDNS/actions/workflows/ci.yml/badge.svg)](https://github.com/CygnusNetworks/PanoptiDNS/actions/workflows/ci.yml)
[![Audit](https://github.com/CygnusNetworks/PanoptiDNS/actions/workflows/audit.yml/badge.svg)](https://github.com/CygnusNetworks/PanoptiDNS/actions/workflows/audit.yml)
[![Release](https://github.com/CygnusNetworks/PanoptiDNS/actions/workflows/release.yml/badge.svg)](https://github.com/CygnusNetworks/PanoptiDNS/actions/workflows/release.yml)
[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.97%2B-orange.svg?logo=rust)](rust-toolchain.toml)
[![Container](https://img.shields.io/badge/ghcr.io-panoptidns-2496ED.svg?logo=docker&logoColor=white)](https://github.com/CygnusNetworks/PanoptiDNS/pkgs/container/panoptidns)
[![Image size](https://img.shields.io/badge/image-~5%20MB%20distroless-success.svg)](Dockerfile)
[![Security policy](https://img.shields.io/badge/security-policy-informational.svg)](SECURITY.md)

A small authoritative DNS server that **synthesizes IPv6 reverse (PTR) and
matching forward (AAAA) records on the fly**, so you never write a zone file for
a /64.

That is the whole point: a /64 holds 18 446 744 073 709 551 616 addresses. No zone
file can enumerate them, but the mapping between an address and a hostname is a
pure function, so it can simply be computed per query in both directions.

```sh
$ dig +short PTR 7.c.e.2.3.4.e.f.f.f.b.d.9.1.2.0.0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa
ipv6-0219dbfffe432ec7.nutzer.example.net.

$ dig +short AAAA ipv6-0219dbfffe432ec7.nutzer.example.net
2001:4d88:100e:ccc0:219:dbff:fe43:2ec7
```

PanoptiDNS is a Rust reimplementation of
[AllKnowingDNS](https://metacpan.org/dist/AllKnowingDNS) v1.7 (Perl, 2013,
unmaintained) by Michael Stapelberg. It reads **the same configuration file**, and
it is built so that the original's security defects are structurally absent rather
than patched. See [docs/MIGRATION-from-AllKnowingDNS.md](docs/MIGRATION-from-AllKnowingDNS.md).

## Quick start

```sh
cp panoptidns.conf.example panoptidns.conf
$EDITOR panoptidns.conf
docker compose up -d
```

Or without Docker:

```sh
cargo build --release
./target/release/panoptidns --check-config -c panoptidns.conf
./target/release/panoptidns -c panoptidns.conf --listen 127.0.0.1:5353
```

## Configuration

The format is AllKnowingDNS's, unchanged. Keywords are case-insensitive and
indentation is decorative.

```
primary     ns1.example.net.
hostmaster  hostmaster.example.net.
ns          ns1.example.net.

network 2001:db8:100e:ccc0::/64
    resolves to ipv6-%DIGITS%.nutzer.example.net
    with upstream 2001:db8:100e:1::2
```

`%DIGITS%` expands to the host part as lowercase hex, zero-padded to
`(128 - prefixlen) / 4` characters. Everything else is in
[panoptidns.conf.example](panoptidns.conf.example), which documents every
directive and its default.

Validate before restarting — it reports every problem at once, with line numbers
and a caret:

```
$ panoptidns --check-config -c panoptidns.conf
error: prefix length /63 is not nibble-aligned (must be a multiple of 4)
 --> panoptidns.conf:12
  |
12 |     network 2001:db8::/63
  |                       ^^^ expected /0, /4, /8, … /128
```

## Delegation

Delegate the reverse zone and one forward domain to this server. In BIND:

```
; reverse
0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa. IN NS ipv6-rdns.example.net.

; forward
nutzer.example.net. IN NS ipv6-rdns.example.net.
```

## Deployment

Both compose files drop all capabilities, use a read-only root filesystem and run
as uid 65532.

- **[docker-compose.yml](docker-compose.yml)** — host networking. Recommended.
- **[docker-compose.bridge.yml](docker-compose.bridge.yml)** — published port.
  Read the caveat: with the default bridge and userland-proxy, Docker rewrites UDP
  source addresses to the gateway, which collapses every rate-limit bucket into
  one and makes `--querylog` useless.
- **[packaging/panoptidns.service](packaging/panoptidns.service)** — systemd, with
  `DynamicUser` and `AmbientCapabilities=CAP_NET_BIND_SERVICE`.

For port 53 as a non-root user, in order of preference:

1. `--sysctl net.ipv4.ip_unprivileged_port_start=0` (applies to IPv6 too) with
   `cap_drop: ALL`. No capabilities at all.
2. A high port inside the container, published to 53.
3. `--cap-add NET_BIND_SERVICE` — **fragile**: Docker does not place added
   capabilities in the *ambient* set, so a non-root process still gets EACCES
   unless the binary carries a file capability, and xattrs do not survive
   `COPY --from` reliably.

## Command line

```
--config PATH           configuration file (default /etc/panoptidns/panoptidns.conf)
--check-config          validate and exit
--listen ADDR[:PORT]    repeatable; overrides `listen` in the config entirely
--querylog              log every query
--log-json              structured logs
--healthcheck           query a local instance, exit 0 if it answers
```

Each has an environment equivalent (`PANOPTIDNS_CONFIG`, `PANOPTIDNS_LISTEN`,
`PANOPTIDNS_QUERYLOG`, `PANOPTIDNS_LOG_JSON`, and `PANOPTIDNS_LOG` for the log
filter). SIGHUP reloads the configuration; a parse error is logged and the running
configuration is kept.

## Design

The server is a pure function of `(config, u128)`. Everything under
`src/config/`, `src/nibble.rs` and `src/zone/` is synchronous, has no clock, no
sockets and no async runtime — the entire behavioural specification lives there,
which is why the acceptance vectors can be tested without binding a port.

Three decisions carry most of the safety:

**Names are never presentation text.** A query name is parsed into a `u128` or
rejected. Every name emitted is built from typed labels out of config data plus
digits generated from that `u128`. This is what makes the original's remote-kill
vector unrepresentable — see below.

**A zone is `(u128, mask)`, not a string.** Reverse matching is a longest-prefix
match on integers; forward matching compares labels with an exact label-count
check, so it is a full match by construction rather than by an anchor someone
might forget.

**The request path cannot abort.** `unwrap`, `expect`, `panic`, indexing and
slicing are denied by lint on that path (verified: adding an `unwrap()` fails the
build), and the handler is wrapped in `catch_unwind` so even a bug becomes
SERVFAIL. `panic = "unwind"` is pinned in the release profile for that reason.

### Why not hickory's `Catalog`

`Catalog` dispatches by longest-suffix match on a zone origin. Our forward zones
deliberately *share* an origin — `oslo-%DIGITS%.ipv6.example.net` and
`web-%DIGITS%.ipv6.example.net` are different zones under the same parent — and
are distinguished by a label pattern, which the catalog cannot express. Rate
limiting and the upstream decision also need the client address and transport,
which the `ZoneHandler` API does not surface.

## The bug that motivated this

AllKnowingDNS v1.7 could be terminated by a single UDP packet. It built records
by interpolating the attacker-controlled query name into a DNS master-file
*presentation string*:

```perl
Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata")
```

`;` (comment) and `"` (quote) are master-file metacharacters, and unlike space and
newline they are **not** escaped in the presentation form. A raw `;` byte in a
query label made the parser die — and `Net::DNS::Nameserver` has no exception
guard anywhere in its request path, so the exception reached `main_loop` and the
process exited. No authentication, no rate limit, endlessly repeatable:

```sh
dig PTR 'a;b.0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa'
```

Against PanoptiDNS that query returns NXDOMAIN and the server keeps serving;
`hostile_query_bytes_do_not_kill_the_server` in
[tests/integration_server.rs](tests/integration_server.rs) asserts exactly that,
for a whole set of hostile byte sequences, by checking that an ordinary query
still succeeds afterwards in the same process.

Five further defects — a blocking upstream lookup that stalled the server for up
to 20 s per query, unfiltered relaying of upstream answers as authoritative data,
a malformed `network` line silently claiming all of `ip6.arpa`, silent truncation
of over-long names, and `[a-z0-9]` used where hex was meant — each have a named
regression test.

## Tests

```sh
cargo test              # 105 tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Layers:

- **Ported acceptance vectors** from the original's five Perl test files, with the
  expected strings copied verbatim. These are the compatibility contract.
- **Property tests** — most valuably, that
  `addr → ip6.arpa name → forward name → parse → addr` is the identity over
  random prefixes and masks.
- **End-to-end tests** against a real server on an ephemeral port: flags, rcodes,
  EDNS, TCP, apex SOA/NS, and the hostile-input regressions.
- **Named regression tests**, one per security finding.

## Contributing

Issues and pull requests are welcome. Before opening a PR:

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

Two rules are load-bearing rather than stylistic, and CI enforces both:

1. **Nothing on the request path may abort.** `unwrap`, `expect`, `panic`,
   `unreachable`, indexing and slicing are denied by lint in `src/nibble.rs`,
   `src/config/`, `src/zone/` and `src/server/handler.rs`. If you need a value
   that "cannot" be missing, return an `Option`/`Result` and let the caller
   decline the query.
2. **Query names never become record data.** Parse to a `u128` or reject. Build
   names from typed labels. Never format or parse a name as presentation text.

Changes to answer behaviour need a test with the concrete query and the expected
records — see `tests/vectors_zone.rs` for the style.

Security issues: please follow [SECURITY.md](SECURITY.md) rather than opening a
public issue.

## Licence and provenance

BSD-3-Clause — see [LICENSE](LICENSE).

PanoptiDNS is an independent reimplementation of
[AllKnowingDNS](https://metacpan.org/dist/AllKnowingDNS), copyright 2012 Michael
Stapelberg, also BSD-licensed. It shares AllKnowingDNS's configuration file
format, and its test suite ports the acceptance vectors from AllKnowingDNS's test
files to preserve behavioural compatibility. No AllKnowingDNS source code is
included in or derived into this work.
