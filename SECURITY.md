# Security Policy

PanoptiDNS is an authoritative DNS server. It parses attacker-controlled input on
an unauthenticated UDP port, so its threat model is unusually direct: **any input
that makes the process stop answering is a vulnerability.**

## Reporting a vulnerability

Please report privately via
[GitHub Security Advisories](https://github.com/CygnusNetworks/PanoptiDNS/security/advisories/new),
through the GitHub Security Advisories link above.

Please include the configuration, the query or packet that triggers it, and what
you observed. A packet capture or a `dig` command line is ideal.

Do not open a public issue for a vulnerability until a fix is available.

We aim to acknowledge within 5 working days.

## Supported versions

Only the latest release is supported. PanoptiDNS is pre-1.0; until then, fixes
land on `main` and in the next release rather than being backported.

## What we consider a vulnerability

- Any input that terminates, hangs or wedges the process.
- Any input that causes an answer containing data not derived from the
  configuration and the queried address — in particular anything reaching record
  construction from the query itself.
- Serving records for a name outside the configured zones.
- Accepting upstream data that the allowlist in `src/upstream.rs` should have
  rejected.
- Amplification beyond what the configured rate limits permit.

## What we do not consider a vulnerability

- Resource exhaustion from traffic volume alone against a server with `rrl off`.
  Rate limiting is on by default; disabling it is a deliberate choice.
- Misconfiguration that `--check-config` rejects.
- Behaviour of a configured upstream server itself. We filter what it returns; we
  do not vouch for it.

## Design measures

These are the properties an exploit would have to defeat, and they exist because
the predecessor this project replaces failed at each of them.

**Query names never become record data.** A query name is parsed into a `u128` or
rejected. Everything emitted is built from typed labels out of configuration plus
digits generated from that `u128`. No name is ever formatted into, or parsed out
of, DNS master-file presentation text.

AllKnowingDNS v1.7 built records with
`Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata")`. Because `;` and `"` are
master-file metacharacters that are *not* escaped in the presentation form, a
single UDP packet containing `a;b.<zone>.ip6.arpa` made the parser die — and
`Net::DNS::Nameserver` has no exception guard in its request path, so the daemon
exited. Unauthenticated, unlimited, endlessly repeatable.

**The request path cannot abort.** `unwrap`, `expect`, `panic`, `unreachable`,
indexing and slicing are denied by lint across `src/nibble.rs`, `src/config/`,
`src/zone/` and `src/server/handler.rs`, enforced in CI with
`clippy -D warnings`. The handler is additionally wrapped in `catch_unwind`, so
even a genuine bug becomes SERVFAIL rather than an exit, and `panic = "unwind"` is
pinned in the release profile for that reason.

**Zones are arithmetic, not strings.** A zone is `(u128, prefix_len)`. Reverse
matching is a longest-prefix match on integers; forward matching compares labels
with an exact label-count check, so it is a full match by construction. A
malformed `network` line is a startup error rather than a zone that silently
matches everything.

**Upstream responses are allowlisted.** Only PTR records in class IN whose owner
name is exactly the name queried are relayed, rebuilt with our own owner name, TTL
clamped, count capped. Authority and additional sections are discarded entirely.

**Rate limiting is on by default**, with separate budgets for answers and negative
responses, aggregated per client prefix. TCP is never limited.

## Verifying the claims

Every item above has a named regression test:

```sh
cargo test
```

- `hostile_query_bytes_do_not_kill_the_server` — sends `;`, `"`, `\`, NUL, `0xFF`,
  63-byte binary labels and more, then asserts an ordinary query still succeeds in
  the same process.
- `malformed_datagrams_do_not_kill_the_server`
- `finding3` / `rejects_everything_not_explicitly_allowed` — hostile upstream.
- `network_without_prefix_length_is_fatal`, `no_zone_can_claim_all_of_ip6_arpa`
- `overlong_reverse_names_are_declined_not_truncated`
- `case_insensitive_but_strictly_hex`, `appended_labels_never_match`

The lint policy is verifiable: adding an `unwrap()` to a request-path module
fails the build.

## Credit

The defects described here were found in a review of AllKnowingDNS v1.7 and are
documented in [docs/MIGRATION-from-AllKnowingDNS.md](docs/MIGRATION-from-AllKnowingDNS.md).
AllKnowingDNS is unmaintained (last release 2013-09-23); this is not a report
against a supported project.
