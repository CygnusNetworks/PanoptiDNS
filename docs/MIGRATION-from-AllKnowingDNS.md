# Migrating from AllKnowingDNS v1.7

PanoptiDNS reads the same configuration file. In most cases you can point it at
your existing `/etc/all-knowing-dns.conf` and it will serve identical answers.

Validate first — it reports every problem at once, with line numbers:

```sh
panoptidns --check-config --config /etc/all-knowing-dns.conf
```

## What is identical

The wire behaviour that AllKnowingDNS's own test suite pinned is reproduced
exactly, and those vectors are now regression tests here:

| Query | Answer |
|---|---|
| `PTR 7.c.e.2.…0.0.2.ip6.arpa` in `2001:4d88:100e:ccc0::/64` with `resolves to ipv6-%DIGITS%-blah.nutzer.raumzeitlabor.de` | `ipv6-0219dbfffe432ec7-blah.nutzer.raumzeitlabor.de.` TTL 3600, AA |
| `AAAA ipv6-0219dbfffe432ec7-blah.nutzer.raumzeitlabor.de` | `2001:4d88:100e:ccc0:219:dbff:fe43:2ec7` |
| `A` on a name a template matches | NOERROR with **zero** records (not NXDOMAIN) |
| PTR zone for `/48`, `/64`, `/80` | `e.0.0.1.…`, `0.c.c.c.e.0.0.1.…`, `0.0.0.0.0.c.c.c.…` |

Also preserved:

- Keywords are case-insensitive; leading indentation is decorative.
- `network`, `listen` and `with upstream` values are lowercased, but
  **`resolves to` is kept verbatim** — AllKnowingDNS deliberately preserved
  capitalisation there, and so do we.
- `%DIGITS%` is matched case-insensitively, so `%digits%` works (the original's
  substitutions carried the `/i` flag).
- Host parts keep their leading zeros: `0000000001920001`, not `1920001`.
- Zones sharing a parent domain (`oslo-%DIGITS%`, `mail-%DIGITS%`,
  `web-%DIGITS%` all under `.ipv6.monsternett.net`) resolve to the right zone.

## What is now a hard error

The original accepted these silently and carried on with a broken configuration.
Each is now fatal at startup, with a caret pointing at the offending value.

### A `network` without a prefix length

```
network 2001:db8::
```

This was the most dangerous defect in AllKnowingDNS. The regex failed, `$mask`
was left undefined, `undef % 16 == 0` passed its only validation, and the
resulting PTR zone was a bare `.ip6.arpa` — which, because zone matching was a
string suffix comparison, matched **every** IPv6 reverse query on the internet.
The server then answered authoritatively for networks it did not own, with no
error anywhere. Add the prefix length.

### Host bits set below the prefix

```
network 2a00:15a0::192:1/64      ->  error: network has bits set below its prefix length
                                     hint: did you mean `2a00:15a0::/64`?
```

### An invalid IPv6 address

```
network 2a00:15a0::192:/64       ->  error: not a valid IPv6 address
```

Note both of these appear in the original's *own* test file `t/005-same-domain.t`
(`2a00:15a0::192:/64`, `2a00:15a0:2::192:/64` — a trailing colon and host bits in
the network part). `NetAddr::IP` tolerated them; PanoptiDNS does not. If your
config contains something similar, mask it properly.

### `resolves to` without exactly one `%DIGITS%`

Missing it meant every address in the network resolved to the same name; having
it twice meant the second occurrence was never substituted.

### Unknown directives

A typo like `netwrok` was silently ignored, so the directive simply did nothing.
Now it fails.

### Global settings after the first `network`

`primary`, `hostmaster`, `ns`, `ttl`, `out-of-zone`, `max-udp-payload`,
`upstream-timeout` and the `rrl` settings are global and must appear before the
first `network`. Because indentation carries no meaning in this format, position
is the only unambiguous scope rule.

## Behaviour changes you should know about

### Prefix lengths: multiples of 4, not 16

AllKnowingDNS required the prefix length to be divisible by 16 — an artifact of
its `unpack("n8")` implementation, not a property of DNS. One `ip6.arpa` label
carries exactly one nibble, so any multiple of **4** is valid. `/36`, `/52` and
`/68` now work. Every configuration that worked before still works.

### Out-of-zone queries are REFUSED, not NXDOMAIN

We are not authoritative for names outside the configured zones, so declining is
the correct answer, and REFUSED is smaller than a synthesized NXDOMAIN — which
matters, because a server that answers for the whole namespace is a useful
reflection amplifier. Restore the old behaviour with:

```
out-of-zone nxdomain
```

### Negative answers now carry a SOA

If `primary` and `hostmaster` are set, in-zone NXDOMAIN and NODATA responses
include the zone's SOA in the authority section, so resolvers can cache the
negative (RFC 2308). AllKnowingDNS sent a bare NXDOMAIN with an empty authority
section, so resolvers had nothing to cache and re-queried indefinitely.

Without those two directives you get a startup warning and the old behaviour.
Existing configs therefore keep working; they just do not benefit.

### Uppercase hex in queries is accepted

The original matched host parts with `[a-z0-9]`, which was wrong in both
directions: it rejected `0219DBFF…` even though DNS names are case-insensitive,
and it accepted `g`–`z`, which Perl's `hex()` silently turned into `0` — yielding
a confidently wrong address. PanoptiDNS accepts either case and rejects anything
that is not a hex digit.

### Reverse queries must be complete addresses

A PTR query must be exactly 32 hex nibbles followed by `ip6.arpa`. The original
compared string suffixes and accepted any prefix whatsoever, concatenating
everything to the left of the zone into the synthesized hostname — so a query
could inject arbitrary bytes and arbitrary length into the answer. Real reverse
lookups are always for a full address, so nothing legitimate is affected.

### `with upstream` is filtered

The feature still works, but:

- the lookup is asynchronous with a hard ~300 ms deadline (configurable), instead
  of blocking for up to 20 seconds in a single-threaded server;
- only PTR records in class IN whose owner name is **exactly** `<query>.upstream`
  are relayed, rebuilt with our own owner name, TTL clamped to 30–3600 s, at most
  8 records. The original relayed the entire answer section verbatim with the AA
  bit set, filtering nothing but a `.upstream` suffix on the name, so a hostile or
  compromised upstream could inject arbitrary records that were then served as
  authoritative data for a zone delegated to us.

If your upstream returns anything other than a plain PTR for the exact
`.upstream` name, it will now be ignored rather than served.

### Rate limiting is on by default

20 responses per second per client prefix (/24 IPv4, /64 IPv6) with a burst of
50, and answers and negative responses have separate budgets. TCP is never
limited. A startup log line states the active settings. Turn it off with
`rrl off` if something upstream of you already does this.

### AXFR/IXFR are REFUSED, NOTIFY/UPDATE are NOTIMP

A /64 holds 2^64 names and there is no zone data to transfer. AllKnowingDNS
needed an explicit `NotifyHandler` workaround purely to avoid *terminating* on a
NOTIFY.

## New command-line interface

```
panoptidns --config PATH          # default /etc/panoptidns/panoptidns.conf
           --check-config         # validate and exit
           --listen ADDR[:PORT]   # repeatable; overrides `listen` in the config
           --querylog             # log every query
           --log-json             # structured logs
           --healthcheck          # query a local instance, exit 0 if it answers
```

Every option also reads an environment variable (`PANOPTIDNS_CONFIG`,
`PANOPTIDNS_LISTEN`, `PANOPTIDNS_QUERYLOG`, `PANOPTIDNS_LOG_JSON`,
`PANOPTIDNS_LOG` for the log filter), which is what makes the container
configurable without rewriting the config file.

`--listen` and `PANOPTIDNS_LISTEN` replace the config's `listen` directives
entirely. This is deliberate: a config copied from a physical host names public
addresses that do not exist inside a container, and binding would fail at
startup.

SIGHUP reloads the configuration. A parse error is logged and the previous
configuration keeps running. `listen` changes are ignored on reload, since the
sockets are already bound — restart for those.

## Why any of this

A security review of AllKnowingDNS v1.7 found six defects, verified against
Net::DNS 0.74. The most serious: it built resource records by interpolating the
attacker-controlled query name into a DNS master-file *presentation string*

```perl
Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata")
```

and `;` and `"` are master-file metacharacters that are not escaped in the
presentation form. A raw `;` byte in a query label therefore made the parser die
— and `Net::DNS::Nameserver` has no exception guard anywhere in its request path,
so the exception propagated up through `main_loop` and the daemon exited. One UDP
packet, no authentication, endlessly repeatable:

```sh
dig PTR 'a;b.0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa'
```

PanoptiDNS never formats or parses names as presentation text. A query name is
converted to a `u128` or rejected, and every name it emits is built from typed
labels out of `(config, u128)`, so attacker bytes cannot reach record
construction at all. The panic-family lints are denied on the request path, and
the handler is additionally wrapped in `catch_unwind` so that even a bug becomes
SERVFAIL rather than an exit.
