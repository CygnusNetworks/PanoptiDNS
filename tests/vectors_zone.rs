//! Query→answer acceptance vectors, ported from the original's `t/003-config.t`,
//! `t/004-handler.t` and `t/005-same-domain.t`.
//!
//! These are the compatibility contract. The expected strings are copied from the
//! Perl assertions; where the original's fixture was itself invalid (see
//! `same_domain_*`) only the network literal is corrected, never the expected
//! output.

use hickory_proto::rr::domain::Name;
use hickory_proto::rr::{RData, RecordType};
use panoptidns::config::Config;
use panoptidns::zone::{lookup, resolve, Outcome};

fn cfg(input: &str) -> Config {
    match Config::parse(input) {
        Ok(c) => c,
        Err(e) => panic!("bad test config:\n{e}"),
    }
}

fn name(s: &str) -> Name {
    Name::from_ascii(s).expect("test name must parse")
}

/// The single zone used by `t/003` and `t/004`.
fn rzl() -> Config {
    cfg("network 2001:4d88:100e:ccc0::/64\n\
         \tresolves to ipv6-%DIGITS%-blah.nutzer.raumzeitlabor.de\n")
}

/// Answer a query and return `(rcode-ish outcome tag, rendered answers)`.
fn answers(config: &Config, qname: &str, qtype: RecordType) -> Option<Vec<String>> {
    match resolve(config, &name(qname), qtype) {
        Outcome::Answer { records, .. } => Some(
            records
                .iter()
                .map(|r| match &r.data {
                    RData::PTR(ptr) => ptr.0.to_ascii(),
                    RData::AAAA(a) => a.0.to_string(),
                    other => format!("{other:?}"),
                })
                .collect(),
        ),
        Outcome::NoName { .. } | Outcome::NoZone => None,
    }
}

const RZL_PTR_QUERY: &str =
    "7.c.e.2.3.4.e.f.f.f.b.d.9.1.2.0.0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa.";

// ---- t/003-config.t -------------------------------------------------------

#[test]
fn empty_config_matches_nothing() {
    let empty = Config::default();
    assert!(lookup::match_ptr(&empty, &name(RZL_PTR_QUERY)).is_none());
    assert!(lookup::match_forward(&empty, &name("ipv6-a-blah.nutzer.raumzeitlabor.de.")).is_none());
    assert!(matches!(
        resolve(&empty, &name(RZL_PTR_QUERY), RecordType::PTR),
        Outcome::NoZone
    ));
}

#[test]
fn ptr_matches_configured_network_only() {
    let config = rzl();
    assert!(lookup::match_ptr(&config, &name(RZL_PTR_QUERY)).is_some());
    // Differs from the configured network by a single nibble (`1.c.c.c` vs
    // `0.c.c.c`), i.e. 2001:4d88:100e:ccc1: — a different /64.
    assert!(lookup::match_ptr(
        &config,
        &name("7.c.e.2.3.4.e.f.f.f.b.d.9.1.2.0.1.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa.")
    )
    .is_none());
}

/// The original's `t/003` used a single-digit host part (`ipv6-a-blah`) with an
/// unbounded `[a-z0-9]+` in its lookup regex, then demanded exactly 16 digits
/// during synthesis — the split-brain bug. We require the exact count in the one
/// place the zone is chosen, so a short host part simply does not match.
#[test]
fn forward_requires_the_exact_digit_count() {
    let config = rzl();
    assert!(
        lookup::match_forward(&config, &name("ipv6-a-blah.nutzer.raumzeitlabor.de.")).is_none()
    );
    assert!(lookup::match_forward(
        &config,
        &name("ipv6-0219dbfffe432ec7-blah.nutzer.raumzeitlabor.de.")
    )
    .is_some());
    // Different parent domain.
    assert!(lookup::match_forward(
        &config,
        &name("ipv6-0219dbfffe432ec7-blah.servers.raumzeitlabor.de.")
    )
    .is_none());
}

// ---- t/004-handler.t ------------------------------------------------------

#[test]
fn empty_config_ptr_query_has_no_zone() {
    assert!(answers(&Config::default(), RZL_PTR_QUERY, RecordType::PTR).is_none());
}

#[test]
fn ptr_answer_matches_perl_vector() {
    assert_eq!(
        answers(&rzl(), RZL_PTR_QUERY, RecordType::PTR).as_deref(),
        Some(&["ipv6-0219dbfffe432ec7-blah.nutzer.raumzeitlabor.de.".to_string()][..])
    );
}

#[test]
fn ptr_answer_carries_ttl_3600_from_the_original() {
    let config = rzl();
    let Outcome::Answer { records, .. } = resolve(&config, &name(RZL_PTR_QUERY), RecordType::PTR)
    else {
        panic!("expected an answer");
    };
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].record_type(), RecordType::PTR);
    assert_eq!(records[0].ttl, 3600);
}

#[test]
fn aaaa_answer_matches_perl_vector() {
    assert_eq!(
        answers(
            &rzl(),
            "ipv6-0219dbfffe432ec7-blah.nutzer.raumzeitlabor.de.",
            RecordType::AAAA
        )
        .as_deref(),
        Some(&["2001:4d88:100e:ccc0:219:dbff:fe43:2ec7".to_string()][..])
    );
}

/// The v1.3 behaviour, pinned by the original: an `A` query for a name the
/// template matches is NOERROR with **zero** records, not NXDOMAIN. The name
/// exists; it just has no IPv4 address.
#[test]
fn a_query_on_a_matching_name_is_empty_noerror() {
    let got = answers(
        &rzl(),
        "ipv6-0219dbfffe432ec7-blah.nutzer.raumzeitlabor.de.",
        RecordType::A,
    );
    assert_eq!(got.as_deref(), Some(&[][..]), "must be NOERROR with 0 RRs");
}

/// The pathological /112 case from `t/004`. Note the original wrote the network
/// out in full (`…:3333:0000/112`), which is a proper network address, so it
/// survives strict validation unchanged.
#[test]
fn non_64_prefix_aaaa_vector() {
    let config = cfg("network 2001:4d88:100e:ccc0:1111:2222:3333:0000/112\n\
                      \tresolves to ipv6-%DIGITS%-blah.nutzer.raumzeitlabor.de\n");
    assert_eq!(config.zones[0].host_nibbles, 4);
    assert_eq!(
        answers(
            &config,
            "ipv6-aaff-blah.nutzer.raumzeitlabor.de.",
            RecordType::AAAA
        )
        .as_deref(),
        Some(&["2001:4d88:100e:ccc0:1111:2222:3333:aaff".to_string()][..])
    );
}

// ---- t/005-same-domain.t --------------------------------------------------

/// Three zones sharing the parent domain `ipv6.monsternett.net`, distinguished
/// only by the literal prefix of the `%DIGITS%` label.
///
/// This is the test that fails if matching is a suffix match rather than a full
/// match: a suffix-only comparison would pick `oslo-` or `mail-` for a `web-`
/// name. The original's networks were written `2a00:15a0::192:/64` and
/// `2a00:15a0:2::192:/64` — both invalid IPv6 (trailing colon) with host bits in
/// the network part — so they are corrected here; the expected answers are
/// verbatim from the Perl assertions.
fn monsternett() -> Config {
    cfg("network 2001:840:5000:2::/64\n\
         \tresolves to oslo-%DIGITS%.ipv6.monsternett.net\n\
         network 2a00:15a0::/64\n\
         \tresolves to mail-%DIGITS%.ipv6.monsternett.net\n\
         network 2a00:15a0:2::/64\n\
         \tresolves to web-%DIGITS%.ipv6.monsternett.net\n")
}

const MONSTERNETT_PTR_QUERY: &str =
    "1.0.0.0.2.9.1.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.0.a.5.1.0.0.a.2.ip6.arpa.";

#[test]
fn same_domain_empty_config_has_no_zone() {
    assert!(answers(&Config::default(), MONSTERNETT_PTR_QUERY, RecordType::PTR).is_none());
}

#[test]
fn same_domain_ptr_selects_the_right_zone() {
    assert_eq!(
        answers(&monsternett(), MONSTERNETT_PTR_QUERY, RecordType::PTR).as_deref(),
        Some(&["web-0000000001920001.ipv6.monsternett.net.".to_string()][..]),
        "must pick the web- zone, and keep all leading zeros"
    );
}

#[test]
fn same_domain_aaaa_round_trips() {
    // The Perl test accepted either the compressed or uncompressed rendering;
    // `Ipv6Addr::to_string` produces the compressed form.
    assert_eq!(
        answers(
            &monsternett(),
            "web-0000000001920001.ipv6.monsternett.net.",
            RecordType::AAAA
        )
        .as_deref(),
        Some(&["2a00:15a0:2::192:1".to_string()][..])
    );
}

#[test]
fn same_domain_each_prefix_resolves_to_its_own_zone() {
    let config = monsternett();
    for (qname, expected) in [
        (
            "oslo-0000000000000001.ipv6.monsternett.net.",
            "2001:840:5000:2::1",
        ),
        (
            "mail-0000000000000002.ipv6.monsternett.net.",
            "2a00:15a0::2",
        ),
        (
            "web-0000000000000003.ipv6.monsternett.net.",
            "2a00:15a0:2::3",
        ),
    ] {
        assert_eq!(
            answers(&config, qname, RecordType::AAAA).as_deref(),
            Some(&[expected.to_string()][..]),
            "{qname}"
        );
    }
}

// ---- regression guards ----------------------------------------------------

/// Finding 6: the original's synthesis regex was unanchored, so appending labels
/// could still match.
#[test]
fn appended_labels_never_match() {
    let config = rzl();
    for qname in [
        "ipv6-0219dbfffe432ec7-blah.nutzer.raumzeitlabor.de.evil.com.",
        "prefix.ipv6-0219dbfffe432ec7-blah.nutzer.raumzeitlabor.de.",
    ] {
        assert!(
            lookup::match_forward(&config, &name(qname)).is_none(),
            "{qname} must not match"
        );
    }
}

/// Finding 6: `[a-z0-9]` is not hex. `zzzz…` used to reach Perl's `hex()`, which
/// returned 0 and produced a confidently wrong address.
#[test]
fn non_hex_digits_never_match() {
    let config = rzl();
    assert!(lookup::match_forward(
        &config,
        &name("ipv6-zzzzzzzzzzzzzzzz-blah.nutzer.raumzeitlabor.de.")
    )
    .is_none());
}

/// Uppercase hex must resolve identically — DNS names are case-insensitive, so a
/// resolver may send either. The original's `[a-z0-9]` rejected this.
#[test]
fn uppercase_hex_resolves_identically() {
    let config = rzl();
    assert_eq!(
        answers(
            &config,
            "IPV6-0219DBFFFE432EC7-BLAH.NUTZER.RAUMZEITLABOR.DE.",
            RecordType::AAAA
        )
        .as_deref(),
        Some(&["2001:4d88:100e:ccc0:219:dbff:fe43:2ec7".to_string()][..])
    );
}

/// Finding 1/5: a partial reverse name inside our zone is NODATA-with-SOA
/// territory, not an answer and not someone else's namespace.
#[test]
fn partial_reverse_name_is_in_zone_but_nameless() {
    let config = rzl();
    // The zone apex itself: 16 nibbles, not an address.
    assert!(matches!(
        resolve(
            &config,
            &name("0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa."),
            RecordType::PTR
        ),
        Outcome::NoName { .. }
    ));
    // A name under our forward apex that no template produces.
    assert!(matches!(
        resolve(
            &config,
            &name("something-else.nutzer.raumzeitlabor.de."),
            RecordType::AAAA
        ),
        Outcome::NoName { .. }
    ));
    // Genuinely unrelated.
    assert!(matches!(
        resolve(&config, &name("www.example.com."), RecordType::A),
        Outcome::NoZone
    ));
}

/// Longest-prefix match, which the original's first-match-in-config-order got
/// wrong for overlapping networks.
#[test]
fn overlapping_networks_use_longest_prefix() {
    let config = cfg("network 2001:db8::/32\n\
                      \tresolves to wide-%DIGITS%.example.net\n\
                      network 2001:db8:1:2::/64\n\
                      \tresolves to narrow-%DIGITS%.example.net\n");
    // 2001:db8:1:2::1 is inside both; the /64 must win.
    let addr = u128::from("2001:db8:1:2::1".parse::<std::net::Ipv6Addr>().unwrap());
    let zone = lookup::zone_for_addr(&config, addr).expect("a zone must match");
    assert_eq!(zone.mask, 64);
    assert_eq!(zone.resolves_to, "narrow-%DIGITS%.example.net");

    // …and an address only in the /32 still gets the wide zone.
    let addr = u128::from("2001:db8:9:9::1".parse::<std::net::Ipv6Addr>().unwrap());
    assert_eq!(
        lookup::zone_for_addr(&config, addr).map(|z| z.mask),
        Some(32)
    );
}

/// The full round trip, for every zone in a realistic config: an address becomes
/// a name and the name becomes the same address again.
#[test]
fn ptr_to_aaaa_round_trip_is_identity() {
    let config = monsternett();
    for zone in &config.zones {
        for host in [0u128, 1, 0x0192_0001, 0xdead_beef_cafe_babe] {
            let addr = zone.prefix | (host & !panoptidns::nibble::mask_bits(zone.mask));
            let fwd = panoptidns::zone::synth::forward_name(zone, addr).expect("renders");
            let back = lookup::match_forward(&config, &fwd);
            assert_eq!(
                back.map(|(z, a)| (z.prefix, a)),
                Some((zone.prefix, addr)),
                "round trip failed for {fwd}"
            );
        }
    }
}
