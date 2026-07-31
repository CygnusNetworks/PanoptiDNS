//! Configuration parsing, ported verbatim from the original's `t/001-parse-config.t`
//! plus the strict-validation cases that file could not express.
//!
//! The vectors here are the compatibility contract: any change that breaks one
//! of them changes how an existing deployment's config is interpreted.

use panoptidns::config::{Config, ConfigErrorKind, FwdLabel};

fn parse_ok(input: &str) -> Config {
    match Config::parse(input) {
        Ok(cfg) => cfg,
        Err(errs) => panic!("expected a valid config, got:\n{errs}"),
    }
}

fn parse_err(input: &str) -> Vec<ConfigErrorKind> {
    match Config::parse(input) {
        Ok(cfg) => panic!("expected errors, got a valid config: {cfg:?}"),
        Err(errs) => errs.errors.into_iter().map(|e| e.kind).collect(),
    }
}

// ---- t/001-parse-config.t -------------------------------------------------

#[test]
fn empty_config_has_no_zones() {
    assert!(!parse_ok("").has_zones());
}

#[test]
fn comment_only_config_has_no_zones() {
    assert!(!parse_ok("# meh").has_zones());
}

/// The original's third fixture, tab-indented.
#[test]
fn single_zone_fixture() {
    let cfg = parse_ok(
        "# RaumZeitLabor\n\
         network 2001:4d88:100e:ccc0::/64\n\
         \tresolves to ipv6-%DIGITS%.nutzer.raumzeitlabor.de\n\
         \twith upstream 2001:4d88:100e:1::2\n",
    );
    assert_eq!(cfg.zones.len(), 1);
    let zone = &cfg.zones[0];
    assert_eq!(zone.mask, 64);
    assert_eq!(zone.host_nibbles, 16);
    assert_eq!(zone.resolves_to, "ipv6-%DIGITS%.nutzer.raumzeitlabor.de");
    assert_eq!(
        zone.upstream.map(|a| a.to_string()).as_deref(),
        Some("2001:4d88:100e:1::2")
    );
    assert_eq!(
        zone.ptr_zone.to_ascii().trim_end_matches('.'),
        "0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa"
    );
}

/// The original's fourth fixture: two zones, the second using 8-space indentation
/// and deliberately scrambled keyword casing.
///
/// This pins the asymmetry that matters: `network` and `with upstream` are
/// lowercased, but `resolves to` is preserved verbatim.
#[test]
fn mixed_case_keywords_and_selective_lowercasing() {
    let cfg = parse_ok(
        "# RaumZeitLabor\n\
         network 2001:4d88:100e:ccc0::/64\n\
         \tresolves to ipv6-%DIGITS%.nutzer.raumzeitlabor.de\n\
         \twith upstream 2001:4d88:100e:1::2\n\
         \n\
         # Chaostreff (spaces instead of tabs, uppercase keywords)\n\
         NETWORK 2001:4D88:100E:CD1::/64\n\
                 ReSoLvEs tO IPV6-%DIGITS%.treff.noname-ev.de\n\
                 WiTh UpStReAm 2001:4d88:100e:1::2\n",
    );
    assert_eq!(cfg.zones.len(), 2);

    // Both are /64, so configuration order is preserved by the stable sort.
    let z1 = &cfg.zones[0];
    let z2 = &cfg.zones[1];

    assert_eq!(z1.resolves_to, "ipv6-%DIGITS%.nutzer.raumzeitlabor.de");

    // `network` was uppercase in the source; the compiled prefix is the same
    // value either way, and the PTR zone is lowercase hex.
    assert_eq!(
        z2.ptr_zone.to_ascii().trim_end_matches('.'),
        "1.d.c.0.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa"
    );
    // `resolves to` keeps the operator's capitalisation.
    assert_eq!(z2.resolves_to, "IPV6-%DIGITS%.treff.noname-ev.de");
    let FwdLabel::Digits { pre, pre_lower, .. } = &z2.fwd.labels[z2.fwd.digits_at] else {
        panic!("expected a digits label");
    };
    assert_eq!(pre, b"IPV6-", "emitted form keeps case");
    assert_eq!(pre_lower, b"ipv6-", "matching form is lowercased");
}

#[test]
fn listen_addresses_keep_order_and_accept_both_families() {
    let cfg = parse_ok("listen 2001:4d88:100e:1::3\nlisten 79.140.39.197\n");
    assert!(!cfg.has_zones());
    let got: Vec<String> = cfg
        .listen
        .iter()
        .map(|l| format!("{}:{}", l.addr, l.port))
        .collect();
    assert_eq!(got, ["2001:4d88:100e:1::3:53", "79.140.39.197:53"]);
}

#[test]
fn listen_accepts_explicit_port() {
    let cfg = parse_ok("listen [::]:5353\nlisten 0.0.0.0:5354\n");
    assert_eq!(cfg.listen[0].port, 5353);
    assert_eq!(cfg.listen[1].port, 5354);
}

/// Indentation is decorative, and whitespace between keyword words is flexible.
#[test]
fn indentation_and_inner_whitespace_are_irrelevant() {
    let cfg = parse_ok(
        "\t   network 2001:db8::/32\n\
         \t\t\tresolves    to    host-%DIGITS%.example.net\n",
    );
    assert_eq!(cfg.zones.len(), 1);
    assert_eq!(cfg.zones[0].resolves_to, "host-%DIGITS%.example.net");
}

#[test]
fn crlf_line_endings_are_accepted() {
    let cfg = parse_ok("network 2001:db8::/32\r\n\tresolves to h-%DIGITS%.example.net\r\n");
    assert_eq!(cfg.zones.len(), 1);
}

/// The shipped `all-knowing-dns.conf` from the original distribution must parse.
#[test]
fn original_shipped_config_parses() {
    let cfg = parse_ok(
        "# Configuration file for AllKnowingDNS v1.3\n\
         \n\
         # RaumZeitLabor\n\
         network 2001:4d88:100e:ccc0::/64\n\
         \tresolves to ipv6-%DIGITS%.nutzer.raumzeitlabor.de\n\
         \twith upstream 2001:4d88:100e:1::2\n",
    );
    assert_eq!(cfg.zones.len(), 1);
}

// ---- strict validation ----------------------------------------------------

/// Finding 4, the one that made the original authoritative for all of IPv6
/// reverse DNS. A missing prefix length is now fatal and named.
#[test]
fn network_without_prefix_length_is_fatal() {
    assert_eq!(
        parse_err("network 2001:db8::\n\tresolves to h-%DIGITS%.example.net\n"),
        [ConfigErrorKind::NetworkMissingPrefixLen]
    );
}

/// No compiled zone may ever be able to match the whole reverse namespace.
#[test]
fn no_zone_can_claim_all_of_ip6_arpa() {
    for input in [
        "network 2001:db8::\n\tresolves to h-%DIGITS%.example.net\n",
        "network ::/0\n\tresolves to h-%DIGITS%.example.net\n",
        "network garbage\n\tresolves to h-%DIGITS%.example.net\n",
        "network /64\n\tresolves to h-%DIGITS%.example.net\n",
    ] {
        match Config::parse(input) {
            Err(_) => {}
            Ok(cfg) => {
                for zone in &cfg.zones {
                    assert_ne!(zone.mask, 0, "a /0 zone matches every reverse query");
                    assert!(
                        zone.ptr_zone.num_labels() > 2,
                        "zone {} collapsed to a bare ip6.arpa",
                        zone.ptr_zone
                    );
                }
            }
        }
    }
}

#[test]
fn prefix_must_be_nibble_aligned() {
    assert_eq!(
        parse_err("network 2001:db8::/63\n\tresolves to h-%DIGITS%.example.net\n"),
        [ConfigErrorKind::NetworkPrefixNotNibbleAligned { mask: 63 }]
    );
    // A multiple of 4 that is not a multiple of 16 is accepted, unlike the
    // original which only allowed multiples of 16.
    assert_eq!(
        parse_ok("network 2001:db8:8000::/36\n\tresolves to h-%DIGITS%.example.net\n").zones[0]
            .mask,
        36
    );
}

#[test]
fn prefix_length_range_is_checked() {
    assert_eq!(
        parse_err("network 2001:db8::/129\n\tresolves to h-%DIGITS%.example.net\n"),
        [ConfigErrorKind::NetworkPrefixLenOutOfRange { mask: 129 }]
    );
    assert_eq!(
        parse_err("network 2001:db8::/64x\n\tresolves to h-%DIGITS%.example.net\n"),
        [ConfigErrorKind::NetworkPrefixLenNotANumber]
    );
    assert_eq!(
        parse_err("network 2001:db8::1/128\n\tresolves to h-%DIGITS%.example.net\n"),
        [ConfigErrorKind::NetworkIsSingleAddress]
    );
}

/// The original's own `t/005` fixture used networks like this. Tolerating host
/// bits hides exactly the class of mistake that finding 4 was about.
#[test]
fn host_bits_below_the_prefix_are_fatal_with_a_suggestion() {
    let errs = parse_err("network 2a00:15a0::192:1/64\n\tresolves to h-%DIGITS%.example.net\n");
    assert_eq!(
        errs,
        [ConfigErrorKind::NetworkHostBitsSet {
            suggestion: "2a00:15a0::/64".into()
        }]
    );
}

/// `2a00:15a0::192:/64` — the verbatim string from `t/005` — is not even a
/// valid IPv6 address. NetAddr::IP accepted it; we do not.
#[test]
fn trailing_colon_address_from_perl_suite_is_rejected() {
    assert_eq!(
        parse_err("network 2a00:15a0::192:/64\n\tresolves to h-%DIGITS%.example.net\n"),
        [ConfigErrorKind::NetworkInvalidAddress]
    );
}

#[test]
fn placeholder_must_appear_exactly_once() {
    assert_eq!(
        parse_err("network 2001:db8::/64\n\tresolves to static.example.net\n"),
        [ConfigErrorKind::PlaceholderMissing]
    );
    assert_eq!(
        parse_err("network 2001:db8::/64\n\tresolves to a-%DIGITS%-%DIGITS%.example.net\n"),
        [ConfigErrorKind::PlaceholderRepeated { count: 2 }]
    );
}

/// The original's substitutions used `/i`, so a lowercase placeholder worked
/// there and must keep working.
#[test]
fn placeholder_is_case_insensitive() {
    let cfg = parse_ok("network 2001:db8::/64\n\tresolves to h-%digits%.example.net\n");
    assert!(matches!(
        cfg.zones[0].fwd.labels[cfg.zones[0].fwd.digits_at],
        FwdLabel::Digits { .. }
    ));
}

#[test]
fn dashed_placeholder_parses_and_flags_the_label() {
    let cfg = parse_ok("network 2001:db8::/64\n\tresolves to h-%DIGITS-DASHED%.example.net\n");
    let FwdLabel::Digits { dashed, .. } = &cfg.zones[0].fwd.labels[cfg.zones[0].fwd.digits_at]
    else {
        panic!("expected a Digits label");
    };
    assert!(*dashed);
}

#[test]
fn dashed_placeholder_is_case_insensitive() {
    let cfg = parse_ok("network 2001:db8::/64\n\tresolves to h-%digits-dashed%.example.net\n");
    let FwdLabel::Digits { dashed, .. } = &cfg.zones[0].fwd.labels[cfg.zones[0].fwd.digits_at]
    else {
        panic!("expected a Digits label");
    };
    assert!(*dashed);
}

/// %DIGITS-DASHED% and %DIGITS% together count as the placeholder appearing
/// twice, same as %DIGITS% used twice.
#[test]
fn dashed_and_plain_placeholder_together_is_repeated() {
    assert_eq!(
        parse_err("network 2001:db8::/64\n\tresolves to a-%DIGITS%-%DIGITS-DASHED%.example.net\n"),
        [ConfigErrorKind::PlaceholderRepeated { count: 2 }]
    );
}

/// A /60 network leaves 17 host nibbles, not a multiple of 4, so grouping in
/// 4s cannot be inverted when matching a forward query.
#[test]
fn dashed_placeholder_requires_nibble_count_multiple_of_4() {
    assert_eq!(
        parse_err("network 2001:db8::/60\n\tresolves to h-%DIGITS-DASHED%.example.net\n"),
        [ConfigErrorKind::DashedDigitsNotNibbleMultipleOfFour { host_nibbles: 17 }]
    );
    // /64 leaves 16 host nibbles — a multiple of 4 — so it is accepted.
    assert!(
        parse_ok("network 2001:db8::/64\n\tresolves to h-%DIGITS-DASHED%.example.net\n")
            .has_zones()
    );
}

#[test]
fn zone_without_resolves_to_is_fatal() {
    assert_eq!(
        parse_err("network 2001:db8::/64\n"),
        [ConfigErrorKind::MissingResolvesTo]
    );
}

#[test]
fn directive_before_any_network_is_fatal() {
    assert_eq!(
        parse_err("resolves to h-%DIGITS%.example.net\n"),
        [ConfigErrorKind::DirectiveBeforeNetwork {
            keyword: "resolves to"
        }]
    );
}

/// The original silently ignored anything it did not recognise, so a typo
/// disabled a directive without a word of warning.
#[test]
fn unknown_directive_is_fatal() {
    assert_eq!(
        parse_err("netwrok 2001:db8::/64\n"),
        [ConfigErrorKind::UnknownDirective {
            keyword: "netwrok".into()
        }]
    );
}

#[test]
fn keyword_without_value_is_reported_as_such() {
    assert_eq!(
        parse_err("network\n"),
        [ConfigErrorKind::MissingValue { keyword: "network" }]
    );
}

#[test]
fn duplicates_are_reported() {
    assert_eq!(
        parse_err(
            "network 2001:db8::/64\n\tresolves to a-%DIGITS%.example.net\n\tresolves to b-%DIGITS%.example.net\n"
        ),
        [ConfigErrorKind::DuplicateDirective {
            keyword: "resolves to",
            first_line: 2
        }]
    );
    assert_eq!(
        parse_err(
            "network 2001:db8::/64\n\tresolves to a-%DIGITS%.example.net\n\
             network 2001:db8::/64\n\tresolves to b-%DIGITS%.example.net\n"
        ),
        [ConfigErrorKind::DuplicateNetwork { first_line: 1 }]
    );
    assert_eq!(
        parse_err(
            "network 2001:db8::/64\n\tresolves to a-%DIGITS%.example.net\n\
             network 2001:db9::/64\n\tresolves to a-%DIGITS%.example.net\n"
        ),
        [ConfigErrorKind::DuplicateForwardPattern { first_line: 2 }]
    );
}

#[test]
fn invalid_upstream_is_fatal() {
    assert_eq!(
        parse_err(
            "network 2001:db8::/64\n\tresolves to h-%DIGITS%.example.net\n\twith upstream nope\n"
        ),
        [ConfigErrorKind::InvalidUpstreamAddress]
    );
}

/// A template whose widest rendering would exceed the 63-byte label limit is
/// rejected at startup, so synthesis can never fail at request time.
#[test]
fn oversized_label_template_is_rejected_at_startup() {
    // /0 is rejected earlier, so use /4: 31 nibbles plus a 40-byte prefix
    // exceeds 63 bytes in one label.
    let long = "x".repeat(40);
    let errs = parse_err(&format!(
        "network 2000::/4\n\tresolves to {long}%DIGITS%.example.net\n"
    ));
    assert!(
        matches!(
            errs.as_slice(),
            [ConfigErrorKind::ForwardNameTooLong { .. }]
        ),
        "got {errs:?}"
    );
}

/// All problems are reported in one pass, not one per run.
#[test]
fn every_error_is_reported_at_once() {
    let errs = parse_err(
        "listen not-an-address\n\
         network 2001:db8::/63\n\
         \tresolves to h-%DIGITS%.example.net\n\
         netwrok typo\n",
    );
    assert_eq!(errs.len(), 3, "got {errs:?}");
}

/// Zones are ordered longest-prefix-first so a linear scan is a correct
/// longest-prefix match regardless of configuration order.
#[test]
fn zones_are_sorted_longest_prefix_first() {
    let cfg = parse_ok(
        "network 2001:db8::/32\n\tresolves to a-%DIGITS%.example.net\n\
         network 2001:db8:1:2::/64\n\tresolves to b-%DIGITS%.example.net\n\
         network 2001:db8:1::/48\n\tresolves to c-%DIGITS%.example.net\n",
    );
    let masks: Vec<u8> = cfg.zones.iter().map(|z| z.mask).collect();
    assert_eq!(masks, [64, 48, 32]);
}

/// The rendered diagnostic must actually point at the mistake.
#[test]
fn diagnostics_are_rustc_shaped_and_point_at_the_value() {
    let Err(errs) = Config::parse(
        "network 2001:db8::/64\n\tresolves to h-%DIGITS%.example.net\n\nnetwork 2001:db8::/63\n\tresolves to i-%DIGITS%.example.net\n",
    ) else {
        panic!("expected an error");
    };
    let rendered = errs
        .with_path("/etc/panoptidns/panoptidns.conf")
        .to_string();
    assert!(rendered.contains("not nibble-aligned"), "{rendered}");
    assert!(
        rendered.contains("--> /etc/panoptidns/panoptidns.conf:4"),
        "{rendered}"
    );
    assert!(rendered.contains("^"), "{rendered}");
    assert!(rendered.contains("expected /0, /4, /8"), "{rendered}");
}
