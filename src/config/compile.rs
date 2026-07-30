//! Validation: raw directives to a checked [`Config`].
//!
//! Everything that could make the request path fail is decided here, at startup,
//! so that answering a query is infallible by construction. In particular the
//! widest name a template can produce is built once and checked against the DNS
//! length limits, which is why synthesis never has to handle an error.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use hickory_proto::rr::domain::Name;

use super::error::{ConfigError, ConfigErrorKind};
use super::parse::{GlobalKey, RawConfig, RawValue, RawZone};
use super::{
    Config, FwdLabel, FwdTemplate, ListenAddr, OutOfZonePolicy, ServerParams, SoaParams, Zone,
    DEFAULT_PORT, DEFAULT_TTL,
};
use crate::nibble::{mask_bits, netmask_to_ptr_name, ADDR_NIBBLES};

/// The `%DIGITS%` placeholder, matched case-insensitively (the original's
/// substitutions carried the `/i` flag, so `%digits%` worked there too).
const PLACEHOLDER: &str = "%digits%";

pub(crate) fn compile(raw: RawConfig, errors: &mut Vec<ConfigError>) -> Config {
    let listen = raw
        .listen
        .iter()
        .filter_map(|v| compile_listen(v, errors))
        .collect();

    let globals = compile_globals(&raw, errors);

    let mut zones: Vec<Zone> = Vec::with_capacity(raw.zones.len());
    // Duplicate detection: a repeated network or forward pattern is always a
    // mistake, and would silently shadow the later zone.
    let mut seen_networks: HashMap<(u128, u8), u32> = HashMap::new();
    let mut seen_patterns: HashMap<String, u32> = HashMap::new();

    for zone in &raw.zones {
        if let Some(mut compiled) =
            compile_zone(zone, errors, &mut seen_networks, &mut seen_patterns)
        {
            compiled.ttl = globals.ttl;
            zones.push(compiled);
        }
    }

    // Longest-prefix-match by linear scan: sort by mask descending. Ties keep
    // configuration order, so behaviour stays predictable.
    zones.sort_by_key(|z| core::cmp::Reverse(z.mask));

    Config {
        listen,
        zones,
        soa: globals.soa,
        nameservers: globals.nameservers,
        params: globals.params,
    }
}

/// Everything the global directives produce.
struct Globals {
    ttl: u32,
    soa: Option<SoaParams>,
    nameservers: Vec<Name>,
    params: ServerParams,
}

fn compile_globals(raw: &RawConfig, errors: &mut Vec<ConfigError>) -> Globals {
    let mut ttl = DEFAULT_TTL;
    let mut params = ServerParams::default();
    let mut primary: Option<Name> = None;
    let mut hostmaster: Option<Name> = None;
    let mut nameservers: Vec<Name> = Vec::new();

    for global in &raw.globals {
        let v = &global.value;
        match global.key {
            GlobalKey::Primary => primary = parse_name(v, "primary", errors),
            GlobalKey::Hostmaster => hostmaster = parse_name(v, "hostmaster", errors),
            GlobalKey::Ns => {
                if let Some(name) = parse_name(v, "ns", errors) {
                    nameservers.push(name);
                }
            }
            GlobalKey::Ttl => {
                if let Some(n) = parse_u32(v, "ttl", "a TTL in seconds (0-2147483647)", errors) {
                    // RFC 2181: the top bit of a TTL must be clear.
                    if n > 0x7FFF_FFFF {
                        errors.push(v.error(ConfigErrorKind::InvalidNumber {
                            what: "ttl",
                            allowed: "a TTL in seconds (0-2147483647)",
                        }));
                    } else {
                        ttl = n;
                    }
                }
            }
            GlobalKey::OutOfZone => match v.value.as_str() {
                "refused" => params.out_of_zone = OutOfZonePolicy::Refused,
                "nxdomain" => params.out_of_zone = OutOfZonePolicy::NxDomain,
                _ => errors.push(v.error(ConfigErrorKind::InvalidChoice {
                    what: "out-of-zone",
                    allowed: "`refused` or `nxdomain`",
                })),
            },
            GlobalKey::MaxUdpPayload => {
                if let Some(n) = parse_u32(v, "max-udp-payload", "512-65535 bytes", errors) {
                    match u16::try_from(n) {
                        Ok(n) if n >= 512 => params.max_udp_payload = n,
                        _ => errors.push(v.error(ConfigErrorKind::InvalidNumber {
                            what: "max-udp-payload",
                            allowed: "512-65535 bytes",
                        })),
                    }
                }
            }
            GlobalKey::UpstreamTimeout => {
                if let Some(n) = parse_u32(v, "upstream-timeout", "1-10000 milliseconds", errors) {
                    if (1..=10_000).contains(&n) {
                        params.upstream_timeout = Duration::from_millis(u64::from(n));
                    } else {
                        errors.push(v.error(ConfigErrorKind::InvalidNumber {
                            what: "upstream-timeout",
                            allowed: "1-10000 milliseconds",
                        }));
                    }
                }
            }
            GlobalKey::RrlOff => params.rrl.enabled = false,
            GlobalKey::RrlRps => {
                if let Some(n) = parse_u32(v, "rrl responses-per-second", "at least 1", errors) {
                    if n >= 1 {
                        params.rrl.responses_per_second = n;
                    } else {
                        errors.push(v.error(ConfigErrorKind::InvalidNumber {
                            what: "rrl responses-per-second",
                            allowed: "at least 1",
                        }));
                    }
                }
            }
            GlobalKey::RrlBurst => {
                if let Some(n) = parse_u32(v, "rrl burst", "at least 1", errors) {
                    if n >= 1 {
                        params.rrl.burst = n;
                    } else {
                        errors.push(v.error(ConfigErrorKind::InvalidNumber {
                            what: "rrl burst",
                            allowed: "at least 1",
                        }));
                    }
                }
            }
            GlobalKey::RrlSlip => {
                if let Some(n) = parse_u32(v, "rrl slip", "0 (always drop) or more", errors) {
                    params.rrl.slip = n;
                }
            }
        }
    }

    // SOA needs both halves; one without the other is a mistake worth naming.
    let soa = match (primary, hostmaster) {
        (Some(primary), Some(hostmaster)) => Some(SoaParams {
            primary,
            hostmaster,
            // A serial only matters for zone transfers, which this server does
            // not offer, so a fixed value is honest and reproducible.
            serial: 1,
            refresh: 604_800,
            retry: 86_400,
            expire: 2_419_200,
            // Negative-cache TTL: deliberately short, because a network's
            // contents change without us being told.
            minimum: 60,
        }),
        (Some(_), None) => {
            errors.push(missing_pair_error(raw, "hostmaster", "primary"));
            None
        }
        (None, Some(_)) => {
            errors.push(missing_pair_error(raw, "primary", "hostmaster"));
            None
        }
        (None, None) => None,
    };

    Globals {
        ttl,
        soa,
        nameservers,
        params,
    }
}

/// Anchor a "you set X but not Y" error at whichever of the two was present.
fn missing_pair_error(raw: &RawConfig, missing: &'static str, present: &str) -> ConfigError {
    let anchor = raw
        .globals
        .iter()
        .find(|g| matches!(g.key, GlobalKey::Primary | GlobalKey::Hostmaster))
        .map(|g| g.value.clone());
    let kind = ConfigErrorKind::MissingCompanionDirective {
        missing,
        present: present.to_string(),
    };
    match anchor {
        Some(v) => v.error(kind),
        None => ConfigError {
            line: 1,
            snippet: String::new(),
            span: None,
            kind,
        },
    }
}

fn parse_name(v: &RawValue, what: &'static str, errors: &mut Vec<ConfigError>) -> Option<Name> {
    match Name::from_str_relaxed(&v.value) {
        Ok(mut name) => {
            name.set_fqdn(true);
            Some(name)
        }
        Err(_) => {
            errors.push(v.error(ConfigErrorKind::InvalidDnsName { what }));
            None
        }
    }
}

fn parse_u32(
    v: &RawValue,
    what: &'static str,
    allowed: &'static str,
    errors: &mut Vec<ConfigError>,
) -> Option<u32> {
    match u32::from_str(&v.value) {
        Ok(n) => Some(n),
        Err(_) => {
            errors.push(v.error(ConfigErrorKind::InvalidNumber { what, allowed }));
            None
        }
    }
}

fn compile_listen(v: &RawValue, errors: &mut Vec<ConfigError>) -> Option<ListenAddr> {
    // `[::]:5353` and `1.2.3.4:53` parse as a socket address; a bare address
    // takes the default port.
    if let Ok(sock) = SocketAddr::from_str(&v.value) {
        return Some(ListenAddr {
            addr: sock.ip(),
            port: sock.port(),
        });
    }
    if let Ok(addr) = IpAddr::from_str(&v.value) {
        return Some(ListenAddr {
            addr,
            port: DEFAULT_PORT,
        });
    }
    errors.push(v.error(ConfigErrorKind::InvalidListenAddress));
    None
}

fn compile_zone(
    raw: &RawZone,
    errors: &mut Vec<ConfigError>,
    seen_networks: &mut HashMap<(u128, u8), u32>,
    seen_patterns: &mut HashMap<String, u32>,
) -> Option<Zone> {
    let (prefix, mask) = compile_network(&raw.network, errors)?;

    if let Some(&first_line) = seen_networks.get(&(prefix, mask)) {
        errors.push(
            raw.network
                .error(ConfigErrorKind::DuplicateNetwork { first_line }),
        );
        return None;
    }

    let Some(resolves_to) = raw.resolves_to.as_ref() else {
        errors.push(raw.network.error(ConfigErrorKind::MissingResolvesTo));
        return None;
    };

    let host_nibbles = (128u8.saturating_sub(mask)) / 4;
    let fwd = compile_template(resolves_to, host_nibbles, errors)?;

    // A repeated pattern would make the earlier zone shadow this one forever.
    let pattern_key = resolves_to.value.to_ascii_lowercase();
    if let Some(&first_line) = seen_patterns.get(&pattern_key) {
        errors.push(resolves_to.error(ConfigErrorKind::DuplicateForwardPattern { first_line }));
        return None;
    }

    let upstream = match raw.upstream.as_ref() {
        Some(v) => match IpAddr::from_str(&v.value) {
            Ok(addr) => Some(addr),
            Err(_) => {
                errors.push(v.error(ConfigErrorKind::InvalidUpstreamAddress));
                return None;
            }
        },
        None => None,
    };

    // Infallible by the checks above, but never unwrap on config data.
    let ptr_zone = match netmask_to_ptr_name(prefix, mask) {
        Some(name) => name,
        None => {
            errors.push(
                raw.network
                    .error(ConfigErrorKind::NetworkPrefixNotNibbleAligned { mask }),
            );
            return None;
        }
    };

    let fwd_parent = match fwd.parent() {
        Ok(name) => name,
        Err(e) => {
            errors.push(resolves_to.error(ConfigErrorKind::ResolvesToInvalidName {
                reason: e.to_string(),
            }));
            return None;
        }
    };

    seen_networks.insert((prefix, mask), raw.network.line);
    seen_patterns.insert(pattern_key, resolves_to.line);

    Some(Zone {
        src_line: raw.network.line,
        prefix,
        mask,
        host_nibbles,
        ptr_zone,
        resolves_to: resolves_to.value.clone(),
        fwd,
        fwd_parent,
        ttl: DEFAULT_TTL,
        upstream,
    })
}

/// Parse `<ipv6>/<prefixlen>` with every failure mode reported distinctly.
fn compile_network(v: &RawValue, errors: &mut Vec<ConfigError>) -> Option<(u128, u8)> {
    let Some((addr_part, mask_part)) = v.value.split_once('/') else {
        // This is the original's most dangerous failure: it left the mask
        // undefined, `undef % 16 == 0` passed its only check, and the resulting
        // PTR zone was a bare `.ip6.arpa` matching every reverse query.
        errors.push(v.error(ConfigErrorKind::NetworkMissingPrefixLen));
        return None;
    };

    let addr = match Ipv6Addr::from_str(addr_part) {
        Ok(addr) => addr,
        Err(_) => {
            errors.push(v.error_at(0, addr_part.len(), ConfigErrorKind::NetworkInvalidAddress));
            return None;
        }
    };

    let mask_offset = addr_part.len().saturating_add(1);
    let mask_u32 = match u32::from_str(mask_part) {
        Ok(m) => m,
        Err(_) => {
            errors.push(v.error_at(
                mask_offset,
                mask_part.len(),
                ConfigErrorKind::NetworkPrefixLenNotANumber,
            ));
            return None;
        }
    };
    if mask_u32 > 128 {
        errors.push(v.error_at(
            mask_offset,
            mask_part.len(),
            ConfigErrorKind::NetworkPrefixLenOutOfRange { mask: mask_u32 },
        ));
        return None;
    }
    let mask = u8::try_from(mask_u32).unwrap_or(128);

    if !mask.is_multiple_of(4) {
        errors.push(v.error_at(
            mask_offset,
            mask_part.len(),
            ConfigErrorKind::NetworkPrefixNotNibbleAligned { mask },
        ));
        return None;
    }
    if mask == 0 {
        errors.push(v.error_at(
            mask_offset,
            mask_part.len(),
            ConfigErrorKind::NetworkPrefixTooShort { mask },
        ));
        return None;
    }
    if mask == 128 {
        errors.push(v.error(ConfigErrorKind::NetworkIsSingleAddress));
        return None;
    }

    let raw_addr = u128::from(addr);
    let prefix = raw_addr & mask_bits(mask);
    if raw_addr != prefix {
        // e.g. `2a00:15a0::192:/64`. The original's own test suite contained
        // networks like this; tolerating them hides real mistakes.
        let suggestion = format!("{}/{mask}", Ipv6Addr::from(prefix));
        errors.push(v.error(ConfigErrorKind::NetworkHostBitsSet { suggestion }));
        return None;
    }

    Some((prefix, mask))
}

/// Split a `resolves to` template at label boundaries around `%DIGITS%`.
fn compile_template(
    v: &RawValue,
    host_nibbles: u8,
    errors: &mut Vec<ConfigError>,
) -> Option<FwdTemplate> {
    // `to_ascii_lowercase` is byte-for-byte length preserving, so offsets found
    // in the lowered copy are valid in the original.
    let lowered = v.value.to_ascii_lowercase();
    let hits: Vec<usize> = lowered.match_indices(PLACEHOLDER).map(|(i, _)| i).collect();
    match hits.len() {
        1 => {}
        0 => {
            errors.push(v.error(ConfigErrorKind::PlaceholderMissing));
            return None;
        }
        count => {
            errors.push(v.error(ConfigErrorKind::PlaceholderRepeated { count }));
            return None;
        }
    }

    // A single trailing dot just marks the name as absolute, which it always is.
    let template = v.value.strip_suffix('.').unwrap_or(&v.value);

    let mut labels: Vec<FwdLabel> = Vec::new();
    let mut digits_at: Option<usize> = None;

    for (idx, segment) in template.split('.').enumerate() {
        if segment.is_empty() {
            errors.push(v.error(ConfigErrorKind::ResolvesToInvalidName {
                reason: "empty label".into(),
            }));
            return None;
        }
        let seg_lower = segment.to_ascii_lowercase();
        match seg_lower.find(PLACEHOLDER) {
            Some(at) => {
                let (pre, rest) = match segment.split_at_checked(at) {
                    Some(parts) => parts,
                    None => {
                        errors.push(v.error(ConfigErrorKind::ResolvesToInvalidName {
                            reason: "malformed placeholder".into(),
                        }));
                        return None;
                    }
                };
                let post = match rest.split_at_checked(PLACEHOLDER.len()) {
                    Some((_, post)) => post,
                    None => {
                        errors.push(v.error(ConfigErrorKind::ResolvesToInvalidName {
                            reason: "malformed placeholder".into(),
                        }));
                        return None;
                    }
                };
                digits_at = Some(idx);
                labels.push(FwdLabel::Digits {
                    pre: pre.as_bytes().to_vec(),
                    pre_lower: pre.to_ascii_lowercase().into_bytes(),
                    post: post.as_bytes().to_vec(),
                    post_lower: post.to_ascii_lowercase().into_bytes(),
                });
            }
            None => labels.push(FwdLabel::Literal {
                verbatim: segment.as_bytes().to_vec(),
                lower: seg_lower.into_bytes(),
            }),
        }
    }

    let Some(digits_at) = digits_at else {
        // The placeholder was found in the whole string but not in any label,
        // which can only happen if it straddles a dot — impossible, since it
        // contains none. Report defensively rather than panicking.
        errors.push(v.error(ConfigErrorKind::ResolvesToInvalidName {
            reason: "placeholder does not lie within a single label".into(),
        }));
        return None;
    };

    let template = FwdTemplate { labels, digits_at };

    // Prove the worst case is representable, so the request path cannot fail.
    // All-`f` is the widest rendering: hex digits are one byte each, so any
    // other value has exactly the same length, but using `f` also catches
    // templates that are only valid for shorter digit strings.
    let widest = "f".repeat(usize::from(host_nibbles.min(ADDR_NIBBLES)));
    if let Err(e) = template.render(&widest) {
        errors.push(v.error(ConfigErrorKind::ForwardNameTooLong {
            reason: e.to_string(),
        }));
        return None;
    }

    Some(template)
}
