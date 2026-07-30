//! Matching a query name against the configured zones.
//!
//! Both directions are exact by construction, which is what makes the original's
//! two matching bugs unrepresentable here:
//!
//! - Reverse: the original compared **string suffixes**, so any prefix was
//!   accepted and everything left of the zone was concatenated into the answer.
//!   Here the name is parsed into a `u128` first, then matched arithmetically.
//! - Forward: the original compiled an anchored regex for zone selection but an
//!   unanchored one for synthesis, with different digit-count rules in each. Here
//!   a single label-count check makes the match total, and the digit count is
//!   validated in the same place the zone is chosen.

use hickory_proto::rr::domain::Name;

use crate::config::{Config, FwdLabel, Zone};
use crate::nibble::{digits_to_host, mask_bits, ptr_name_to_addr};

/// Case-insensitively strip `prefix`, which must already be lowercase.
#[inline]
fn strip_prefix_ci<'a>(label: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let (head, tail) = label.split_at_checked(prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then_some(tail)
}

/// Case-insensitively strip `suffix`, which must already be lowercase.
#[inline]
fn strip_suffix_ci<'a>(label: &'a [u8], suffix: &[u8]) -> Option<&'a [u8]> {
    let split = label.len().checked_sub(suffix.len())?;
    let (head, tail) = label.split_at_checked(split)?;
    tail.eq_ignore_ascii_case(suffix).then_some(head)
}

/// Find the zone containing `addr`, longest prefix first.
///
/// `Config::zones` is pre-sorted by prefix length descending, so the first hit is
/// the most specific one regardless of the order the operator wrote them in. The
/// original returned the first zone in *configuration* order, which silently gave
/// the wrong answer for overlapping networks.
#[must_use]
pub fn zone_for_addr(config: &Config, addr: u128) -> Option<&Zone> {
    config
        .zones
        .iter()
        .find(|zone| addr & mask_bits(zone.mask) == zone.prefix)
}

/// Match a reverse-DNS query name.
///
/// Returns the zone and the address the name denotes, or `None` if the name is
/// not a well-formed full `ip6.arpa` address or falls outside every network.
#[must_use]
pub fn match_ptr<'a>(config: &'a Config, qname: &Name) -> Option<(&'a Zone, u128)> {
    let addr = ptr_name_to_addr(qname)?;
    zone_for_addr(config, addr).map(|zone| (zone, addr))
}

/// Match `qname` against one zone's forward template.
///
/// Returns the address the name encodes. The label count must match exactly, so
/// this can never succeed on a mere suffix — `…example.net.evil.com` is rejected
/// structurally rather than by an anchor that someone might forget.
#[must_use]
pub fn match_zone_forward(zone: &Zone, qname: &Name) -> Option<u128> {
    if usize::from(qname.num_labels()) != zone.fwd.label_count() {
        return None;
    }

    let mut host: Option<u128> = None;
    for (label, template) in qname.iter().zip(&zone.fwd.labels) {
        match template {
            FwdLabel::Literal { lower, .. } => {
                if !label.eq_ignore_ascii_case(lower) {
                    return None;
                }
            }
            FwdLabel::Digits {
                pre_lower,
                post_lower,
                ..
            } => {
                let rest = strip_prefix_ci(label, pre_lower)?;
                let middle = strip_suffix_ci(rest, post_lower)?;
                // Length and hex-ness are both checked here, once.
                host = Some(digits_to_host(middle, zone.host_nibbles)?);
            }
        }
    }

    // `prefix` is already masked at config-compile time, so this OR cannot
    // corrupt the network part.
    host.map(|host| zone.prefix | host)
}

/// Match a forward query name against every zone.
#[must_use]
pub fn match_forward<'a>(config: &'a Config, qname: &Name) -> Option<(&'a Zone, u128)> {
    config
        .zones
        .iter()
        .find_map(|zone| match_zone_forward(zone, qname).map(|addr| (zone, addr)))
}

/// The zone whose namespace contains `qname`, if any.
///
/// Used to answer "inside a zone we are authoritative for, but there is no such
/// record" with a SOA so resolvers can cache the negative, instead of the bare
/// NXDOMAIN the original returned for every miss.
#[must_use]
pub fn zone_containing<'a>(config: &'a Config, qname: &Name) -> Option<&'a Zone> {
    config
        .zones
        .iter()
        .find(|zone| zone.ptr_zone.zone_of(qname) || zone.fwd_parent.zone_of(qname))
}
