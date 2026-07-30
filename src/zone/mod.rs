//! Pure zone resolution: query name in, records out.
//!
//! This module is the whole behavioural specification of the server, and it
//! touches no sockets, no clock and no async runtime. Everything the original's
//! test suite asserted is asserted here, which is why `tests/` can pin the
//! contract without binding a port.

pub mod lookup;
pub mod synth;

use hickory_proto::rr::domain::Name;
use hickory_proto::rr::{Record, RecordType};

use crate::config::{Config, Zone};

/// What the configuration says about a query.
#[derive(Debug)]
pub enum Outcome<'a> {
    /// Records to return, authoritatively. May be empty, which means NODATA:
    /// the name exists but holds nothing of the requested type.
    Answer {
        zone: &'a Zone,
        records: Vec<Record>,
    },
    /// The name lies inside a zone we serve but denotes nothing at all. The
    /// caller answers NXDOMAIN *with* the zone's SOA, so resolvers can cache it.
    NoName { zone: &'a Zone },
    /// Not our namespace. The caller decides between REFUSED and NXDOMAIN.
    NoZone,
}

/// Resolve a query against the configuration.
///
/// Precedence follows the original: a PTR query is matched against the reverse
/// zones first, then the name is tried against the forward templates regardless
/// of query type.
#[must_use]
pub fn resolve<'a>(config: &'a Config, qname: &Name, qtype: RecordType) -> Outcome<'a> {
    if synth::reverse_has_type(qtype) {
        if let Some((zone, addr)) = lookup::match_ptr(config, qname) {
            let records = synth::ptr_record(zone, qname, addr)
                .map(|r| vec![r])
                .unwrap_or_default();
            return Outcome::Answer { zone, records };
        }
    }

    if let Some((zone, addr)) = lookup::match_forward(config, qname) {
        // The name exists. If the type does not match it is NODATA, not
        // NXDOMAIN — an `A` query for a synthesized name must be an empty
        // NOERROR.
        let records = if synth::forward_has_type(qtype) {
            vec![synth::aaaa_record(zone, qname, addr)]
        } else {
            Vec::new()
        };
        return Outcome::Answer { zone, records };
    }

    // A reverse name inside one of our zones that is not a well-formed address,
    // or a forward name under one of our apexes that no template produces.
    match lookup::zone_containing(config, qname) {
        Some(zone) => Outcome::NoName { zone },
        None => Outcome::NoZone,
    }
}
