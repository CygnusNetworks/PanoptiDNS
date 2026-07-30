//! Building the records we answer with.
//!
//! Every record here is constructed from typed values — a `Name` built out of
//! config-supplied labels plus digits we generated from a `u128`, and an
//! `Ipv6Addr` built from that same `u128`. Nothing is ever formatted into, or
//! parsed out of, DNS master-file presentation text.
//!
//! That is the whole fix for the defect that let one UDP packet terminate the
//! original: it built records with
//! `Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata")`, and a `;` or `"`
//! byte in a query label made the presentation parser die.

use std::net::Ipv6Addr;

use hickory_proto::rr::rdata::{AAAA, PTR};
use hickory_proto::rr::{RData, Record, RecordType};

use crate::config::Zone;
use crate::nibble::host_digits;

/// The forward name that `addr` reverse-resolves to, e.g.
/// `ipv6-0219dbfffe432ec7-blah.nutzer.raumzeitlabor.de.`
///
/// Returns `None` only if the template could not render, which
/// [`crate::config`] proves impossible at startup by rendering the widest
/// possible case.
#[must_use]
pub fn forward_name(zone: &Zone, addr: u128) -> Option<hickory_proto::rr::domain::Name> {
    let digits = host_digits(addr, zone.host_nibbles)?;
    zone.fwd.render(&digits).ok()
}

/// Build the PTR record answering a reverse query for `addr`.
///
/// `qname` is the *parsed* query name, cloned as a typed value. Echoing it back
/// verbatim also preserves DNS-0x20 case randomisation for free.
#[must_use]
pub fn ptr_record(
    zone: &Zone,
    qname: &hickory_proto::rr::domain::Name,
    addr: u128,
) -> Option<Record> {
    let target = forward_name(zone, addr)?;
    Some(
        Record::from_rdata(qname.clone(), zone.ttl, RData::PTR(PTR(target))).into_record_of_rdata(),
    )
}

/// Build the AAAA record for a synthesized forward name.
#[must_use]
pub fn aaaa_record(zone: &Zone, qname: &hickory_proto::rr::domain::Name, addr: u128) -> Record {
    let rdata = RData::AAAA(AAAA(Ipv6Addr::from(addr)));
    Record::from_rdata(qname.clone(), zone.ttl, rdata).into_record_of_rdata()
}

/// Does this zone hold records of `qtype` for a forward name?
///
/// Only AAAA. An `A` query for a name the template *does* match is answered
/// NOERROR with zero records — never NXDOMAIN — because the name demonstrably
/// exists, it just has no IPv4 address. The original got this right and its test
/// suite pins it.
#[must_use]
pub fn forward_has_type(qtype: RecordType) -> bool {
    matches!(qtype, RecordType::AAAA | RecordType::ANY)
}

/// Does this zone hold records of `qtype` for a reverse name? Only PTR.
#[must_use]
pub fn reverse_has_type(qtype: RecordType) -> bool {
    matches!(qtype, RecordType::PTR | RecordType::ANY)
}
