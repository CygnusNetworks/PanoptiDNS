//! PanoptiDNS — a tiny authoritative DNS server that synthesizes IPv6 reverse
//! (PTR) and matching forward (AAAA) records on the fly.
//!
//! A reimplementation of AllKnowingDNS v1.7 (Perl, 2013, unmaintained). It reads
//! the same configuration file, but is built so that the security defects of the
//! original are *structurally absent* rather than patched. See
//! `docs/MIGRATION-from-AllKnowingDNS.md` for every behavioural difference.
//!
//! # Layering
//!
//! The crate is split along a hard purity boundary:
//!
//! - [`nibble`] and (later) the config and zone modules are **pure**: no I/O, no
//!   clock, no sockets, no async. The entire behavioural specification lives
//!   here, and so do all the acceptance vectors ported from the original's test
//!   suite.
//! - the server, upstream and rate-limiting layers are I/O and sit on top.
//!
//! Keeping the specification in a pure layer is what makes it testable without
//! binding a port, and it is why answer synthesis provably cannot depend on
//! anything but `(config, u128)`.
//!
//! # Why the lint policy below is a security control
//!
//! The original could be killed by a single UDP packet: it built resource
//! records by interpolating the attacker-controlled query name into a DNS
//! master-file *presentation string*, and a `;` or `"` byte in a query label
//! made the parser die. `Net::DNS::Nameserver` had no exception guard anywhere
//! in its request path, so the exception terminated the daemon.
//!
//! Two rules prevent that class of bug here:
//!
//! 1. Names are never built from, or parsed as, presentation text on the
//!    request path. A query name is converted to a `u128` *or rejected*, and
//!    every name we emit is constructed from typed labels out of
//!    `(config, u128)`.
//! 2. The panic-family lints below are denied, so the request path cannot
//!    contain an implicit abort. The server adds `catch_unwind` on top as
//!    defence in depth.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::indexing_slicing,
    clippy::string_slice
)]
// Rationale for *not* denying `clippy::arithmetic_side_effects`: integer
// overflow does not panic in release builds, so it is not a remote-abort vector,
// and denying it across the nibble math would force `checked_*` on arithmetic
// that is provably in range (nibble shifts are bounded by construction). Debug
// and test builds keep overflow checks on, so genuine overflow bugs still fail
// loudly in CI. The lints above are the ones that turn hostile input into an
// abort, and those are absolute.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

// Re-exported so integration tests and embedders can build a server without
// having to pin the same hickory versions themselves.
pub use hickory_proto;
pub use hickory_server;

pub mod config;
pub mod nibble;
pub mod rrl;
pub mod server;
pub mod upstream;
pub mod zone;
