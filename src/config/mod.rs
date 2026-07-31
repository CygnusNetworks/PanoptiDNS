//! Configuration model and parser for the AllKnowingDNS file format.
//!
//! [`Config`] is immutable once built and cheap to share across threads, so the
//! server keeps it behind an atomic pointer swap and every request reads it
//! without locking.

mod compile;
pub mod error;
mod parse;

pub use error::{ConfigError, ConfigErrorKind, ConfigErrors};

use std::net::IpAddr;

use hickory_proto::rr::domain::Name;
use hickory_proto::ProtoError;

/// TTL of synthesized records. The original hard-coded 3600 and its test suite
/// pins it.
pub const DEFAULT_TTL: u32 = 3600;

/// Default DNS port, used when a `listen` directive omits one.
pub const DEFAULT_PORT: u16 = 53;

/// An address the server should bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenAddr {
    pub addr: IpAddr,
    pub port: u16,
}

/// One label of a forward-name template.
///
/// Both a verbatim and a lowercased form are kept: matching an incoming query
/// must be case-insensitive (DNS is), but the name we *emit* has to preserve the
/// operator's capitalisation, because the original deliberately did so and its
/// test suite pins it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FwdLabel {
    Literal {
        verbatim: Vec<u8>,
        lower: Vec<u8>,
    },
    /// The label that carries `%DIGITS%` or `%DIGITS-DASHED%`, split around the
    /// placeholder.
    Digits {
        pre: Vec<u8>,
        pre_lower: Vec<u8>,
        post: Vec<u8>,
        post_lower: Vec<u8>,
        /// Whether the placeholder was `%DIGITS-DASHED%`: group hex digits in
        /// 4s, separated by `-`, instead of one contiguous run.
        dashed: bool,
    },
}

/// A `resolves to` template, pre-split at label boundaries.
///
/// Storing the template as labels rather than a regex is what makes matching a
/// *full* match by construction. The original compiled an unanchored regex in one
/// place and an anchored one in another, so `…example.net.evil.com` could match
/// and zones sharing a parent domain could be selected wrongly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FwdTemplate {
    pub labels: Vec<FwdLabel>,
    /// Index into `labels` of the [`FwdLabel::Digits`] entry.
    pub digits_at: usize,
}

impl FwdTemplate {
    /// Number of labels a matching query name must have.
    #[must_use]
    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    /// The apex: everything to the right of the `%DIGITS%` label.
    pub fn parent(&self) -> Result<Name, ProtoError> {
        let tail: Vec<Vec<u8>> = self
            .labels
            .iter()
            .skip(self.digits_at.saturating_add(1))
            .map(|label| match label {
                FwdLabel::Literal { verbatim, .. } => verbatim.clone(),
                // A template has exactly one digits label, so this arm is
                // unreachable in practice; falling back to the literal bytes
                // keeps the function total.
                FwdLabel::Digits { pre, post, .. } => {
                    let mut joined = pre.clone();
                    joined.extend_from_slice(post);
                    joined
                }
            })
            .collect();
        let mut name = Name::from_labels(tail)?;
        name.set_fqdn(true);
        Ok(name)
    }

    /// Render the template with `digits` substituted, as a fully-qualified name.
    ///
    /// `digits` must already be lowercase hex produced by
    /// [`crate::nibble::host_digits`]; the caller never passes attacker bytes
    /// here, which is the property that makes synthesized names safe.
    pub fn render(&self, digits: &str) -> Result<Name, ProtoError> {
        let mut labels: Vec<Vec<u8>> = Vec::with_capacity(self.labels.len());
        for label in &self.labels {
            match label {
                FwdLabel::Literal { verbatim, .. } => labels.push(verbatim.clone()),
                FwdLabel::Digits {
                    pre, post, dashed, ..
                } => {
                    let mut joined = Vec::with_capacity(pre.len() + digits.len() + post.len());
                    joined.extend_from_slice(pre);
                    if *dashed {
                        joined.extend_from_slice(crate::nibble::dash_group(digits).as_bytes());
                    } else {
                        joined.extend_from_slice(digits.as_bytes());
                    }
                    joined.extend_from_slice(post);
                    labels.push(joined);
                }
            }
        }
        let mut name = Name::from_labels(labels)?;
        name.set_fqdn(true);
        Ok(name)
    }
}

/// A configured network and the forward names it maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    /// Line of the `network` directive, for diagnostics.
    pub src_line: u32,
    /// Network address, already masked — so `prefix | host` needs no further
    /// masking, unlike the original which OR-ed into an unmasked address.
    pub prefix: u128,
    /// Prefix length; always `<= 128` and a multiple of 4.
    pub mask: u8,
    /// `(128 - mask) / 4`: how many hex digits `%DIGITS%` expands to.
    pub host_nibbles: u8,
    /// The `ip6.arpa` zone this network delegates to.
    pub ptr_zone: Name,
    /// The `resolves to` value verbatim, for diagnostics.
    pub resolves_to: String,
    pub fwd: FwdTemplate,
    /// The forward apex: the labels to the right of the `%DIGITS%` label.
    ///
    /// Needed to tell "inside a zone we are authoritative for, but no such
    /// record" (NODATA/NXDOMAIN with a SOA, so resolvers can cache the negative)
    /// apart from "not our namespace at all". The original answered a bare
    /// NXDOMAIN with no SOA in either case, which defeats negative caching.
    pub fwd_parent: Name,
    pub ttl: u32,
    pub upstream: Option<IpAddr>,
}

/// What to answer for a name outside every configured zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutOfZonePolicy {
    /// RFC-correct for an authoritative server, and the default: we are not
    /// authoritative for that name, so we decline rather than assert it does not
    /// exist. Also stops the server being a useful reflector, since REFUSED is
    /// smaller than a synthesized NXDOMAIN.
    #[default]
    Refused,
    /// What the original did. Available for compatibility.
    NxDomain,
}

/// SOA parameters for the zone apexes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoaParams {
    /// MNAME — the primary server for these zones.
    pub primary: Name,
    /// RNAME — the responsible mailbox.
    pub hostmaster: Name,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    /// Also the negative-caching TTL (RFC 2308).
    pub minimum: u32,
}

/// Response-rate-limiting parameters.
///
/// A server that synthesizes an unbounded number of records is an attractive
/// reflection amplifier, so this is on by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RrlParams {
    pub enabled: bool,
    /// Sustained responses per second, per client prefix.
    pub responses_per_second: u32,
    /// Burst allowance above the sustained rate.
    pub burst: u32,
    /// Every Nth suppressed response is answered truncated instead of dropped,
    /// so a legitimate resolver can retry over TCP. 0 means always drop.
    pub slip: u32,
    /// Client-address aggregation prefix lengths.
    pub ipv4_prefix: u8,
    pub ipv6_prefix: u8,
}

impl Default for RrlParams {
    fn default() -> Self {
        Self {
            enabled: true,
            responses_per_second: 20,
            burst: 50,
            slip: 2,
            ipv4_prefix: 24,
            ipv6_prefix: 64,
        }
    }
}

/// Server-wide knobs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerParams {
    pub out_of_zone: OutOfZonePolicy,
    /// Upper bound on the UDP response size we advertise and emit. 1232 avoids
    /// IPv6 fragmentation (RFC 9715).
    pub max_udp_payload: u16,
    /// Hard deadline for an upstream lookup. The original blocked for up to 20
    /// seconds per query in a single-threaded server.
    pub upstream_timeout: core::time::Duration,
    pub rrl: RrlParams,
}

impl Default for ServerParams {
    fn default() -> Self {
        Self {
            out_of_zone: OutOfZonePolicy::default(),
            max_udp_payload: 1232,
            upstream_timeout: core::time::Duration::from_millis(300),
            rrl: RrlParams::default(),
        }
    }
}

/// A validated configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    pub listen: Vec<ListenAddr>,
    /// Sorted by `mask` descending, so a linear scan yields longest-prefix match.
    pub zones: Vec<Zone>,
    /// Apex SOA/NS data, if `primary` and `hostmaster` were configured.
    ///
    /// Optional on purpose: an unmodified AllKnowingDNS v1.7 config has neither,
    /// and must keep working. Without it we cannot put a SOA in the authority
    /// section, so negative caching degrades to what the original did — a
    /// startup warning says so.
    pub soa: Option<SoaParams>,
    /// Apex NS records, if configured.
    pub nameservers: Vec<Name>,
    pub params: ServerParams,
}

impl Config {
    /// Parse and validate a configuration file body.
    ///
    /// Every problem in the file is reported at once rather than one per run.
    pub fn parse(input: &str) -> Result<Self, ConfigErrors> {
        let (raw, mut errors) = parse::parse(input);
        let config = compile::compile(raw, &mut errors);
        if errors.is_empty() {
            Ok(config)
        } else {
            Err(ConfigErrors::new(errors))
        }
    }

    #[must_use]
    pub fn has_zones(&self) -> bool {
        !self.zones.is_empty()
    }

    /// Warnings that do not prevent startup but that the operator should see.
    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.soa.is_none() {
            out.push(
                "no `primary`/`hostmaster` configured: serving without apex SOA/NS records, \
                 so resolvers cannot cache negative answers (set both to fix)"
                    .to_string(),
            );
        }
        if !self.params.rrl.enabled {
            out.push("response rate limiting is disabled".to_string());
        }
        if self.zones.is_empty() {
            out.push("no `network` configured: every query will be declined".to_string());
        }
        out
    }

    /// Every distinct apex we are authoritative for: each zone's `ip6.arpa`
    /// origin and each forward parent, deduplicated.
    #[must_use]
    pub fn apexes(&self) -> Vec<Name> {
        let mut out: Vec<Name> = Vec::new();
        for zone in &self.zones {
            for name in [&zone.ptr_zone, &zone.fwd_parent] {
                if !out.contains(name) {
                    out.push(name.clone());
                }
            }
        }
        out
    }
}
