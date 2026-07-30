//! The single `RequestHandler`.
//!
//! We implement [`RequestHandler`] directly rather than plugging into hickory's
//! `Catalog`/`ZoneHandler` machinery, for three reasons:
//!
//! - `Catalog` dispatches by longest-suffix match on a zone origin, but our
//!   forward zones deliberately *share* an origin (`ipv6.monsternett.net`) and are
//!   distinguished by a label pattern. The catalog cannot express that.
//! - Rate limiting and the upstream decision need the client address and the
//!   transport, which the `ZoneHandler` API does not surface.
//! - One handler gives exactly one choke point for the panic guard and for the
//!   authority-section policy.

use std::collections::HashMap;
use std::net::IpAddr;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use arc_swap::ArcSwap;
use futures_util::FutureExt;
use hickory_proto::op::{Edns, Header, HeaderCounts, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{NS, SOA};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use hickory_server::net::runtime::Time;
use hickory_server::net::xfer::Protocol;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;

use crate::config::{Config, OutOfZonePolicy, SoaParams};
use crate::rrl::{Decision, Kind, Rrl};
use crate::upstream::Upstream;
use crate::zone::{resolve, Outcome};

/// The hot-swappable half of the server's state.
///
/// Kept behind an [`ArcSwap`] so a SIGHUP reload is a single atomic pointer
/// store and every request reads it with one atomic load — no locking on the
/// request path.
pub struct Zones {
    pub config: Config,
    /// One reusable client per distinct upstream address.
    pub upstreams: HashMap<IpAddr, Arc<Upstream>>,
}

impl Zones {
    /// Build the upstream clients a config calls for.
    pub fn new(config: Config) -> Result<Self, String> {
        let mut upstreams: HashMap<IpAddr, Arc<Upstream>> = HashMap::new();
        for zone in &config.zones {
            if let Some(addr) = zone.upstream {
                if let std::collections::hash_map::Entry::Vacant(slot) = upstreams.entry(addr) {
                    let upstream = Upstream::new(addr, config.params.upstream_timeout)?;
                    slot.insert(Arc::new(upstream));
                }
            }
        }
        Ok(Self { config, upstreams })
    }
}

pub struct Handler {
    zones: Arc<ArcSwap<Zones>>,
    /// Deliberately *outside* the swap: reloading the config must not reset every
    /// client's rate-limit bucket, or a reload would become an amnesty.
    rrl: Arc<Rrl>,
    querylog: bool,
}

impl Handler {
    #[must_use]
    pub fn new(zones: Arc<ArcSwap<Zones>>, rrl: Arc<Rrl>, querylog: bool) -> Self {
        Self {
            zones,
            rrl,
            querylog,
        }
    }
}

/// What we decided to answer, before it is serialised.
struct Reply {
    code: ResponseCode,
    authoritative: bool,
    answers: Vec<Record>,
    /// Authority section: NS records for a referral-ish answer, or the SOA for a
    /// negative one.
    authority: Vec<Record>,
    kind: Kind,
}

impl Reply {
    fn refused() -> Self {
        Self {
            code: ResponseCode::Refused,
            authoritative: false,
            answers: Vec::new(),
            authority: Vec::new(),
            kind: Kind::Negative,
        }
    }

    fn error(code: ResponseCode) -> Self {
        Self {
            code,
            authoritative: false,
            answers: Vec::new(),
            authority: Vec::new(),
            kind: Kind::Negative,
        }
    }
}

/// Build the SOA record for a zone apex, used to make negative answers cacheable.
///
/// The original returned a bare NXDOMAIN with an empty authority section, so
/// resolvers had nothing to cache and re-queried indefinitely.
fn soa_record(apex: &hickory_proto::rr::domain::Name, soa: &SoaParams, ttl: u32) -> Record {
    let rdata = RData::SOA(SOA::new(
        soa.primary.clone(),
        soa.hostmaster.clone(),
        soa.serial,
        // `SOA::new` takes signed values for the interval fields.
        i32::try_from(soa.refresh).unwrap_or(i32::MAX),
        i32::try_from(soa.retry).unwrap_or(i32::MAX),
        i32::try_from(soa.expire).unwrap_or(i32::MAX),
        soa.minimum,
    ));
    // The negative-caching TTL is min(SOA TTL, SOA MINIMUM) per RFC 2308.
    Record::from_rdata(apex.clone(), ttl.min(soa.minimum), rdata).into_record_of_rdata()
}

fn ns_records(apex: &hickory_proto::rr::domain::Name, config: &Config, ttl: u32) -> Vec<Record> {
    config
        .nameservers
        .iter()
        .map(|ns| {
            Record::from_rdata(apex.clone(), ttl, RData::NS(NS(ns.clone()))).into_record_of_rdata()
        })
        .collect()
}

impl Handler {
    /// Decide what to answer. Pure apart from the optional upstream lookup.
    async fn decide(
        &self,
        zones: &Zones,
        qname: &hickory_proto::rr::domain::Name,
        qtype: RecordType,
        qclass: DNSClass,
    ) -> Reply {
        let config = &zones.config;

        // Authoritative-only: we never serve anything outside class IN.
        if !matches!(qclass, DNSClass::IN | DNSClass::ANY) {
            return Reply::refused();
        }

        // A /64 cannot be transferred and we hold no zone data, so decline
        // rather than pretend. The original needed a NotifyHandler workaround
        // just to avoid terminating on a NOTIFY.
        if matches!(qtype, RecordType::AXFR | RecordType::IXFR) {
            return Reply::refused();
        }

        // Apex queries: SOA and NS for a zone origin we serve.
        if matches!(qtype, RecordType::SOA | RecordType::NS | RecordType::ANY) {
            if let Some(apex) = config.apexes().into_iter().find(|a| a == qname) {
                let ttl = config.zones.first().map_or(3600, |z| z.ttl);
                let mut answers = Vec::new();
                if matches!(qtype, RecordType::SOA | RecordType::ANY) {
                    if let Some(soa) = config.soa.as_ref() {
                        answers.push(soa_record(&apex, soa, ttl));
                    }
                }
                if matches!(qtype, RecordType::NS | RecordType::ANY) {
                    answers.extend(ns_records(&apex, config, ttl));
                }
                let kind = if answers.is_empty() {
                    Kind::Negative
                } else {
                    Kind::Answer
                };
                return Reply {
                    code: ResponseCode::NoError,
                    authoritative: true,
                    answers,
                    authority: Vec::new(),
                    kind,
                };
            }
        }

        match resolve(config, qname, qtype) {
            Outcome::Answer { zone, mut records } => {
                // An upstream may override a PTR with a real hostname. Only ever
                // consulted for a name our own zones already matched, so this can
                // never become an open forwarder.
                if !records.is_empty() && qtype == RecordType::PTR {
                    if let Some(upstream) =
                        zone.upstream.and_then(|addr| zones.upstreams.get(&addr))
                    {
                        let relayed = upstream.lookup_ptr(qname).await;
                        if !relayed.is_empty() {
                            records = relayed;
                        }
                    }
                }
                let kind = if records.is_empty() {
                    Kind::Negative
                } else {
                    Kind::Answer
                };
                Reply {
                    code: ResponseCode::NoError,
                    // We hold the delegation, so answers *and* NODATA are
                    // authoritative.
                    authoritative: true,
                    answers: records,
                    authority: self.negative_authority(config, qname, kind),
                    kind,
                }
            }
            Outcome::NoName { zone } => {
                // Inside our namespace but nothing there: NXDOMAIN with the SOA
                // so the negative answer is cacheable.
                let apex = if zone.ptr_zone.zone_of(qname) {
                    &zone.ptr_zone
                } else {
                    &zone.fwd_parent
                };
                let authority = config
                    .soa
                    .as_ref()
                    .map(|soa| vec![soa_record(apex, soa, zone.ttl)])
                    .unwrap_or_default();
                Reply {
                    code: ResponseCode::NXDomain,
                    authoritative: true,
                    answers: Vec::new(),
                    authority,
                    kind: Kind::Negative,
                }
            }
            Outcome::NoZone => match config.params.out_of_zone {
                // Not our namespace: declining is both correct and smaller than
                // a synthesized NXDOMAIN, which matters for amplification.
                OutOfZonePolicy::Refused => Reply::refused(),
                OutOfZonePolicy::NxDomain => Reply {
                    code: ResponseCode::NXDomain,
                    authoritative: false,
                    answers: Vec::new(),
                    authority: Vec::new(),
                    kind: Kind::Negative,
                },
            },
        }
    }

    /// SOA for the authority section of a NODATA answer.
    fn negative_authority(
        &self,
        config: &Config,
        qname: &hickory_proto::rr::domain::Name,
        kind: Kind,
    ) -> Vec<Record> {
        if kind != Kind::Negative {
            return Vec::new();
        }
        let Some(soa) = config.soa.as_ref() else {
            return Vec::new();
        };
        config
            .zones
            .iter()
            .find_map(|zone| {
                for apex in [&zone.ptr_zone, &zone.fwd_parent] {
                    if apex.zone_of(qname) {
                        return Some(vec![soa_record(apex, soa, zone.ttl)]);
                    }
                }
                None
            })
            .unwrap_or_default()
    }

    async fn handle_inner<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> Result<ResponseInfo, String> {
        let info = request
            .request_info()
            .map_err(|e| format!("malformed request: {e}"))?;
        let src = info.src;
        let is_tcp = matches!(info.protocol, Protocol::Tcp);
        let request_meta = *info.metadata;
        let qname = info.query.name().into();
        let qtype = info.query.query_type();
        let qclass = info.query.query_class();

        if self.querylog {
            tracing::info!(
                %src,
                protocol = ?info.protocol,
                query = %qname,
                r#type = %qtype,
                "query"
            );
        }

        let builder = MessageResponseBuilder::from_message_request(request);

        // Only standard queries. NOTIFY and UPDATE are not implemented — and
        // unlike the original, refusing them cannot terminate the process.
        if request_meta.op_code != OpCode::Query {
            return self
                .send(
                    response_handle,
                    builder,
                    &request_meta,
                    Reply::error(ResponseCode::NotImp),
                    request,
                    is_tcp,
                )
                .await;
        }

        // EDNS version negotiation: we speak version 0 only.
        if request.version() > 0 {
            return self
                .send(
                    response_handle,
                    builder,
                    &request_meta,
                    Reply::error(ResponseCode::BADVERS),
                    request,
                    is_tcp,
                )
                .await;
        }

        let zones = self.zones.load();
        let reply = self.decide(&zones, &qname, qtype, qclass).await;

        // Rate limiting is applied to the *response*, after we know whether it
        // is an answer or a negative — the two have separate budgets.
        match self.rrl.decide(src.ip(), reply.kind, is_tcp) {
            Decision::Allow => {}
            Decision::Drop => {
                tracing::debug!(%src, "rate limited: dropping response");
                // Returning without sending anything is the point: a dropped
                // response is what makes us useless as a reflector.
                return Ok(response_info(Metadata::response_from_request(
                    &request_meta,
                )));
            }
            Decision::Truncate => {
                tracing::debug!(%src, "rate limited: sending truncated response");
                let mut metadata = Metadata::response_from_request(&request_meta);
                metadata.truncation = true;
                let response = builder.build_no_records(metadata);
                return response_handle
                    .send_response(response)
                    .await
                    .map_err(|e| format!("send failed: {e}"));
            }
        }

        self.send(
            response_handle,
            builder,
            &request_meta,
            reply,
            request,
            is_tcp,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn send<R: ResponseHandler>(
        &self,
        mut response_handle: R,
        builder: MessageResponseBuilder<'_>,
        request_meta: &Metadata,
        reply: Reply,
        request: &Request,
        is_tcp: bool,
    ) -> Result<ResponseInfo, String> {
        let mut metadata = Metadata::response_from_request(request_meta);
        metadata.response_code = reply.code;
        metadata.authoritative = reply.authoritative;
        // Authoritative-only server: we never offer recursion, and we never
        // assert DNSSEC validation we did not do.
        metadata.recursion_available = false;
        metadata.authentic_data = false;

        // Echo an OPT if the client sent one, clamping the advertised payload to
        // our configured ceiling (1232 by default, to avoid IPv6 fragmentation).
        let mut builder = builder;
        let edns_holder;
        if request.edns.is_some() {
            let max = self.zones.load().config.params.max_udp_payload;
            let advertised = if is_tcp {
                max
            } else {
                request.max_payload().clamp(512, max)
            };
            let mut edns = Edns::new();
            edns.set_max_payload(advertised);
            edns.set_version(0);
            edns_holder = edns;
            builder.edns(&edns_holder);
        }

        let response = builder.build(
            metadata,
            reply.answers.iter(),
            reply.authority.iter(),
            // The `soa` slot is emitted into the authority section; we already
            // put ours in `authority`, so this stays empty.
            core::iter::empty(),
            core::iter::empty(),
        );

        response_handle
            .send_response(response)
            .await
            .map_err(|e| format!("send failed: {e}"))
    }
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        // Defence in depth. The lint policy in `lib.rs` already forbids the
        // panic-family constructs on this path, but hickory does not guard the
        // handler call — and an unguarded handler is precisely how a single UDP
        // packet could terminate the original. A panic here becomes SERVFAIL.
        let guarded = AssertUnwindSafe(self.handle_inner(request, response_handle.clone()))
            .catch_unwind()
            .await;

        match guarded {
            Ok(Ok(info)) => info,
            Ok(Err(reason)) => {
                tracing::warn!(src = %request.src(), reason, "request rejected");
                servfail(request, response_handle).await
            }
            Err(_panic) => {
                tracing::error!(
                    src = %request.src(),
                    "PANIC in request handler; answering SERVFAIL. This is a bug."
                );
                servfail(request, response_handle).await
            }
        }
    }
}

/// Last-resort SERVFAIL, used when normal reply construction failed.
async fn servfail<R: ResponseHandler>(request: &Request, mut handle: R) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut metadata = Metadata::new(request.metadata.id, MessageType::Response, OpCode::Query);
    metadata.response_code = ResponseCode::ServFail;
    let response = builder.build_no_records(metadata);
    match handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            tracing::warn!(error = %e, "could not send SERVFAIL");
            response_info(metadata)
        }
    }
}

/// `ResponseInfo` is only built from a `Header`, and the counts are bookkeeping
/// the caller does not read for a suppressed response.
fn response_info(metadata: Metadata) -> ResponseInfo {
    ResponseInfo::from(Header {
        metadata,
        counts: HeaderCounts::default(),
    })
}
