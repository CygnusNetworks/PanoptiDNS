//! Optional upstream PTR lookups (`with upstream`).
//!
//! Before synthesizing a PTR, the configured upstream is asked for
//! `<qname>.upstream`, so an operator can override individual addresses with real
//! hostnames.
//!
//! The original's version of this feature had two serious defects, and both are
//! addressed structurally here:
//!
//! 1. It was a **blocking** lookup inside a single-threaded server, with the
//!    default retry policy of 4 attempts × 5 s — up to 20 seconds of total
//!    stall per query. Flooding PTR queries for a zone with an unreachable
//!    upstream wedged the whole daemon. Here the lookup is async, has a hard
//!    deadline of a few hundred milliseconds, and holds a semaphore permit that
//!    is acquired with `try_acquire`: if the upstream is saturated we skip it
//!    immediately and synthesize instead. Nothing ever queues, so a dead upstream
//!    cannot build a backlog.
//! 2. It relayed the upstream's **entire answer section verbatim** with the AA
//!    bit set, filtering nothing but a `.upstream` suffix on the name. A hostile
//!    or compromised upstream could therefore inject arbitrary records that we
//!    would serve as authoritative data for a zone delegated to us. Here
//!    [`filter_upstream`] is an allowlist: only PTR records in class IN whose
//!    owner name is *exactly* the name we asked for survive, and each survivor is
//!    rebuilt with our own owner name rather than edited as text.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::rr::domain::Name;
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};
use tokio::sync::Semaphore;
use tokio::time::Instant;

/// Cap on relayed records, so a hostile upstream cannot inflate our response.
const MAX_RELAYED_RECORDS: usize = 8;

/// TTL clamp for relayed records.
const MIN_RELAY_TTL: u32 = 30;
const MAX_RELAY_TTL: u32 = 3600;

/// Concurrent in-flight upstream queries. Beyond this we synthesize instead of
/// waiting, which is what makes a black-holed upstream harmless.
const MAX_INFLIGHT: usize = 64;

/// Consecutive failures before the upstream is skipped entirely for a while.
const BREAKER_THRESHOLD: u32 = 8;
const BREAKER_COOLDOWN: Duration = Duration::from_secs(10);

/// The label appended to a query before asking the upstream.
const UPSTREAM_LABEL: &str = "upstream";

/// Keep only records we are willing to serve as our own authoritative data.
///
/// This is an allowlist, deliberately: anything not explicitly permitted is
/// dropped. It is a pure function so the hostile-upstream regression tests need
/// no network.
///
/// Rules:
/// - class IN and type PTR only (a `PTR` query does not stop a responder putting
///   A, CNAME or DNAME records in the answer section),
/// - owner name **exactly** equal to the name we asked for — not a suffix match,
///   which is what let the original's `s/\.upstream$//` pass unrelated names
///   through untouched,
/// - each survivor rebuilt with `qname` as the owner, typed, never by editing
///   text,
/// - TTL clamped, record count capped.
///
/// Authority and additional sections are not considered at all; the caller
/// discards them.
#[must_use]
pub fn filter_upstream(qname: &Name, up_qname: &Name, answers: &[Record]) -> Vec<Record> {
    answers
        .iter()
        .filter(|record| {
            record.dns_class == DNSClass::IN
                && record.record_type() == RecordType::PTR
                // `Name`'s PartialEq is case-insensitive, which is what we want,
                // but it is an *equality* test, not a suffix test.
                && &record.name == up_qname
                && matches!(record.data, RData::PTR(_))
        })
        .take(MAX_RELAYED_RECORDS)
        .map(|record| {
            let ttl = record.ttl.clamp(MIN_RELAY_TTL, MAX_RELAY_TTL);
            // Rebuild rather than mutate: the owner is ours, the target is
            // theirs, and no upstream flag survives.
            Record::from_rdata(qname.clone(), ttl, record.data.clone()).into_record_of_rdata()
        })
        .collect()
}

/// Append the `.upstream` label, typed.
///
/// A full reverse name is 34 short labels (~77 bytes), so this stays comfortably
/// inside the 255-byte limit; the `Result` is propagated rather than unwrapped
/// because the input is attacker-influenced.
pub fn upstream_qname(qname: &Name) -> Option<Name> {
    qname.clone().append_label(UPSTREAM_LABEL).ok()
}

/// Simple consecutive-failure circuit breaker.
#[derive(Debug, Default)]
struct Breaker {
    state: Mutex<BreakerState>,
}

#[derive(Debug, Default)]
struct BreakerState {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

impl Breaker {
    /// True if the upstream should be skipped right now.
    fn is_open(&self) -> bool {
        let mut state = match self.state.lock() {
            Ok(g) => g,
            // A poisoned lock must not take the server down; fail open (i.e.
            // allow the query) since that is the non-degrading choice.
            Err(poisoned) => poisoned.into_inner(),
        };
        match state.open_until {
            Some(until) if Instant::now() < until => true,
            Some(_) => {
                state.open_until = None;
                state.consecutive_failures = 0;
                false
            }
            None => false,
        }
    }

    fn record_success(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.consecutive_failures = 0;
            state.open_until = None;
        }
    }

    /// Returns true if this failure tripped the breaker.
    fn record_failure(&self) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.consecutive_failures >= BREAKER_THRESHOLD && state.open_until.is_none() {
            state.open_until = Some(Instant::now() + BREAKER_COOLDOWN);
            return true;
        }
        false
    }
}

/// A configured upstream resolver, shared across requests.
pub struct Upstream {
    addr: IpAddr,
    resolver: TokioResolver,
    inflight: Arc<Semaphore>,
    breaker: Breaker,
    timeout: Duration,
}

impl Upstream {
    /// Build an upstream client for `addr`.
    ///
    /// The resolver is created once and reused. The original created a fresh
    /// resolver per query, which meant a fresh socket and no connection reuse on
    /// every single request.
    pub fn new(addr: IpAddr, timeout: Duration) -> Result<Self, String> {
        // Exactly one name server, no domain and no search list: this is a
        // targeted query at an operator-named address, not a system resolver.
        let config =
            ResolverConfig::from_parts(None, Vec::new(), vec![NameServerConfig::udp_and_tcp(addr)]);

        let mut opts = ResolverOpts::default();
        // One attempt, hard deadline. The point is to fail fast and synthesize;
        // a slow upstream must never become our latency.
        opts.timeout = timeout;
        opts.attempts = 0;
        // Authoritative-only: we are not asking anyone to recurse for us.
        opts.recursion_desired = false;
        opts.edns0 = true;
        // Caching bounds upstream QPS under a flood. It also means a repeated
        // hostile answer is filtered once rather than every time.
        opts.cache_size = 4096;
        opts.try_tcp_on_error = false;
        opts.num_concurrent_reqs = 1;

        let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(opts)
            .build()
            .map_err(|e| format!("cannot build upstream resolver for {addr}: {e}"))?;

        Ok(Self {
            addr,
            resolver,
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT)),
            breaker: Breaker::default(),
            timeout,
        })
    }

    #[must_use]
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// Ask the upstream to override this PTR, returning records safe to serve.
    ///
    /// Returns an empty vector for every failure mode — timeout, refusal, hostile
    /// content, saturation, open breaker — so the caller simply falls through to
    /// synthesis. Upstream trouble degrades to the normal answer, never to an
    /// error for the client.
    pub async fn lookup_ptr(&self, qname: &Name) -> Vec<Record> {
        if self.breaker.is_open() {
            tracing::debug!(upstream = %self.addr, "skipping upstream: breaker open");
            return Vec::new();
        }

        // No permit means the upstream is already saturated. Skip it rather than
        // queue: queueing is what let a black-holed upstream stall the original.
        let Ok(_permit) = self.inflight.clone().try_acquire_owned() else {
            tracing::debug!(upstream = %self.addr, "skipping upstream: too many in flight");
            return Vec::new();
        };

        let Some(up_qname) = upstream_qname(qname) else {
            return Vec::new();
        };

        let lookup = tokio::time::timeout(
            self.timeout,
            self.resolver.lookup(up_qname.clone(), RecordType::PTR),
        )
        .await;

        match lookup {
            Ok(Ok(found)) => {
                self.breaker.record_success();
                let kept = filter_upstream(qname, &up_qname, found.answers());
                let seen = found.answers().len();
                if kept.len() != seen {
                    tracing::debug!(
                        upstream = %self.addr,
                        seen,
                        kept = kept.len(),
                        "discarded upstream records that failed the allowlist"
                    );
                }
                kept
            }
            // A negative answer is the normal case for an address with no
            // override, so it is not a failure of the upstream.
            Ok(Err(_)) => {
                self.breaker.record_success();
                Vec::new()
            }
            Err(_elapsed) => {
                if self.breaker.record_failure() {
                    tracing::warn!(
                        upstream = %self.addr,
                        cooldown_secs = BREAKER_COOLDOWN.as_secs(),
                        "upstream timed out repeatedly; skipping it for now"
                    );
                }
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, AAAA, CNAME, PTR};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn name(s: &str) -> Name {
        Name::from_ascii(s).expect("test name")
    }

    fn ptr(owner: &str, target: &str, ttl: u32) -> Record {
        Record::from_rdata(name(owner), ttl, RData::PTR(PTR(name(target)))).into_record_of_rdata()
    }

    const QNAME: &str = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa.";

    fn up(qname: &str) -> Name {
        upstream_qname(&name(qname)).expect("appendable")
    }

    #[test]
    fn appends_upstream_label() {
        assert_eq!(up(QNAME).to_ascii(), format!("{QNAME}upstream."));
    }

    #[test]
    fn keeps_a_well_formed_override() {
        let q = name(QNAME);
        let uq = up(QNAME);
        let answers = vec![ptr(&uq.to_ascii(), "real-host.example.net.", 600)];
        let kept = filter_upstream(&q, &uq, &answers);
        assert_eq!(kept.len(), 1);
        // The owner is rewritten to the name the client asked about, typed.
        assert_eq!(kept[0].name, q);
        assert_eq!(kept[0].ttl, 600);
        assert!(matches!(&kept[0].data, RData::PTR(p) if p.0 == name("real-host.example.net.")));
    }

    /// The core of finding 3: a hostile upstream stuffing the answer section.
    #[test]
    fn rejects_everything_not_explicitly_allowed() {
        let q = name(QNAME);
        let uq = up(QNAME);
        let uq_str = uq.to_ascii();

        let answers = vec![
            // Right type, wrong owner — the injection the original allowed.
            ptr("victim.example.com.", "attacker.example.net.", 600),
            // Owner lacks the `.upstream` label entirely.
            ptr(QNAME, "sneaky.example.net.", 600),
            // Right owner, wrong type.
            Record::from_rdata(uq.clone(), 600, RData::A(A(Ipv4Addr::new(192, 0, 2, 1))))
                .into_record_of_rdata(),
            Record::from_rdata(uq.clone(), 600, RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)))
                .into_record_of_rdata(),
            Record::from_rdata(
                uq.clone(),
                600,
                RData::CNAME(CNAME(name("elsewhere.example.net."))),
            )
            .into_record_of_rdata(),
            // A near-miss: the allowed name with an extra label appended.
            ptr(&format!("extra.{uq_str}"), "nope.example.net.", 600),
        ];

        assert!(
            filter_upstream(&q, &uq, &answers).is_empty(),
            "nothing in this set may be relayed"
        );
    }

    #[test]
    fn owner_match_is_case_insensitive_but_exact() {
        let q = name(QNAME);
        let uq = up(QNAME);
        let upper = uq.to_ascii().to_uppercase();
        let answers = vec![ptr(&upper, "host.example.net.", 600)];
        assert_eq!(
            filter_upstream(&q, &uq, &answers).len(),
            1,
            "DNS names are case-insensitive"
        );
    }

    #[test]
    fn clamps_ttl() {
        let q = name(QNAME);
        let uq = up(QNAME);
        let uq_str = uq.to_ascii();
        let answers = vec![ptr(&uq_str, "a.example.net.", 0)];
        assert_eq!(filter_upstream(&q, &uq, &answers)[0].ttl, MIN_RELAY_TTL);

        let answers = vec![ptr(&uq_str, "a.example.net.", u32::MAX)];
        assert_eq!(filter_upstream(&q, &uq, &answers)[0].ttl, MAX_RELAY_TTL);
    }

    #[test]
    fn caps_record_count() {
        let q = name(QNAME);
        let uq = up(QNAME);
        let uq_str = uq.to_ascii();
        let answers: Vec<Record> = (0..100)
            .map(|i| ptr(&uq_str, &format!("h{i}.example.net."), 600))
            .collect();
        assert_eq!(
            filter_upstream(&q, &uq, &answers).len(),
            MAX_RELAYED_RECORDS
        );
    }

    #[test]
    fn empty_answers_yield_nothing() {
        let q = name(QNAME);
        let uq = up(QNAME);
        assert!(filter_upstream(&q, &uq, &[]).is_empty());
    }

    #[test]
    fn breaker_opens_after_threshold_failures_and_is_idempotent() {
        let breaker = Breaker::default();
        assert!(!breaker.is_open());
        for _ in 0..(BREAKER_THRESHOLD - 1) {
            assert!(!breaker.record_failure());
        }
        assert!(breaker.record_failure(), "threshold failure trips it");
        assert!(breaker.is_open());
        // Already open: a further failure must not re-report.
        assert!(!breaker.record_failure());
        breaker.record_success();
        assert!(!breaker.is_open(), "success closes it");
    }
}
