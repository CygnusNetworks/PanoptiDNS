//! Response rate limiting.
//!
//! An authoritative server that synthesizes an unbounded number of records is an
//! attractive reflection amplifier: a small forged query yields a larger answer,
//! and there is no cache to exhaust. The original had no limiting at all.
//!
//! Clients are aggregated by address prefix (a /24 or /64 by default) because a
//! single attacker trivially controls every address in their own /64. Answers and
//! negative responses are limited separately: the negative path is the one an
//! attacker can drive with random names, so it deserves its own budget.
//!
//! TCP is never limited — completing a handshake already proves the source
//! address, so there is nothing to amplify.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};

use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};

use crate::config::RrlParams;

/// A client bucket key: the client address masked to the configured prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ClientKey {
    V4(u32),
    V6(u64),
}

impl ClientKey {
    /// Aggregate `addr` to the configured prefix length.
    #[must_use]
    pub fn new(addr: IpAddr, ipv4_prefix: u8, ipv6_prefix: u8) -> Self {
        match addr {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4);
                let shift = 32u32.saturating_sub(u32::from(ipv4_prefix.min(32)));
                Self::V4(if shift >= 32 {
                    0
                } else {
                    bits >> shift << shift
                })
            }
            IpAddr::V6(v6) => {
                // The top 64 bits are enough: a /64 is the smallest unit anyone
                // is realistically delegated, and aggregating further up only
                // makes the limit stricter.
                let high = (u128::from(v6) >> 64) as u64;
                let prefix = ipv6_prefix.min(64);
                let shift = 64u32.saturating_sub(u32::from(prefix));
                Self::V6(if shift >= 64 {
                    0
                } else {
                    high >> shift << shift
                })
            }
        }
    }
}

/// Which budget a response draws from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A real answer with records.
    Answer,
    /// NXDOMAIN, NODATA or REFUSED — the amplification-relevant path, since an
    /// attacker can drive it with arbitrary random names.
    Negative,
}

/// What the limiter decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Send the response.
    Allow,
    /// Send nothing at all.
    Drop,
    /// Send an empty truncated response, so a legitimate resolver retries over
    /// TCP (BIND calls this "slip").
    Truncate,
}

type Limiter = RateLimiter<ClientKey, DefaultKeyedStateStore<ClientKey>, DefaultClock>;

/// Keyed token-bucket limiter with separate answer and negative budgets.
pub struct Rrl {
    params: RrlParams,
    answers: Limiter,
    negatives: Limiter,
    /// Counts suppressed responses, to implement `slip` deterministically.
    suppressed: AtomicU64,
}

impl Rrl {
    #[must_use]
    pub fn new(params: RrlParams) -> Self {
        let quota = Self::quota(&params);
        Self {
            params,
            answers: RateLimiter::keyed(quota),
            negatives: RateLimiter::keyed(quota),
            suppressed: AtomicU64::new(0),
        }
    }

    fn quota(params: &RrlParams) -> Quota {
        // Both values are validated `>= 1` at config-compile time; the fallbacks
        // exist so this cannot panic even if that ever changes.
        let rps = NonZeroU32::new(params.responses_per_second).unwrap_or(NonZeroU32::MIN);
        let burst = NonZeroU32::new(params.burst).unwrap_or(rps);
        Quota::per_second(rps).allow_burst(burst)
    }

    /// Decide whether to send a response of `kind` to `addr`.
    ///
    /// `is_tcp` short-circuits to [`Decision::Allow`]: a completed TCP handshake
    /// already proves the source address.
    #[must_use]
    pub fn decide(&self, addr: IpAddr, kind: Kind, is_tcp: bool) -> Decision {
        if !self.params.enabled || is_tcp {
            return Decision::Allow;
        }
        let key = ClientKey::new(addr, self.params.ipv4_prefix, self.params.ipv6_prefix);
        let limiter = match kind {
            Kind::Answer => &self.answers,
            Kind::Negative => &self.negatives,
        };
        if limiter.check_key(&key).is_ok() {
            return Decision::Allow;
        }

        // Over budget. Every `slip`th suppressed response becomes a truncated
        // reply so a real resolver can fall back to TCP; `slip 0` always drops.
        let n = self.suppressed.fetch_add(1, Ordering::Relaxed);
        match self.params.slip {
            0 => Decision::Drop,
            slip if n.is_multiple_of(u64::from(slip)) => Decision::Truncate,
            _ => Decision::Drop,
        }
    }

    /// Drop bucket state for clients that have gone quiet.
    ///
    /// `governor`'s keyed store grows without bound between sweeps, so this must
    /// be called periodically; the server does so on a timer.
    pub fn sweep(&self) {
        self.answers.retain_recent();
        self.negatives.retain_recent();
    }

    /// Number of tracked client buckets, for the sweep task's logging.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.answers.len().saturating_add(self.negatives.len())
    }

    #[must_use]
    pub fn enabled(&self) -> bool {
        self.params.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address")
    }

    #[test]
    fn v4_aggregates_to_prefix() {
        let a = ClientKey::new(ip("192.0.2.7"), 24, 64);
        let b = ClientKey::new(ip("192.0.2.200"), 24, 64);
        let c = ClientKey::new(ip("192.0.3.7"), 24, 64);
        assert_eq!(a, b, "same /24 shares a bucket");
        assert_ne!(a, c, "different /24 does not");
    }

    #[test]
    fn v6_aggregates_to_prefix() {
        let a = ClientKey::new(ip("2001:db8:1:2::1"), 24, 64);
        let b = ClientKey::new(ip("2001:db8:1:2::ffff"), 24, 64);
        let c = ClientKey::new(ip("2001:db8:1:3::1"), 24, 64);
        assert_eq!(a, b, "same /64 shares a bucket");
        assert_ne!(a, c);

        // A shorter prefix aggregates more addresses together.
        assert_eq!(
            ClientKey::new(ip("2001:db8:1:2::1"), 24, 32),
            ClientKey::new(ip("2001:db8:9:9::1"), 24, 32)
        );
    }

    #[test]
    fn prefix_zero_collapses_everything() {
        assert_eq!(
            ClientKey::new(ip("192.0.2.1"), 0, 0),
            ClientKey::new(ip("198.51.100.1"), 0, 0)
        );
    }

    #[test]
    fn disabled_always_allows() {
        let rrl = Rrl::new(RrlParams {
            enabled: false,
            ..RrlParams::default()
        });
        for _ in 0..1000 {
            assert_eq!(
                rrl.decide(ip("192.0.2.1"), Kind::Answer, false),
                Decision::Allow
            );
        }
    }

    #[test]
    fn tcp_is_never_limited() {
        let rrl = Rrl::new(RrlParams {
            responses_per_second: 1,
            burst: 1,
            ..RrlParams::default()
        });
        for _ in 0..100 {
            assert_eq!(
                rrl.decide(ip("192.0.2.1"), Kind::Answer, true),
                Decision::Allow
            );
        }
    }

    #[test]
    fn burst_is_allowed_then_suppressed() {
        let rrl = Rrl::new(RrlParams {
            responses_per_second: 1,
            burst: 5,
            slip: 0,
            ..RrlParams::default()
        });
        let addr = ip("192.0.2.1");
        let allowed = (0..20)
            .filter(|_| rrl.decide(addr, Kind::Answer, false) == Decision::Allow)
            .count();
        assert!(
            (1..=6).contains(&allowed),
            "allowed {allowed}, expected ~burst"
        );
    }

    /// The two budgets must be independent, so a flood of random names cannot
    /// starve legitimate answers.
    #[test]
    fn answer_and_negative_budgets_are_independent() {
        let rrl = Rrl::new(RrlParams {
            responses_per_second: 1,
            burst: 2,
            slip: 0,
            ..RrlParams::default()
        });
        let addr = ip("192.0.2.1");
        // Exhaust the negative budget.
        while rrl.decide(addr, Kind::Negative, false) == Decision::Allow {}
        // Answers must still be available.
        assert_eq!(rrl.decide(addr, Kind::Answer, false), Decision::Allow);
    }

    #[test]
    fn slip_yields_periodic_truncation() {
        let rrl = Rrl::new(RrlParams {
            responses_per_second: 1,
            burst: 1,
            slip: 2,
            ..RrlParams::default()
        });
        let addr = ip("192.0.2.1");
        let mut decisions = Vec::new();
        for _ in 0..12 {
            decisions.push(rrl.decide(addr, Kind::Answer, false));
        }
        let truncated = decisions
            .iter()
            .filter(|d| **d == Decision::Truncate)
            .count();
        let dropped = decisions.iter().filter(|d| **d == Decision::Drop).count();
        assert!(truncated > 0, "slip must produce some truncated replies");
        assert!(dropped > 0, "slip must still drop most of them");
    }

    #[test]
    fn separate_clients_have_separate_budgets() {
        let rrl = Rrl::new(RrlParams {
            responses_per_second: 1,
            burst: 1,
            slip: 0,
            ..RrlParams::default()
        });
        assert_eq!(
            rrl.decide(ip("192.0.2.1"), Kind::Answer, false),
            Decision::Allow
        );
        // A different /24 is unaffected by the first client's spend.
        assert_eq!(
            rrl.decide(ip("198.51.100.1"), Kind::Answer, false),
            Decision::Allow
        );
    }

    #[test]
    fn sweep_is_safe_on_an_empty_limiter() {
        let rrl = Rrl::new(RrlParams::default());
        rrl.sweep();
        assert_eq!(rrl.tracked(), 0);
    }
}
