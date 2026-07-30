//! Conversions between IPv6 addresses and `ip6.arpa` names, at nibble
//! granularity.
//!
//! Everything here is a total function: hostile input yields `None`, never a
//! panic and never a partially-parsed value. This is the module where the
//! original's remote-kill vector dies — see the crate-level docs.

use hickory_proto::rr::domain::Name;

/// Nibbles in a full IPv6 address (128 bits / 4 bits per nibble).
pub const ADDR_NIBBLES: u8 = 32;

/// Labels in a fully-qualified `<32 nibbles>.ip6.arpa` name.
const PTR_QUERY_LABELS: u8 = ADDR_NIBBLES + 2;

/// Lowercase hex alphabet. Synthesized names use *only* these bytes, which is
/// what makes generated record data provably free of attacker-chosen content.
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// Decode one ASCII hex digit.
///
/// Upper and lower case both decode: DNS names are case-insensitive on the wire,
/// so a resolver is free to send `0219DBFF…` and must get the same answer. The
/// Perl original used the character class `[a-z0-9]`, which got this wrong in
/// both directions — it rejected uppercase hex, and it accepted `g`–`z`, which
/// Perl's `hex()` then silently turned into `0`, yielding a confidently wrong
/// address.
#[inline]
const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Bitmask selecting the network part of a `mask`-bit prefix.
///
/// `mask` must be `<= 128`; wider values saturate to the full mask rather than
/// overflowing the shift.
#[inline]
#[must_use]
pub const fn mask_bits(mask: u8) -> u128 {
    match mask {
        0 => 0,
        m if m >= 128 => u128::MAX,
        // `m` is in 1..=127 here, so the shift is always in range.
        m => !(u128::MAX >> m),
    }
}

/// Strictly parse a `<32 nibbles>.ip6.arpa` query name into the address it
/// denotes.
///
/// Returns `None` unless the name is *exactly* a single /128 address: 32
/// single-byte hex labels followed by `ip6.arpa`. That strictness is deliberate
/// and is a security property, not pedantry:
///
/// - The original matched a query against a zone by comparing **string
///   suffixes**, accepting any prefix whatsoever. Everything to the left of the
///   zone was then concatenated into the synthesized hostname, so a query could
///   inject arbitrary bytes (including DNS master-file metacharacters) and
///   arbitrary length into the answer.
/// - Real reverse-DNS lookups are always for a full address, so nothing
///   legitimate is lost.
///
/// Note that this is *not* [`Name::parse_arpa_name`]: that function is
/// deliberately length-tolerant (a shorter name yields a shorter prefix) and
/// allocates a `ProtoError` on every rejection, which would put an allocation on
/// an attacker-controlled path. `tests::agrees_with_hickory_arpa_parser` pins the
/// two implementations together for the /128 case.
#[must_use]
pub fn ptr_name_to_addr(name: &Name) -> Option<u128> {
    if name.num_labels() != PTR_QUERY_LABELS {
        return None;
    }

    let mut labels = name.iter();
    let mut addr: u128 = 0;

    // Labels run least-significant nibble first: in
    // `7.c.e.….8.d.4.1.0.0.2.ip6.arpa` label 0 (`7`) is the address's low
    // nibble and label 31 (`2`) its high nibble.
    for position in 0..ADDR_NIBBLES {
        let &[digit] = labels.next()? else {
            // A label that is not exactly one byte long cannot be a nibble.
            return None;
        };
        let value = hex_val(digit)?;
        addr |= u128::from(value) << (position * 4);
    }

    if !labels.next()?.eq_ignore_ascii_case(b"ip6") {
        return None;
    }
    if !labels.next()?.eq_ignore_ascii_case(b"arpa") {
        return None;
    }
    // `num_labels` was checked above, so the iterator is exhausted.
    debug_assert!(labels.next().is_none());

    Some(addr)
}

/// Build the `ip6.arpa` zone name that a network prefix delegates to.
///
/// ```text
/// (2001:4d88:100e:ccc0::, 64) -> 0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa
/// ```
///
/// Returns `None` if `mask` exceeds 128 or is not nibble-aligned. The original
/// required a multiple of *16* — an artifact of its `unpack("n8")` implementation
/// rather than a property of DNS. A multiple of 4 is the real constraint, since
/// one `ip6.arpa` label carries exactly one nibble, so this accepts strictly more
/// valid configurations than the original while still rejecting prefixes that
/// cannot map onto a zone boundary at all.
///
/// This is called at configuration-compile time, not per query, so the
/// allocations are irrelevant.
#[must_use]
pub fn netmask_to_ptr_name(prefix: u128, mask: u8) -> Option<Name> {
    if mask > 128 || !mask.is_multiple_of(4) {
        return None;
    }
    let ptr_nibbles = mask / 4;

    // Emit the prefix's top `ptr_nibbles` nibbles in reverse order (RFC 3596
    // §2.5), i.e. ascending by significance starting just above the host part.
    let mut labels: Vec<Vec<u8>> = Vec::with_capacity(usize::from(ptr_nibbles) + 2);
    for position in (ADDR_NIBBLES - ptr_nibbles)..ADDR_NIBBLES {
        let nibble = ((prefix >> (position * 4)) & 0xF) as usize;
        let digit = *HEX_LOWER.get(nibble)?;
        labels.push(vec![digit]);
    }
    labels.push(b"ip6".to_vec());
    labels.push(b"arpa".to_vec());

    let mut name = Name::from_labels(labels).ok()?;
    name.set_fqdn(true);
    Some(name)
}

/// Render the host part of `addr` — the low `host_nibbles` nibbles — as
/// lowercase hex, zero-padded to exactly `host_nibbles` digits.
///
/// The padding is load-bearing: the original's own test suite pins
/// `0000000001920001`, so leading zeros are part of the observable contract and
/// dropping them would change every synthesized hostname.
///
/// Returns `None` if `host_nibbles` exceeds [`ADDR_NIBBLES`].
#[must_use]
pub fn host_digits(addr: u128, host_nibbles: u8) -> Option<String> {
    if host_nibbles > ADDR_NIBBLES {
        return None;
    }
    let width = usize::from(host_nibbles);
    if width == 0 {
        // A zero-nibble host part is the empty string. `format!` would not give
        // us that: a width of 0 is a *minimum*, so `{0:00x}` still renders the
        // value as "0". A /128 zone has no digits to vary and is rejected at
        // config-compile time, but this function stays total regardless.
        return Some(String::new());
    }
    let host = addr & !mask_bits(128 - host_nibbles * 4);
    Some(format!("{host:0width$x}"))
}

/// Decode exactly `host_nibbles` hex digits into the host part of an address.
///
/// Returns `None` on any non-hex byte or on a length mismatch. The length is
/// checked here, in the same place the digits are decoded, so the original's
/// split-brain bug — zone lookup matching `[a-z0-9]+` while synthesis demanded
/// `[a-z0-9]{n}` — cannot recur.
#[must_use]
pub fn digits_to_host(digits: &[u8], host_nibbles: u8) -> Option<u128> {
    if digits.len() != usize::from(host_nibbles) {
        return None;
    }
    let mut host: u128 = 0;
    for &byte in digits {
        let value = hex_val(byte)?;
        host = (host << 4) | u128::from(value);
    }
    Some(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    fn name(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn addr(s: &str) -> u128 {
        u128::from(Ipv6Addr::from_str(s).unwrap())
    }

    /// Renders a PTR zone the way the original's `netmask_to_ptrzone` did, i.e.
    /// without the trailing root dot, so the ported vectors stay verbatim.
    fn ptr_zone_display(prefix: u128, mask: u8) -> String {
        let name = netmask_to_ptr_name(prefix, mask).unwrap();
        name.to_ascii().trim_end_matches('.').to_string()
    }

    // ---- ported from t/002-util.t ------------------------------------------

    #[test]
    fn netmask_to_ptrzone_vectors_from_perl_suite() {
        let net = addr("2001:4d88:100e:ccc0::");
        assert_eq!(
            ptr_zone_display(net, 64),
            "0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa"
        );
        assert_eq!(
            ptr_zone_display(net, 48),
            "e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa"
        );
        assert_eq!(
            ptr_zone_display(net, 80),
            "0.0.0.0.0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn netmask_rejects_non_nibble_aligned_prefix() {
        let net = addr("2001:db8::");
        for mask in [1u8, 2, 3, 63, 65, 127] {
            assert!(
                netmask_to_ptr_name(net, mask).is_none(),
                "/{mask} must be rejected"
            );
        }
        // Multiples of 4 that are *not* multiples of 16 are accepted here,
        // unlike the Perl original.
        for mask in [4u8, 20, 60, 68, 124] {
            assert!(
                netmask_to_ptr_name(net, mask).is_some(),
                "/{mask} must be accepted"
            );
        }
    }

    #[test]
    fn netmask_edge_masks() {
        assert_eq!(ptr_zone_display(addr("::"), 0), "ip6.arpa");
        assert_eq!(
            ptr_zone_display(addr("2001:4d88:100e:ccc0:219:dbff:fe43:2ec7"), 128),
            "7.c.e.2.3.4.e.f.f.f.b.d.9.1.2.0.0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa"
        );
        assert!(netmask_to_ptr_name(addr("::"), 129).is_none());
    }

    // ---- PTR query parsing -------------------------------------------------

    #[test]
    fn parses_full_ptr_query() {
        let q = name("7.c.e.2.3.4.e.f.f.f.b.d.9.1.2.0.0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa.");
        assert_eq!(
            ptr_name_to_addr(&q),
            Some(addr("2001:4d88:100e:ccc0:219:dbff:fe43:2ec7"))
        );
    }

    #[test]
    fn ptr_query_is_case_insensitive() {
        // Same address, uppercase hex and uppercase suffix.
        let lower =
            name("7.c.e.2.3.4.e.f.f.f.b.d.9.1.2.0.0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa.");
        let upper =
            name("7.C.E.2.3.4.E.F.F.F.B.D.9.1.2.0.0.C.C.C.E.0.0.1.8.8.D.4.1.0.0.2.IP6.ARPA.");
        assert_eq!(ptr_name_to_addr(&lower), ptr_name_to_addr(&upper));
        assert!(ptr_name_to_addr(&upper).is_some());
    }

    #[test]
    fn rejects_partial_and_overlong_ptr_queries() {
        // 16 nibbles: a /64 zone apex, not an address.
        assert_eq!(
            ptr_name_to_addr(&name("0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa.")),
            None
        );
        // 33 nibbles.
        assert_eq!(
            ptr_name_to_addr(&name(
                "1.7.c.e.2.3.4.e.f.f.f.b.d.9.1.2.0.0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa."
            )),
            None
        );
        assert_eq!(ptr_name_to_addr(&name("ip6.arpa.")), None);
    }

    #[test]
    fn rejects_wrong_suffix() {
        let mut labels: Vec<Vec<u8>> = (0..32).map(|_| b"0".to_vec()).collect();
        labels.push(b"ip6".to_vec());
        labels.push(b"example".to_vec());
        let mut n = Name::from_labels(labels).unwrap();
        n.set_fqdn(true);
        assert_eq!(ptr_name_to_addr(&n), None);
    }

    #[test]
    fn rejects_non_hex_and_multibyte_nibble_labels() {
        // `g` is not hex. Perl's `[a-z0-9]` accepted it and `hex()` returned 0.
        let with_g =
            name("g.c.e.2.3.4.e.f.f.f.b.d.9.1.2.0.0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa.");
        assert_eq!(ptr_name_to_addr(&with_g), None);

        // A two-byte label is not a nibble, even though it is valid hex.
        let two_byte =
            name("7c.e.2.3.4.e.f.f.f.b.d.9.1.2.0.0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa.");
        assert_eq!(ptr_name_to_addr(&two_byte), None);
    }

    /// Regression guard for the finding that killed the original: a query label
    /// containing DNS master-file metacharacters must be rejected cleanly.
    #[test]
    fn rejects_master_file_metacharacters_without_panicking() {
        for evil in [
            b";".as_slice(),
            b"\"".as_slice(),
            b"a;b".as_slice(),
            b"(".as_slice(),
            b"\\".as_slice(),
            b"\n".as_slice(),
            b"\0".as_slice(),
            &[0xFF],
            &[b'a'; 63],
        ] {
            let mut labels: Vec<Vec<u8>> = vec![evil.to_vec()];
            labels.extend((0..31).map(|_| b"0".to_vec()));
            labels.push(b"ip6".to_vec());
            labels.push(b"arpa".to_vec());
            // Some of these are not even constructible as a Name; either way the
            // outcome must be a rejection, never a panic.
            if let Ok(mut n) = Name::from_labels(labels) {
                n.set_fqdn(true);
                assert_eq!(
                    ptr_name_to_addr(&n),
                    None,
                    "label {evil:?} must not parse as a nibble"
                );
            }
        }
    }

    /// Differential test against hickory's own arpa parser. We do not *use* it
    /// on the hot path (it is length-tolerant and allocates on rejection), so
    /// this pins the two together for the case where they must agree.
    #[test]
    fn agrees_with_hickory_arpa_parser() {
        use hickory_proto::rr::domain::IntoName;

        for sample in [
            "2001:4d88:100e:ccc0:219:dbff:fe43:2ec7",
            "::",
            "::1",
            "2a00:15a0:2:0:0:0:192:1",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            let expected = addr(sample);
            let arpa = ptr_zone_display(expected, 128);
            let n = format!("{arpa}.").into_name().unwrap();

            assert_eq!(ptr_name_to_addr(&n), Some(expected), "ours: {sample}");

            match n.parse_arpa_name().unwrap() {
                ipnet::IpNet::V6(net) => {
                    assert_eq!(net.prefix_len(), 128);
                    assert_eq!(u128::from(net.addr()), expected, "hickory: {sample}");
                }
                other => panic!("expected V6, got {other:?}"),
            }
        }
    }

    // ---- host digit round-trip --------------------------------------------

    #[test]
    fn host_digits_vectors_from_perl_suite() {
        // t/004-handler.t
        assert_eq!(
            host_digits(addr("2001:4d88:100e:ccc0:219:dbff:fe43:2ec7"), 16).unwrap(),
            "0219dbfffe432ec7"
        );
        // t/005-same-domain.t — leading zeros are part of the contract.
        assert_eq!(
            host_digits(addr("2a00:15a0:2:0:0:0:192:1"), 16).unwrap(),
            "0000000001920001"
        );
        // /112 case: 4 nibbles.
        assert_eq!(
            host_digits(addr("2001:4d88:100e:ccc0:1111:2222:3333:aaff"), 4).unwrap(),
            "aaff"
        );
    }

    #[test]
    fn host_digits_ignores_network_part() {
        let a = addr("2001:4d88:100e:ccc0:219:dbff:fe43:2ec7");
        let b = addr("fe80::219:dbff:fe43:2ec7");
        assert_eq!(host_digits(a, 16).unwrap(), host_digits(b, 16).unwrap());
    }

    #[test]
    fn host_digits_edges() {
        assert_eq!(host_digits(u128::MAX, 0).unwrap(), "");
        assert_eq!(host_digits(u128::MAX, 32).unwrap(), "f".repeat(32));
        assert_eq!(host_digits(0, 32).unwrap(), "0".repeat(32));
        assert!(host_digits(0, 33).is_none());
    }

    #[test]
    fn digits_to_host_rejects_wrong_length_and_non_hex() {
        assert_eq!(digits_to_host(b"aaff", 4), Some(0xaaff));
        assert_eq!(digits_to_host(b"AAFF", 4), Some(0xaaff));
        assert_eq!(digits_to_host(b"aaf", 4), None, "too short");
        assert_eq!(digits_to_host(b"aaffa", 4), None, "too long");
        assert_eq!(digits_to_host(b"zzzz", 4), None, "not hex");
        assert_eq!(digits_to_host(b"", 0), Some(0));
    }

    // ---- properties --------------------------------------------------------

    proptest::proptest! {
        /// The single most valuable invariant in the crate: an address survives
        /// the trip out to an `ip6.arpa` name and back completely unchanged.
        #[test]
        fn ptr_name_roundtrip_is_identity(raw in proptest::prelude::any::<u128>()) {
            let n = netmask_to_ptr_name(raw, 128).unwrap();
            proptest::prop_assert_eq!(ptr_name_to_addr(&n), Some(raw));
        }

        /// Host digits round-trip for every nibble-aligned network/host split,
        /// and always occupy exactly the advertised number of characters.
        #[test]
        fn host_digit_roundtrip_is_identity(
            raw in proptest::prelude::any::<u128>(),
            nibbles in 1u8..=32,
        ) {
            let digits = host_digits(raw, nibbles).unwrap();
            proptest::prop_assert_eq!(digits.len(), usize::from(nibbles));
            let host = digits_to_host(digits.as_bytes(), nibbles).unwrap();
            proptest::prop_assert_eq!(host, raw & !mask_bits(128 - nibbles * 4));
        }

        /// A PTR zone name carries exactly one label per network nibble, plus
        /// `ip6.arpa`. Guards the class of bug where a malformed prefix
        /// collapsed the zone to a bare `.ip6.arpa` that matched everything.
        #[test]
        fn ptr_zone_has_one_label_per_network_nibble(
            raw in proptest::prelude::any::<u128>(),
            q in 0u8..=32,
        ) {
            let n = netmask_to_ptr_name(raw, q * 4).unwrap();
            proptest::prop_assert_eq!(n.num_labels(), q + 2);
        }

        /// Arbitrary label bytes must never panic. Anything we *do* accept has
        /// to rebuild to an equal name — which also pins the claim that
        /// `Name`'s equality is case-insensitive.
        #[test]
        fn arbitrary_labels_never_panic(
            labels in proptest::collection::vec(
                proptest::collection::vec(proptest::prelude::any::<u8>(), 0..3),
                0..40,
            ),
        ) {
            if let Ok(mut n) = Name::from_labels(labels) {
                n.set_fqdn(true);
                if let Some(parsed) = ptr_name_to_addr(&n) {
                    let rebuilt = netmask_to_ptr_name(parsed, 128).unwrap();
                    proptest::prop_assert_eq!(rebuilt, n);
                }
            }
        }

        /// Every address we synthesize from a zone stays inside that zone.
        #[test]
        fn synthesized_address_stays_in_prefix(
            prefix_raw in proptest::prelude::any::<u128>(),
            q in 1u8..=32,
            host_raw in proptest::prelude::any::<u128>(),
        ) {
            let mask = q * 4;
            let prefix = prefix_raw & mask_bits(mask);
            let host_nibbles = (128 - mask) / 4;
            let host = host_raw & !mask_bits(mask);
            let addr = prefix | host;

            let digits = host_digits(addr, host_nibbles).unwrap();
            let decoded = digits_to_host(digits.as_bytes(), host_nibbles).unwrap();
            proptest::prop_assert_eq!(prefix | decoded, addr);
            proptest::prop_assert_eq!(addr & mask_bits(mask), prefix);
        }
    }

    #[test]
    fn mask_bits_boundaries() {
        assert_eq!(mask_bits(0), 0);
        assert_eq!(mask_bits(128), u128::MAX);
        assert_eq!(mask_bits(64), 0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000);
        assert_eq!(mask_bits(255), u128::MAX, "must saturate, not overflow");
    }
}
