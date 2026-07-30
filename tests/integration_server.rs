//! End-to-end tests against a real server on a real ephemeral port.
//!
//! The unit and vector tests pin the pure logic; these pin the wire behaviour —
//! flags, rcodes, EDNS, TCP — and, most importantly, that hostile input cannot
//! stop the daemon.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use panoptidns::config::{Config, ListenAddr};
use panoptidns::hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use panoptidns::hickory_proto::rr::domain::Name;
use panoptidns::hickory_proto::rr::{DNSClass, RData, RecordType};
use panoptidns::hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use panoptidns::rrl::Rrl;
use panoptidns::server::bind::bind_all;
use panoptidns::server::{Handler, Zones};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const CONFIG: &str = "\
primary ns1.example.net.
hostmaster hostmaster.example.net.
ns ns1.example.net.
ns ns2.example.net.
rrl off

network 2001:4d88:100e:ccc0::/64
\tresolves to ipv6-%DIGITS%-blah.nutzer.raumzeitlabor.de
";

const PTR_QUERY: &str = "7.c.e.2.3.4.e.f.f.f.b.d.9.1.2.0.0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa.";
const FWD_NAME: &str = "ipv6-0219dbfffe432ec7-blah.nutzer.raumzeitlabor.de.";

/// A running server, plus the address it actually bound.
struct Harness {
    addr: SocketAddr,
    _server: panoptidns::hickory_server::server::Server<Handler>,
}

async fn start(config_text: &str) -> Harness {
    let config = match Config::parse(config_text) {
        Ok(c) => c,
        Err(e) => panic!("test config invalid:\n{e}"),
    };
    // RRL is disabled in the shared config so these tests are not rate limited;
    // the limiter has its own unit tests.
    let rrl = Arc::new(Rrl::new(config.params.rrl));
    let zones = Arc::new(ArcSwap::from_pointee(
        Zones::new(config).expect("upstream clients"),
    ));

    let bound = bind_all(&[ListenAddr {
        addr: "127.0.0.1".parse().expect("loopback"),
        port: 0,
    }])
    .expect("bind loopback");
    let addr = bound.addrs[0];

    let handler = Handler::new(zones, rrl, false);
    let mut server = panoptidns::hickory_server::server::Server::new(handler);
    for socket in bound.udp {
        server.register_socket(socket);
    }
    for listener in bound.tcp {
        server.register_listener(listener, Duration::from_secs(5), 4096);
    }

    Harness {
        addr,
        _server: server,
    }
}

fn query_bytes(name: Name, qtype: RecordType) -> Vec<u8> {
    let mut query = Query::new();
    query.set_name(name);
    query.set_query_type(qtype);
    query.set_query_class(DNSClass::IN);
    let mut message = Message::query();
    message.metadata.id = 0x1234;
    message.metadata.message_type = MessageType::Query;
    message.metadata.op_code = OpCode::Query;
    message.add_query(query);
    message.to_bytes().expect("encode query")
}

/// Send raw bytes over UDP and return the decoded response, if any arrives.
async fn ask_raw(addr: SocketAddr, bytes: &[u8]) -> Option<Message> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("client socket");
    socket.send_to(bytes, addr).await.expect("send");
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => Some(Message::from_bytes(&buf[..len]).expect("decode response")),
        _ => None,
    }
}

async fn ask(addr: SocketAddr, name: &str, qtype: RecordType) -> Message {
    let name = Name::from_ascii(name).expect("test name");
    ask_raw(addr, &query_bytes(name, qtype))
        .await
        .expect("a response")
}

async fn ask_tcp(addr: SocketAddr, name: &str, qtype: RecordType) -> Message {
    let name = Name::from_ascii(name).expect("test name");
    let bytes = query_bytes(name, qtype);
    let mut stream = TcpStream::connect(addr).await.expect("tcp connect");
    // DNS over TCP prefixes each message with a 2-byte length.
    let len = u16::try_from(bytes.len()).expect("query fits");
    stream
        .write_all(&len.to_be_bytes())
        .await
        .expect("write len");
    stream.write_all(&bytes).await.expect("write body");

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.expect("read len");
    let mut body = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
    stream.read_exact(&mut body).await.expect("read body");
    Message::from_bytes(&body).expect("decode tcp response")
}

// ---- the happy path over both transports -----------------------------------

#[tokio::test]
async fn ptr_query_answers_over_udp() {
    let h = start(CONFIG).await;
    let response = ask(h.addr, PTR_QUERY, RecordType::PTR).await;

    assert_eq!(response.response_code, ResponseCode::NoError);
    assert!(response.authoritative, "we hold the delegation");
    assert!(!response.recursion_available, "we never offer recursion");
    assert_eq!(response.answers.len(), 1);
    match &response.answers[0].data {
        RData::PTR(ptr) => assert_eq!(ptr.0.to_ascii(), FWD_NAME),
        other => panic!("expected PTR, got {other:?}"),
    }
}

#[tokio::test]
async fn aaaa_query_answers_over_udp() {
    let h = start(CONFIG).await;
    let response = ask(h.addr, FWD_NAME, RecordType::AAAA).await;

    assert_eq!(response.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1);
    match &response.answers[0].data {
        RData::AAAA(a) => assert_eq!(a.0.to_string(), "2001:4d88:100e:ccc0:219:dbff:fe43:2ec7"),
        other => panic!("expected AAAA, got {other:?}"),
    }
}

#[tokio::test]
async fn tcp_and_udp_agree() {
    let h = start(CONFIG).await;
    let over_udp = ask(h.addr, PTR_QUERY, RecordType::PTR).await;
    let over_tcp = ask_tcp(h.addr, PTR_QUERY, RecordType::PTR).await;
    assert_eq!(over_udp.answers, over_tcp.answers);
    assert_eq!(over_udp.response_code, over_tcp.response_code);
}

/// The v1.3 behaviour the original pinned: the name exists, so an `A` query is
/// an empty NOERROR rather than NXDOMAIN.
#[tokio::test]
async fn a_query_on_a_synthesized_name_is_empty_noerror() {
    let h = start(CONFIG).await;
    let response = ask(h.addr, FWD_NAME, RecordType::A).await;
    assert_eq!(response.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 0);
    assert!(response.authoritative);
}

// ---- policy ----------------------------------------------------------------

#[tokio::test]
async fn out_of_zone_is_refused_by_default() {
    let h = start(CONFIG).await;
    let response = ask(h.addr, "www.example.com.", RecordType::A).await;
    assert_eq!(response.response_code, ResponseCode::Refused);
    assert!(!response.authoritative);
}

#[tokio::test]
async fn out_of_zone_can_be_nxdomain_for_compatibility() {
    let config = format!("out-of-zone nxdomain\n{CONFIG}");
    let h = start(&config).await;
    let response = ask(h.addr, "www.example.com.", RecordType::A).await;
    assert_eq!(response.response_code, ResponseCode::NXDomain);
}

/// In-zone but nonexistent must carry the SOA, or resolvers cannot cache the
/// negative and will re-query forever. The original sent a bare NXDOMAIN.
#[tokio::test]
async fn in_zone_nxdomain_carries_a_soa() {
    let h = start(CONFIG).await;
    let response = ask(
        h.addr,
        "does-not-exist.nutzer.raumzeitlabor.de.",
        RecordType::AAAA,
    )
    .await;
    assert_eq!(response.response_code, ResponseCode::NXDomain);
    assert!(response.authoritative);
    let soas = response
        .authorities
        .iter()
        .filter(|r| r.record_type() == RecordType::SOA)
        .count();
    assert_eq!(soas, 1, "authority section must hold exactly one SOA");
}

#[tokio::test]
async fn apex_soa_and_ns_are_served() {
    let h = start(CONFIG).await;

    let soa = ask(h.addr, "nutzer.raumzeitlabor.de.", RecordType::SOA).await;
    assert_eq!(soa.response_code, ResponseCode::NoError);
    assert_eq!(soa.answers.len(), 1);
    assert_eq!(soa.answers[0].record_type(), RecordType::SOA);

    let ns = ask(h.addr, "nutzer.raumzeitlabor.de.", RecordType::NS).await;
    assert_eq!(ns.answers.len(), 2, "both configured nameservers");

    // The reverse apex is equally ours.
    let rev = ask(
        h.addr,
        "0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa.",
        RecordType::SOA,
    )
    .await;
    assert_eq!(rev.answers.len(), 1);
}

#[tokio::test]
async fn zone_transfer_is_refused() {
    let h = start(CONFIG).await;
    // A /64 holds 2^64 names; there is nothing transferable here.
    let response = ask_tcp(h.addr, "nutzer.raumzeitlabor.de.", RecordType::AXFR).await;
    assert_eq!(response.response_code, ResponseCode::Refused);
}

#[tokio::test]
async fn unknown_edns_version_gets_badvers() {
    use panoptidns::hickory_proto::op::Edns;

    let h = start(CONFIG).await;
    let name = Name::from_ascii(PTR_QUERY).expect("name");
    let mut query = Query::new();
    query.set_name(name);
    query.set_query_type(RecordType::PTR);
    query.set_query_class(DNSClass::IN);
    let mut message = Message::query();
    message.add_query(query);
    let mut edns = Edns::new();
    edns.set_version(1);
    edns.set_max_payload(4096);
    message.set_edns(edns);

    let response = ask_raw(h.addr, &message.to_bytes().expect("encode"))
        .await
        .expect("a response");
    // Extended RCODE 16 is BADVERS (RFC 6891) *and* BADSIG (RFC 2845) — the two
    // share a number, and hickory's decoder resolves the ambiguity as BADSIG.
    // What matters on the wire is the value, so accept either name.
    assert!(
        matches!(
            response.response_code,
            ResponseCode::BADVERS | ResponseCode::BADSIG
        ),
        "expected extended RCODE 16, got {:?}",
        response.response_code
    );
}

#[tokio::test]
async fn edns_opt_is_echoed_and_payload_clamped() {
    use panoptidns::hickory_proto::op::Edns;

    let h = start(CONFIG).await;
    let name = Name::from_ascii(PTR_QUERY).expect("name");
    let mut query = Query::new();
    query.set_name(name);
    query.set_query_type(RecordType::PTR);
    query.set_query_class(DNSClass::IN);
    let mut message = Message::query();
    message.add_query(query);
    let mut edns = Edns::new();
    edns.set_version(0);
    // Deliberately larger than our 1232-byte ceiling.
    edns.set_max_payload(65535);
    message.set_edns(edns);

    let response = ask_raw(h.addr, &message.to_bytes().expect("encode"))
        .await
        .expect("a response");
    let echoed = response.edns.as_ref().expect("an OPT in the reply");
    assert_eq!(echoed.version(), 0);
    assert!(
        echoed.max_payload() <= 1232,
        "advertised {} must be clamped to avoid IPv6 fragmentation",
        echoed.max_payload()
    );
}

// ---- regression: the packet that killed AllKnowingDNS -----------------------

/// Finding 1, end to end.
///
/// The original built records by interpolating the query name into a DNS
/// master-file presentation string, so a `;` (comment) or `"` (quote) byte in a
/// query label made the parser die — and `Net::DNS::Nameserver` had no exception
/// guard anywhere in its request path, so the daemon exited.
///
/// The assertion that matters is the *second* one: after every hostile packet, a
/// perfectly ordinary query must still be answered by the same process.
#[tokio::test]
async fn hostile_query_bytes_do_not_kill_the_server() {
    let h = start(CONFIG).await;

    let zone_labels: Vec<Vec<u8>> = "0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa"
        .split('.')
        .map(|s| s.as_bytes().to_vec())
        .collect();

    let hostile: Vec<Vec<u8>> = vec![
        b";".to_vec(),
        b"a;b".to_vec(),
        b"\"".to_vec(),
        b"a\"b".to_vec(),
        b"(".to_vec(),
        b")".to_vec(),
        b"\\".to_vec(),
        b"\n".to_vec(),
        b"\t".to_vec(),
        b" ".to_vec(),
        vec![0x00],
        vec![0xFF],
        vec![0x80, 0x81, 0x82],
        vec![b'a'; 63],
    ];

    for evil in hostile {
        let mut labels = vec![evil.clone()];
        labels.extend(zone_labels.iter().cloned());
        let Ok(mut name) = Name::from_labels(labels) else {
            continue; // not even constructible; nothing to send
        };
        name.set_fqdn(true);

        let bytes = query_bytes(name, RecordType::PTR);
        // A response is not required — dropping is a legitimate outcome — but
        // the process must survive.
        let _ = ask_raw(h.addr, &bytes).await;

        let followup = ask(h.addr, PTR_QUERY, RecordType::PTR).await;
        assert_eq!(
            followup.response_code,
            ResponseCode::NoError,
            "server stopped answering after a label containing {:?}",
            String::from_utf8_lossy(&evil)
        );
        assert_eq!(followup.answers.len(), 1);
    }
}

/// Truncated, empty and garbage datagrams must not stop the server either.
#[tokio::test]
async fn malformed_datagrams_do_not_kill_the_server() {
    let h = start(CONFIG).await;

    let junk: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0xFF; 12],
        vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01],
        (0u16..600).map(|i| (i % 251) as u8).collect(),
    ];

    for bytes in junk {
        let _ = ask_raw(h.addr, &bytes).await;
    }

    let followup = ask(h.addr, PTR_QUERY, RecordType::PTR).await;
    assert_eq!(followup.response_code, ResponseCode::NoError);
}

/// Finding 5: an over-long host part used to be silently truncated into a wrong
/// answer, with a warning logged per query.
#[tokio::test]
async fn overlong_reverse_names_are_declined_not_truncated() {
    let h = start(CONFIG).await;

    // 200 single-nibble labels in front of the zone: far more than the 32 a real
    // address has.
    let mut labels: Vec<Vec<u8>> = (0..200).map(|_| b"a".to_vec()).collect();
    labels.extend(
        "0.c.c.c.e.0.0.1.8.8.d.4.1.0.0.2.ip6.arpa"
            .split('.')
            .map(|s| s.as_bytes().to_vec()),
    );

    if let Ok(mut name) = Name::from_labels(labels) {
        name.set_fqdn(true);
        if let Some(response) = ask_raw(h.addr, &query_bytes(name, RecordType::PTR)).await {
            assert!(
                response.answers.is_empty(),
                "a malformed reverse name must never produce an answer"
            );
        }
    }

    let followup = ask(h.addr, PTR_QUERY, RecordType::PTR).await;
    assert_eq!(followup.response_code, ResponseCode::NoError);
}

/// Finding 6: uppercase hex must work, non-hex must not.
#[tokio::test]
async fn case_insensitive_but_strictly_hex() {
    let h = start(CONFIG).await;

    let upper = ask(
        h.addr,
        "IPV6-0219DBFFFE432EC7-BLAH.NUTZER.RAUMZEITLABOR.DE.",
        RecordType::AAAA,
    )
    .await;
    assert_eq!(upper.answers.len(), 1, "DNS names are case-insensitive");

    let not_hex = ask(
        h.addr,
        "ipv6-zzzzzzzzzzzzzzzz-blah.nutzer.raumzeitlabor.de.",
        RecordType::AAAA,
    )
    .await;
    assert!(not_hex.answers.is_empty());

    let appended = ask(
        h.addr,
        "ipv6-0219dbfffe432ec7-blah.nutzer.raumzeitlabor.de.evil.com.",
        RecordType::AAAA,
    )
    .await;
    assert!(
        appended.answers.is_empty(),
        "matching must be a full match, not a suffix match"
    );
}

#[tokio::test]
async fn notify_and_update_are_not_implemented_rather_than_fatal() {
    let h = start(CONFIG).await;

    for opcode in [OpCode::Update, OpCode::Notify] {
        let name = Name::from_ascii("nutzer.raumzeitlabor.de.").expect("name");
        let mut query = Query::new();
        query.set_name(name);
        query.set_query_type(RecordType::SOA);
        query.set_query_class(DNSClass::IN);
        let mut message = Message::query();
        message.metadata.message_type = MessageType::Query;
        message.metadata.op_code = opcode;
        message.add_query(query);

        if let Some(response) = ask_raw(h.addr, &message.to_bytes().expect("encode")).await {
            assert_eq!(
                response.response_code,
                ResponseCode::NotImp,
                "{opcode:?} must be declined"
            );
        }
    }

    // The original needed a NotifyHandler workaround purely to avoid exiting here.
    let followup = ask(h.addr, PTR_QUERY, RecordType::PTR).await;
    assert_eq!(followup.response_code, ResponseCode::NoError);
}

/// An unmodified AllKnowingDNS v1.7 config must still work, warnings and all.
#[tokio::test]
async fn original_v17_config_still_serves() {
    let h = start(
        "network 2001:4d88:100e:ccc0::/64\n\
         \tresolves to ipv6-%DIGITS%.nutzer.raumzeitlabor.de\n",
    )
    .await;
    let response = ask(h.addr, PTR_QUERY, RecordType::PTR).await;
    assert_eq!(response.response_code, ResponseCode::NoError);
    match &response.answers[0].data {
        RData::PTR(ptr) => assert_eq!(
            ptr.0.to_ascii(),
            "ipv6-0219dbfffe432ec7.nutzer.raumzeitlabor.de."
        ),
        other => panic!("expected PTR, got {other:?}"),
    }
}
