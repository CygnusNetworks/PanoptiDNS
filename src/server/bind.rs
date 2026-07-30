//! Socket creation.
//!
//! Returns the addresses actually bound, which matters for two reasons: the
//! startup log should state the truth rather than the intent, and tests bind port
//! 0 and need to learn what they got.

use std::net::{IpAddr, SocketAddr};

use socket2::{Domain, Protocol as SockProtocol, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};

use crate::config::ListenAddr;

/// Backlog for TCP listeners.
const TCP_BACKLOG: i32 = 128;

/// Sockets bound and ready to hand to the server.
pub struct Bound {
    pub udp: Vec<UdpSocket>,
    pub tcp: Vec<TcpListener>,
    /// The addresses actually bound, in the order they were requested.
    pub addrs: Vec<SocketAddr>,
}

/// Configure a socket the way both transports need it.
///
/// `IPV6_V6ONLY` is the important part: without it, binding `[::]` also claims
/// every IPv4 address on Linux, and a subsequent bind of `0.0.0.0` on the same
/// port fails with EADDRINUSE. Since the sensible container default is to listen
/// on both wildcards, the two must be kept separate.
fn configure(addr: SocketAddr, kind: Type, proto: SockProtocol) -> Result<Socket, String> {
    let domain = match addr.ip() {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, kind, Some(proto))
        .map_err(|e| format!("cannot create socket for {addr}: {e}"))?;

    if addr.is_ipv6() {
        socket
            .set_only_v6(true)
            .map_err(|e| format!("cannot set IPV6_V6ONLY on {addr}: {e}"))?;
    }
    // Allows a restart to rebind immediately instead of waiting out TIME_WAIT.
    socket
        .set_reuse_address(true)
        .map_err(|e| format!("cannot set SO_REUSEADDR on {addr}: {e}"))?;
    socket
        .set_nonblocking(true)
        .map_err(|e| format!("cannot set O_NONBLOCK on {addr}: {e}"))?;
    socket
        .bind(&addr.into())
        .map_err(|e| bind_error(addr, &e))?;
    Ok(socket)
}

/// Turn a bind failure into something an operator can act on.
fn bind_error(addr: SocketAddr, e: &std::io::Error) -> String {
    let hint = match e.kind() {
        std::io::ErrorKind::PermissionDenied if addr.port() < 1024 => {
            " (binding a port below 1024 needs CAP_NET_BIND_SERVICE, or run with \
             --sysctl net.ipv4.ip_unprivileged_port_start=0, or pick a high port \
             and publish it)"
        }
        std::io::ErrorKind::AddrNotAvailable => {
            " (the address does not exist on this host — a config copied from \
             elsewhere often hardcodes addresses; override with --listen)"
        }
        _ => "",
    };
    format!("cannot bind {addr}: {e}{hint}")
}

/// Bind UDP and TCP for every requested address.
///
/// Must be called from within a Tokio runtime context: registering a socket with
/// the reactor requires one, even though this function is itself synchronous.
///
/// Both transports are always bound: TCP is required for responses that do not
/// fit in a UDP datagram, and the rate limiter deliberately exempts TCP, so it
/// must be available as the fallback path.
pub fn bind_all(listen: &[ListenAddr]) -> Result<Bound, String> {
    let mut bound = Bound {
        udp: Vec::with_capacity(listen.len()),
        tcp: Vec::with_capacity(listen.len()),
        addrs: Vec::with_capacity(listen.len()),
    };

    for target in listen {
        let requested = SocketAddr::new(target.addr, target.port);

        let udp_socket = configure(requested, Type::DGRAM, SockProtocol::UDP)?;
        let udp = UdpSocket::from_std(udp_socket.into())
            .map_err(|e| format!("cannot register UDP socket for {requested}: {e}"))?;
        let actual = udp
            .local_addr()
            .map_err(|e| format!("cannot read local address of {requested}: {e}"))?;

        // Port 0 means "any free port"; the TCP listener must land on the same
        // one the kernel just picked for UDP, not another random port.
        let tcp_target = SocketAddr::new(target.addr, actual.port());
        let tcp_socket = configure(tcp_target, Type::STREAM, SockProtocol::TCP)?;
        tcp_socket
            .listen(TCP_BACKLOG)
            .map_err(|e| format!("cannot listen on {tcp_target}: {e}"))?;
        let tcp = TcpListener::from_std(tcp_socket.into())
            .map_err(|e| format!("cannot register TCP listener for {tcp_target}: {e}"))?;

        bound.udp.push(udp);
        bound.tcp.push(tcp);
        bound.addrs.push(actual);
    }

    Ok(bound)
}

/// The default bind set when neither the config nor the CLI names one.
///
/// Both wildcards, which is what a container almost always wants. `IPV6_V6ONLY`
/// keeps them from colliding.
#[must_use]
pub fn default_listen(port: u16) -> Vec<ListenAddr> {
    vec![
        ListenAddr {
            addr: IpAddr::from([0, 0, 0, 0]),
            port,
        },
        ListenAddr {
            addr: IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 0]),
            port,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn binds_ephemeral_and_reports_the_real_port() {
        let listen = vec![ListenAddr {
            addr: IpAddr::from([127, 0, 0, 1]),
            port: 0,
        }];
        let bound = bind_all(&listen).expect("loopback bind must work");
        assert_eq!(bound.addrs.len(), 1);
        assert_ne!(bound.addrs[0].port(), 0, "must report the assigned port");
        // UDP and TCP must agree, or clients that retry over TCP break.
        let tcp_port = bound.tcp[0].local_addr().expect("tcp addr").port();
        assert_eq!(bound.addrs[0].port(), tcp_port);
    }

    /// Both wildcards on the same port must coexist; this is what `IPV6_V6ONLY`
    /// buys, and it is the default container configuration.
    #[tokio::test]
    async fn both_wildcards_can_share_a_port() {
        let probe = bind_all(&[ListenAddr {
            addr: IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 0]),
            port: 0,
        }])
        .expect("v6 wildcard bind");
        let port = probe.addrs[0].port();
        drop(probe);

        match bind_all(&default_listen(port)) {
            Ok(bound) => assert_eq!(bound.addrs.len(), 2),
            // A port can be taken between the probe and the retry; that is a
            // flaky environment, not a failure of the code under test.
            Err(e) => assert!(e.contains("cannot bind"), "unexpected error: {e}"),
        }
    }

    #[test]
    fn privileged_port_error_is_actionable() {
        let err = bind_error(
            "0.0.0.0:53".parse().expect("literal"),
            &std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        assert!(err.contains("CAP_NET_BIND_SERVICE"), "{err}");
    }

    #[test]
    fn missing_address_error_mentions_the_listen_override() {
        let err = bind_error(
            "192.0.2.99:53".parse().expect("literal"),
            &std::io::Error::from(std::io::ErrorKind::AddrNotAvailable),
        );
        assert!(err.contains("--listen"), "{err}");
    }
}
