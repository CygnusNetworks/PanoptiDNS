//! PanoptiDNS binary: CLI, process lifecycle and signal handling.

use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use clap::Parser;
use panoptidns::config::{Config, ConfigErrors, ListenAddr, DEFAULT_PORT};
use panoptidns::rrl::Rrl;
use panoptidns::server::bind::{self, bind_all};
use panoptidns::server::{Handler, Zones};
use tokio::signal::unix::{signal, SignalKind};

const DEFAULT_CONFIG: &str = "/etc/panoptidns/panoptidns.conf";

/// How long a TCP connection may idle before it is closed.
const TCP_IDLE: Duration = Duration::from_secs(5);
/// Per-connection outgoing buffer.
const TCP_RESPONSE_BUFFER: usize = 4096;
/// How often rate-limit buckets for quiet clients are discarded.
const RRL_SWEEP_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Parser, Debug)]
#[command(
    name = "panoptidns",
    version,
    about = "Authoritative DNS server that synthesizes IPv6 reverse (PTR) and forward (AAAA) records on the fly",
    long_about = None
)]
struct Cli {
    /// Path to the configuration file.
    #[arg(short, long, default_value = DEFAULT_CONFIG, env = "PANOPTIDNS_CONFIG")]
    config: PathBuf,

    /// Validate the configuration and exit. Prints every problem it finds.
    #[arg(long)]
    check_config: bool,

    /// Address to listen on, repeatable. Overrides `listen` in the config
    /// entirely — a config copied from a physical host usually names addresses
    /// that do not exist inside a container.
    #[arg(short, long, env = "PANOPTIDNS_LISTEN", value_delimiter = ',')]
    listen: Vec<String>,

    /// Log every query. Intended for debugging, not production.
    #[arg(long, env = "PANOPTIDNS_QUERYLOG")]
    querylog: bool,

    /// Emit logs as JSON instead of human-readable text.
    #[arg(long, env = "PANOPTIDNS_LOG_JSON")]
    log_json: bool,

    /// Send a real query to a running instance and exit 0 if it answers.
    /// Used as the container health check, since distroless has no shell.
    #[arg(long)]
    healthcheck: bool,

    /// Port the health check queries.
    #[arg(long, default_value_t = DEFAULT_PORT)]
    healthcheck_port: u16,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(&cli);

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            // Config diagnostics are already multi-line and self-describing, so
            // they are printed as-is rather than wrapped in another prefix.
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn init_logging(cli: &Cli) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("PANOPTIDNS_LOG")
        .unwrap_or_else(|_| EnvFilter::new(if cli.querylog { "info" } else { "warn" }));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if cli.log_json {
        builder.json().init();
    } else {
        builder.init();
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start the async runtime: {e}"))?;

    if cli.healthcheck {
        return runtime.block_on(healthcheck(cli.healthcheck_port));
    }

    let config = load_config(&cli.config)?;

    if cli.check_config {
        for warning in config.warnings() {
            eprintln!("warning: {warning}");
        }
        println!(
            "{}: OK — {} zone(s), {} listen address(es)",
            cli.config.display(),
            config.zones.len(),
            config.listen.len()
        );
        return Ok(());
    }

    runtime.block_on(serve(cli, config))
}

fn load_config(path: &Path) -> Result<Config, String> {
    let body =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Config::parse(&body).map_err(|errors: ConfigErrors| errors.with_path(path).to_string())
}

/// Resolve the effective bind set: CLI/env wins over the config file, and if
/// neither says anything we take both wildcards on port 53.
fn effective_listen(cli: &Cli, config: &Config) -> Result<Vec<ListenAddr>, String> {
    if !cli.listen.is_empty() {
        return cli
            .listen
            .iter()
            .map(|s| parse_listen(s.trim()))
            .collect::<Result<Vec<_>, _>>();
    }
    if !config.listen.is_empty() {
        return Ok(config.listen.clone());
    }
    Ok(bind::default_listen(DEFAULT_PORT))
}

fn parse_listen(s: &str) -> Result<ListenAddr, String> {
    if let Ok(sock) = SocketAddr::from_str(s) {
        return Ok(ListenAddr {
            addr: sock.ip(),
            port: sock.port(),
        });
    }
    IpAddr::from_str(s)
        .map(|addr| ListenAddr {
            addr,
            port: DEFAULT_PORT,
        })
        .map_err(|_| format!("--listen {s}: not an IP address or address:port"))
}

async fn serve(cli: Cli, config: Config) -> Result<(), String> {
    for warning in config.warnings() {
        tracing::warn!("{warning}");
    }

    let listen = effective_listen(&cli, &config)?;
    let rrl_params = config.params.rrl;
    let zones = Arc::new(ArcSwap::from_pointee(Zones::new(config)?));
    let rrl = Arc::new(Rrl::new(rrl_params));

    // Bind before anything else that can fail, so a permission problem is
    // reported immediately rather than after the server looks started.
    let bound = bind_all(&listen)?;
    for addr in &bound.addrs {
        tracing::info!(%addr, "listening (UDP and TCP)");
    }
    if rrl.enabled() {
        tracing::info!(
            responses_per_second = rrl_params.responses_per_second,
            burst = rrl_params.burst,
            slip = rrl_params.slip,
            "response rate limiting active"
        );
    }

    let handler = Handler::new(Arc::clone(&zones), Arc::clone(&rrl), cli.querylog);
    let mut server = hickory_server::server::Server::new(handler);
    for socket in bound.udp {
        server.register_socket(socket);
    }
    for listener in bound.tcp {
        server.register_listener(listener, TCP_IDLE, TCP_RESPONSE_BUFFER);
    }

    // `governor`'s keyed store grows unbounded between sweeps, so this task is
    // what actually bounds the limiter's memory.
    let sweeper = tokio::spawn({
        let rrl = Arc::clone(&rrl);
        async move {
            let mut ticker = tokio::time::interval(RRL_SWEEP_INTERVAL);
            loop {
                ticker.tick().await;
                rrl.sweep();
            }
        }
    });

    let reloader = tokio::spawn({
        let zones = Arc::clone(&zones);
        let path = cli.config.clone();
        async move {
            let Ok(mut hup) = signal(SignalKind::hangup()) else {
                tracing::warn!("cannot install SIGHUP handler; reload unavailable");
                return;
            };
            while hup.recv().await.is_some() {
                match load_config(&path).and_then(Zones::new) {
                    Ok(next) => {
                        for warning in next.config.warnings() {
                            tracing::warn!("{warning}");
                        }
                        // Note: `listen` changes are ignored on reload; the
                        // sockets are already bound. Restart to change them.
                        zones.store(Arc::new(next));
                        tracing::info!("configuration reloaded");
                    }
                    // Keeping the old config running is the only safe choice: a
                    // typo must not take the service down.
                    Err(e) => tracing::error!("reload failed, keeping previous config:\n{e}"),
                }
            }
        }
    });

    let mut term = signal(SignalKind::terminate())
        .map_err(|e| format!("cannot install SIGTERM handler: {e}"))?;
    let mut int = signal(SignalKind::interrupt())
        .map_err(|e| format!("cannot install SIGINT handler: {e}"))?;

    let outcome = tokio::select! {
        result = server.block_until_done() => {
            result.map_err(|e| format!("server stopped: {e}"))
        }
        _ = term.recv() => {
            tracing::info!("SIGTERM received, shutting down");
            Ok(())
        }
        _ = int.recv() => {
            tracing::info!("SIGINT received, shutting down");
            Ok(())
        }
    };

    sweeper.abort();
    reloader.abort();
    let _ = server.shutdown_gracefully().await;
    outcome
}

/// Query a locally running instance, for the container health check.
///
/// Distroless images have no shell, so the health check has to live in the
/// binary. Asking for the SOA of a configured apex would need the config; instead
/// this sends a deliberately out-of-zone query, because *any* well-formed
/// response — including REFUSED — proves the server is answering.
async fn healthcheck(port: u16) -> Result<(), String> {
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::domain::Name;
    use hickory_proto::rr::{DNSClass, RecordType};
    use hickory_proto::serialize::binary::BinEncodable;
    use tokio::net::UdpSocket;

    let name = Name::from_ascii("health-check.panoptidns.invalid.")
        .map_err(|e| format!("cannot build health-check name: {e}"))?;
    let mut query = Query::new();
    query.set_name(name);
    query.set_query_type(RecordType::SOA);
    query.set_query_class(DNSClass::IN);

    let mut message = Message::query();
    message.add_query(query);
    let bytes = message
        .to_bytes()
        .map_err(|e| format!("cannot encode health-check query: {e}"))?;

    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("health check cannot bind a socket: {e}"))?;
    socket
        .send_to(&bytes, ("127.0.0.1", port))
        .await
        .map_err(|e| format!("health check cannot send: {e}"))?;

    let mut buf = [0u8; 512];
    match tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) if len > 0 => Ok(()),
        Ok(Ok(_)) => Err("health check got an empty response".to_string()),
        Ok(Err(e)) => Err(format!("health check receive failed: {e}")),
        Err(_) => Err("health check timed out".to_string()),
    }
}
