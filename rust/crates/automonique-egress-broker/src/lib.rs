// SPDX-License-Identifier: Elastic-2.0

//! A loopback `CONNECT` proxy that lets a contained workload reach an
//! allowlisted destination and nothing else.
//!
//! # What problem this solves
//!
//! A provider process has to reach its model endpoint. The runner's sandbox
//! denies the network, so the pre-broker live-provider path relaxed it twice:
//! it granted the workload TCP sockets with `connect` to port 443 *on any
//! address*, and it granted UDP sockets so the workload's own resolver could do
//! DNS — which nothing in the sandbox bounds. Those two grants are the entire
//! network exposure of a contained run, and the second one is unbounded egress
//! wearing a resolver's clothes.
//!
//! This crate removes both. The broker runs **outside** the sandbox, holds the
//! allowlist, does the resolution, and makes the outbound connection. The
//! workload is pointed at it with `HTTPS_PROXY=http://127.0.0.1:<port>` and
//! keeps exactly one network capability: a TCP `connect` to that one loopback
//! port.
//!
//! ## The launch policy this enables
//!
//! ```text
//! LaunchPlan::new(provider_binary)?
//!     .socket_grant(SocketGrant::Tcp)?              // create TCP sockets
//!     .socket_grant(SocketGrant::Unix)?             // the async runtime's self-pipe
//!     .allow_connect_port(broker.local_addr().port())?
//!     .environment("HTTPS_PROXY", &broker.proxy_url())?
//!     .environment("HTTP_PROXY", &broker.proxy_url())?
//! ```
//!
//! Against the pre-broker relaxation this drops, in order of how much they
//! mattered:
//!
//! - **`SocketGrant::InetDatagram` is gone.** The workload can no longer create
//!   a UDP socket at all, so it cannot send a datagram anywhere — not to a
//!   nameserver, not to anything else. This was the only grant the sandbox
//!   could not bound.
//! - **`allow_connect_port(443)` is gone.** No grant remains that names a
//!   port anyone else is listening on.
//! - **The resolver's files are no longer granted.** With no DNS to do, the
//!   workload needs neither `/etc/resolv.conf` nor `/etc/hosts` in its
//!   filesystem allowlist.
//!
//! What the workload keeps is `SocketGrant::Tcp` plus one `connect` port. The
//! CA trust store grant stays, and must: the broker does not terminate TLS, so
//! the workload validates the destination's real certificate itself.
//!
//! ## The honest limit: Landlock scopes ports, not addresses
//!
//! `allow_connect_port(P)` permits `connect` to port `P` **on every address the
//! workload can route to**, because a Landlock network rule names a port and
//! nothing else. No released Landlock ABI adds an address-scoped network rule;
//! ABI 4's per-port `bind`/`connect` rules are the whole network surface, and
//! ABI 5 through 9 add nothing to it. So this is not "the workload can only
//! reach the broker" — it is "the workload can only reach port `P`, anywhere."
//!
//! Three things narrow that in practice, and none of them is the kernel:
//!
//! - The broker binds a **kernel-assigned ephemeral port on `127.0.0.1`**, so
//!   `P` is unpredictable and is not a port a public service listens on.
//! - The workload has **no way to resolve a name** (no UDP grant), so to reach
//!   port `P` off-host it would need an IP literal it already knows.
//! - The plan grants no `bind` port, so the workload **cannot listen on `P`**
//!   itself and impersonate the broker for anything else on the host.
//!
//! Closing it properly needs a mechanism Landlock does not have: an unrouted
//! network namespace, or a cgroup-attached BPF egress hook. Both need
//! privileges this control plane does not assume. Until one of those is
//! available this residual is real, and it is stated here rather than papered
//! over.
//!
//! # What the broker does and does not see
//!
//! It sees the `CONNECT` line — a host and a port — and after that, ciphertext.
//! It does not terminate TLS, mint certificates, or hold a trust root, so it
//! cannot read, alter, or record request contents even by mistake; a change
//! that made it able to would announce itself as this crate acquiring a TLS
//! dependency. It has no logging surface at all: what an operator can learn
//! from it is [`BrokerStats`], which is counters.
//!
//! # No proxy authentication, deliberately
//!
//! The listener is loopback-only, so its reachable set is processes on this
//! host. A local process that is *not* contained already has unrestricted
//! egress and gains nothing from a proxy that only reaches the allowlist; a
//! local process that *is* contained is the one being confined. A shared secret
//! would therefore add no confinement, and delivering one to the workload means
//! putting it in the process environment — readable from `/proc/<pid>/environ`
//! by every same-uid process, which is exactly the leak the runner's admission
//! surface refuses credentials over. So there is none.
//!
//! # Fail closed
//!
//! Every refusal path answers a status and closes. A destination that is not on
//! the allowlist is never resolved and never dialled; a request the parser
//! cannot read exactly is never acted on; a configuration the broker cannot
//! honour is refused at [`EgressBroker::start`] rather than started weaker than
//! asked for.

pub mod allowlist;
pub mod relay;
pub mod request;

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub use allowlist::{
    AddressScope, Destination, DestinationAllowlist, DestinationError, DestinationHost,
};
pub use relay::RelayOutcome;
pub use request::{ConnectRequest, RequestError};

/// The environment variables that point a workload at the broker.
///
/// Both are set to the same URL. This is the pair that was observed to work
/// against the real provider: its websocket transport and its HTTPS transport
/// both tunnel through `HTTPS_PROXY`, and `HTTP_PROXY` covers a plaintext
/// request the broker will refuse anyway (it answers only `CONNECT`), so
/// setting it turns an unproxied plaintext call into a visible refusal rather
/// than a direct connection attempt.
pub const PROXY_ENVIRONMENT_NAMES: [&str; 2] = ["HTTPS_PROXY", "HTTP_PROXY"];

/// Hard ceiling on concurrent tunnels, whatever a configuration asks for.
pub const MAX_CONNECTION_LIMIT: usize = 64;

/// Most resolved addresses tried for one destination before giving up.
pub const MAX_RESOLVED_ADDRESSES: usize = 4;

/// Longest any configurable deadline may be.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(3600);

/// How often the accept loop checks for shutdown while idle.
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Why a broker could not be configured or started.
#[derive(Debug)]
pub enum BrokerError {
    /// A connection limit of zero, or above [`MAX_CONNECTION_LIMIT`].
    ConnectionLimitRejected(usize),
    /// A zero or over-long deadline. A zero timeout means "never block" to the
    /// kernel, which would turn every deadline into a busy failure.
    TimeoutRejected(Duration),
    /// The loopback listener could not be bound.
    ListenerRefused(std::io::Error),
}

impl fmt::Display for BrokerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionLimitRejected(limit) => write!(
                formatter,
                "a connection limit of {limit} is outside 1..={MAX_CONNECTION_LIMIT}"
            ),
            Self::TimeoutRejected(timeout) => write!(
                formatter,
                "a timeout of {timeout:?} is outside 1ms..={MAX_TIMEOUT:?}"
            ),
            Self::ListenerRefused(error) => {
                write!(formatter, "the loopback listener was refused: {error}")
            }
        }
    }
}

impl std::error::Error for BrokerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ListenerRefused(error) => Some(error),
            _ => None,
        }
    }
}

/// What one broker will permit, how many tunnels at once, and every deadline.
///
/// The default denies everything: an allowlist must be supplied deliberately.
#[derive(Clone, Debug)]
pub struct BrokerConfig {
    allowlist: DestinationAllowlist,
    port: u16,
    max_connections: usize,
    head_timeout: Duration,
    connect_timeout: Duration,
    idle_timeout: Duration,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            allowlist: DestinationAllowlist::deny_all(),
            port: 0,
            max_connections: 8,
            head_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            // Long enough for a streaming model response between chunks, which
            // is the tunnel shape this exists for.
            idle_timeout: Duration::from_secs(300),
        }
    }
}

impl BrokerConfig {
    /// A configuration permitting `allowlist` and using the default bounds.
    #[must_use]
    pub fn new(allowlist: DestinationAllowlist) -> Self {
        Self {
            allowlist,
            ..Self::default()
        }
    }

    /// Bind a fixed loopback port instead of a kernel-assigned one.
    ///
    /// The default (`0`) is the better choice: an unpredictable port is one of
    /// the few things narrowing Landlock's port-scoped `connect` grant. A fixed
    /// port exists for a deployment that must know the number in advance.
    #[must_use]
    pub const fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Cap concurrent tunnels. Beyond it, new clients are answered `503`.
    #[must_use]
    pub const fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// How long a client may take to send its `CONNECT` head.
    #[must_use]
    pub const fn with_head_timeout(mut self, timeout: Duration) -> Self {
        self.head_timeout = timeout;
        self
    }

    /// How long one dial to one resolved address may take.
    #[must_use]
    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// How long either side of an established tunnel may be silent.
    #[must_use]
    pub const fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// The destinations this configuration permits.
    #[must_use]
    pub fn allowlist(&self) -> &DestinationAllowlist {
        &self.allowlist
    }

    fn validate(&self) -> Result<(), BrokerError> {
        if self.max_connections == 0 || self.max_connections > MAX_CONNECTION_LIMIT {
            return Err(BrokerError::ConnectionLimitRejected(self.max_connections));
        }
        for timeout in [self.head_timeout, self.connect_timeout, self.idle_timeout] {
            if timeout < Duration::from_millis(1) || timeout > MAX_TIMEOUT {
                return Err(BrokerError::TimeoutRejected(timeout));
            }
        }
        Ok(())
    }
}

/// A point-in-time reading of a broker's counters.
///
/// Counters and byte totals only. There is deliberately no surface here that
/// could carry a host name, a request, or any tunnelled byte.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BrokerStats {
    /// Client connections accepted.
    pub accepted: u64,
    /// Tunnels that reached the relay.
    pub established: u64,
    /// Requests refused because the destination was not allowlisted.
    pub denied_destination: u64,
    /// Requests refused because the destination resolved outside its scope.
    pub denied_scope: u64,
    /// Requests refused because they could not be parsed, or never arrived.
    pub refused_malformed: u64,
    /// Clients refused because the connection limit was reached.
    pub refused_saturated: u64,
    /// Allowlisted destinations that could not be resolved or dialled.
    pub destination_unreachable: u64,
    /// Bytes relayed towards destinations.
    pub bytes_to_destination: u64,
    /// Bytes relayed towards clients.
    pub bytes_to_client: u64,
}

#[derive(Default)]
struct Counters {
    accepted: AtomicU64,
    established: AtomicU64,
    denied_destination: AtomicU64,
    denied_scope: AtomicU64,
    refused_malformed: AtomicU64,
    refused_saturated: AtomicU64,
    destination_unreachable: AtomicU64,
    bytes_to_destination: AtomicU64,
    bytes_to_client: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> BrokerStats {
        BrokerStats {
            accepted: self.accepted.load(Ordering::Relaxed),
            established: self.established.load(Ordering::Relaxed),
            denied_destination: self.denied_destination.load(Ordering::Relaxed),
            denied_scope: self.denied_scope.load(Ordering::Relaxed),
            refused_malformed: self.refused_malformed.load(Ordering::Relaxed),
            refused_saturated: self.refused_saturated.load(Ordering::Relaxed),
            destination_unreachable: self.destination_unreachable.load(Ordering::Relaxed),
            bytes_to_destination: self.bytes_to_destination.load(Ordering::Relaxed),
            bytes_to_client: self.bytes_to_client.load(Ordering::Relaxed),
        }
    }
}

/// The sockets of one in-flight connection, so a shutdown can reach them.
struct LiveConnection {
    client: TcpStream,
    destination: Option<TcpStream>,
}

#[derive(Default)]
struct LiveConnections {
    next_id: u64,
    open: BTreeMap<u64, LiveConnection>,
}

struct Shared {
    config: BrokerConfig,
    counters: Counters,
    live: Mutex<LiveConnections>,
    stopping: AtomicBool,
}

impl Shared {
    /// Take a connection slot, or `None` when saturated or shutting down.
    ///
    /// The cap is enforced here, while the map lock is held, so it is a real
    /// bound rather than a racy check.
    fn register(self: &Arc<Self>, client: &TcpStream) -> Option<ConnectionSlot> {
        let mut live = self.live.lock().ok()?;
        if self.stopping.load(Ordering::SeqCst) || live.open.len() >= self.config.max_connections {
            return None;
        }
        let client = client.try_clone().ok()?;
        let id = live.next_id;
        live.next_id += 1;
        live.open.insert(
            id,
            LiveConnection {
                client,
                destination: None,
            },
        );
        Some(ConnectionSlot {
            shared: Arc::clone(self),
            id,
        })
    }

    fn stop_all(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        if let Ok(live) = self.live.lock() {
            for connection in live.open.values() {
                let _ = connection.client.shutdown(Shutdown::Both);
                if let Some(destination) = &connection.destination {
                    let _ = destination.shutdown(Shutdown::Both);
                }
            }
        }
    }
}

/// A registered connection; deregisters itself when the handler ends.
struct ConnectionSlot {
    shared: Arc<Shared>,
    id: u64,
}

impl ConnectionSlot {
    /// Record the destination socket so a shutdown can tear it down too.
    fn attach_destination(&self, destination: &TcpStream) {
        if let (Ok(mut live), Ok(clone)) = (self.shared.live.lock(), destination.try_clone())
            && let Some(connection) = live.open.get_mut(&self.id)
        {
            connection.destination = Some(clone);
        }
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        if let Ok(mut live) = self.shared.live.lock() {
            live.open.remove(&self.id);
        }
    }
}

/// A running broker.
///
/// Starting one binds the listener and returns once the port is known, so a
/// caller can put the port into a launch plan without racing the accept loop.
/// Dropping one stops it.
pub struct EgressBroker {
    local_addr: SocketAddr,
    shared: Arc<Shared>,
    accept_thread: Mutex<Option<JoinHandle<()>>>,
}

impl fmt::Debug for EgressBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EgressBroker")
            .field("local_addr", &self.local_addr)
            .field("allowlist", &self.shared.config.allowlist)
            .field("stats", &self.shared.counters.snapshot())
            .finish()
    }
}

impl EgressBroker {
    /// Bind the loopback listener and start accepting.
    ///
    /// The bind address is `127.0.0.1`, always: it is not configurable, because
    /// a broker reachable from off-host is an open relay to the allowlist and
    /// there is no deployment of this crate that wants one.
    pub fn start(config: BrokerConfig) -> Result<Self, BrokerError> {
        config.validate()?;
        let listener = TcpListener::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            config.port,
        ))
        .map_err(BrokerError::ListenerRefused)?;
        let local_addr = listener
            .local_addr()
            .map_err(BrokerError::ListenerRefused)?;
        listener
            .set_nonblocking(true)
            .map_err(BrokerError::ListenerRefused)?;

        let shared = Arc::new(Shared {
            config,
            counters: Counters::default(),
            live: Mutex::new(LiveConnections::default()),
            stopping: AtomicBool::new(false),
        });
        let accept_shared = Arc::clone(&shared);
        let accept_thread = thread::spawn(move || accept_loop(&listener, &accept_shared));
        Ok(Self {
            local_addr,
            shared,
            accept_thread: Mutex::new(Some(accept_thread)),
        })
    }

    /// The bound loopback address. Its port is what a launch plan grants.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The value for [`PROXY_ENVIRONMENT_NAMES`].
    #[must_use]
    pub fn proxy_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.local_addr.port())
    }

    /// The counters as they stand.
    #[must_use]
    pub fn stats(&self) -> BrokerStats {
        self.shared.counters.snapshot()
    }

    /// The destinations this broker permits.
    #[must_use]
    pub fn allowlist(&self) -> &DestinationAllowlist {
        &self.shared.config.allowlist
    }

    /// Stop accepting, tear down every in-flight tunnel, and wait for the
    /// threads to finish. Idempotent; [`Drop`] calls it.
    pub fn shutdown(&self) {
        self.shared.stop_all();
        let handle = self.accept_thread.lock().ok().and_then(|mut it| it.take());
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}

impl Drop for EgressBroker {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Accept until told to stop, then wait for every handler.
fn accept_loop(listener: &TcpListener, shared: &Arc<Shared>) {
    let mut handlers: Vec<JoinHandle<()>> = Vec::new();
    while !shared.stopping.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((client, peer)) => {
                handlers.retain(|handle| !handle.is_finished());
                let shared = Arc::clone(shared);
                handlers.push(thread::spawn(move || serve(&shared, client, peer)));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            // An accept that fails for any other reason is this listener's
            // problem, not the process's: stop rather than spin.
            Err(_) => break,
        }
    }
    for handle in handlers {
        let _ = handle.join();
    }
}

/// One HTTP status this broker can answer with. There is no variant carrying a
/// body or a reason string built from the request: nothing a client sent is
/// ever echoed back to it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Refusal {
    BadRequest,
    Forbidden,
    RequestTimeout,
    BadGateway,
    ServiceUnavailable,
}

impl Refusal {
    const fn status_line(self) -> &'static str {
        match self {
            Self::BadRequest => "HTTP/1.1 400 Bad Request\r\n",
            Self::Forbidden => "HTTP/1.1 403 Forbidden\r\n",
            Self::RequestTimeout => "HTTP/1.1 408 Request Timeout\r\n",
            Self::BadGateway => "HTTP/1.1 502 Bad Gateway\r\n",
            Self::ServiceUnavailable => "HTTP/1.1 503 Service Unavailable\r\n",
        }
    }
}

/// Answer a refusal and close. Bounded by a write deadline so a client that
/// never reads cannot hold the handler open.
fn refuse(client: &TcpStream, refusal: Refusal, deadline: Duration) {
    let _ = client.set_write_timeout(Some(deadline));
    let mut sink = client;
    let _ = sink.write_all(refusal.status_line().as_bytes());
    let _ = sink.write_all(b"Content-Length: 0\r\nConnection: close\r\n\r\n");
    let _ = sink.flush();
    let _ = client.shutdown(Shutdown::Both);
}

/// Serve one client connection from accept to tunnel teardown.
fn serve(shared: &Arc<Shared>, client: TcpStream, peer: SocketAddr) {
    let config = &shared.config;
    shared.counters.accepted.fetch_add(1, Ordering::Relaxed);

    // The listener is bound to loopback, so this cannot fire; it is kept as a
    // standing assertion rather than a comment, because "the bind address is
    // loopback" is the whole reason no proxy authentication is needed.
    if !peer.ip().is_loopback() {
        shared
            .counters
            .denied_destination
            .fetch_add(1, Ordering::Relaxed);
        refuse(&client, Refusal::Forbidden, config.head_timeout);
        return;
    }

    // Registered before the head is read, so slow-head clients are inside the
    // connection cap rather than outside it.
    let Some(slot) = shared.register(&client) else {
        shared
            .counters
            .refused_saturated
            .fetch_add(1, Ordering::Relaxed);
        refuse(&client, Refusal::ServiceUnavailable, config.head_timeout);
        return;
    };

    let read = match request::read_request(&client, config.head_timeout) {
        Ok(read) => read,
        Err(error) => {
            shared
                .counters
                .refused_malformed
                .fetch_add(1, Ordering::Relaxed);
            let refusal = match error {
                RequestError::HeadTimedOut => Refusal::RequestTimeout,
                _ => Refusal::BadRequest,
            };
            refuse(&client, refusal, config.head_timeout);
            return;
        }
    };

    // The allowlist decision happens here, before any resolution and any dial:
    // a destination that is not permitted produces no packet of any kind.
    let Some(destination) = config
        .allowlist
        .permits(read.request.host(), read.request.port())
    else {
        shared
            .counters
            .denied_destination
            .fetch_add(1, Ordering::Relaxed);
        refuse(&client, Refusal::Forbidden, config.head_timeout);
        return;
    };

    let addresses = match resolve(destination) {
        Ok(addresses) if !addresses.is_empty() => addresses,
        _ => {
            shared
                .counters
                .destination_unreachable
                .fetch_add(1, Ordering::Relaxed);
            refuse(&client, Refusal::BadGateway, config.head_timeout);
            return;
        }
    };
    let in_scope: Vec<SocketAddr> = addresses
        .into_iter()
        .filter(|address| destination.scope().permits(address.ip()))
        .collect();
    if in_scope.is_empty() {
        shared.counters.denied_scope.fetch_add(1, Ordering::Relaxed);
        refuse(&client, Refusal::Forbidden, config.head_timeout);
        return;
    }

    let Some(upstream) = dial(&in_scope, config.connect_timeout) else {
        shared
            .counters
            .destination_unreachable
            .fetch_add(1, Ordering::Relaxed);
        refuse(&client, Refusal::BadGateway, config.head_timeout);
        return;
    };
    slot.attach_destination(&upstream);

    if relay::install_deadlines(&client, &upstream, config.idle_timeout).is_err() {
        // A tunnel whose deadline could not be installed is a tunnel that can
        // hang, so it is refused rather than run unbounded.
        shared
            .counters
            .destination_unreachable
            .fetch_add(1, Ordering::Relaxed);
        refuse(&client, Refusal::BadGateway, config.head_timeout);
        return;
    }

    let _ = client.set_write_timeout(Some(config.head_timeout));
    let mut sink = &client;
    if sink
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }
    // Bytes the client pipelined behind its head belong to the destination and
    // must arrive before anything the relay carries.
    let mut upstream_sink = &upstream;
    if !read.early_data.is_empty() && upstream_sink.write_all(&read.early_data).is_err() {
        return;
    }
    let early = read.early_data.len() as u64;

    shared.counters.established.fetch_add(1, Ordering::Relaxed);
    if let Ok(outcome) = relay::relay(client, upstream) {
        shared
            .counters
            .bytes_to_destination
            .fetch_add(outcome.to_destination + early, Ordering::Relaxed);
        shared
            .counters
            .bytes_to_client
            .fetch_add(outcome.to_client, Ordering::Relaxed);
    }
}

/// Resolve a destination to at most [`MAX_RESOLVED_ADDRESSES`] addresses.
///
/// An IP-literal destination is returned as written and never reaches the
/// resolver — so a literal destination can be neither rebound nor delayed by
/// one. A named destination goes through the platform resolver, which is the
/// one wait in this crate that carries **no deadline of its own**: the standard
/// library exposes no timeout on name resolution, so a stuck resolver is
/// bounded by the system's own resolver configuration and, here, by the
/// connection cap that limits how many handlers can be waiting on it at once.
/// That is stated rather than fixed, because fixing it means either a resolver
/// dependency or a thread that outlives its request.
fn resolve(destination: &Destination) -> std::io::Result<Vec<SocketAddr>> {
    match destination.host() {
        DestinationHost::Address(address) => {
            Ok(vec![SocketAddr::new(*address, destination.port())])
        }
        DestinationHost::Name(name) => Ok((name.as_str(), destination.port())
            .to_socket_addrs()?
            .take(MAX_RESOLVED_ADDRESSES)
            .collect()),
    }
}

/// Dial the first address that answers within `timeout`.
///
/// The deadline is per address, and at most [`MAX_RESOLVED_ADDRESSES`] are
/// tried, so the worst case is bounded by their product rather than unbounded.
fn dial(addresses: &[SocketAddr], timeout: Duration) -> Option<TcpStream> {
    addresses
        .iter()
        .find_map(|address| TcpStream::connect_timeout(address, timeout).ok())
}

#[cfg(test)]
mod tests {
    use super::{
        AddressScope, BrokerConfig, BrokerError, Destination, DestinationAllowlist, EgressBroker,
        MAX_CONNECTION_LIMIT, MAX_RESOLVED_ADDRESSES, MAX_TIMEOUT, resolve,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn a_broker_binds_loopback_and_reports_the_port_a_launch_plan_needs() {
        let broker = EgressBroker::start(BrokerConfig::default()).unwrap();
        assert_eq!(broker.local_addr().ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(broker.local_addr().port(), 0);
        assert_eq!(
            broker.proxy_url(),
            format!("http://127.0.0.1:{}", broker.local_addr().port())
        );
        assert_eq!(broker.stats(), super::BrokerStats::default());
    }

    #[test]
    fn a_default_broker_permits_nothing() {
        let broker = EgressBroker::start(BrokerConfig::default()).unwrap();
        assert!(broker.allowlist().denies_everything());
    }

    #[test]
    fn a_configuration_the_broker_cannot_honour_is_refused_before_it_binds() {
        let rejected = [0, MAX_CONNECTION_LIMIT + 1];
        for limit in rejected {
            let error = EgressBroker::start(BrokerConfig::default().with_max_connections(limit))
                .unwrap_err();
            assert!(matches!(error, BrokerError::ConnectionLimitRejected(_)));
        }
        for timeout in [Duration::ZERO, MAX_TIMEOUT + Duration::from_secs(1)] {
            for configure in [
                BrokerConfig::with_head_timeout,
                BrokerConfig::with_connect_timeout,
                BrokerConfig::with_idle_timeout,
            ] {
                let error =
                    EgressBroker::start(configure(BrokerConfig::default(), timeout)).unwrap_err();
                assert!(matches!(error, BrokerError::TimeoutRejected(_)));
            }
        }
    }

    #[test]
    fn shutdown_is_idempotent_and_stops_the_listener() {
        let broker = EgressBroker::start(BrokerConfig::default()).unwrap();
        let address = broker.local_addr();
        broker.shutdown();
        broker.shutdown();
        assert!(
            std::net::TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err(),
            "the port must be closed once the broker has stopped"
        );
    }

    #[test]
    fn an_ip_literal_destination_never_reaches_the_resolver() {
        let destination = Destination::new("127.0.0.1", 8443, AddressScope::Loopback).unwrap();
        let addresses = resolve(&destination).unwrap();
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0].port(), 8443);
        assert_eq!(addresses[0].ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn resolution_is_capped_so_one_name_cannot_produce_an_unbounded_dial_list() {
        let destination = Destination::new("localhost", 9, AddressScope::Loopback).unwrap();
        let addresses = resolve(&destination).unwrap();
        assert!(addresses.len() <= MAX_RESOLVED_ADDRESSES);
        assert!(addresses.iter().all(|address| address.ip().is_loopback()));
    }

    #[test]
    fn an_allowlist_is_carried_onto_the_running_broker_unchanged() {
        let allowlist = DestinationAllowlist::deny_all()
            .allowing("chatgpt.com", 443, AddressScope::Public)
            .unwrap();
        let broker = EgressBroker::start(BrokerConfig::new(allowlist.clone())).unwrap();
        assert_eq!(broker.allowlist(), &allowlist);
    }
}
