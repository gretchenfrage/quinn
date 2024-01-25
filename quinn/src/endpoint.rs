use std::{
    collections::VecDeque,
    future::Future,
    io,
    io::IoSliceMut,
    mem::MaybeUninit,
    net::{SocketAddr, SocketAddrV6},
    pin::Pin,
    str,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Instant,
};

use crate::runtime::{default_runtime, AsyncUdpSocket, Runtime};
use bytes::{Bytes, BytesMut};
use pin_project_lite::pin_project;
use proto::{
    self as proto, ClientConfig, ConnectError, ConnectionHandle, DatagramEvent, ServerConfig,
};
use rustc_hash::FxHashMap;
use tokio::sync::{futures::Notified, mpsc, Notify};
use tracing::{Instrument, Span};
use udp::{RecvMeta, BATCH_SIZE};

use crate::{
    connection::Connecting, work_limiter::WorkLimiter, ConnectionEvent, EndpointConfig,
    EndpointEvent, VarInt, IO_LOOP_BOUND, MAX_TRANSMIT_QUEUE_CONTENTS_LEN, RECV_TIME_BOUND,
    SEND_TIME_BOUND,
};

/// A QUIC endpoint.
///
/// An endpoint corresponds to a single UDP socket, may host many connections, and may act as both
/// client and server for different connections.
///
/// May be cloned to obtain another handle to the same endpoint.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub(crate) inner: EndpointRef,
    pub(crate) default_client_config: Option<ClientConfig>,
    runtime: Arc<dyn Runtime>,
}

impl Endpoint {
    /// Helper to construct an endpoint for use with outgoing connections only
    ///
    /// Note that `addr` is the *local* address to bind to, which should usually be a wildcard
    /// address like `0.0.0.0:0` or `[::]:0`, which allow communication with any reachable IPv4 or
    /// IPv6 address respectively from an OS-assigned port.
    ///
    /// Platform defaults for dual-stack sockets vary. For example, any socket bound to a wildcard
    /// IPv6 address on Windows will not by default be able to communicate with IPv4
    /// addresses. Portable applications should bind an address that matches the family they wish to
    /// communicate within.
    #[cfg(feature = "ring")]
    pub fn client(addr: SocketAddr) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(addr)?;
        let runtime = default_runtime()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no async runtime found"))?;
        Self::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            runtime.wrap_udp_socket(socket)?,
            runtime,
        )
    }

    /// Helper to construct an endpoint for use with both incoming and outgoing connections
    ///
    /// Platform defaults for dual-stack sockets vary. For example, any socket bound to a wildcard
    /// IPv6 address on Windows will not by default be able to communicate with IPv4
    /// addresses. Portable applications should bind an address that matches the family they wish to
    /// communicate within.
    #[cfg(feature = "ring")]
    pub fn server(config: ServerConfig, addr: SocketAddr) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(addr)?;
        let runtime = default_runtime()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no async runtime found"))?;
        Self::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(config),
            runtime.wrap_udp_socket(socket)?,
            runtime,
        )
    }

    /// Construct an endpoint with arbitrary configuration and socket
    pub fn new(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: std::net::UdpSocket,
        runtime: Arc<dyn Runtime>,
    ) -> io::Result<Self> {
        let socket = runtime.wrap_udp_socket(socket)?;
        Self::new_with_abstract_socket(config, server_config, socket, runtime)
    }

    /// Construct an endpoint with arbitrary configuration and pre-constructed abstract socket
    ///
    /// Useful when `socket` has additional state (e.g. sidechannels) attached for which shared
    /// ownership is needed.
    pub fn new_with_abstract_socket(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: Arc<dyn AsyncUdpSocket>,
        runtime: Arc<dyn Runtime>,
    ) -> io::Result<Self> {
        let addr = socket.local_addr()?;
        let allow_mtud = !socket.may_fragment();
        let rc = EndpointRef::new(
            socket,
            proto::Endpoint::new(
                Arc::new(config),
                server_config.map(Arc::new),
                allow_mtud,
                None,
            ),
            addr.is_ipv6(),
            runtime.clone(),
        );
        let driver = EndpointDriver(rc.clone());
        runtime.spawn(Box::pin(
            async {
                if let Err(e) = driver.await {
                    tracing::error!("I/O error: {}", e);
                }
            }
            .instrument(Span::current()),
        ));
        Ok(Self {
            inner: rc,
            default_client_config: None,
            runtime,
        })
    }

    /// Get the next incoming connection attempt from a client.
    ///
    /// Yields [`Connecting`] futures that must be `await`ed to obtain the final `Connection`, or
    /// `None` if the endpoint is [`close`](Self::close)d.
    ///
    /// If the server config's retry policy is set to manual, thus causing this method to encounter
    /// an incoming connection attempt which the server has not yet accepted, this method will
    /// simply automatically accept it. See `next_incoming` for an API that allows further
    /// deferring allocation of server resources to incoming connection attempts.
    pub fn accept(&self) -> Accept<'_> {
        Accept {
            endpoint: self,
            notify: self.inner.shared.incoming.notified(),
        }
    }

    /// Get the next incoming connection attempt from a client without the server necessarily
    /// having begun its half of the handshake.
    ///
    /// Yields [`GenericIncoming`] enums. If the server config's retry policy is set to "manual",
    /// these will contain `IncomingConnection`s, which can be used to accept, reject, or retry the
    /// connection attempt.
    ///
    /// This can be useful for increasing the effectiveness of IP blocking against
    /// denial-of-service attacks. If you don't need that, see `accept` for a simpler API.
    pub fn next_incoming(&self) -> NextIncoming<'_> {
        NextIncoming {
            endpoint: self,
            notify: self.inner.shared.incoming.notified(),
        }
    }

    /// Set the client configuration used by `connect`
    pub fn set_default_client_config(&mut self, config: ClientConfig) {
        self.default_client_config = Some(config);
    }

    /// Connect to a remote endpoint
    ///
    /// `server_name` must be covered by the certificate presented by the server. This prevents a
    /// connection from being intercepted by an attacker with a valid certificate for some other
    /// server.
    ///
    /// May fail immediately due to configuration errors, or in the future if the connection could
    /// not be established.
    pub fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<Connecting, ConnectError> {
        let config = match &self.default_client_config {
            Some(config) => config.clone(),
            None => return Err(ConnectError::NoDefaultClientConfig),
        };

        self.connect_with(config, addr, server_name)
    }

    /// Connect to a remote endpoint using a custom configuration.
    ///
    /// See [`connect()`] for details.
    ///
    /// [`connect()`]: Endpoint::connect
    pub fn connect_with(
        &self,
        config: ClientConfig,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<Connecting, ConnectError> {
        let mut endpoint = self.inner.state.lock().unwrap();
        if endpoint.driver_lost {
            return Err(ConnectError::EndpointStopping);
        }
        if addr.is_ipv6() && !endpoint.ipv6 {
            return Err(ConnectError::InvalidRemoteAddress(addr));
        }
        let addr = if endpoint.ipv6 {
            SocketAddr::V6(ensure_ipv6(addr))
        } else {
            addr
        };

        let (ch, conn) = endpoint
            .inner
            .connect(Instant::now(), config, addr, server_name)?;

        let socket = endpoint.socket.clone();
        Ok(endpoint
            .connections
            .insert(ch, conn, socket, self.runtime.clone()))
    }

    /// Switch to a new UDP socket
    ///
    /// Allows the endpoint's address to be updated live, affecting all active connections. Incoming
    /// connections and connections to servers unreachable from the new address will be lost.
    ///
    /// On error, the old UDP socket is retained.
    pub fn rebind(&self, socket: std::net::UdpSocket) -> io::Result<()> {
        let addr = socket.local_addr()?;
        let socket = self.runtime.wrap_udp_socket(socket)?;
        let mut inner = self.inner.state.lock().unwrap();
        inner.socket = socket;
        inner.ipv6 = addr.is_ipv6();

        // Generate some activity so peers notice the rebind
        for sender in inner.connections.senders.values() {
            // Ignoring errors from dropped connections
            let _ = sender.send(ConnectionEvent::Ping);
        }

        Ok(())
    }

    /// Replace the server configuration, affecting new incoming connections only
    ///
    /// Useful for e.g. refreshing TLS certificates without disrupting existing connections.
    pub fn set_server_config(&self, server_config: Option<ServerConfig>) {
        self.inner
            .state
            .lock()
            .unwrap()
            .inner
            .set_server_config(server_config.map(Arc::new))
    }

    /// Get the local `SocketAddr` the underlying socket is bound to
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.state.lock().unwrap().socket.local_addr()
    }

    /// Reject new incoming connections without affecting existing connections
    ///
    /// Convenience short-hand for using
    /// [`set_server_config`](Self::set_server_config) to update
    /// [`concurrent_connections`](ServerConfig::concurrent_connections) to
    /// zero.
    pub fn reject_new_connections(&self) {
        self.inner
            .state
            .lock()
            .unwrap()
            .inner
            .reject_new_connections();
    }

    /// Close all of this endpoint's connections immediately and cease accepting new connections.
    ///
    /// See [`Connection::close()`] for details.
    ///
    /// [`Connection::close()`]: crate::Connection::close
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        let reason = Bytes::copy_from_slice(reason);
        let mut endpoint = self.inner.state.lock().unwrap();
        endpoint.connections.close = Some((error_code, reason.clone()));
        for sender in endpoint.connections.senders.values() {
            // Ignoring errors from dropped connections
            let _ = sender.send(ConnectionEvent::Close {
                error_code,
                reason: reason.clone(),
            });
        }
        self.inner.shared.incoming.notify_waiters();
    }

    /// Wait for all connections on the endpoint to be cleanly shut down
    ///
    /// Waiting for this condition before exiting ensures that a good-faith effort is made to notify
    /// peers of recent connection closes, whereas exiting immediately could force them to wait out
    /// the idle timeout period.
    ///
    /// Does not proactively close existing connections or cause incoming connections to be
    /// rejected. Consider calling [`close()`] if that is desired.
    ///
    /// [`close()`]: Endpoint::close
    pub async fn wait_idle(&self) {
        loop {
            {
                let endpoint = &mut *self.inner.state.lock().unwrap();
                if endpoint.connections.is_empty() {
                    break;
                }
                // Construct future while lock is held to avoid race
                self.inner.shared.idle.notified()
            }
            .await;
        }
    }
}

/// A future that drives IO on an endpoint
///
/// This task functions as the switch point between the UDP socket object and the
/// `Endpoint` responsible for routing datagrams to their owning `Connection`.
/// In order to do so, it also facilitates the exchange of different types of events
/// flowing between the `Endpoint` and the tasks managing `Connection`s. As such,
/// running this task is necessary to keep the endpoint's connections running.
///
/// `EndpointDriver` futures terminate when all clones of the `Endpoint` have been dropped, or when
/// an I/O error occurs.
#[must_use = "endpoint drivers must be spawned for I/O to occur"]
#[derive(Debug)]
pub(crate) struct EndpointDriver(pub(crate) EndpointRef);

impl Future for EndpointDriver {
    type Output = Result<(), io::Error>;

    #[allow(unused_mut)] // MSRV
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let mut endpoint = self.0.state.lock().unwrap();
        if endpoint.driver.is_none() {
            endpoint.driver = Some(cx.waker().clone());
        }

        let now = Instant::now();
        let mut keep_going = false;
        keep_going |= endpoint.drive_recv(cx, now)?;
        keep_going |= endpoint.handle_events(cx, &self.0.shared);
        keep_going |= endpoint.drive_send(cx)?;

        if !endpoint.incoming.is_empty() {
            self.0.shared.incoming.notify_waiters();
        }

        if endpoint.ref_count == 0 && endpoint.connections.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            drop(endpoint);
            // If there is more work to do schedule the endpoint task again.
            // `wake_by_ref()` is called outside the lock to minimize
            // lock contention on a multithreaded runtime.
            if keep_going {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
    }
}

impl Drop for EndpointDriver {
    fn drop(&mut self) {
        let mut endpoint = self.0.state.lock().unwrap();
        endpoint.driver_lost = true;
        self.0.shared.incoming.notify_waiters();
        // Drop all outgoing channels, signaling the termination of the endpoint to the associated
        // connections.
        endpoint.connections.senders.clear();
    }
}

#[derive(Debug)]
pub(crate) struct EndpointInner {
    pub(crate) state: Mutex<State>,
    pub(crate) shared: Shared,
}

#[derive(Debug)]
pub(crate) struct State {
    socket: Arc<dyn AsyncUdpSocket>,
    inner: proto::Endpoint,
    outgoing: VecDeque<udp::Transmit>,
    incoming: VecDeque<PortableGenericIncoming>,
    driver: Option<Waker>,
    ipv6: bool,
    connections: ConnectionSet,
    events: mpsc::UnboundedReceiver<(ConnectionHandle, EndpointEvent)>,
    /// Number of live handles that can be used to initiate or handle I/O; excludes the driver
    ref_count: usize,
    driver_lost: bool,
    recv_limiter: WorkLimiter,
    recv_buf: Box<[u8]>,
    send_limiter: WorkLimiter,
    runtime: Arc<dyn Runtime>,
    /// The aggregateed contents length of the packets in the transmit queue
    transmit_queue_contents_len: usize,
}

#[derive(Debug)]
pub(crate) struct Shared {
    incoming: Notify,
    idle: Notify,
}

impl State {
    fn drive_recv<'a>(&'a mut self, cx: &mut Context, now: Instant) -> Result<bool, io::Error> {
        self.recv_limiter.start_cycle();
        let mut metas = [RecvMeta::default(); BATCH_SIZE];
        let mut iovs = MaybeUninit::<[IoSliceMut<'a>; BATCH_SIZE]>::uninit();
        self.recv_buf
            .chunks_mut(self.recv_buf.len() / BATCH_SIZE)
            .enumerate()
            .for_each(|(i, buf)| unsafe {
                iovs.as_mut_ptr()
                    .cast::<IoSliceMut>()
                    .add(i)
                    .write(IoSliceMut::<'a>::new(buf));
            });
        let mut iovs = unsafe { iovs.assume_init() };
        loop {
            match self.socket.poll_recv(cx, &mut iovs, &mut metas) {
                Poll::Ready(Ok(msgs)) => {
                    self.recv_limiter.record_work(msgs);
                    for (meta, buf) in metas.iter().zip(iovs.iter()).take(msgs) {
                        let mut data: BytesMut = buf[0..meta.len].into();
                        while !data.is_empty() {
                            let buf = data.split_to(meta.stride.min(data.len()));
                            let mut response_buffer = BytesMut::new();
                            // this is where we call that
                            match self.inner.handle(
                                now,
                                meta.addr,
                                meta.dst_ip,
                                meta.ecn.map(proto_ecn),
                                buf,
                                &mut response_buffer,
                            ) {
                                Some(DatagramEvent::NewConnection(handle, conn)) => {
                                    let conn = self.connections.insert(
                                        handle,
                                        conn,
                                        self.socket.clone(),
                                        self.runtime.clone(),
                                    );
                                    self.incoming.push_back(PortableGenericIncoming::Automatic(conn));
                                }
                                Some(DatagramEvent::IncomingConnection(incoming_conn)) => {
                                    self.incoming.push_back(PortableGenericIncoming::Manual {
                                        inner: incoming_conn,
                                        response_buffer,
                                    });
                                }
                                Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                                    // Ignoring errors from dropped connections that haven't yet been cleaned up
                                    let _ = self
                                        .connections
                                        .senders
                                        .get_mut(&handle)
                                        .unwrap()
                                        .send(ConnectionEvent::Proto(event));
                                }
                                Some(DatagramEvent::Response(transmit)) => {
                                    Self::respond(
                                        &mut self.transmit_queue_contents_len,
                                        &mut self.outgoing,
                                        transmit,
                                        response_buffer,
                                    );
                                }
                                None => {}
                            }
                        }
                    }
                }
                Poll::Pending => {
                    break;
                }
                // Ignore ECONNRESET as it's undefined in QUIC and may be injected by an
                // attacker
                Poll::Ready(Err(ref e)) if e.kind() == io::ErrorKind::ConnectionReset => {
                    continue;
                }
                Poll::Ready(Err(e)) => {
                    return Err(e);
                }
            }
            if !self.recv_limiter.allow_work() {
                self.recv_limiter.finish_cycle();
                return Ok(true);
            }
        }

        self.recv_limiter.finish_cycle();
        Ok(false)
    }

    fn respond( // TODO: factor the relevant sub-selves into sub-struct
        transmit_queue_contents_len: &mut usize,
        outgoing: &mut VecDeque<udp::Transmit>,
        transmit: proto::Transmit,
        mut response_buffer: BytesMut,
    ) {
        // Limiting the memory usage for items queued in the outgoing queue from endpoint
        // generated packets. Otherwise, we may see a build-up of the queue under test with
        // flood of initial packets against the endpoint. The sender with the sender-limiter
        // may not keep up the pace of these packets queued into the queue.
        if *transmit_queue_contents_len < MAX_TRANSMIT_QUEUE_CONTENTS_LEN {
            let contents_len = transmit.size;
            outgoing.push_back(udp_transmit(
                transmit,
                response_buffer.split_to(contents_len).freeze(),
            ));
            *transmit_queue_contents_len = transmit_queue_contents_len
                .saturating_add(contents_len);
        }
    }

    fn drive_send(&mut self, cx: &mut Context) -> Result<bool, io::Error> {
        self.send_limiter.start_cycle();

        let result = loop {
            if self.outgoing.is_empty() {
                break Ok(false);
            }

            if !self.send_limiter.allow_work() {
                break Ok(true);
            }

            match self.socket.poll_send(cx, self.outgoing.as_slices().0) {
                Poll::Ready(Ok(n)) => {
                    let contents_len: usize =
                        self.outgoing.drain(..n).map(|t| t.contents.len()).sum();
                    self.transmit_queue_contents_len = self
                        .transmit_queue_contents_len
                        .saturating_sub(contents_len);
                    // We count transmits instead of `poll_send` calls since the cost
                    // of a `sendmmsg` still linearly increases with number of packets.
                    self.send_limiter.record_work(n);
                }
                Poll::Pending => {
                    break Ok(false);
                }
                Poll::Ready(Err(e)) => {
                    break Err(e);
                }
            }
        };

        self.send_limiter.finish_cycle();
        result
    }

    fn handle_events(&mut self, cx: &mut Context, shared: &Shared) -> bool {
        use EndpointEvent::*;
        for _ in 0..IO_LOOP_BOUND {
            match self.events.poll_recv(cx) {
                Poll::Ready(Some((ch, event))) => match event {
                    Proto(e) => {
                        if e.is_drained() {
                            self.connections.senders.remove(&ch);
                            if self.connections.is_empty() {
                                shared.idle.notify_waiters();
                            }
                        }
                        if let Some(event) = self.inner.handle_event(ch, e) {
                            // Ignoring errors from dropped connections that haven't yet been cleaned up
                            let _ = self
                                .connections
                                .senders
                                .get_mut(&ch)
                                .unwrap()
                                .send(ConnectionEvent::Proto(event));
                        }
                    }
                    Transmit(t, buf) => {
                        let contents_len = buf.len();
                        self.outgoing.push_back(udp_transmit(t, buf));
                        self.transmit_queue_contents_len = self
                            .transmit_queue_contents_len
                            .saturating_add(contents_len);
                    }
                },
                Poll::Ready(None) => unreachable!("EndpointInner owns one sender"),
                Poll::Pending => {
                    return false;
                }
            }
        }

        true
    }
}

#[inline]
fn udp_transmit(t: proto::Transmit, buffer: Bytes) -> udp::Transmit {
    udp::Transmit {
        destination: t.destination,
        ecn: t.ecn.map(udp_ecn),
        contents: buffer,
        segment_size: t.segment_size,
        src_ip: t.src_ip,
    }
}

#[inline]
fn udp_ecn(ecn: proto::EcnCodepoint) -> udp::EcnCodepoint {
    match ecn {
        proto::EcnCodepoint::Ect0 => udp::EcnCodepoint::Ect0,
        proto::EcnCodepoint::Ect1 => udp::EcnCodepoint::Ect1,
        proto::EcnCodepoint::Ce => udp::EcnCodepoint::Ce,
    }
}

#[inline]
fn proto_ecn(ecn: udp::EcnCodepoint) -> proto::EcnCodepoint {
    match ecn {
        udp::EcnCodepoint::Ect0 => proto::EcnCodepoint::Ect0,
        udp::EcnCodepoint::Ect1 => proto::EcnCodepoint::Ect1,
        udp::EcnCodepoint::Ce => proto::EcnCodepoint::Ce,
    }
}

#[derive(Debug)]
struct ConnectionSet {
    /// Senders for communicating with the endpoint's connections
    senders: FxHashMap<ConnectionHandle, mpsc::UnboundedSender<ConnectionEvent>>,
    /// Stored to give out clones to new ConnectionInners
    sender: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
    /// Set if the endpoint has been manually closed
    close: Option<(VarInt, Bytes)>,
}

impl ConnectionSet {
    fn insert(
        &mut self,
        handle: ConnectionHandle,
        conn: proto::Connection,
        socket: Arc<dyn AsyncUdpSocket>,
        runtime: Arc<dyn Runtime>,
    ) -> Connecting {
        let (send, recv) = mpsc::unbounded_channel();
        if let Some((error_code, ref reason)) = self.close {
            send.send(ConnectionEvent::Close {
                error_code,
                reason: reason.clone(),
            })
            .unwrap();
        }
        self.senders.insert(handle, send);
        Connecting::new(handle, conn, self.sender.clone(), recv, socket, runtime)
    }

    fn is_empty(&self) -> bool {
        self.senders.is_empty()
    }
}

fn ensure_ipv6(x: SocketAddr) -> SocketAddrV6 {
    match x {
        SocketAddr::V6(x) => x,
        SocketAddr::V4(x) => SocketAddrV6::new(x.ip().to_ipv6_mapped(), x.port(), 0, 0),
    }
}

pin_project! {
    /// Future produced by [`Endpoint::accept`]
    pub struct Accept<'a> {
        endpoint: &'a Endpoint,
        #[pin]
        notify: Notified<'a>,
    }
}

impl<'a> Future for Accept<'a> {
    type Output = Option<Connecting>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let endpoint = &mut *this.endpoint.inner.state.lock().unwrap();
        loop {
            if endpoint.driver_lost {
                return Poll::Ready(None);
            }
            if let Some(gen_incoming) = endpoint.incoming.pop_front() {
                match gen_incoming.with_endpoint(this.endpoint) {
                    GenericIncoming::Automatic(conn) => {
                        return Poll::Ready(Some(conn));
                    },
                    GenericIncoming::Manual(incoming_conn) => {
                        if let Some(conn) = incoming_conn.accept() {
                            return Poll::Ready(Some(conn));
                        } else {
                            continue;
                        }
                    }
                }
            }
            if endpoint.connections.close.is_some() {
                return Poll::Ready(None);
            }
            break;
        }
        loop {
            match this.notify.as_mut().poll(ctx) {
                // `state` lock ensures we didn't race with readiness
                Poll::Pending => return Poll::Pending,
                // Spurious wakeup, get a new future
                Poll::Ready(()) => this
                    .notify
                    .set(this.endpoint.inner.shared.incoming.notified()),
            }
        }
    }
}

pin_project! {
    /// Future produced by [`Endpoint::next_incoming`]
    pub struct NextIncoming<'a> {
        endpoint: &'a Endpoint,
        #[pin]
        notify: Notified<'a>,
    }
}

impl<'a> Future for NextIncoming<'a> {
    type Output = Option<GenericIncoming<'a>>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let endpoint = &mut *this.endpoint.inner.state.lock().unwrap();
        if endpoint.driver_lost {
            return Poll::Ready(None);
        }
        if let Some(gen_incoming) = endpoint.incoming.pop_front() {
            return Poll::Ready(Some(gen_incoming.with_endpoint(this.endpoint)));
        }
        if endpoint.connections.close.is_some() {
            return Poll::Ready(None);
        }
        loop {
            match this.notify.as_mut().poll(ctx) {
                // `state` lock ensures we didn't race with readiness
                Poll::Pending => return Poll::Pending,
                // Spurious wakeup, get a new future
                Poll::Ready(()) => this
                    .notify
                    .set(this.endpoint.inner.shared.incoming.notified()),
            }
        }
    }
}

/// Value yielded from [`Endpoint::next_incoming`]
#[derive(Debug)]
pub enum GenericIncoming<'a> {
    Automatic(Connecting),
    Manual(IncomingConnection<'a>),
}

// GenericIncoming minus the &Endpoint
#[derive(Debug)]
enum PortableGenericIncoming {
    Automatic(Connecting),
    Manual {
        inner: proto::IncomingConnection,
        response_buffer: BytesMut,
    }
}

impl PortableGenericIncoming {
    fn with_endpoint(self, endpoint: &Endpoint) -> GenericIncoming<'_> {
        match self {
            PortableGenericIncoming::Automatic(conn) => GenericIncoming::Automatic(conn),
            PortableGenericIncoming::Manual {
                inner,
                response_buffer,
            } => GenericIncoming::Manual(IncomingConnection { inner, response_buffer, endpoint }),
        }
    }
}

/// An incoming connection for which the server has not yet begun its part of the handshake
#[derive(Debug)] // TODO: make this capable of becoming static
pub struct IncomingConnection<'a> {
    inner: proto::IncomingConnection,
    response_buffer: BytesMut,
    endpoint: &'a Endpoint,
}

impl<'a> IncomingConnection<'a> {
    /// Whether the socket address that is initiating this connection has been validated
    ///
    /// This means that the sender of the initial packet has proved that they can receive traffic
    /// sent to `self.remote_address()`.
    pub fn is_validated(&self) -> bool {
        self.inner.is_validated()
    }

    /// The purported socket address that is initiating this connection
    pub fn remote_address(&self) -> SocketAddr {
        self.inner.remote_address()
    }

    /// Whether it is legal to require the client to retry
    ///
    /// If `is_validated` is false, `may_retry` is necessarily true.
    pub fn may_retry(&self) -> bool {
        self.inner.may_retry()
    }

    /// Attempt to accept this incoming connection (an error may still occur)
    pub fn accept(mut self) -> Option<Connecting> {
        let mut endpoint = self.endpoint.inner.0.state.lock().unwrap();
        match self.inner.accept(&mut endpoint.inner, Instant::now(), &mut self.response_buffer) {
            Ok((handle, conn)) => {
                let socket = endpoint.socket.clone();
                let runtime = endpoint.runtime.clone();
                Some(endpoint.connections.insert(handle, conn, socket, runtime))
            },
            Err(response) => {
                if let Some(transmit) = response {
                    let thing = &mut *endpoint;
                    State::respond(
                        &mut thing.transmit_queue_contents_len,
                        &mut thing.outgoing,
                        transmit,
                        self.response_buffer,
                    );
                }
                None
            }
        }
    }

    /// Reject this incoming connection attempt
    pub fn reject(mut self) {
        let mut endpoint = self.endpoint.inner.0.state.lock().unwrap();
        let transmit = self.inner.reject(&mut endpoint.inner, &mut self.response_buffer);
        let thing = &mut *endpoint;
        State::respond(
            &mut thing.transmit_queue_contents_len,
            &mut thing.outgoing,
            transmit,
            self.response_buffer,
        );
    }

    /// Respond with a retry packet, requiring the client to retry with address validation
    ///
    /// Panics if `may_retry` is false.
    pub fn retry(mut self) {
        let mut endpoint = self.endpoint.inner.0.state.lock().unwrap();
        let transmit = self.inner.retry(&mut endpoint.inner, &mut self.response_buffer);
        let thing = &mut *endpoint;
        State::respond(
            &mut thing.transmit_queue_contents_len,
            &mut thing.outgoing,
            transmit,
            self.response_buffer,
        );
    }
}

#[derive(Debug)]
pub(crate) struct EndpointRef(Arc<EndpointInner>);

impl EndpointRef {
    pub(crate) fn new(
        socket: Arc<dyn AsyncUdpSocket>,
        inner: proto::Endpoint,
        ipv6: bool,
        runtime: Arc<dyn Runtime>,
    ) -> Self {
        let recv_buf = vec![
            0;
            inner.config().get_max_udp_payload_size().min(64 * 1024) as usize
                * socket.max_receive_segments()
                * BATCH_SIZE
        ];
        let (sender, events) = mpsc::unbounded_channel();
        Self(Arc::new(EndpointInner {
            shared: Shared {
                incoming: Notify::new(),
                idle: Notify::new(),
            },
            state: Mutex::new(State {
                socket,
                inner,
                ipv6,
                events,
                outgoing: VecDeque::new(),
                incoming: VecDeque::new(),
                driver: None,
                connections: ConnectionSet {
                    senders: FxHashMap::default(),
                    sender,
                    close: None,
                },
                ref_count: 0,
                driver_lost: false,
                recv_buf: recv_buf.into(),
                recv_limiter: WorkLimiter::new(RECV_TIME_BOUND),
                send_limiter: WorkLimiter::new(SEND_TIME_BOUND),
                runtime,
                transmit_queue_contents_len: 0,
            }),
        }))
    }
}

impl Clone for EndpointRef {
    fn clone(&self) -> Self {
        self.0.state.lock().unwrap().ref_count += 1;
        Self(self.0.clone())
    }
}

impl Drop for EndpointRef {
    fn drop(&mut self) {
        let endpoint = &mut *self.0.state.lock().unwrap();
        if let Some(x) = endpoint.ref_count.checked_sub(1) {
            endpoint.ref_count = x;
            if x == 0 {
                // If the driver is about to be on its own, ensure it can shut down if the last
                // connection is gone.
                if let Some(task) = endpoint.driver.take() {
                    task.wake();
                }
            }
        }
    }
}

impl std::ops::Deref for EndpointRef {
    type Target = EndpointInner;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
