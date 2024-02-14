use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Poll, Context},
    future::{Future, IntoFuture},
};

use bytes::BytesMut;
use proto::ConnectionError;

use crate::{
    connection::{Connecting, Connection},
    endpoint::EndpointRef,
};

/// An incoming connection for which the server has not yet begun its part of the handshake
#[must_use = "futures/streams/sinks do nothing unless you `.await` or poll them"]
pub struct IncomingConnection(Option<State>);

struct State {
    inner: proto::IncomingConnection,
    endpoint: EndpointRef,
    response_buffer: BytesMut,
}

impl IncomingConnection {
    pub(crate) fn new(
        inner: proto::IncomingConnection,
        endpoint: EndpointRef,
        response_buffer: BytesMut,
    ) -> Self {
        Self(Some(State {
            inner,
            endpoint,
            response_buffer,
        }))
    }

    /// The local IP address which was used when the peer established
    /// the connection
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.0.as_ref().unwrap().inner.local_ip()
    }

    /// The peer's UDP address
    pub fn remote_address(&self) -> SocketAddr {
        self.0.as_ref().unwrap().inner.remote_address()
    }

    /// Whether the socket address that is initiating this connection has been validated
    ///
    /// This means that the sender of the initial packet has proved that they can receive traffic
    /// sent to `self.remote_address()`.
    pub fn remote_address_validated(&self) -> bool {
        self.0.as_ref().unwrap().inner.remote_address_validated()
    }

    /// Attempt to accept this incoming connection (an error may still occur)
    pub fn accept(mut self) -> Result<Connecting, ConnectionError> {
        let state = self.0.take().unwrap();
        state
            .endpoint
            .accept(state.inner, state.response_buffer)
            .ok_or_else(|| {
                ConnectionError::TransportError(proto::TransportError {
                    code: proto::TransportErrorCode::PROTOCOL_VIOLATION,
                    frame: None,
                    reason: "Problem with initial packet".to_owned(),
                })
            })
    }

    /// Reject this incoming connection attempt
    pub fn reject(mut self) {
        let state = self.0.take().unwrap();
        state.endpoint.reject(state.inner, state.response_buffer);
    }

    /// Respond with a retry packet, requiring the client to retry with address validation
    ///
    /// Panics if `incoming.remote_address_validated()` is true.
    pub fn retry(mut self) {
        let state = self.0.take().unwrap();
        state.endpoint.retry(state.inner, state.response_buffer);
    }

    /// Ignore this incoming connection attempt, not sending any packet in response
    pub fn ignore(mut self) {
        self.0.take().unwrap();
    }
}

impl Drop for IncomingConnection {
    fn drop(&mut self) {
        // Implicit reject, similar to Connection's implicit close
        if let Some(state) = self.0.take() {
            state.endpoint.reject(state.inner, state.response_buffer);
        }
    }
}

impl fmt::Debug for IncomingConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let state = self.0.as_ref().unwrap();
        f.debug_struct("IncomingConnection")
            .field("inner", &state.inner)
            .field("endpoint", &state.endpoint)
            // response_buffer is too big and not meaningful enough
            .finish_non_exhaustive()
    }
}


/// Basic adapter to let [`IncomingConnection`] be `await`-ed like a [`Connecting`]
#[derive(Debug)]
pub struct IncomingConnectionFuture(Result<Connecting, ConnectionError>);

impl Future for IncomingConnectionFuture {
    type Output = Result<Connection, ConnectionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match &mut self.0 {
            Ok(ref mut connecting) => Pin::new(connecting).poll(cx),
            Err(e) => Poll::Ready(Err(e.clone())),
        }
    }
}

impl IntoFuture for IncomingConnection {
    type Output = Result<Connection, ConnectionError>;
    type IntoFuture = IncomingConnectionFuture;

    fn into_future(self) -> Self::IntoFuture {
        IncomingConnectionFuture(self.accept())
    }
}
