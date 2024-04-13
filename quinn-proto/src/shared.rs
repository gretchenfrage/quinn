use std::{fmt, net::SocketAddr, time::Instant};

use bytes::{Buf, BufMut, BytesMut};

use crate::{coding::BufExt, packet::PartialDecode, ResetToken, MAX_CID_SIZE};

/// Events sent from an Endpoint to a Connection
pub struct ConnectionEvent {
    pub(crate) inner: ConnectionEventInner,
    /// Tracing span providing context for the creation of this ConnectionEvent
    pub span: tracing::Span,
}

impl fmt::Debug for ConnectionEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.inner {
            ConnectionEventInner::Datagram {
                now,
                remote,
                ecn,
                first_decode,
                remaining,
            } => f.debug_struct("Datagram")
                .field("now", &format_args!("{:?}", now))
                .field("remote", &format_args!("{:?}", remote))
                .field("ecn", &format_args!("{:?}", ecn))
                .field("first_decode", first_decode)
                .field("remaining.as_ref().map(|b| b.len())", &remaining.as_ref().map(|b| b.len()))
                .finish(),
            ConnectionEventInner::NewIdentifiers(cids, now) => f
                .debug_tuple("NewIdentifiers")
                .field(cids)
                .field(&format_args!("{:?}", now))
                .finish(),
        }
    }
}

pub(crate) enum ConnectionEventInner {
    /// A datagram has been received for the Connection
    Datagram {
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        first_decode: PartialDecode,
        remaining: Option<BytesMut>,
    },
    /// New connection identifiers have been issued for the Connection
    NewIdentifiers(Vec<IssuedCid>, Instant),
}

/// Events sent from a Connection to an Endpoint
pub struct EndpointEvent {
    pub(crate) inner: EndpointEventInner,
    /// Tracing span providing context for the creation of this EndpointEvent
    pub span: tracing::Span,
}

impl EndpointEvent {
    /// Construct an event that indicating that a `Connection` will no longer emit events
    ///
    /// Useful for notifying an `Endpoint` that a `Connection` has been destroyed outside of the
    /// usual state machine flow, e.g. when being dropped by the user.
    pub fn drained() -> Self {
        EndpointEvent {
            inner: EndpointEventInner::Drained,
            span: tracing::Span::current(),
        }
    }

    /// Determine whether this is the last event a `Connection` will emit
    ///
    /// Useful for determining when connection-related event loop state can be freed.
    pub fn is_drained(&self) -> bool {
        self.inner == EndpointEventInner::Drained
    }
}

impl fmt::Debug for EndpointEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::EndpointEventInner::*;
        match &self.inner {
            Drained => f.write_str("Drained"),
            ResetToken(a, t) => write!(f, "ResetToken({:?}, {:?})", a, t),
            NeedIdentifiers(i, n) => write!(f, "NeedIdentifiers({:?}, {})", i, n),
            RetireConnectionId(i, n, b) => write!(f, "RetireConnectionId({:?}, {}, {})", i, n, b),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EndpointEventInner {
    /// The connection has been drained
    Drained,
    /// The reset token and/or address eligible for generating resets has been updated
    ResetToken(SocketAddr, ResetToken),
    /// The connection needs connection identifiers
    NeedIdentifiers(Instant, u64),
    /// Stop routing connection ID for this sequence number to the connection
    /// When `bool == true`, a new connection ID will be issued to peer
    RetireConnectionId(Instant, u64, bool),
}

/// Protocol-level identifier for a connection.
///
/// Mainly useful for identifying this connection's packets on the wire with tools like Wireshark.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ConnectionId {
    /// length of CID
    len: u8,
    /// CID in byte array
    bytes: [u8; MAX_CID_SIZE],
}

impl ConnectionId {
    /// Construct cid from byte array
    pub fn new(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() <= MAX_CID_SIZE);
        let mut res = Self {
            len: bytes.len() as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        res.bytes[..bytes.len()].copy_from_slice(bytes);
        res
    }

    /// Constructs cid by reading `len` bytes from a `Buf`
    ///
    /// Callers need to assure that `buf.remaining() >= len`
    pub(crate) fn from_buf(buf: &mut impl Buf, len: usize) -> Self {
        debug_assert!(len <= MAX_CID_SIZE);
        let mut res = Self {
            len: len as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        buf.copy_to_slice(&mut res[..len]);
        res
    }

    /// Decode from long header format
    pub(crate) fn decode_long(buf: &mut impl Buf) -> Option<Self> {
        let len = buf.get::<u8>().ok()? as usize;
        match len > MAX_CID_SIZE || buf.remaining() < len {
            false => Some(Self::from_buf(buf, len)),
            true => None,
        }
    }

    /// Encode in long header format
    pub(crate) fn encode_long(&self, buf: &mut impl BufMut) {
        buf.put_u8(self.len() as u8);
        buf.put_slice(self);
    }
}

impl ::std::ops::Deref for ConnectionId {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[0..self.len as usize]
    }
}

impl ::std::ops::DerefMut for ConnectionId {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[0..self.len as usize]
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<")?;
        for byte in self.iter() {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ">")
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<")?;
        for byte in self.iter() {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ">")
    }
}

/// Explicit congestion notification codepoint
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EcnCodepoint {
    #[doc(hidden)]
    Ect0 = 0b10,
    #[doc(hidden)]
    Ect1 = 0b01,
    #[doc(hidden)]
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Create new object from the given bits
    pub fn from_bits(x: u8) -> Option<Self> {
        use self::EcnCodepoint::*;
        Some(match x & 0b11 {
            0b10 => Ect0,
            0b01 => Ect1,
            0b11 => Ce,
            _ => {
                return None;
            }
        })
    }

    /// Returns whether the codepoint is a CE, signalling that congestion was experienced
    pub fn is_ce(self) -> bool {
        matches!(self, Self::Ce)
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct IssuedCid {
    pub(crate) sequence: u64,
    pub(crate) id: ConnectionId,
    pub(crate) reset_token: ResetToken,
}
