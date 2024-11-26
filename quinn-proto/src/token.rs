use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
};

use bytes::{Buf, BufMut};

use crate::{
    coding::{BufExt, BufMutExt},
    crypto::{CryptoError, HandshakeTokenKey, HmacKey},
    packet::InitialHeader,
    shared::ConnectionId,
    Duration, ServerConfig, SystemTime, RESET_TOKEN_SIZE, UNIX_EPOCH,
};

/// State in an [`Incoming`] determined by a token or lack thereof
#[derive(Debug)]
pub(crate) struct IncomingTokenState {
    pub(crate) retry_src_cid: Option<ConnectionId>,
    pub(crate) orig_dst_cid: ConnectionId,
}

impl IncomingTokenState {
    /// Construct for an `Incoming` which is not validated by a token
    pub(crate) fn default(header: &InitialHeader) -> Self {
        IncomingTokenState {
            retry_src_cid: None,
            orig_dst_cid: header.dst_cid,
        }
    }
}

/// A retry token
///
/// The data in this struct is encoded and encrypted in the context of not only a handshake token
/// key, but also a client socket address.
pub(crate) struct Token {
    /// The destination connection ID set in the very first packet from the client
    pub(crate) orig_dst_cid: ConnectionId,
    /// The time at which this token was issued
    pub(crate) issued: SystemTime,
}

impl Token {
    /// Encode and encrypt
    pub(crate) fn encode(
        &self,
        key: &dyn HandshakeTokenKey,
        address: &SocketAddr,
        retry_src_cid: &ConnectionId,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_inner(&mut buf, address);
        let aead_key = key.aead_from_hkdf(retry_src_cid);
        aead_key.seal(&mut buf, &[]).unwrap();

        buf
    }

    /// Decrypt and decode
    pub(crate) fn decode(
        key: &dyn HandshakeTokenKey,
        address: &SocketAddr,
        retry_src_cid: &ConnectionId,
        raw_token_bytes: &[u8],
    ) -> Result<Self, TokenDecodeError> {
        let aead_key = key.aead_from_hkdf(retry_src_cid);
        let mut sealed_token = raw_token_bytes.to_vec();
        let encoded = aead_key.open(&mut sealed_token, &[])?;

        let mut cursor = io::Cursor::new(encoded);
        let token = Self::decode_inner(&mut cursor, address)?;
        if cursor.has_remaining() {
            return Err(TokenDecodeError::UnknownToken);
        }

        Ok(token)
    }

    /// Ensure that this token validates an `Incoming`, and construct its token state
    pub(crate) fn validate(
        &self,
        header: &InitialHeader,
        server_config: &ServerConfig,
    ) -> Result<IncomingTokenState, TokenDecodeError> {
        let Token {
            orig_dst_cid,
            issued,
        } = *self;
        if issued + server_config.retry_token_lifetime > SystemTime::now() {
            Ok(IncomingTokenState {
                retry_src_cid: Some(header.dst_cid),
                orig_dst_cid,
            })
        } else {
            Err(TokenDecodeError::InvalidRetry)
        }
    }

    /// Encode without encryption
    fn encode_inner(&self, buf: &mut Vec<u8>, address: &SocketAddr) {
        encode_socket_addr(buf, address);
        self.orig_dst_cid.encode_long(buf);
        encode_time(buf, self.issued);
    }

    /// Try to decode without encryption, but do validate that the address is acceptable
    fn decode_inner<B: Buf>(buf: &mut B, address: &SocketAddr) -> Result<Self, TokenDecodeError> {
        let token_address = decode_socket_addr(buf).ok_or(TokenDecodeError::UnknownToken)?;
        if token_address != *address {
            return Err(TokenDecodeError::InvalidRetry);
        }
        let orig_dst_cid = ConnectionId::decode_long(buf).ok_or(TokenDecodeError::UnknownToken)?;
        let issued = decode_time(buf).ok_or(TokenDecodeError::UnknownToken)?;
        Ok(Self {
            orig_dst_cid,
            issued,
        })
    }
}

fn encode_socket_addr(buf: &mut Vec<u8>, address: &SocketAddr) {
    encode_ip_addr(buf, &address.ip());
    buf.put_u16(address.port());
}

fn encode_ip_addr(buf: &mut Vec<u8>, address: &IpAddr) {
    match address {
        IpAddr::V4(x) => {
            buf.put_u8(0);
            buf.put_slice(&x.octets());
        }
        IpAddr::V6(x) => {
            buf.put_u8(1);
            buf.put_slice(&x.octets());
        }
    }
}

fn decode_socket_addr<B: Buf>(buf: &mut B) -> Option<SocketAddr> {
    let ip = decode_ip_addr(buf)?;
    let port = buf.get::<u16>().ok()?;
    Some(SocketAddr::new(ip, port))
}

fn decode_ip_addr<B: Buf>(buf: &mut B) -> Option<IpAddr> {
    Some(match buf.get::<u8>().ok()? {
        0 => IpAddr::V4(buf.get().ok()?),
        1 => IpAddr::V6(buf.get().ok()?),
        _ => return None,
    })
}

fn encode_time(buf: &mut Vec<u8>, time: SystemTime) {
    buf.write::<u64>(
        time.duration_since(UNIX_EPOCH)
            .map(|x| x.as_secs())
            .unwrap_or(0),
    );
}

fn decode_time<B: Buf>(buf: &mut B) -> Option<SystemTime> {
    Some(UNIX_EPOCH + Duration::new(buf.get::<u64>().ok()?, 0))
}

/// Error for a token failing to validate a client's address
#[derive(Debug, Copy, Clone)]
pub(crate) enum TokenDecodeError {
    /// Token may have come from a NEW_TOKEN frame (including from a different server or a previous
    /// run of this server with different keys), and was not valid
    ///
    /// It should be silently ignored.
    ///
    /// In cases where a token cannot be decrypted/decoded, we must allow for the possibility that
    /// this is caused not by client malfeasance, but by the token having been generated by an
    /// incompatible endpoint, e.g. a different version or a neighbor behind the same load
    /// balancer. In such cases we proceed as if there was no token.
    ///
    /// [_RFC 9000 § 8.1.3:_](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.3-10)
    ///
    /// > If the token is invalid, then the server SHOULD proceed as if the client did not have a
    /// > validated address, including potentially sending a Retry packet.
    UnknownToken,
    /// Token was unambiguously from a Retry packet, and was not valid.
    ///
    /// The connection cannot be established.
    InvalidRetry,
}

impl From<CryptoError> for TokenDecodeError {
    fn from(CryptoError: CryptoError) -> Self {
        Self::UnknownToken
    }
}

/// Stateless reset token
///
/// Used for an endpoint to securely communicate that it has lost state for a connection.
#[allow(clippy::derived_hash_with_manual_eq)] // Custom PartialEq impl matches derived semantics
#[derive(Debug, Copy, Clone, Hash)]
pub(crate) struct ResetToken([u8; RESET_TOKEN_SIZE]);

impl ResetToken {
    pub(crate) fn new(key: &dyn HmacKey, id: &ConnectionId) -> Self {
        let mut signature = vec![0; key.signature_len()];
        key.sign(id, &mut signature);
        // TODO: Server ID??
        let mut result = [0; RESET_TOKEN_SIZE];
        result.copy_from_slice(&signature[..RESET_TOKEN_SIZE]);
        result.into()
    }
}

impl PartialEq for ResetToken {
    fn eq(&self, other: &Self) -> bool {
        crate::constant_time::eq(&self.0, &other.0)
    }
}

impl Eq for ResetToken {}

impl From<[u8; RESET_TOKEN_SIZE]> for ResetToken {
    fn from(x: [u8; RESET_TOKEN_SIZE]) -> Self {
        Self(x)
    }
}

impl std::ops::Deref for ResetToken {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for ResetToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.iter() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(all(test, any(feature = "aws-lc-rs", feature = "ring")))]
mod test {
    #[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
    use aws_lc_rs::hkdf;
    #[cfg(feature = "ring")]
    use ring::hkdf;

    #[test]
    fn token_sanity() {
        use super::*;
        use crate::cid_generator::{ConnectionIdGenerator, RandomConnectionIdGenerator};
        use crate::MAX_CID_SIZE;
        use crate::{Duration, UNIX_EPOCH};

        use rand::RngCore;
        use std::net::Ipv6Addr;

        let rng = &mut rand::thread_rng();

        let mut master_key = [0; 64];
        rng.fill_bytes(&mut master_key);

        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&master_key);

        let addr = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433);
        let retry_src_cid = RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid();
        let token = Token {
            orig_dst_cid: RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid(),
            issued: UNIX_EPOCH + Duration::new(42, 0), // Fractional seconds would be lost
        };
        let encoded = token.encode(&prk, &addr, &retry_src_cid);

        let decoded =
            Token::decode(&prk, &addr, &retry_src_cid, &encoded).expect("token didn't validate");
        assert_eq!(token.orig_dst_cid, decoded.orig_dst_cid);
        assert_eq!(token.issued, decoded.issued);
    }

    #[test]
    fn invalid_token_returns_err() {
        use super::*;
        use crate::cid_generator::{ConnectionIdGenerator, RandomConnectionIdGenerator};
        use crate::MAX_CID_SIZE;
        use rand::RngCore;
        use std::net::Ipv6Addr;

        let rng = &mut rand::thread_rng();

        let mut master_key = [0; 64];
        rng.fill_bytes(&mut master_key);

        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&master_key);

        let addr = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433);
        let retry_src_cid = RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid();

        let mut invalid_token = Vec::new();

        let mut random_data = [0; 32];
        rand::thread_rng().fill_bytes(&mut random_data);
        invalid_token.put_slice(&random_data);

        // Assert: garbage sealed data returns err
        assert!(Token::decode(&prk, &addr, &retry_src_cid, &invalid_token).is_err());
    }
}
