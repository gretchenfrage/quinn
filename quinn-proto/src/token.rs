use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    coding::{BufExt, BufMutExt},
    crypto::{AeadKey, CryptoError, HandshakeTokenKey, HmacKey},
    shared::ConnectionId,
    MAX_CID_SIZE, RESET_TOKEN_SIZE,
};

pub(crate) struct RetryToken {
    /// The destination connection ID set in the very first packet from the client
    pub(crate) orig_dst_cid: ConnectionId,
    /// The time at which this token was issued
    pub(crate) issued: SystemTime,
}

impl RetryToken {
    pub(crate) fn encode(
        &self,
        key: &dyn HandshakeTokenKey,
        address: &SocketAddr,
        retry_src_cid: &ConnectionId,
    ) -> Vec<u8> {
        let aead_key = handshake_token_aead_key(key, address, retry_src_cid);

        let mut buf = Vec::new();
        self.orig_dst_cid.encode_long(&mut buf);
        buf.write::<u64>(
            self.issued
                .duration_since(UNIX_EPOCH)
                .map(|x| x.as_secs())
                .unwrap_or(0),
        );

        aead_key.seal(&mut buf, &[]).unwrap();

        buf
    }

    pub(crate) fn from_bytes(
        key: &dyn HandshakeTokenKey,
        address: &SocketAddr,
        retry_src_cid: &ConnectionId,
        raw_token_bytes: &[u8],
    ) -> Result<Self, TokenDecodeError> {
        let aead_key = handshake_token_aead_key(key, address, retry_src_cid);
        let mut sealed_token = raw_token_bytes.to_vec();

        let data = aead_key.open(&mut sealed_token, &[])?;
        let mut reader = io::Cursor::new(data);
        let orig_dst_cid = ConnectionId::decode_long(&mut reader).ok_or(TokenDecodeError)?;
        let issued =
            UNIX_EPOCH + Duration::new(reader.get::<u64>().map_err(|_| TokenDecodeError)?, 0);

        Ok(Self {
            orig_dst_cid,
            issued,
        })
    }
}

fn handshake_token_aead_key(
    key: &dyn HandshakeTokenKey,
    address: &SocketAddr,
    retry_src_cid: &ConnectionId,
) -> Box<dyn AeadKey> {
    use io::Write as _;

    // encoded IPV6 socket address = 19 bytes
    let mut buf = [0; MAX_CID_SIZE + 19];
    let mut cursor = io::Cursor::new(buf.as_mut_slice());
    match address.ip() {
        IpAddr::V4(x) => {
            cursor.write_all(&[0]).unwrap();
            cursor.write_all(&x.octets()).unwrap();
        }
        IpAddr::V6(x) => {
            cursor.write_all(&[1]).unwrap();
            cursor.write_all(&x.octets()).unwrap();
        }
    }
    cursor.write_all(&u16::to_ne_bytes(address.port())).unwrap();
    cursor.write_all(retry_src_cid).unwrap();
    key.aead_from_hkdf(&cursor.get_ref()[..cursor.position() as usize])
}

/// Token was not recognized. It should be silently ignored.
#[derive(Debug, Copy, Clone)]
pub(crate) struct TokenDecodeError;

impl From<CryptoError> for TokenDecodeError {
    fn from(CryptoError: CryptoError) -> Self {
        TokenDecodeError
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

#[cfg(test)]
mod test {
    use bytes::BufMut;

    #[cfg(feature = "ring")]
    #[test]
    fn token_sanity() {
        use super::*;
        use crate::cid_generator::{ConnectionIdGenerator, RandomConnectionIdGenerator};
        use crate::MAX_CID_SIZE;

        use rand::RngCore;
        use std::{
            net::Ipv6Addr,
            time::{Duration, UNIX_EPOCH},
        };

        let rng = &mut rand::thread_rng();

        let mut master_key = [0; 64];
        rng.fill_bytes(&mut master_key);

        let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[]).extract(&master_key);

        let addr = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433);
        let retry_src_cid = RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid();
        let token = RetryToken {
            orig_dst_cid: RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid(),
            issued: UNIX_EPOCH + Duration::new(42, 0), // Fractional seconds would be lost
        };
        let encoded = token.encode(&prk, &addr, &retry_src_cid);

        let decoded = RetryToken::from_bytes(&prk, &addr, &retry_src_cid, &encoded)
            .expect("token didn't validate");
        assert_eq!(token.orig_dst_cid, decoded.orig_dst_cid);
        assert_eq!(token.issued, decoded.issued);
    }

    #[cfg(feature = "ring")]
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

        let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[]).extract(&master_key);

        let addr = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433);
        let retry_src_cid = RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid();

        let mut invalid_token = Vec::new();

        let mut random_data = [0; 32];
        rand::thread_rng().fill_bytes(&mut random_data);
        invalid_token.put_slice(&random_data);

        // Assert: garbage sealed data returns err
        assert!(RetryToken::from_bytes(&prk, &addr, &retry_src_cid, &invalid_token).is_err());
    }
}
