use bytes::Bytes;

/// Responsible for storing address validation tokens received from servers and retrieving them for
/// use in subsequent connections
pub trait TokenStore: Send + Sync {
    /// Potentially store a token for later one-time use
    ///
    /// Called when a NEW_TOKEN frame is received from the server.
    fn insert(&self, server_name: &str, token: Bytes);

    /// Try to find and take a token that was stored with the given server name
    ///
    /// The same token must never be returned from `take` twice, as doing so can be used to
    /// de-anonymize a client's traffic.
    ///
    /// Called when trying to connect to a server. It is always ok for this to return `None`.
    fn take(&self, server_name: &str) -> Option<Bytes>;
}
