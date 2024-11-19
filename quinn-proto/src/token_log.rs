//! Limiting clients' ability to reuse tokens from NEW_TOKEN frames

use std::{
    collections::HashSet,
    f64::consts::LN_2,
    hash::{BuildHasher, Hasher},
    mem::{size_of, swap},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fastbloom::BloomFilter;
use rustc_hash::FxBuildHasher;
use tracing::warn;

/// Error for when a validation token may have been reused
pub struct TokenReuseError;

/// Responsible for limiting clients' ability to reuse validation tokens
///
/// [_RFC 9000 § 8.1.4:_](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.4)
///
/// > Attackers could replay tokens to use servers as amplifiers in DDoS attacks. To protect
/// > against such attacks, servers MUST ensure that replay of tokens is prevented or limited.
/// > Servers SHOULD ensure that tokens sent in Retry packets are only accepted for a short time,
/// > as they are returned immediately by clients. Tokens that are provided in NEW_TOKEN frames
/// > (Section 19.7) need to be valid for longer but SHOULD NOT be accepted multiple times.
/// > Servers are encouraged to allow tokens to be used only once, if possible; tokens MAY include
/// > additional information about clients to further narrow applicability or reuse.
///
/// `TokenLog` pertains only to tokens provided in NEW_TOKEN frames.
pub trait TokenLog: Send + Sync {
    /// Record that the token was used and, ideally, return a token reuse error if the token was
    /// already used previously
    ///
    /// False negatives and false positives are both permissible. Called when a client uses an
    /// address validation token.
    ///
    /// Parameters:
    /// - `rand`: A server-generated random unique value for the token.
    /// - `issued`: The time the server issued the token.
    /// - `lifetime`: The expiration time of address validation tokens sent via NEW_TOKEN frames,
    ///   as configured by [`ServerConfig::validation_token_lifetime`][1].
    ///
    /// [1]: crate::ServerConfig::validation_token_lifetime
    fn check_and_insert(
        &self,
        rand: u128,
        issued: SystemTime,
        lifetime: Duration,
    ) -> Result<(), TokenReuseError>;
}

/// The token's rand needs to guarantee uniqueness because of the role it plays in the encryption
/// of the tokens, so it is 128 bits. But since the token log can tolerate both false positives and
/// false negatives, we trim it down to 64 bits, which would still only have a small collision rate
/// even at significant amounts of usage, while allowing us to store twice as many in the hash set
/// variant.
///
/// Token rand values are uniformly randomly generated server-side and cryptographically integrity-
/// checked, so we don't need to employ secure hashing for this, we can simply truncate.
fn rand_to_fingerprint(rand: u128) -> u64 {
    (rand & 0xffffffff) as u64
}

/// `BuildHasher` of `IdentityHasher`.
#[derive(Default)]
struct IdentityBuildHasher;

impl BuildHasher for IdentityBuildHasher {
    type Hasher = IdentityHasher;

    fn build_hasher(&self) -> Self::Hasher {
        IdentityHasher::default()
    }
}

/// Hasher that assumes the thing being hashes is a `u64` and is the identity operation.
#[derive(Default)]
struct IdentityHasher {
    data: [u8; 8],
    #[cfg(debug_assertions)]
    wrote_8_byte_slice: bool,
}

impl Hasher for IdentityHasher {
    fn write(&mut self, bytes: &[u8]) {
        #[cfg(debug_assertions)]
        {
            assert!(!self.wrote_8_byte_slice);
            assert_eq!(bytes.len(), 8);
            self.wrote_8_byte_slice = true;
        }
        self.data.copy_from_slice(bytes);
    }

    fn finish(&self) -> u64 {
        #[cfg(debug_assertions)]
        assert!(self.wrote_8_byte_slice);
        u64::from_ne_bytes(self.data)
    }
}

/// Hash set of `u64` which are assumed to already be uniformly randomly distributed, and thus
/// effectively pre-hashed.
type IdentityHashSet = HashSet<u64, IdentityBuildHasher>;

/// Bloom filter that uses `FxHasher`s.
type FxBloomFilter = BloomFilter<512, FxBuildHasher>;

/// Bloom filter-based `TokenLog`
///
/// Parameterizable over an approximate maximum number of bytes to allocate. Starts out by storing
/// used tokens in a hash set. Once the hash set becomes too large, converts it to a bloom filter.
/// This achieves a memory profile of linear growth with an upper bound.
///
/// Divides time into periods based on `lifetime` and stores two filters at any given moment, for
/// each of the two periods currently non-expired tokens could expire in. As such, turns over
/// filters as time goes on to avoid bloom filter false positive rate increasing infinitely over
/// time.
pub struct BloomTokenLog(Mutex<State>);

/// Lockable state of [`BloomTokenLog`]
struct State {
    filter_max_bytes: usize,
    k_num: u32,

    // filter_1 covers tokens that expire in the period starting at
    // UNIX_EPOCH + period_idx_1 * lifetime and extending lifetime after.
    // filter_2 covers tokens for the next lifetime after that.
    period_idx_1: u128,
    filter_1: Filter,
    filter_2: Filter,
}

/// Period filter within [`State`]
enum Filter {
    Set(IdentityHashSet),
    Bloom(FxBloomFilter),
}

impl BloomTokenLog {
    /// Construct with an approximate maximum memory usage and expected number of validation token
    /// usages per expiration period
    ///
    /// Calculates the optimal bloom filter k number automatically.
    pub fn new_expected_items(max_bytes: usize, expected_hits: u64) -> Self {
        Self::new(max_bytes, optimal_k_num(max_bytes, expected_hits))
    }

    /// Construct with an approximate maximum memory usage and a bloom filter k number
    ///
    /// If choosing a custom k number, note that `BloomTokenLog` always maintains two filters
    /// between them and divides the allocation budget of `max_bytes` evenly between them. As such,
    /// each bloom filter will contain `max_bytes * 4` bits.
    pub fn new(max_bytes: usize, k_num: u32) -> Self {
        assert!(max_bytes >= 2, "BloomTokenLog max_bytes too low");
        assert!(k_num >= 1, "BloomTokenLog k_num must be at least 1");

        Self(Mutex::new(State {
            filter_max_bytes: max_bytes / 2,
            k_num,
            period_idx_1: 0,
            filter_1: Filter::Set(IdentityHashSet::default()),
            filter_2: Filter::Set(IdentityHashSet::default()),
        }))
    }
}

fn optimal_k_num(num_bytes: usize, expected_hits: u64) -> u32 {
    assert!(expected_hits > 0, "BloomTokenLog expected hits too low");
    let num_bits = (num_bytes as u64)
        .checked_mul(8)
        .expect("BloomTokenLog num bytes too high");
    (((num_bits as f64 / expected_hits as f64) * LN_2).round() as u32).max(1)
}

impl TokenLog for BloomTokenLog {
    fn check_and_insert(
        &self,
        rand: u128,
        issued: SystemTime,
        lifetime: Duration,
    ) -> Result<(), TokenReuseError> {
        let mut guard = self.0.lock().unwrap();
        let state = &mut *guard;
        let fingerprint = rand_to_fingerprint(rand);

        // calculate period index for token
        let period_idx = (issued + lifetime)
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            / lifetime.as_nanos();

        // get relevant filter
        let filter = if period_idx < state.period_idx_1 {
            // shouldn't happen unless time travels backwards or new_token_lifetime changes
            warn!("BloomTokenLog presented with token too far in past");
            return Err(TokenReuseError);
        } else if period_idx == state.period_idx_1 {
            &mut state.filter_1
        } else if period_idx == state.period_idx_1 + 1 {
            &mut state.filter_2
        } else {
            // turn over filters
            if period_idx == state.period_idx_1 + 2 {
                swap(&mut state.filter_1, &mut state.filter_2);
            } else {
                state.filter_1 = Filter::Set(IdentityHashSet::default());
            }
            state.filter_2 = Filter::Set(IdentityHashSet::default());
            state.period_idx_1 = period_idx - 1;

            &mut state.filter_2
        };

        // query and insert
        match *filter {
            Filter::Set(ref mut hset) => {
                if !hset.insert(fingerprint) {
                    return Err(TokenReuseError);
                }

                if hset.capacity() * size_of::<u64>() > state.filter_max_bytes {
                    // convert to bloom
                    let mut bloom = BloomFilter::with_num_bits(state.filter_max_bytes * 8)
                        .hasher(FxBuildHasher)
                        .hashes(state.k_num);
                    for item in hset.iter() {
                        bloom.insert(item);
                    }
                    *filter = Filter::Bloom(bloom);
                }
            }
            Filter::Bloom(ref mut bloom) => {
                if bloom.insert(&fingerprint) {
                    return Err(TokenReuseError);
                }
            }
        }

        Ok(())
    }
}

const DEFAULT_MAX_BYTES: usize = 10 << 20;
const DEFAULT_EXPECTED_HITS: u64 = 1_000_000;

/// Default to 20 MiB max memory consumption and expected one million hits
impl Default for BloomTokenLog {
    fn default() -> Self {
        Self::new_expected_items(DEFAULT_MAX_BYTES, DEFAULT_EXPECTED_HITS)
    }
}
