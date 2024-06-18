//! Limiting clients' ability to reuse tokens from NEW_TOKEN frames

use std::{
    hash::{Hash as _, Hasher as _},
    iter,
    mem::swap,
    sync::{
        atomic::{AtomicU64, Ordering},
        RwLock,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rustc_hash::FxHasher;
use tracing::warn;

/// Error for when a token may have been reused
pub struct TokenReuseError;

/// Responsible for limiting clients' ability to reuse tokens from NEW_TOKEN frames
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
pub trait TokenReusePreventer: Send + Sync {
    /// Called when a client uses a token from a NEW_TOKEN frame
    ///
    /// False negatives and false positives are both permissible.
    fn using(
        &self,
        token_rand: u128,
        issued: SystemTime,
        new_token_lifetime: Duration,
    ) -> Result<(), TokenReuseError>;
}

/// Bloom filter-based `TokenReusePreventer`
pub struct BloomTokenReusePreventer(RwLock<BloomTokenReusePreventerState>);

struct BloomTokenReusePreventerState {
    hashers: [FxHasher; 2],
    k: u32,

    turnover_idx_1: u128,
    // bits_1 is a bloom filter for tokens with expiration time in the period starting at:
    //
    //     UNIX_EPOCH + turnover_idx_1 * turnover_period
    //
    // and extending another turnover_period beyond that. bits_2 is for the next turnover_period
    // after that.
    bits_1: Vec<AtomicU64>,
    bits_2: Vec<AtomicU64>,
}

impl BloomTokenReusePreventer {
    /// Construct new
    ///
    /// `bitmap_size` is the size in bytes of each of the two bloom filters. Thus, the memory
    /// consumption of a `BloomTokenReusePreventer` will be
    pub fn new(bitmap_size: usize, k: u32) -> Self {
        // TODO assertions
        BloomTokenReusePreventer(RwLock::new(BloomTokenReusePreventerState {
            hashers: [FxHasher::default(), FxHasher::default()],
            k,

            turnover_idx_1: 0,
            bits_1: iter::from_fn(|| Some(AtomicU64::new(0)))
                .take(bitmap_size / 8)
                .collect(),
            bits_2: iter::from_fn(|| Some(AtomicU64::new(0)))
                .take(bitmap_size / 8)
                .collect(),
        }))
    }
}

impl TokenReusePreventer for BloomTokenReusePreventer {
    fn using(
        &self,
        token_rand: u128,
        issued: SystemTime,
        new_token_lifetime: Duration,
    ) -> Result<(), TokenReuseError> {
        let expires = issued + new_token_lifetime;
        let turnover_idx =
            expires.duration_since(UNIX_EPOCH).unwrap().as_nanos() / new_token_lifetime.as_nanos();

        let mut turn_over = false;
        loop {
            if turn_over {
                let mut state = self.0.write().unwrap();
                if turnover_idx < state.turnover_idx_1 {
                    // shouldn't happen unless time travels backwards or new_token_lifetime changes
                    warn!("BloomTokenReusePreventer presented with token too far in past");
                    return Err(TokenReuseError);
                }
                if turnover_idx > state.turnover_idx_1 + 1 {
                    if turnover_idx == state.turnover_idx_1 + 2 {
                        let state_borrow = &mut *state;
                        swap(&mut state_borrow.bits_1, &mut state_borrow.bits_2);
                    } else {
                        for n in &mut state.bits_1 {
                            *n = AtomicU64::new(0);
                        }
                    }
                    for n in &mut state.bits_2 {
                        *n = AtomicU64::new(0);
                    }
                    state.turnover_idx_1 = turnover_idx - 1;
                }
                turn_over = false;
            } else {
                let state = self.0.read().unwrap();
                let bits = if turnover_idx < state.turnover_idx_1 {
                    // shouldn't happen unless time travels backwards or new_token_lifetime changes
                    warn!("BloomTokenReusePreventer presented with token too far in past");
                    return Err(TokenReuseError);
                } else if turnover_idx == state.turnover_idx_1 {
                    &state.bits_1
                } else if turnover_idx == state.turnover_idx_1 + 1 {
                    &state.bits_2
                } else {
                    turn_over = true;
                    continue;
                };

                let mut reuse = true;
                for i in state.iter(token_rand) {
                    let mask = 1 << (i % 8);
                    if (bits[(i / 8) as usize].fetch_or(mask, Ordering::Relaxed) & mask) == 0 {
                        reuse = false;
                    }
                }
                break if reuse { Err(TokenReuseError) } else { Ok(()) };
            }
        }
    }
}

impl Default for BloomTokenReusePreventer {
    fn default() -> Self {
        // 10 MiB per bloom filter, totalling 20 MiB
        // k=55 is optimal for a 10 MiB bloom filter and one million hits
        Self::new(10 << 20, 55)
    }
}

struct BloomIter<'a> {
    state: &'a BloomTokenReusePreventerState,
    hashes: [u64; 2],
    item: u128,
    next_ki: u32,
}

impl BloomTokenReusePreventerState {
    fn iter(&self, item: u128) -> BloomIter {
        BloomIter {
            state: self,
            hashes: [0; 2],
            item,
            next_ki: 0,
        }
    }
}

impl<'a> Iterator for BloomIter<'a> {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        if self.next_ki >= self.state.k {
            return None;
        }

        let ki = self.next_ki;
        self.next_ki += 1;
        Some(
            if ki < 2 {
                let mut hasher = self.state.hashers[ki as usize].clone();
                self.item.hash(&mut hasher);
                self.hashes[ki as usize] = hasher.finish();
                self.hashes[ki as usize]
            } else {
                self.hashes[0].wrapping_add((ki as u64).wrapping_mul(self.hashes[1]))
                    % 0xFFFF_FFFF_FFFF_FFC5
            } % (self.state.bits_1.len() as u64 * 8),
        )
    }
}
