//! Storing tokens sent from servers in NEW_TOKEN frames and using them in subsequent connections

use bytes::Bytes;
use slab::Slab;
use std::{
    collections::{hash_map, HashMap},
    mem::take,
    sync::{Arc, Mutex},
};

/// Responsible for storing address validation tokens received from servers and retrieving them for
/// use in subsequent connections
pub trait ValidationTokenStore: Send + Sync {
    /// Potentially store a token for later one-time use
    ///
    /// Called when a NEW_TOKEN frame is received from the server.
    fn store(&self, server_name: &str, token: Bytes);

    /// Try to find and take a token that was stored with the given server name
    ///
    /// The same token must never be returned from `take` twice, as doing so can be used to
    /// de-anonymize a client's traffic.
    ///
    /// Called when trying to connect to a server. It is always ok for this to return `None`.
    fn take(&self, server_name: &str) -> Option<Bytes>;
}

/// `ValidationTokenMemoryCache` implementation that stores up to `N` tokens per server name for up
/// to a limited number of server names, in-memory
pub struct ValidationTokenMemoryCache<const N: usize>(Mutex<State<N>>);

impl<const N: usize> ValidationTokenMemoryCache<N> {
    /// Construct empty
    pub fn new(max_server_names: usize) -> Self {
        Self(Mutex::new(State::new(max_server_names)))
    }
}

impl<const N: usize> ValidationTokenStore for ValidationTokenMemoryCache<N> {
    fn store(&self, server_name: &str, token: Bytes) {
        self.0.lock().unwrap().store(server_name, token)
    }

    fn take(&self, server_name: &str) -> Option<Bytes> {
        self.0.lock().unwrap().take(server_name)
    }
}

/// Defaults to a size limit of 256
impl<const N: usize> Default for ValidationTokenMemoryCache<N> {
    fn default() -> Self {
        Self::new(256)
    }
}

/// Lockable inner state of `ValidationTokenMemoryCache`.
#[derive(Debug)]
struct State<const N: usize> {
    max_server_names: usize,
    // linked hash table structure
    lookup: HashMap<Arc<str>, usize>,
    entries: Slab<CacheEntry<N>>,
    oldest_newest: Option<(usize, usize)>,
}

/// Cache entry within `State`.
#[derive(Debug)]
struct CacheEntry<const N: usize> {
    server_name: Arc<str>,
    older: Option<usize>,
    newer: Option<usize>,
    tokens: Queue<N>,
}

impl<const N: usize> State<N> {
    fn new(max_server_names: usize) -> Self {
        assert!(max_server_names > 0, "size limit cannot be 0");
        Self {
            max_server_names,
            lookup: HashMap::new(),
            entries: Slab::new(),
            oldest_newest: None,
        }
    }

    /// Unlink an entry's neighbors from it
    fn unlink(
        idx: usize,
        entries: &mut Slab<CacheEntry<N>>,
        oldest_newest: &mut Option<(usize, usize)>,
    ) {
        if let Some(older) = entries[idx].older {
            entries[older].newer = entries[idx].newer;
        } else {
            // unwrap safety: entries[idx] exists, therefore oldest_newest is some
            *oldest_newest = entries[idx]
                .newer
                .map(|newer| (oldest_newest.unwrap().0, newer));
        }
        if let Some(newer) = entries[idx].newer {
            entries[newer].older = entries[idx].older;
        } else {
            // unwrap safety: oldest_newest is none iff entries[idx] was the only entry.
            //                if entries[idx].older is some, entries[idx] was not the only entry
            //                therefore oldest_newest is some.
            *oldest_newest = entries[idx]
                .older
                .map(|older| (older, oldest_newest.unwrap().1));
        }
    }

    /// Link an entry as the most recently used entry
    ///
    /// Assumes any pre-existing neighbors are already unlinked.
    fn link(
        idx: usize,
        entries: &mut Slab<CacheEntry<N>>,
        oldest_newest: &mut Option<(usize, usize)>,
    ) {
        entries[idx].newer = None;
        entries[idx].older = oldest_newest.map(|(_, newest)| newest);
        if let &mut Some((_, ref mut newest)) = oldest_newest {
            *newest = idx;
        } else {
            *oldest_newest = Some((idx, idx));
        }
    }

    fn store(&mut self, server_name: &str, token: Bytes) {
        let server_name = Arc::<str>::from(server_name);
        let idx = match self.lookup.entry(server_name.clone()) {
            hash_map::Entry::Occupied(hmap_entry) => {
                // key already exists, add the new token to its token stack
                let entry = &mut self.entries[*hmap_entry.get()];
                entry.tokens.push(token);

                // unlink the entry and set it up to be linked as the most recently used
                Self::unlink(
                    *hmap_entry.get(),
                    &mut self.entries,
                    &mut self.oldest_newest,
                );
                *hmap_entry.get()
            }
            hash_map::Entry::Vacant(hmap_entry) => {
                // key does not yet exist, create a new one, evicting the oldest if necessary
                let removed_key = if self.entries.len() >= self.max_server_names {
                    // unwrap safety: max_server_names is > 0, so there's at least one entry, so
                    //                oldest_newest is some
                    let oldest = self.oldest_newest.unwrap().0;
                    Self::unlink(oldest, &mut self.entries, &mut self.oldest_newest);
                    Some(self.entries.remove(oldest).server_name)
                } else {
                    None
                };

                let mut tokens = Queue::new();
                tokens.push(token);
                let idx = self.entries.insert(CacheEntry {
                    server_name,
                    // we'll link these after the fact
                    older: None,
                    newer: None,
                    tokens,
                });
                hmap_entry.insert(idx);

                // for borrowing reasons, we must defer removing the evicted hmap entry
                if let Some(removed_key) = removed_key {
                    let removed = self.lookup.remove(&removed_key);
                    debug_assert!(removed.is_some());
                }

                idx
            }
        };

        // link it as the newest entry
        Self::link(idx, &mut self.entries, &mut self.oldest_newest);
    }

    fn take(&mut self, server_name: &str) -> Option<Bytes> {
        if let hash_map::Entry::Occupied(hmap_entry) = self.lookup.entry(server_name.into()) {
            let entry = &mut self.entries[*hmap_entry.get()];
            // pop from entry's token stack
            let token = entry.tokens.pop();
            if entry.tokens.len > 1 {
                // re-link entry as most recently used
                Self::unlink(
                    *hmap_entry.get(),
                    &mut self.entries,
                    &mut self.oldest_newest,
                );
                Self::link(
                    *hmap_entry.get(),
                    &mut self.entries,
                    &mut self.oldest_newest,
                );
            } else {
                // token stack emptied, remove entry
                Self::unlink(
                    *hmap_entry.get(),
                    &mut self.entries,
                    &mut self.oldest_newest,
                );
                self.entries.remove(*hmap_entry.get());
                hmap_entry.remove();
            }
            Some(token)
        } else {
            None
        }
    }
}

/// In-place deque queue of up to `N` `Bytes`
#[derive(Debug)]
struct Queue<const N: usize> {
    elems: [Bytes; N],
    // if len > 0, front is elems[start]
    // invariant: start < N
    start: usize,
    // if len > 0, back is elems[(start + len - 1) % N]
    len: usize,
}

impl<const N: usize> Queue<N> {
    /// Construct empty
    fn new() -> Self {
        const EMPTY_BYTES: Bytes = Bytes::new();
        Self {
            elems: [EMPTY_BYTES; N],
            start: 0,
            len: 0,
        }
    }

    /// Push to back, popping from front first if already at capacity
    fn push(&mut self, elem: Bytes) {
        self.elems[(self.start + self.len) % N] = elem;
        if self.len < N {
            self.len += 1;
        } else {
            self.start += 1;
            self.start %= N;
        }
    }

    /// Pop from front, panicking if empty
    fn pop(&mut self) -> Bytes {
        self.len = self
            .len
            .checked_sub(1)
            .expect("ValidationTokenMemoryCache popped from empty Queue, this is a bug!");
        take(&mut self.elems[(self.start + self.len) % N])
    }
}
