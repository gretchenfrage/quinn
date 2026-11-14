use std::{collections::VecDeque, mem::replace};

use bytes::Bytes;
use thiserror::Error;
use tracing::debug;

use super::{Connection, Event};
use crate::{
    TransportError,
    frame::{Datagram, FrameStruct, datagram_overhead},
};

/// API to control datagram traffic
pub struct Datagrams<'a> {
    pub(super) conn: &'a mut Connection,
}

impl Datagrams<'_> {
    /// Queue an unreliable, unordered datagram for immediate transmission
    ///
    /// If `drop` is true, previously queued datagrams which are still unsent may be discarded to
    /// make space for this datagram, in order of oldest to newest. If `drop` is false, and there
    /// isn't enough space due to previously queued datagrams, this function will return
    /// `SendDatagramError::Blocked`. `Event::DatagramsUnblocked` will be emitted once datagrams
    /// have been sent.
    ///
    /// Returns `Err` iff a `len`-byte datagram cannot currently be sent.
    pub fn send(&mut self, data: Bytes, drop: bool) -> Result<(), SendDatagramError> {
        self.send_provider(Box::new(BasicDatagramProvider(data)), drop)
    }

    pub fn send_provider(
        &mut self,
        provider: Box<dyn DatagramProvider>,
        drop: bool,
    ) -> Result<(), SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        self.conn.datagrams.outgoing.push_back(
            provider,
            drop,
            max,
            self.conn.config.datagram_send_buffer_size,
        )
    }

    /// Discard queued datagrams that no longer fit the active path, waking blocked senders.
    pub(super) fn drop_oversized(&mut self) {
        let Some(max_datagram_size) = self.max_size() else {
            return;
        };
        self.conn
            .datagrams
            .outgoing
            .drop_oversized(
                max_datagram_size,
                self.conn.config.datagram_send_buffer_size,
            )
            .expect("TODO");
        if self.conn.datagrams.send_blocked {
            self.conn.events.push_back(Event::DatagramsUnblocked);
        }

        self.conn.datagrams.send_blocked = false;
    }

    /// Compute the maximum size of datagrams that may passed to `send_datagram`
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path MTU
    /// estimate. The peer can also enforce an arbitrarily small fixed limit, but if the peer's
    /// limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    pub fn max_size(&self) -> Option<usize> {
        // We use the conservative overhead bound for any packet number, reducing the budget by at
        // most 3 bytes, so that PN size fluctuations don't cause users sending maximum-size
        // datagrams to suffer avoidable packet loss.
        let max_size = self.conn.path.current_mtu() as usize
            - self.conn.predict_1rtt_overhead(None)
            - Datagram::SIZE_BOUND;
        let limit = self
            .conn
            .peer_params
            .max_datagram_frame_size?
            .into_inner()
            .saturating_sub(Datagram::SIZE_BOUND as u64);
        Some(limit.min(max_size as u64) as usize)
    }

    /// Receive an unreliable, unordered datagram
    pub fn recv(&mut self) -> Option<Bytes> {
        self.conn.datagrams.recv()
    }

    /// Bytes available in the outgoing datagram buffer
    ///
    /// When greater than zero, [`send`](Self::send)ing a datagram of at most this size is
    /// guaranteed not to cause older datagrams to be dropped.
    pub fn send_buffer_space(&self) -> usize {
        self.conn
            .config
            .datagram_send_buffer_size
            .saturating_sub(self.conn.datagrams.outgoing.memory_used as usize)
            .saturating_sub(size_of::<QueuedDatagramProvider>())
    }
}

#[derive(Default)]
pub(super) struct DatagramState {
    pub(super) incoming: DatagramBuffer,
    pub(super) outgoing: DatagramSendBuffer,
    pub(super) send_blocked: bool,
}

impl DatagramState {
    pub(super) fn received(
        &mut self,
        datagram: Datagram,
        window: &Option<usize>,
    ) -> Result<bool, TransportError> {
        let window = match window {
            None => {
                return Err(TransportError::PROTOCOL_VIOLATION(
                    "unexpected DATAGRAM frame",
                ));
            }
            Some(x) => *x,
        };

        let size_with_overhead = datagram.data.len() + size_of::<Datagram>();

        if size_with_overhead > window {
            // A valid frame can still exceed the local memory budget because of queue metadata.
            debug!("dropping datagram exceeding receive memory budget");
            return Ok(false);
        }

        let was_empty = self.incoming.is_empty();
        while self.incoming.memory_used() + size_with_overhead > window {
            debug!("dropping stale datagram");
            self.recv();
        }

        self.incoming.push_back(datagram);
        Ok(was_empty)
    }

    pub(super) fn recv(&mut self) -> Option<Bytes> {
        let x = self.incoming.pop_front()?.data;
        Some(x)
    }
}

#[derive(Default)]
pub(super) struct DatagramBuffer {
    queue: VecDeque<Datagram>,
    payload_bytes: usize,
}

impl DatagramBuffer {
    fn push_back(&mut self, datagram: Datagram) {
        self.payload_bytes += datagram.data.len();
        self.queue.push_back(datagram);
    }

    fn pop_front(&mut self) -> Option<Datagram> {
        let datagram = self.queue.pop_front()?;
        self.payload_bytes -= datagram.data.len();
        Some(datagram)
    }

    fn memory_used(&self) -> usize {
        self.payload_bytes
            .saturating_add(self.queue.len() * size_of::<Datagram>())
    }

    pub(super) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[derive(Default)]
pub(super) struct DatagramSendBuffer {
    queue: VecDeque<QueuedDatagramProvider>,
    // if max_size is less than this, we know we cannot make progress until it increases
    min_max_size_to_send_1rtt: usize,
    // memory_used is the sum of a usize value for each element of a Vec. assuming usize fits
    // within u64, making this a u128 is the simplest way to make overflow impossible.
    //
    // between calls, memory_used is bounded by max_memory_used, which is a usize.
    memory_used: u128,
    // these reusable buffers are empty between calls
    to_transmit: Vec<Bytes>,
    to_enqueue: Vec<Box<dyn DatagramProvider>>,
}

impl DatagramSendBuffer {
    /// Discard outgoing datagrams with a payload larger than `max_payload` bytes
    ///
    /// Used to ensure that reductions in MTU don't get us stuck in a state where we have a datagram
    /// queued but can't send it.
    pub(super) fn drop_oversized(
        &mut self,
        max_payload: usize,
        max_memory_used: usize,
    ) -> Result<(), &'static str> {
        self.queue.retain_mut(|slot| {
            // remove
            let provider = replace(&mut slot.provider, Box::new(DummyDatagramProvider));
            self.memory_used -= slot.memory_used as u128;

            // drop_oversized and maybe replace
            if let Some(provider) = provider.drop_oversized(max_payload) {
                slot.memory_used = provider.memory_used(size_of::<QueuedDatagramProvider>());
                self.memory_used += slot.memory_used as u128;
                slot.provider = provider;
                true
            } else {
                false
            }
        });

        // make_space
        self.make_space(max_memory_used)
    }

    /// Attempt to write as many datagrams frames as currently possible into `buf`, consuming them
    /// from this buffer
    ///
    /// Returns the number of frames written. At most `max_size` bytes will be written, including
    /// framing.
    pub(super) fn write(
        &mut self,
        buf: &mut Vec<u8>,
        max_size: usize,
        max_memory_used: usize,
    ) -> Result<u64, &'static str> {
        let mut num_frames = 0;

        // dequeue loop
        while let Some(provider) = self.queue.pop_front() {
            self.memory_used -= provider.memory_used as u128;

            // provide
            debug_assert!(self.to_transmit.is_empty());
            debug_assert!(self.to_enqueue.is_empty());
            let replacement = provider.provider.provide(
                max_size - buf.len(),
                &mut self.to_transmit,
                &mut self.to_enqueue,
            );

            // infinite loop protection
            if self.to_transmit.is_empty() && !self.to_enqueue.is_empty() && replacement.is_none() {
                return Err("DatagramProvider.provide violated infinite loop protection");
            }

            // transmit datagrams
            num_frames += self.to_transmit.len() as u64;
            for data in self.to_transmit.drain(..) {
                debug_assert!(buf.len() <= max_size);
                Datagram { data }.encode(buf);
                if buf.len() > max_size {
                    return Err("DatagramProvider.provide violated max_size limit");
                }
            }

            // re-enqueue to back
            for provider in self.to_enqueue.drain(..) {
                let provider = QueuedDatagramProvider {
                    memory_used: provider.memory_used(size_of::<QueuedDatagramProvider>()),
                    provider,
                };
                self.memory_used += provider.memory_used as u128;
                self.queue.push_back(provider);
            }

            // replace at front
            let early_break = replacement.is_some();
            if let Some(provider) = replacement {
                let provider = QueuedDatagramProvider {
                    memory_used: provider.memory_used(size_of::<QueuedDatagramProvider>()),
                    provider,
                };
                self.memory_used += provider.memory_used as u128;
                self.queue.push_front(provider);
            }

            // make space
            self.make_space(max_memory_used)?;

            // break loop if provide returned Some
            if early_break {
                break;
            }
        }
        Ok(num_frames)
    }

    pub(super) fn can_send_1rtt(&self, max_size: usize) -> bool {
        max_size >= self.min_max_size_to_send_1rtt
    }

    fn push_back(
        &mut self,
        provider: Box<dyn DatagramProvider>,
        drop: bool,
        max_payload: usize,
        max_memory_used: usize,
    ) -> Result<(), SendDatagramError> {
        let Some(provider) = provider.drop_oversized(max_payload) else {
            return Err(SendDatagramError::TooLarge);
        };
        let mut provider = QueuedDatagramProvider {
            memory_used: provider.memory_used(size_of::<QueuedDatagramProvider>()),
            provider: provider,
        };
        let provider_mmu = if drop {
            max_memory_used
        } else {
            max_memory_used - self.memory_used as usize
        };
        if provider.memory_used > provider_mmu {
            let Some(successor) = provider
                .provider
                .make_space(provider_mmu, size_of::<QueuedDatagramProvider>())
            else {
                return if provider_mmu == max_memory_used {
                    Err(SendDatagramError::TooLarge)
                } else {
                    debug_assert!(!drop);
                    #[allow(unreachable_code)] // TODO
                    Err(SendDatagramError::Blocked(todo!()))
                };
            };
            provider.memory_used = successor.memory_used(size_of::<QueuedDatagramProvider>());
            provider.provider = successor;
            if provider.memory_used > provider_mmu {
                panic!(
                    "TODO this should be an error not a panic: DatagramProvider.make_space violated max_memory_used"
                );
            }
        }
        self.memory_used += provider.memory_used as u128;
        self.queue.push_back(provider);
        self.make_space(max_memory_used).expect("TODO");
        Ok(())
    }

    fn make_space(&mut self, max_memory_used: usize) -> Result<(), &'static str> {
        let mut i = 0;
        while self.memory_used > max_memory_used as u128 {
            // a DatagramProvider is always allowed to avoid eviction if it reports 0 memory_used
            if self.queue[i].memory_used == 0 {
                i += 1;
                continue;
            }

            // remove
            let provider = self.queue.remove(i).unwrap();
            self.memory_used -= provider.memory_used as u128;

            // make_space and maybe reinsert successor
            //
            // saturating sub because a DatagramProvider is always allowed to avoid eviction if it
            // reports 0 memory_used
            let provider_mmu = (max_memory_used as u128).saturating_sub(self.memory_used) as usize;
            if let Some(provider) = provider
                .provider
                .make_space(provider_mmu, size_of::<QueuedDatagramProvider>())
            {
                let provider = QueuedDatagramProvider {
                    memory_used: provider.memory_used(size_of::<QueuedDatagramProvider>()),
                    provider,
                };
                if provider.memory_used > provider_mmu {
                    return Err("DatagramProvider.make_space violated max_memory_used");
                }
                self.memory_used += provider.memory_used as u128;
                self.queue.insert(i, provider);
                i += 1;
            }
        }
        debug_assert!(self.memory_used <= max_memory_used as u128);
        Ok(())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

pub trait DatagramProvider: Send {
    /// Provide unreliable datagrams to be transmitted
    ///
    /// ## When this is called and how its outputs are interpreted
    ///
    /// When a connection's `DatagramProvider` queue is non-empty, and the connection has the
    /// ability to send a non-zero number of bytes of unreliable datagrams, it may pop the front of
    /// the queue and call `provide` on it. The `DatagramProvider` then has the chance to do the
    /// following things:
    ///
    /// - It can transmit unreliable datagrams by pushing them to `to_transmit`, within the byte
    ///   limit specified by `max_size`, including overhead.
    /// - It re-enqueue additional `DatagramProvider`s to the back of the queue by pushing them to
    ///   `to_enqueue`.
    /// - It can replace itself with a new `DatagramProvider` at the front of the queue by returning
    ///   `Some`.
    ///
    /// When a connection is polling for unreliable datagrams to transmit, it repeatedly pops the
    /// front of its `DatagramProvider` queue and calls `provide` on it until either the queue is
    /// empty or `provide` returns `Some`. If the loop is ended by `provide` returning `Some`,
    /// `provide` is typically not called again until `max_size` increases.
    ///
    /// ## Caller requirements
    ///
    /// The caller must pass a non-zero `max_size` and empty `to_transmit` and `to_enqueue`
    /// vectors.
    ///
    /// ## Implementation requirements
    ///
    /// When `provide` returns, the sum of the byte length of all entries in `to_transmit` plus
    /// the [`datagram_overhead`][1] of all entries in `to_transmit` must be less than or equal to
    /// `max_size`, or the connection will close with an error.
    ///
    /// [1]: crate::datagram_overhead
    ///
    /// To protect against infinite loops, when `provide` returns, at least one of the following
    /// must be true, or the connection will close with an error:
    ///
    /// - `to_transmit` is non-empty.
    /// - `to_enqueue` is empty.
    /// - The returned value is `Some`.
    ///
    /// ## Implementation conventions
    ///
    /// If `provide` returns `Some`, the returned `DatagramProvider` is re-inserted to the front
    /// of the queue, and `provide` is typically not called on it again until `max_size` increases.
    /// This means that a `DatagramProvider` blocks the `DatagramProvider`s behind it for as long
    /// as it and its successors return `Some`. A `DatagramProvider` should therefore make progress
    /// towards eventually returning `None` once `max_size` is large enough.
    ///
    /// Alternatively, `provide` can return `None` but also put `DatagramProvider`s in `to_enqueue`
    /// before returning. This allows it to put a successor in the back of the queue rather than
    /// the front, and yield to the next `DatagramProvider` while still allowing the successor to
    /// circle back to its successor if `max_size` remains high enough. If a `DatagramProvider`
    /// represents an entire dynamic queue of datagrams, this allows it to share the connection's
    /// bandwidth with other `DatagramProvider`s round-robin.
    ///
    /// However, if a `DatagramProvider` were allowed to re-insert itself as-is to `to_enqueue` and
    /// return `None`, the connection could enter an infinite loop of popping it from the front of
    /// the queue, moving it through `provide`, and pushing it back to the back of the queue.
    /// Therefore, a `DatagramProvider` should return `Some` until `max_size` is large enough to
    /// transmit at least one of the datagrams it represents before yielding in this fashion. The
    /// infinite loop protection mechanism exists to enforce this.
    fn provide(
        self: Box<Self>,
        max_size: usize,
        to_transmit: &mut Vec<Bytes>,
        to_enqueue: &mut Vec<Box<dyn DatagramProvider>>,
    ) -> Option<Box<dyn DatagramProvider>>;

    /// Discard outgoing datagrams with a payload larger than `max_payload` bytes
    ///
    /// When a `DatagramProvider` is first enqueued into the connection, the connection filters it
    /// through `drop_oversized` with the current MTU. If the MTU decreases, the connection filters
    /// all currently enqueued through `drop_oversized` again.
    ///
    /// If `drop_oversized` returns `Some`, it must ensure that the returned `DatagramProvider`'s
    /// [`provide`][1] implementation is not waiting for `max_size` to reach a value greater than
    /// `max_payload` before returning `None`. Otherwise, it could block unreliable datagram
    /// sending forever.
    ///
    /// If the connection removes a `DatagramProvider` from its queue and passes ownership of it to
    /// a method on itself, such as [`provide`][1], or [`make_space`][2], which returns successor
    /// `DatagramProvider`s to be re-inserted, the connection will not call `drop_oversized` on
    /// those successors unless the MTU decreases again. Therefore, `drop_oversized` must ensure
    /// that `max_payload` is inherited by not only the returned value, but also all its downstream
    /// successors.
    ///
    /// [1]: Self::provide
    /// [2]: Self::make_space
    fn drop_oversized(self: Box<Self>, max_payload: usize) -> Option<Box<dyn DatagramProvider>>;

    /// How many bytes of the connection's [`datagram_send_buffer_size`][1] budget `self` consumes
    ///
    /// When a `DatagramProvider` is enqueued into a connection's `DatagramProvider` queue, its
    /// `memory_used` value is counted against the connection's [`datagram_send_buffer_size`][1]
    /// budget until it is dequeued.
    ///
    /// After a `DatagramProvider` is enqueued into a connection's `DatagramProvider` queue, if the
    /// connection's `memory_used` total is over that budget, the `DatagramProvider` closest to the
    /// front of the queue will be repeatedly moved through [`make_space`][2] until it is no longer
    /// over budget.
    ///
    /// Whenever the connection calls a method of `DatagramProvider` that takes ownership of `self`
    /// and potentially returns successor(s), it counts as `self` being dequeued and the
    /// successor(s) being enqueued, thus providing an opportunity for `memory_used` to change.
    ///
    /// The caller passes `overhead` equalling the memory overhead for the caller to retain an
    /// individual `DatagramProvider`. `memory_used` is encouraged to saturating-add this to
    /// `self`'s own memory consumption.
    ///
    /// [1]: crate::TransportConfig::datagram_send_buffer_size
    /// [2]: Self::make_space
    fn memory_used(&self, overhead: usize) -> usize;

    /// Free up bytes of the connection's [`datagram_send_buffer_size`][1] budget consumed by `self`
    ///
    /// If this returns `Some`, the returned `DatagramProvider`'s [`memory_used`][2] value must be
    /// less than or equal to `max_memory_used`.
    ///
    /// When a connection's [`memory_used`][2] total is over its [`datagram_send_buffer_size`][1]
    /// budget, it repeatedly removes the oldest enqueued `DatagramProvider` with a non-zero
    /// [`memory_used`][2], calls `make_space` on it, and if `make_space` returns `Some`,
    /// re-inserts the returned `DatagramProvider` at the original position.
    ///
    /// [1]: crate::TransportConfig::datagram_send_buffer_size
    /// [2]: Self::memory_used
    fn make_space(
        self: Box<Self>,
        max_memory_used: usize,
        overhead: usize,
    ) -> Option<Box<dyn DatagramProvider>>;
}

struct DummyDatagramProvider;
impl DatagramProvider for DummyDatagramProvider {
    fn provide(
        self: Box<Self>,
        _: usize,
        _: &mut Vec<Bytes>,
        _: &mut Vec<Box<dyn DatagramProvider>>,
    ) -> Option<Box<dyn DatagramProvider>> {
        None
    }

    fn drop_oversized(self: Box<Self>, _: usize) -> Option<Box<dyn DatagramProvider>> {
        None
    }

    fn memory_used(&self, _: usize) -> usize {
        0xDEADBEEF
    }

    fn make_space(self: Box<Self>, _: usize, _: usize) -> Option<Box<dyn DatagramProvider>> {
        None
    }
}

pub struct BasicDatagramProvider(pub Bytes);
impl DatagramProvider for BasicDatagramProvider {
    fn provide(
        self: Box<Self>,
        max_size: usize,
        to_transmit: &mut Vec<Bytes>,
        _: &mut Vec<Box<dyn DatagramProvider>>,
    ) -> Option<Box<dyn DatagramProvider>> {
        if datagram_overhead(self.0.len()) + self.0.len() <= max_size {
            to_transmit.push(self.0);
            None
        } else {
            Some(self)
        }
    }

    fn drop_oversized(self: Box<Self>, max_payload: usize) -> Option<Box<dyn DatagramProvider>> {
        if datagram_overhead(self.0.len()) + self.0.len() <= max_payload {
            Some(self)
        } else {
            None
        }
    }

    fn memory_used(&self, overhead: usize) -> usize {
        size_of::<Self>()
            .saturating_sub(self.0.len())
            .saturating_sub(overhead)
    }

    fn make_space(
        self: Box<Self>,
        max_memory_used: usize,
        overhead: usize,
    ) -> Option<Box<dyn DatagramProvider>> {
        if size_of::<Self>()
            .saturating_sub(self.0.len())
            .saturating_sub(overhead)
            <= max_memory_used
        {
            Some(self)
        } else {
            None
        }
    }
}

struct QueuedDatagramProvider {
    provider: Box<dyn DatagramProvider>,
    memory_used: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_frame_flood_limit() {
        let mut state = DatagramState::default();
        let datagram = Datagram { data: Bytes::new() };
        let window = 100;
        loop {
            let initial_count = state.incoming.queue.len();
            state.received(datagram.clone(), &Some(window)).unwrap();
            assert!(state.incoming.queue.len() * size_of::<Datagram>() <= window);
            if state.incoming.queue.len() == initial_count {
                // Datagrams are getting dropped
                break;
            }
        }
    }
}

/// Errors that can arise when sending a datagram
#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SendDatagramError {
    /// The peer does not support receiving datagram frames
    #[error("datagrams not supported by peer")]
    UnsupportedByPeer,
    /// Datagram support is disabled locally
    #[error("datagram support disabled")]
    Disabled,
    /// The datagram is larger than the connection can currently accommodate
    ///
    /// Indicates that the path MTU minus overhead or the limit advertised by the peer has been
    /// exceeded.
    #[error("datagram too large")]
    TooLarge,
    /// Send would block
    #[error("datagram send blocked")]
    Blocked(Bytes),
}
