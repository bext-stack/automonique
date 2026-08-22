// SPDX-License-Identifier: Elastic-2.0

//! The live fan-out authority: one bounded replay per attempt, and one bounded
//! queue per subscriber.
//!
//! # Why this exists, given that the spool already holds everything
//!
//! Because nothing can read the spool while the attempt owns it. The runner
//! takes an exclusive `flock` for the whole attempt — that is what makes the
//! writer single, and it is load-bearing — so the durable record is unreadable
//! by anyone else until the terminal event is written and the lock released.
//! Between those two moments a chat bridge has nothing to draw.
//!
//! So there are two tiers, and they are different things:
//!
//! - **This hub** is a short-lived echo. It holds what the backend just
//!   appended, keyed by the sequence the spool gave it, and it forgets the
//!   oldest when it fills. It is not a record and no decision may rest on it.
//! - **The spool** is the record. After the attempt is terminal it re-opens and
//!   replays in full, hash-chain verified, from any cursor.
//!
//! A consumer therefore reads live frames here and complete ones there, and the
//! sequence means the same thing in both — which is what makes moving between
//! them a continuation rather than a re-read.
//!
//! # The two-tier replay story, and the number that sizes it
//!
//! [`HUB_TERMINAL_RETENTION`] is the whole of what this tier promises: an
//! attempt that reached its terminal is kept for that long and then forgotten.
//! It is sized to cover a *bridge restart* — a connector process that dies and
//! comes back within seconds resumes from its cursor and misses nothing — and
//! deliberately not sized to be a record. Anything longer would be this tier
//! pretending to be the spool while still evicting under
//! [`HUB_ATTEMPT_FRAMES`] and [`HUB_ATTEMPT_BYTES`], which is the worst of both:
//! a window that looks like a log. A consumer that needs completeness reads the
//! spool, and the [`StreamMessage::ResyncRequired`] answer is how it is told to.
//!
//! # Two ways a subscriber's stream stops, and neither is a cancellation
//!
//! **A transport disconnect is never a cancellation.** Nothing in this module
//! stops, signals, kills or un-admits a run. Dropping every subscriber, closing
//! the socket, and dropping the hub itself all leave every attempt running
//! exactly as it was; cancellation is the explicit dispatcher path
//! ([`crate::attempt_host`], reached from the Execute lane's `cancel_run` and
//! the CLI's `cancel` verb) and there is no route from here to there. This is
//! the same rule the runner's control socket states — "peer disconnection is
//! never interpreted as cancellation" — and it holds here for a stronger
//! reason: this endpoint holds no containment handle, no cancellation sink and
//! no registration, so it could not cancel anything if it decided to.
//!
//! What *does* stop is one subscriber's stream, in one of two ways, and they
//! are two wire kinds because a client acts on them differently:
//!
//! - [`StreamMessage::Lagged`] — this subscriber could not take frames as fast
//!   as they were produced, so its queue was discarded and it was disconnected.
//!   Frames exist that it did not receive. It reconnects with the cursor the
//!   message carries and either resumes exactly or is told to resync.
//! - [`StreamMessage::Retired`] — the attempt is terminal. Everything queued was
//!   delivered first, and there is nothing further to receive live.
//!
//! Both are distinct again from a `run_terminal` [`ProgressFrame`], which is the
//! *provider stream's* end travelling inside a frame. Three endings, three
//! things to draw.
//!
//! # The producer never blocks
//!
//! [`ProgressHub::publish`] is called by the thread supervising a live process
//! tree, between two polls of it. It therefore takes one short lock, appends to
//! a ring, hands one reference-counted payload to each subscriber's queue, and
//! returns. It never waits on a socket, never waits on a writer thread, and
//! never applies backpressure: a subscriber whose queue would exceed
//! [`SUBSCRIBER_QUEUE_FRAMES`] or [`SUBSCRIBER_QUEUE_BYTES`] has its *whole
//! queue discarded*, is marked lagged, and is disconnected. Dropping a slow
//! reader is the correct trade here and it is not close: the durable record
//! already has every frame, and the alternative — slowing the supervisor of a
//! live workload because a chat client is busy — would let a renderer affect a
//! run.
//!
//! # Threads, and their budget
//!
//! One accept thread for the endpoint, plus exactly one writer thread per
//! connected subscriber, bounded at [`HUB_SUBSCRIBERS`]. The bound is checked
//! *before* a thread is spawned and before a request byte is parsed, so a peer
//! over the ceiling costs one refusal on the accept thread and nothing else.
//! Every writer is joined by [`ProgressEndpoint::shutdown`], which is what makes
//! the endpoint's end of life a fact rather than a hope.
//!
//! # Locks, and their order
//!
//! Two levels, and one rule: **the hub lock is outermost, and a queue lock is
//! never held while the hub lock is taken.** The producer holds the hub lock and
//! reaches into each queue; a writer takes its queue lock, releases it with
//! owned data in hand, and only then touches the hub. Every method here is
//! written so that discipline is visible at the call site rather than promised.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::socket::{MsgFlags, getsockopt, recv, sockopt};
use nix::unistd::geteuid;

use automonique_observability::ProgressObservation;
use automonique_protocol::admin::ADMIN_CAPABILITY;
use automonique_protocol::codec::{FrameDecode, LENGTH_PREFIX_BYTES, decode_frame, encode_frame};
use automonique_protocol::event::SubscriptionStart;
use automonique_protocol::progress_api::{
    MAX_SUBSCRIBE_CANONICAL_BYTES, ProgressFrame, StreamMessage, StreamRefusal, SubscribeRequest,
    resume_from,
};
use automonique_runner::backend::ProgressPublisher;

/// Frames one attempt may have retained at once.
pub const HUB_ATTEMPT_FRAMES: usize = 512;

/// Bytes of retained payload one attempt may hold at once.
pub const HUB_ATTEMPT_BYTES: usize = 512 * 1024;

/// Attempts the hub retains frames for at once.
///
/// Comfortably above the execution lane's own live-attempt ceiling, so the hub
/// is never the thing that stops a run from being watched; the bound is here to
/// keep a leaked retirement from becoming unbounded memory rather than to
/// ration anything.
pub const HUB_ATTEMPTS: usize = 64;

/// How long an attempt's frames survive its terminal.
///
/// A policy number, and the module documentation says what it is a policy
/// about: covering a bridge restart, and not pretending to be the record. Thirty
/// seconds is generous for a connector that dies and is restarted by its
/// supervisor, and short enough that a finished attempt's window is gone long
/// before it could be mistaken for durable.
pub const HUB_TERMINAL_RETENTION: Duration = Duration::from_secs(30);

/// Subscribers this hub serves at once.
///
/// Counted from the peers that actually exist: the CLI's subscribe verb, the two
/// chat connectors, and one desktop client, with headroom for a second of each
/// during a handover. A ninth is refused with
/// [`StreamRefusal::SubscriberLimit`] rather than served worse, because each
/// subscriber costs a thread and every thread here is joined.
pub const HUB_SUBSCRIBERS: usize = 8;

/// Frames one subscriber's queue may hold before it is judged to have lagged.
pub const SUBSCRIBER_QUEUE_FRAMES: usize = 256;

/// Bytes one subscriber's queue may hold before it is judged to have lagged.
pub const SUBSCRIBER_QUEUE_BYTES: usize = 256 * 1024;

/// Filename of the live progress endpoint, a sibling of the admin socket.
pub const PROGRESS_SOCKET_NAME: &str = concat!("progress", ".sock");

/// Deadline for one read or one write on a subscriber's connection.
///
/// This is a liveness backstop, not the backpressure mechanism. Backpressure is
/// the queue bound: a subscriber that is merely slow fills its socket buffer and
/// then its queue, and is told it lagged. A subscriber that has not taken a byte
/// in two seconds is not slow, it is gone, and the connection is closed as a
/// transport failure — which, like every other disconnect here, cancels nothing.
const IO_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a writer waits for a frame before looking at the stop flag.
const WRITER_POLL: Duration = Duration::from_millis(100);

/// How long the accept loop waits between polls of a nonblocking listener.
const ACCEPT_POLL: Duration = Duration::from_millis(25);

/// Usable bytes of `sockaddr_un::sun_path` on Linux, excluding the terminator.
const MAX_SOCKET_PATH_BYTES: usize = 107;

/// One retained frame: its durable position, its canonical bytes, and when it
/// arrived.
///
/// The payload is shared rather than copied: one frame reaches the ring and up
/// to [`HUB_SUBSCRIBERS`] queues, and the producer is a supervisor loop that
/// should not be memcpy-ing a frame nine times.
#[derive(Clone, Debug)]
struct Retained {
    sequence: u64,
    payload: Arc<[u8]>,
    at: Instant,
}

/// What one attempt has retained, and whether it has finished.
#[derive(Debug)]
struct AttemptRing {
    frames: VecDeque<Retained>,
    bytes: usize,
    /// When the attempt reached its terminal, if it has.
    ///
    /// `None` is a live attempt. `Some` starts the [`HUB_TERMINAL_RETENTION`]
    /// clock, and the frames stay readable for the whole of it.
    terminal_at: Option<Instant>,
}

impl AttemptRing {
    fn new() -> Self {
        Self {
            frames: VecDeque::new(),
            bytes: 0,
            terminal_at: None,
        }
    }

    /// Retain one frame, evicting the oldest until both bounds hold.
    ///
    /// Returns the shared payload so the caller can fan it out without copying.
    fn retain(&mut self, sequence: u64, payload: &[u8], at: Instant) -> Option<Arc<[u8]>> {
        // A frame larger than the whole ring is not retained: evicting
        // everything to hold one would turn a replay buffer into a single-frame
        // buffer, which is worse than not answering.
        if payload.len() > HUB_ATTEMPT_BYTES {
            return None;
        }
        let payload: Arc<[u8]> = Arc::from(payload);
        self.frames.push_back(Retained {
            sequence,
            payload: Arc::clone(&payload),
            at,
        });
        self.bytes = self.bytes.saturating_add(payload.len());
        while self.frames.len() > HUB_ATTEMPT_FRAMES || self.bytes > HUB_ATTEMPT_BYTES {
            let Some(dropped) = self.frames.pop_front() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(dropped.payload.len());
        }
        Some(payload)
    }

    /// The inclusive window this ring still holds, or nothing.
    fn window(&self) -> Option<(u64, u64)> {
        let first = self.frames.front()?.sequence;
        let last = self.frames.back()?.sequence;
        Some((first, last))
    }

    /// Whether this attempt's retention has elapsed.
    fn expired(&self, now: Instant) -> bool {
        self.terminal_at
            .is_some_and(|at| now.duration_since(at) >= HUB_TERMINAL_RETENTION)
    }
}

/// How one subscriber's stream ended.
///
/// Two variants and no third: a stream that has not ended has no value here at
/// all, which is what makes the terminal message unambiguous when the writer
/// finds one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamEnd {
    /// The subscriber fell behind; its queue was discarded.
    Lagged,
    /// The attempt is terminal; the queue was delivered first.
    Retired,
}

/// What one subscriber's queue holds, under its own lock.
#[derive(Debug, Default)]
struct QueueState {
    frames: VecDeque<Arc<[u8]>>,
    bytes: usize,
    /// Set once, and never cleared. A queue that has ended takes nothing more.
    end: Option<StreamEnd>,
}

/// One subscriber's bounded queue and the signal its writer waits on.
#[derive(Debug, Default)]
struct SubscriberQueue {
    state: Mutex<QueueState>,
    ready: Condvar,
}

/// What one offer did to a subscriber's queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Offered {
    /// Bytes the queue held at its fullest during this offer.
    high_water_bytes: usize,
    /// Frames discarded, which is non-zero exactly when the queue lagged.
    dropped: usize,
}

impl SubscriberQueue {
    /// Hand one frame to this subscriber, or discard its whole queue.
    ///
    /// Never blocks on anything but its own short lock, and never fails: a queue
    /// that has already ended silently ignores the frame, because the subscriber
    /// it belonged to has been told its stream is over and telling it again
    /// would be a second ending.
    fn offer(&self, payload: &Arc<[u8]>) -> Offered {
        let Ok(mut state) = self.state.lock() else {
            return Offered {
                high_water_bytes: 0,
                dropped: 0,
            };
        };
        if state.end.is_some() {
            return Offered {
                high_water_bytes: 0,
                dropped: 0,
            };
        }
        state.frames.push_back(Arc::clone(payload));
        state.bytes = state.bytes.saturating_add(payload.len());
        // Measured before the discard, because the number worth reporting is how
        // full the queue got, not how empty it was left.
        let high_water_bytes = state.bytes;
        let mut dropped = 0;
        if state.frames.len() > SUBSCRIBER_QUEUE_FRAMES || state.bytes > SUBSCRIBER_QUEUE_BYTES {
            dropped = state.frames.len();
            state.frames.clear();
            state.bytes = 0;
            state.end = Some(StreamEnd::Lagged);
        }
        self.ready.notify_one();
        Offered {
            high_water_bytes,
            dropped,
        }
    }

    /// End this subscriber's stream without discarding what it has not read.
    ///
    /// The difference from a lag is the whole distinction the two wire kinds
    /// carry: a retirement flushes, a lag discards.
    fn finish(&self, end: StreamEnd) {
        if let Ok(mut state) = self.state.lock()
            && state.end.is_none()
        {
            state.end = Some(end);
        }
        self.ready.notify_all();
    }

    /// Take everything queued, waiting up to `timeout` for the first frame.
    ///
    /// Returns with the lock released, which is what lets the caller write to a
    /// socket — an operation that may block for as long as the peer likes —
    /// without the producer ever waiting on it.
    fn take(&self, timeout: Duration) -> (Vec<Arc<[u8]>>, Option<StreamEnd>) {
        let Ok(mut state) = self.state.lock() else {
            // A poisoned queue is a writer that panicked. There is nothing to
            // deliver and no way to learn more; ending the stream is the only
            // honest answer.
            return (Vec::new(), Some(StreamEnd::Lagged));
        };
        if state.frames.is_empty() && state.end.is_none() {
            let Ok((guard, _)) = self.ready.wait_timeout(state, timeout) else {
                return (Vec::new(), Some(StreamEnd::Lagged));
            };
            state = guard;
        }
        state.bytes = 0;
        let frames = state.frames.drain(..).collect();
        (frames, state.end)
    }
}

/// One connected subscriber, as the hub sees it.
struct SubscriberSlot {
    id: u64,
    run_id: String,
    queue: Arc<SubscriberQueue>,
}

/// Everything one hub holds, under one lock.
///
/// One lock over the rings *and* the subscribers rather than one each: every
/// operation is a push or a scan of a bounded collection, and publishing one
/// frame under two locks would be a producer with an ordering rule to get wrong.
#[derive(Default)]
struct HubState {
    attempts: BTreeMap<String, AttemptRing>,
    subscribers: Vec<SubscriberSlot>,
    next_subscriber_id: u64,
}

/// Cumulative counters this hub reports through the observability lane.
///
/// Atomics rather than fields under the hub lock, so reading them for a status
/// answer never contends with a supervisor publishing a frame.
#[derive(Debug, Default)]
struct HubMetrics {
    queue_high_water_bytes: AtomicU64,
    frames_dropped: AtomicU64,
    lag_disconnects: AtomicU64,
}

impl HubMetrics {
    fn record(&self, offered: Offered) {
        let high_water = u64::try_from(offered.high_water_bytes).unwrap_or(u64::MAX);
        self.queue_high_water_bytes
            .fetch_max(high_water, Ordering::Relaxed);
        if offered.dropped > 0 {
            self.frames_dropped.fetch_add(
                u64::try_from(offered.dropped).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            self.lag_disconnects.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Live replay and fan-out for the attempts this daemon is running.
#[derive(Default)]
pub struct ProgressHub {
    state: Mutex<HubState>,
    metrics: HubMetrics,
}

impl std::fmt::Debug for ProgressHub {
    /// Deliberately narrow: no run identifier, no frame and no subscriber
    /// identity reaches a debug rendering.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProgressHub")
            .field("attempts", &self.retained_attempts())
            .field("subscribers", &self.subscriber_count())
            .finish_non_exhaustive()
    }
}

impl ProgressHub {
    /// Start an empty hub.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A publisher the runner's backend can hand appended frames to.
    ///
    /// Returned as the runner's own trait object so the backend depends on the
    /// seam rather than on this type.
    #[must_use]
    pub fn publisher(self: &Arc<Self>, run_id: &str) -> Box<dyn ProgressPublisher> {
        Box::new(HubPublisher {
            hub: Arc::clone(self),
            run_id: run_id.to_owned(),
        })
    }

    /// Retain one appended frame and hand it to every subscriber watching.
    ///
    /// Silent on every failure. This is called between two polls of a live
    /// process tree by the thread that owns it, and there is nothing a replay
    /// buffer could report that would be worth interrupting that for — the
    /// durable record already has the frame.
    pub fn publish(&self, run_id: &str, sequence: u64, payload: &[u8]) {
        self.publish_at(run_id, sequence, payload, Instant::now());
    }

    /// [`ProgressHub::publish`] against a caller-supplied instant.
    ///
    /// The clock seam. Retention is a duration since an event rather than a wall
    /// time, so it is measured on the monotonic clock, and a test that needs to
    /// watch a window expire supplies its own instants rather than sleeping
    /// through one.
    pub fn publish_at(&self, run_id: &str, sequence: u64, payload: &[u8], at: Instant) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if !state.attempts.contains_key(run_id) && state.attempts.len() >= HUB_ATTEMPTS {
            return;
        }
        let Some(shared) = state
            .attempts
            .entry(run_id.to_owned())
            .or_insert_with(AttemptRing::new)
            .retain(sequence, payload, at)
        else {
            return;
        };
        for slot in &state.subscribers {
            if slot.run_id == run_id {
                self.metrics.record(slot.queue.offer(&shared));
            }
        }
    }

    /// Every retained frame after `cursor`, in sequence order.
    ///
    /// A frame that no longer decodes is skipped rather than refused: the bytes
    /// came from this build's own encoder moments ago, so a decode failure is
    /// this process disagreeing with itself, and the durable spool is where a
    /// reader goes for an answer it can rely on.
    #[must_use]
    pub fn frames_after(&self, run_id: &str, cursor: u64) -> Vec<ProgressFrame> {
        let Ok(state) = self.state.lock() else {
            return Vec::new();
        };
        state.attempts.get(run_id).map_or_else(Vec::new, |ring| {
            ring.frames
                .iter()
                .filter(|frame| frame.sequence > cursor)
                .filter_map(|frame| ProgressFrame::from_canonical_bytes(&frame.payload).ok())
                .collect()
        })
    }

    /// The oldest sequence still retained for one attempt.
    ///
    /// A reader whose cursor is below this has fallen out of the window and
    /// must read the durable spool instead. `None` means nothing is retained,
    /// which is also the answer for an attempt that never streamed.
    #[must_use]
    pub fn oldest_retained(&self, run_id: &str) -> Option<u64> {
        let state = self.state.lock().ok()?;
        Some(state.attempts.get(run_id)?.window()?.0)
    }

    /// Record that one attempt reached its terminal.
    ///
    /// Two things happen, and they are deliberately different: every subscriber
    /// watching this attempt is finished with [`StreamMessage::Retired`] *after*
    /// what it has queued, because the spool is readable from this moment and is
    /// strictly better; and the frames stay for [`HUB_TERMINAL_RETENTION`], so a
    /// bridge that restarts inside that window still resumes from its cursor.
    ///
    /// It is not a cancellation and it does not become one: this method is
    /// called *because* an attempt ended, never to make one end.
    pub fn retire(&self, run_id: &str) {
        self.retire_at(run_id, Instant::now());
    }

    /// [`ProgressHub::retire`] against a caller-supplied instant.
    pub fn retire_at(&self, run_id: &str, at: Instant) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if let Some(ring) = state.attempts.get_mut(run_id) {
            ring.terminal_at.get_or_insert(at);
        }
        for slot in &state.subscribers {
            if slot.run_id == run_id {
                slot.queue.finish(StreamEnd::Retired);
            }
        }
        // Swept here rather than on every publish: a sweep is a scan of a
        // bounded map, and a retirement is the only event that can make one
        // necessary. A finished attempt therefore costs at most one scan.
        Self::sweep_locked(&mut state, at);
    }

    /// Forget every attempt whose retention has elapsed.
    ///
    /// Exposed so a caller with its own cadence can bound the hub's memory
    /// between retirements. It is never required for correctness — a retirement
    /// sweeps, and [`HUB_ATTEMPTS`] bounds what a missed sweep can hold.
    pub fn sweep(&self) {
        self.sweep_at(Instant::now());
    }

    /// [`ProgressHub::sweep`] against a caller-supplied instant.
    pub fn sweep_at(&self, now: Instant) {
        if let Ok(mut state) = self.state.lock() {
            Self::sweep_locked(&mut state, now);
        }
    }

    fn sweep_locked(state: &mut HubState, now: Instant) {
        state.attempts.retain(|_, ring| !ring.expired(now));
    }

    /// How many attempts are retained. For metrics and tests.
    #[must_use]
    pub fn retained_attempts(&self) -> usize {
        self.state.lock().map_or(0, |state| state.attempts.len())
    }

    /// How many subscribers are attached. For metrics and tests.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.state.lock().map_or(0, |state| state.subscribers.len())
    }

    /// What this hub has observed, for the operational projection.
    #[must_use]
    pub fn observation(&self) -> ProgressObservation {
        self.observation_at(Instant::now())
    }

    /// [`ProgressHub::observation`] against a caller-supplied instant.
    #[must_use]
    pub fn observation_at(&self, now: Instant) -> ProgressObservation {
        let oldest_retained_age_ms = self.state.lock().map_or(0, |state| {
            state
                .attempts
                .values()
                .filter_map(|ring| ring.frames.front())
                .map(|frame| now.saturating_duration_since(frame.at))
                .max()
                .map_or(0, |age| u64::try_from(age.as_millis()).unwrap_or(u64::MAX))
        });
        ProgressObservation {
            queue_high_water_bytes: self.metrics.queue_high_water_bytes.load(Ordering::Relaxed),
            frames_dropped: self.metrics.frames_dropped.load(Ordering::Relaxed),
            lag_disconnects: self.metrics.lag_disconnects.load(Ordering::Relaxed),
            oldest_retained_age_ms,
        }
    }

    /// Attach one subscriber at `cursor`, or say why it cannot resume there.
    ///
    /// The decision and the attachment happen under one lock, which is what
    /// makes resumption exact: there is no instant between "what is retained
    /// after your cursor" and "you are now receiving new frames" in which a
    /// frame could be published and belong to neither.
    ///
    /// A [`SubscriptionStart::ResyncRequired`] answer attaches nothing and
    /// carries the window this hub does hold, so the caller can say exactly what
    /// is missing rather than merely that something is.
    pub fn subscribe(self: &Arc<Self>, run_id: &str, cursor: u64) -> Subscription {
        self.subscribe_at(run_id, cursor, Instant::now())
    }

    /// [`ProgressHub::subscribe`] against a caller-supplied instant.
    pub fn subscribe_at(self: &Arc<Self>, run_id: &str, cursor: u64, now: Instant) -> Subscription {
        let Ok(mut state) = self.state.lock() else {
            // A poisoned hub retains nothing anybody may rely on. Answering
            // "resync from the spool" is the one answer that stays true.
            return Subscription {
                start: SubscriptionStart::ResyncRequired {
                    snapshot_from: 0,
                    snapshot_to: 0,
                },
                feed: None,
            };
        };
        Self::sweep_locked(&mut state, now);
        let window = state.attempts.get(run_id).and_then(AttemptRing::window);
        let start = resume_from(cursor, window);
        if matches!(start, SubscriptionStart::ResyncRequired { .. }) {
            return Subscription { start, feed: None };
        }
        let queue = Arc::new(SubscriberQueue::default());
        if let Some(ring) = state.attempts.get(run_id) {
            for frame in ring.frames.iter().filter(|frame| frame.sequence > cursor) {
                self.metrics.record(queue.offer(&frame.payload));
            }
            // A subscriber attaching to an attempt that has already finished is
            // told so once it has drained the replay, exactly as one that was
            // attached when it finished would be.
            if ring.terminal_at.is_some() {
                queue.finish(StreamEnd::Retired);
            }
        }
        let id = state.next_subscriber_id;
        state.next_subscriber_id = state.next_subscriber_id.saturating_add(1);
        state.subscribers.push(SubscriberSlot {
            id,
            run_id: run_id.to_owned(),
            queue: Arc::clone(&queue),
        });
        Subscription {
            start,
            feed: Some(SubscriberFeed {
                hub: Arc::clone(self),
                id,
                queue,
            }),
        }
    }

    /// Detach one subscriber. Called only by [`SubscriberFeed`]'s drop.
    fn release(&self, id: u64) {
        if let Ok(mut state) = self.state.lock() {
            state.subscribers.retain(|slot| slot.id != id);
        }
    }
}

/// What one attempt's binding of the hub to the runner's publishing seam is.
struct HubPublisher {
    hub: Arc<ProgressHub>,
    run_id: String,
}

impl ProgressPublisher for HubPublisher {
    fn publish(&self, sequence: u64, payload: &[u8]) {
        self.hub.publish(&self.run_id, sequence, payload);
    }
}

/// The answer to one subscription request.
pub struct Subscription {
    start: SubscriptionStart,
    feed: Option<SubscriberFeed>,
}

impl Subscription {
    /// Where this subscriber may resume, in the protocol's own vocabulary.
    #[must_use]
    pub const fn start(&self) -> SubscriptionStart {
        match self.start {
            SubscriptionStart::Live { from } => SubscriptionStart::Live { from },
            SubscriptionStart::ResyncRequired {
                snapshot_from,
                snapshot_to,
            } => SubscriptionStart::ResyncRequired {
                snapshot_from,
                snapshot_to,
            },
        }
    }

    /// The attached feed, absent exactly when the answer was a resync.
    #[must_use]
    pub fn into_feed(self) -> Option<SubscriberFeed> {
        self.feed
    }
}

/// One subscriber's end of the fan-out.
///
/// Holding it is what keeps the hub's slot alive; dropping it releases the slot,
/// on every path out including a panic. That is the whole of the lifecycle, and
/// it is why nothing else in this module removes a subscriber.
pub struct SubscriberFeed {
    hub: Arc<ProgressHub>,
    id: u64,
    queue: Arc<SubscriberQueue>,
}

impl SubscriberFeed {
    /// Take everything queued, waiting up to [`WRITER_POLL`] for the first
    /// frame, and say whether the stream ended.
    ///
    /// The queue lock is released before this returns, so a caller may spend as
    /// long as it likes writing what it was handed without the producer ever
    /// waiting on it.
    fn take(&self) -> (Vec<Arc<[u8]>>, Option<StreamEnd>) {
        self.queue.take(WRITER_POLL)
    }
}

impl Drop for SubscriberFeed {
    fn drop(&mut self) {
        self.hub.release(self.id);
    }
}

/// Why a progress endpoint could not be bound or started.
///
/// Host-side failures, none of which is reachable from the wire.
#[derive(Debug)]
pub enum ProgressEndpointError {
    /// A filesystem or socket operation failed.
    Io(std::io::Error),
    /// The socket path is not absolute, or names no final component.
    SocketPathNotAbsolute,
    /// The socket path does not fit `sockaddr_un::sun_path`.
    SocketPathTooLong,
    /// The named socket is not an owned mode-`0600` socket, or its identity
    /// drifted between inspection and unlink.
    UnsafeSocket,
    /// Another process is accepting connections at this path.
    SocketInUse,
    /// This process runs as root. A root endpoint would have to admit root
    /// peers, so it refuses to exist instead.
    RootEffectiveUid,
    /// The endpoint was started twice.
    AlreadyStarted,
}

impl ProgressEndpointError {
    /// Stable category spelling for logs and refusal metrics.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Io(_) => "progress_io",
            Self::SocketPathNotAbsolute => "progress_socket_path_not_absolute",
            Self::SocketPathTooLong => "progress_socket_path_too_long",
            Self::UnsafeSocket => "progress_unsafe_socket",
            Self::SocketInUse => "progress_socket_in_use",
            Self::RootEffectiveUid => "progress_root_effective_uid",
            Self::AlreadyStarted => "progress_already_started",
        }
    }
}

impl std::fmt::Display for ProgressEndpointError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "progress endpoint I/O failed: {error}"),
            Self::SocketPathNotAbsolute => {
                formatter.write_str("progress socket path is not an absolute file path")
            }
            Self::SocketPathTooLong => write!(
                formatter,
                "progress socket path exceeds {MAX_SOCKET_PATH_BYTES} bytes of sun_path"
            ),
            Self::UnsafeSocket => {
                formatter.write_str("progress socket path is not a private owned socket")
            }
            Self::SocketInUse => {
                formatter.write_str("progress socket path already has a live listener")
            }
            Self::RootEffectiveUid => {
                formatter.write_str("progress endpoint refused: effective UID is root")
            }
            Self::AlreadyStarted => formatter.write_str("progress endpoint is already serving"),
        }
    }
}

impl std::error::Error for ProgressEndpointError {}

impl From<std::io::Error> for ProgressEndpointError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// The socket subscribers connect to, and the threads that answer them.
///
/// Binding and serving are two steps on purpose, and it is the same split the
/// daemon makes for its own socket: opening one composes an endpoint and starts
/// no thread, so a process that bound and never served has answered nobody.
/// [`ProgressEndpoint::start`] is what puts the accept loop on a thread, and
/// [`ProgressEndpoint::shutdown`] is what takes it and every writer off again.
pub struct ProgressEndpoint {
    listener: Option<UnixListener>,
    socket_path: PathBuf,
    socket_identity: (u64, u64),
    hub: Arc<ProgressHub>,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl ProgressEndpoint {
    /// Bind the socket at `socket_path` with mode `0600`, serving `hub`.
    ///
    /// The containing directory is not created here: this endpoint is a sibling
    /// of the admin socket inside a runtime directory the daemon has already
    /// established and validated, and creating it a second time would be a
    /// second opinion about whether it is private.
    ///
    /// # Errors
    ///
    /// Returns [`ProgressEndpointError::RootEffectiveUid`] when this process is
    /// root, [`ProgressEndpointError::SocketPathNotAbsolute`] or
    /// [`ProgressEndpointError::SocketPathTooLong`] before any filesystem call,
    /// [`ProgressEndpointError::UnsafeSocket`] when the path is not a private
    /// owned socket, and [`ProgressEndpointError::SocketInUse`] when a live
    /// listener already answers there.
    pub fn bind(
        socket_path: impl Into<PathBuf>,
        hub: Arc<ProgressHub>,
    ) -> Result<Self, ProgressEndpointError> {
        let socket_path = socket_path.into();
        if !socket_path.is_absolute() || socket_path.file_name().is_none() {
            return Err(ProgressEndpointError::SocketPathNotAbsolute);
        }
        if socket_path.as_os_str().len() > MAX_SOCKET_PATH_BYTES {
            return Err(ProgressEndpointError::SocketPathTooLong);
        }
        let admitted_uid = geteuid().as_raw();
        if admitted_uid == 0 {
            return Err(ProgressEndpointError::RootEffectiveUid);
        }
        prepare_socket_path(&socket_path, admitted_uid)?;
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::symlink_metadata(&socket_path)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != admitted_uid
            || metadata.mode() & 0o7777 != 0o600
        {
            // The inode answering this name is not the one just created, so
            // unlinking it would delete a replacement. Refuse without unlink.
            return Err(ProgressEndpointError::UnsafeSocket);
        }
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener: Some(listener),
            socket_path,
            socket_identity: (metadata.dev(), metadata.ino()),
            hub,
            stop: Arc::new(AtomicBool::new(false)),
            accept: None,
        })
    }

    /// Bound socket path.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Put the accept loop on a thread.
    ///
    /// # Errors
    ///
    /// Returns [`ProgressEndpointError::AlreadyStarted`] on a second call, and
    /// [`ProgressEndpointError::Io`] if the listener could not be handed over.
    pub fn start(&mut self) -> Result<(), ProgressEndpointError> {
        if self.accept.is_some() {
            return Err(ProgressEndpointError::AlreadyStarted);
        }
        let listener = self
            .listener
            .take()
            .ok_or(ProgressEndpointError::AlreadyStarted)?;
        let hub = Arc::clone(&self.hub);
        let stop = Arc::clone(&self.stop);
        self.accept = Some(std::thread::spawn(move || {
            accept_loop(&listener, &hub, &stop)
        }));
        Ok(())
    }

    /// Stop accepting, join every thread, and unlink the socket.
    ///
    /// Joining is the point: a daemon must not return while a writer thread is
    /// still holding a subscriber slot on a hub the daemon is about to drop. It
    /// cancels nothing — see this module's documentation — and every attempt
    /// that was running keeps running.
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
    }
}

impl std::fmt::Debug for ProgressEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProgressEndpoint")
            .field("serving", &self.accept.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for ProgressEndpoint {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        let Ok(metadata) = fs::symlink_metadata(&self.socket_path) else {
            return;
        };
        // Only the exact inode this endpoint created is unlinked; a replacement
        // observed by this check survives.
        if metadata.file_type().is_socket()
            && metadata.uid() == geteuid().as_raw()
            && metadata.mode() & 0o7777 == 0o600
            && (metadata.dev(), metadata.ino()) == self.socket_identity
        {
            let _ = fs::remove_file(&self.socket_path);
        }
    }
}

/// Accept connections until told to stop, spawning one writer thread each.
///
/// The subscriber ceiling is enforced here, before a thread exists and before a
/// request byte is read: a peer over [`HUB_SUBSCRIBERS`] is greeted, refused and
/// closed on this thread.
fn accept_loop(listener: &UnixListener, hub: &Arc<ProgressHub>, stop: &Arc<AtomicBool>) {
    let admitted_uid = geteuid().as_raw();
    let mut writers: Vec<JoinHandle<()>> = Vec::new();
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                writers.retain(|writer| !writer.is_finished());
                if !admit_peer(&stream, admitted_uid) {
                    // A refused peer receives nothing at all — not even the
                    // greeting — and the connection closes with zero request
                    // bytes read.
                    continue;
                }
                if writers.len() >= HUB_SUBSCRIBERS {
                    refuse_connection(stream, StreamRefusal::SubscriberLimit);
                    continue;
                }
                let hub = Arc::clone(hub);
                let stop = Arc::clone(stop);
                writers.push(std::thread::spawn(move || {
                    serve_subscriber(stream, &hub, &stop);
                }));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
            }
            // A listener-level failure ends the loop. Every writer already
            // spawned is still joined below, so no thread outlives this one.
            Err(_) => break,
        }
    }
    for writer in writers {
        let _ = writer.join();
    }
}

/// Why one connection stopped.
///
/// Private, and no value of it reaches a peer: a client learns that its
/// subscription was refused, never which of this endpoint's internal
/// distinctions applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionEnd {
    /// The peer disconnected, stalled past the deadline, or its socket failed.
    Transport,
    /// The peer did not send one bounded canonical subscription.
    Malformed,
}

/// Greet, read one subscription, then write frames until the stream ends.
fn serve_subscriber(mut stream: UnixStream, hub: &Arc<ProgressHub>, stop: &AtomicBool) {
    if stream.set_nonblocking(false).is_err()
        || stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
    {
        return;
    }
    // The greeting is written before a request byte is read, so a client that
    // does not recognise this endpoint learns nothing about what the operator
    // wanted.
    if write_message(
        &mut stream,
        &StreamMessage::Greeting {
            capability: ADMIN_CAPABILITY,
        },
    )
    .is_err()
    {
        return;
    }
    let payload = match read_request(&mut stream) {
        Ok(payload) => payload,
        // A peer that went away is told nothing, because there is nobody to
        // tell. A peer that spoke badly is told which of the two it was.
        Err(ConnectionEnd::Transport) => return,
        Err(ConnectionEnd::Malformed) => {
            let _ = write_message(
                &mut stream,
                &StreamMessage::Refused {
                    refusal: StreamRefusal::MalformedRequest,
                },
            );
            return;
        }
    };
    let Ok(request) = SubscribeRequest::from_canonical_bytes(&payload) else {
        let _ = write_message(
            &mut stream,
            &StreamMessage::Refused {
                refusal: StreamRefusal::FieldInvalid,
            },
        );
        return;
    };
    let subscription = hub.subscribe(request.run_id().as_str(), request.cursor());
    if write_message(
        &mut stream,
        &StreamMessage::from_subscription(subscription.start()),
    )
    .is_err()
    {
        return;
    }
    let Some(feed) = subscription.into_feed() else {
        // A resync answer is terminal: this hub cannot serve the continuation,
        // and the spool can.
        return;
    };
    pump(&mut stream, &feed, stop);
}

/// Write queued frames until the stream ends, the peer goes, or we stop.
///
/// The slot is released when `feed` drops, which happens on every path out of
/// this function including a panic.
fn pump(stream: &mut UnixStream, feed: &SubscriberFeed, stop: &AtomicBool) {
    let mut delivered_through = 0_u64;
    loop {
        let (frames, end) = feed.take();
        let idle = frames.is_empty();
        for payload in frames {
            // Decoded and re-encoded rather than spliced: the frame owns its
            // canonical bytes and the message owns its envelope, and a hand-made
            // concatenation here would be a third party to keep equal to both. A
            // frame that does not decode is skipped — it came from this build's
            // own encoder, so a failure is this process disagreeing with itself
            // and the spool is where a reader goes for an answer it can rely on.
            let Ok(frame) = ProgressFrame::from_canonical_bytes(&payload) else {
                continue;
            };
            let sequence = frame.sequence();
            if write_message(stream, &StreamMessage::Frame(frame)).is_err() {
                return;
            }
            delivered_through = sequence;
        }
        if let Some(end) = end {
            let _ = write_message(
                stream,
                &match end {
                    StreamEnd::Lagged => StreamMessage::Lagged { delivered_through },
                    StreamEnd::Retired => StreamMessage::Retired { delivered_through },
                },
            );
            return;
        }
        if stop.load(Ordering::Acquire) {
            return;
        }
        if idle && peer_disconnected(stream) {
            return;
        }
    }
}

/// Detect a peer that closed while no new frame was available to write.
///
/// A write observes disconnects while the stream is active. Once a subscriber
/// has drained its queue, however, the writer may otherwise wait forever and
/// retain its hub slot because this protocol expects no second client request.
/// Peeking one byte without consuming it distinguishes EOF from a connected
/// peer with no input and keeps unexpected extra input available for any later
/// protocol decision.
fn peer_disconnected(stream: &UnixStream) -> bool {
    let mut byte = [0_u8; 1];
    match recv(
        stream.as_raw_fd(),
        &mut byte,
        MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT,
    ) {
        Ok(0) => true,
        Ok(_) | Err(Errno::EAGAIN | Errno::EINTR) => false,
        Err(_) => true,
    }
}

/// Read exactly one length-prefixed request frame under a bounded ceiling.
fn read_request(stream: &mut UnixStream) -> Result<Vec<u8>, ConnectionEnd> {
    let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
    stream
        .read_exact(&mut prefix)
        .map_err(|_| ConnectionEnd::Transport)?;
    let declared =
        usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| ConnectionEnd::Malformed)?;
    if declared == 0 || declared > MAX_SUBSCRIBE_CANONICAL_BYTES {
        return Err(ConnectionEnd::Malformed);
    }
    let mut framed = Vec::with_capacity(LENGTH_PREFIX_BYTES + declared);
    framed.extend_from_slice(&prefix);
    framed.resize(LENGTH_PREFIX_BYTES + declared, 0);
    stream
        .read_exact(&mut framed[LENGTH_PREFIX_BYTES..])
        .map_err(|_| ConnectionEnd::Transport)?;
    match decode_frame(&framed) {
        Ok(FrameDecode::Frame { payload, consumed }) if consumed == framed.len() => {
            Ok(payload.to_vec())
        }
        _ => Err(ConnectionEnd::Malformed),
    }
}

/// Encode and write one stream message.
fn write_message(stream: &mut UnixStream, message: &StreamMessage) -> Result<(), ConnectionEnd> {
    let payload = message
        .to_canonical_bytes()
        .map_err(|_| ConnectionEnd::Malformed)?;
    let mut framed = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
    encode_frame(&payload, &mut framed).map_err(|_| ConnectionEnd::Malformed)?;
    stream
        .write_all(&framed)
        .map_err(|_| ConnectionEnd::Transport)?;
    stream.flush().map_err(|_| ConnectionEnd::Transport)
}

/// Answer one connection with a refusal and close it.
fn refuse_connection(mut stream: UnixStream, refusal: StreamRefusal) {
    if stream.set_nonblocking(false).is_err() || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
    {
        return;
    }
    let _ = write_message(
        &mut stream,
        &StreamMessage::Greeting {
            capability: ADMIN_CAPABILITY,
        },
    );
    let _ = write_message(&mut stream, &StreamMessage::Refused { refusal });
}

/// Whether the kernel says this peer is this process's own non-root user.
///
/// The whole admission rule, applied before any byte is written or read. There
/// is no configuration point that widens it and no request field that can assert
/// an identity. It is not authorization: the same user can already read the
/// mode-`0600` spool and this process's memory.
fn admit_peer(stream: &UnixStream, admitted_uid: u32) -> bool {
    getsockopt(stream, sockopt::PeerCredentials).is_ok_and(|credentials| {
        credentials.pid() > 0 && credentials.uid() != 0 && credentials.uid() == admitted_uid
    })
}

/// Clear a stale socket, or refuse.
///
/// Absent is fine. A live listener refuses. Only a refused connection proves
/// staleness, and even then the exact inode is revalidated immediately before
/// the unlink so a replacement is never deleted.
fn prepare_socket_path(path: &Path, admitted_uid: u32) -> Result<(), ProgressEndpointError> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if !metadata.file_type().is_socket()
        || metadata.uid() != admitted_uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(ProgressEndpointError::UnsafeSocket);
    }
    let identity = (metadata.dev(), metadata.ino());
    match UnixStream::connect(path) {
        Ok(_) => Err(ProgressEndpointError::SocketInUse),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            let current = fs::symlink_metadata(path)?;
            if !current.file_type().is_socket()
                || current.uid() != admitted_uid
                || current.mode() & 0o7777 != 0o600
                || current.nlink() != 1
                || (current.dev(), current.ino()) != identity
            {
                return Err(ProgressEndpointError::UnsafeSocket);
            }
            fs::remove_file(path)?;
            Ok(())
        }
        // Permission denied, a timeout or any other error is ambiguous: it does
        // not prove the socket is dead, so nothing is unlinked.
        Err(error) => Err(ProgressEndpointError::Io(error)),
    }
}

const _: () = assert!(
    SUBSCRIBER_QUEUE_BYTES <= HUB_ATTEMPT_BYTES,
    "a subscriber queue that could outgrow the ring would lag on frames the ring \
     never held, which is a bound about nothing"
);
