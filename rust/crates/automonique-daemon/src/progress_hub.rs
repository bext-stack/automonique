// SPDX-License-Identifier: Elastic-2.0

//! A bounded in-memory replay of frames a live attempt has already recorded.
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
//! # What this is deliberately not
//!
//! Not a fan-out authority. There is no socket, no subscriber, no per-consumer
//! queue and no lag protocol; a reader polls with a cursor and takes what is
//! retained. Growing this into a push-capable authority with bounded subscriber
//! queues, a distinguishable `lagged` terminal frame and a cursor-too-old
//! refusal is its own change, and the shape it will carry —
//! `SubscriptionStart::ResyncRequired` — already exists in the protocol.
//!
//! # Bounds
//!
//! Three, all enforced on the way in: frames per attempt, bytes per attempt,
//! and attempts. The producer is the supervision loop of a live process tree,
//! so nothing here may block or grow: a full ring drops its oldest frame, and a
//! hub at its attempt ceiling refuses to start retaining a new one rather than
//! evicting an attempt somebody is watching.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use automonique_protocol::progress_api::ProgressFrame;
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

/// One retained frame: its durable position and its canonical bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Retained {
    sequence: u64,
    payload: Vec<u8>,
}

/// What one attempt has retained.
#[derive(Debug, Default)]
struct AttemptRing {
    frames: VecDeque<Retained>,
    bytes: usize,
}

impl AttemptRing {
    fn retain(&mut self, sequence: u64, payload: &[u8]) {
        // A frame larger than the whole ring is not retained: evicting
        // everything to hold one would turn a replay buffer into a single-frame
        // buffer, which is worse than not answering.
        if payload.len() > HUB_ATTEMPT_BYTES {
            return;
        }
        self.frames.push_back(Retained {
            sequence,
            payload: payload.to_vec(),
        });
        self.bytes = self.bytes.saturating_add(payload.len());
        while self.frames.len() > HUB_ATTEMPT_FRAMES || self.bytes > HUB_ATTEMPT_BYTES {
            let Some(dropped) = self.frames.pop_front() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(dropped.payload.len());
        }
    }
}

/// Live replay for the attempts this daemon is running.
#[derive(Debug, Default)]
pub struct ProgressHub {
    // One lock over the whole map rather than one per attempt: every operation
    // is a push or a scan of a bounded deque, and a producer that took two locks
    // to publish one frame would be a producer with an ordering rule to get
    // wrong.
    attempts: Mutex<BTreeMap<String, AttemptRing>>,
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

    /// Retain one appended frame.
    ///
    /// Silent on every failure. This is called between two polls of a live
    /// process tree by the thread that owns it, and there is nothing a replay
    /// buffer could report that would be worth interrupting that for — the
    /// durable record already has the frame.
    pub fn publish(&self, run_id: &str, sequence: u64, payload: &[u8]) {
        let Ok(mut attempts) = self.attempts.lock() else {
            return;
        };
        if !attempts.contains_key(run_id) && attempts.len() >= HUB_ATTEMPTS {
            return;
        }
        attempts
            .entry(run_id.to_owned())
            .or_default()
            .retain(sequence, payload);
    }

    /// Every retained frame after `cursor`, in sequence order.
    ///
    /// A frame that no longer decodes is skipped rather than refused: the bytes
    /// came from this build's own encoder moments ago, so a decode failure is
    /// this process disagreeing with itself, and the durable spool is where a
    /// reader goes for an answer it can rely on.
    #[must_use]
    pub fn frames_after(&self, run_id: &str, cursor: u64) -> Vec<ProgressFrame> {
        let Ok(attempts) = self.attempts.lock() else {
            return Vec::new();
        };
        attempts.get(run_id).map_or_else(Vec::new, |ring| {
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
        let attempts = self.attempts.lock().ok()?;
        attempts
            .get(run_id)?
            .frames
            .front()
            .map(|frame| frame.sequence)
    }

    /// Forget one attempt.
    ///
    /// Called when the attempt is terminal, because from that moment the spool
    /// is readable and is strictly better: complete, verified, and not a window.
    pub fn retire(&self, run_id: &str) {
        if let Ok(mut attempts) = self.attempts.lock() {
            attempts.remove(run_id);
        }
    }

    /// How many attempts are retained. For metrics and tests.
    #[must_use]
    pub fn retained_attempts(&self) -> usize {
        self.attempts.lock().map_or(0, |attempts| attempts.len())
    }
}

/// One attempt's binding of the hub to the runner's publishing seam.
struct HubPublisher {
    hub: Arc<ProgressHub>,
    run_id: String,
}

impl ProgressPublisher for HubPublisher {
    fn publish(&self, sequence: u64, payload: &[u8]) {
        self.hub.publish(&self.run_id, sequence, payload);
    }
}
