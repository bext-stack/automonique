// SPDX-License-Identifier: Elastic-2.0

//! The live fan-out: bounded queues, exact resumption, and three endings.
//!
//! Six claims, each measured against a real socket and real threads rather than
//! against the hub's in-process API — because every one of them is about what a
//! *peer* observes, and an in-process assertion would be measuring the half of
//! the machinery that cannot fail:
//!
//! 1. a subscriber that stops reading never slows the producer, and is
//!    disconnected with exactly one `lagged` frame while the run itself is
//!    untouched;
//! 2. a subscriber that disconnects mid-stream and reconnects with its cursor
//!    resumes byte-exactly, checked against the spool's hash-chained record;
//! 3. a cursor below the window is refused with the window it fell out of;
//! 4. a disconnect is never a cancellation;
//! 5. the greeting carries the capability integer, and the subscriber ceiling
//!    refuses the ninth peer rather than serving it worse;
//! 6. what the hub observed reaches the observability snapshot.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use automonique_daemon::progress_hub::{
    HUB_SUBSCRIBERS, PROGRESS_SOCKET_NAME, ProgressEndpoint, ProgressHub, SUBSCRIBER_QUEUE_BYTES,
};
use automonique_observability::{MetricName, MetricValue};
use automonique_protocol::admin::ADMIN_CAPABILITY;
use automonique_protocol::codec::{FrameDecode, decode_frame, encode_frame};
use automonique_protocol::event::{Authority, EventKind};
use automonique_protocol::primitives::EpochMillis;
use automonique_protocol::progress_api::{
    ProgressBody, ProgressBodyParts, ProgressFrame, ProgressFrameParts, ProgressText,
    StreamMessage, StreamRefusal, SubscribeRequest,
};
use automonique_protocol::tools::RunId;
use automonique_runner::{Authority as SpoolAuthority, EventKind as SpoolKind, Spool};

const RUN: &str = "run-fanout-suite";

/// A generous ceiling on anything that should be immediate.
///
/// Every wait in this file is a poll against it rather than a sleep, so a slow
/// machine makes the tests slower and never makes them wrong.
const PATIENCE: Duration = Duration::from_secs(5);

/// One live endpoint over one hub, with its socket in a private directory.
struct Endpoint {
    _directory: tempfile::TempDir,
    socket_path: PathBuf,
    hub: Arc<ProgressHub>,
    endpoint: Option<ProgressEndpoint>,
}

/// A temporary directory only this user can reach.
///
/// Every durable thing this suite opens — the socket, the spool, the store —
/// refuses a directory anybody else can read, so the mode is set before the
/// first of them is created rather than after.
fn private_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("a directory");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("a private mode");
    directory
}

impl Endpoint {
    fn start() -> Self {
        let directory = private_directory();
        let socket_path = directory.path().join(PROGRESS_SOCKET_NAME);
        let hub = Arc::new(ProgressHub::new());
        let mut endpoint =
            ProgressEndpoint::bind(&socket_path, Arc::clone(&hub)).expect("the endpoint binds");
        endpoint.start().expect("the endpoint serves");
        Self {
            _directory: directory,
            socket_path,
            hub,
            endpoint: Some(endpoint),
        }
    }

    fn connect(&self) -> Client {
        Client::connect(&self.socket_path)
    }

    fn shutdown(&mut self) {
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.shutdown();
        }
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// One subscriber, speaking the endpoint's framed canonical JSON.
struct Client {
    stream: UnixStream,
    buffered: Vec<u8>,
}

impl Client {
    fn connect(socket_path: &Path) -> Self {
        let stream = UnixStream::connect(socket_path).expect("the endpoint answers");
        stream
            .set_read_timeout(Some(PATIENCE))
            .expect("a read deadline");
        stream
            .set_write_timeout(Some(PATIENCE))
            .expect("a write deadline");
        Self {
            stream,
            buffered: Vec::new(),
        }
    }

    /// Read one message, or `None` when the endpoint closed the connection.
    fn read(&mut self) -> Option<StreamMessage> {
        let mut chunk = [0_u8; 4096];
        loop {
            match decode_frame(&self.buffered) {
                Ok(FrameDecode::Frame { payload, consumed }) => {
                    let message =
                        StreamMessage::from_canonical_bytes(payload).expect("a decodable message");
                    self.buffered.drain(..consumed);
                    return Some(message);
                }
                Ok(FrameDecode::NeedMore { .. }) => {}
                Err(error) => panic!("the endpoint wrote something unparsable: {error}"),
            }
            let read = self.stream.read(&mut chunk).expect("a readable stream");
            if read == 0 {
                return None;
            }
            self.buffered.extend_from_slice(&chunk[..read]);
        }
    }

    fn greeting(&mut self) -> u32 {
        match self.read() {
            Some(StreamMessage::Greeting { capability }) => capability,
            other => panic!("the endpoint did not greet: {other:?}"),
        }
    }

    fn subscribe(&mut self, run_id: &str, cursor: u64) -> StreamMessage {
        let payload = SubscribeRequest::new(RunId::new(run_id).expect("a run identity"), cursor)
            .to_canonical_bytes()
            .expect("a request encodes");
        let mut framed = Vec::new();
        encode_frame(&payload, &mut framed).expect("a request frames");
        self.stream.write_all(&framed).expect("a writable stream");
        self.stream.flush().expect("a flushable stream");
        self.read().expect("an answer to the subscription")
    }

    /// Greet, subscribe and require the answer to be live delivery.
    fn attach(&mut self, run_id: &str, cursor: u64) -> u64 {
        assert_eq!(self.greeting(), ADMIN_CAPABILITY);
        match self.subscribe(run_id, cursor) {
            StreamMessage::Live { from } => from,
            other => panic!("expected live delivery, got {other:?}"),
        }
    }
}

/// One frame at `sequence`, carrying `text`.
fn frame(sequence: u64, text: &str) -> ProgressFrame {
    ProgressFrame::new(ProgressFrameParts {
        run_id: RunId::new(RUN).expect("a run identity"),
        sequence,
        at_ms: EpochMillis::from_millis(1_700_000_000_000),
        authority: Authority::Synthetic,
        kind: EventKind::AssistantMessageDelta,
        body: ProgressBody::new(
            EventKind::AssistantMessageDelta,
            ProgressBodyParts {
                text: Some(ProgressText::new(text).expect("plain text")),
                step: None,
                retry: None,
            },
        )
        .expect("a delta with its text"),
    })
    .expect("a stamped frame")
}

/// The one frame that is the provider stream's own end.
fn run_terminal(sequence: u64) -> ProgressFrame {
    ProgressFrame::new(ProgressFrameParts {
        run_id: RunId::new(RUN).expect("a run identity"),
        sequence,
        at_ms: EpochMillis::from_millis(1_700_000_000_000),
        authority: Authority::Authoritative,
        kind: EventKind::RunTerminal,
        body: ProgressBody::empty(EventKind::RunTerminal).expect("an empty terminal body"),
    })
    .expect("a stamped frame")
}

fn publish(hub: &ProgressHub, frame: &ProgressFrame) {
    hub.publish(
        RUN,
        frame.sequence(),
        &frame.to_canonical_bytes().expect("it encodes"),
    );
}

/// Poll `condition` until it holds or [`PATIENCE`] elapses.
fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("timed out waiting for {what}");
}

/// Claim 7: a subscriber is greeted when it arrives, not when the loop wakes.
///
/// A renderer attaching to a live run is the shape a napping accept loop taxes:
/// it opens one connection, waits for the greeting, and only then subscribes.
/// The nap put most of the accept interval in front of the first byte a
/// watching human sees.
mod arrival {
    use super::*;

    /// Sequential arrivals to measure over. One could not be told apart from a
    /// scheduling hiccup; this many separates the two implementations by more
    /// than any plausible noise.
    const ARRIVALS: u32 = 30;

    /// `progress_hub::ACCEPT_POLL`, mirrored.
    ///
    /// Mirrored rather than imported because it is private, and because a case
    /// that read the constant would still pass if the constant and the loop
    /// were changed together. The number defended is the one written here.
    const ACCEPT_POLL: Duration = Duration::from_millis(25);

    /// Connect, and wait for the first thing the endpoint says.
    ///
    /// Either answer counts. A greeting is the ordinary one; the subscriber
    /// ceiling is a legitimate second, because a peer whose predecessor's
    /// thread has not yet been scheduled is refused on the accept thread —
    /// which is still the endpoint having accepted, which is what is timed.
    /// Insisting on a greeting would make this case fail for a reason that has
    /// nothing to do with waiting.
    fn arrive(endpoint: &Endpoint) {
        let mut client = endpoint.connect();
        match client.read() {
            Some(StreamMessage::Greeting { .. } | StreamMessage::Refused { .. }) => {}
            other => panic!("the endpoint did not answer an arrival: {other:?}"),
        }
    }

    #[test]
    fn a_subscriber_is_not_charged_the_accept_interval_to_be_greeted() {
        let endpoint = Endpoint::start();

        // One arrival before the clock starts, so the measurement is of a
        // steady state rather than of the endpoint's first connection.
        arrive(&endpoint);

        let started = Instant::now();
        for _ in 0..ARRIVALS {
            arrive(&endpoint);
        }
        let elapsed = started.elapsed();

        let sleeping_cost = ACCEPT_POLL * ARRIVALS;
        assert!(
            elapsed < sleeping_cost / 2,
            "{ARRIVALS} sequential arrivals took {elapsed:?}. A loop that waits on its listener \
             greets each as it arrives; one that naps charges most of {ACCEPT_POLL:?} to each, \
             which is the {sleeping_cost:?} this is within reach of"
        );
    }
}

/// Claim 1: a slow subscriber costs the producer nothing and ends distinctly.
mod lagging {
    use super::*;

    #[test]
    fn a_subscriber_that_stops_reading_is_dropped_and_the_run_is_untouched() {
        let endpoint = Endpoint::start();
        let mut client = endpoint.connect();
        assert_eq!(client.attach(RUN, 0), 1);
        eventually("the subscriber to attach", || {
            endpoint.hub.subscriber_count() == 1
        });

        // Frames large enough that a few dozen exceed both the socket buffer and
        // the queue's byte bound, so the overflow is arithmetic rather than a
        // race we hope wins.
        let text = "x".repeat(8 * 1024);
        let flood = 200;
        assert!(
            flood * text.len() > 4 * SUBSCRIBER_QUEUE_BYTES,
            "the flood must be able to overflow the queue several times over"
        );

        // THE MEASUREMENT: the producer's own wall time. The client is not
        // reading a byte, so every one of these publishes happens while a writer
        // thread is blocked in `write_all`.
        let started = Instant::now();
        for sequence in 1..=flood {
            publish(
                &endpoint.hub,
                &frame(u64::try_from(sequence).expect("a small index"), &text),
            );
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(1),
            "the producer waited {elapsed:?} on a subscriber that was not reading"
        );

        // The run reaches its own terminal while the subscriber is being dropped,
        // and that frame is retained exactly as any other would be.
        let terminal = run_terminal(u64::try_from(flood).expect("a small index") + 1);
        publish(&endpoint.hub, &terminal);
        assert_eq!(
            endpoint
                .hub
                .frames_after(RUN, u64::try_from(flood).expect("a small index")),
            vec![terminal],
            "the run's own terminal frame was affected by a lagging subscriber"
        );

        // Now read. Whatever was already in flight arrives, then exactly one
        // terminal `lagged`, then the connection closes.
        let mut frames = 0_usize;
        let mut endings = Vec::new();
        while let Some(message) = client.read() {
            match message {
                StreamMessage::Frame(_) => frames += 1,
                other => endings.push(other),
            }
        }
        assert!(frames > 0, "the subscriber received nothing at all");
        assert_eq!(
            endings.len(),
            1,
            "a lagged subscriber received {endings:?} rather than one ending"
        );
        assert!(
            matches!(endings[0], StreamMessage::Lagged { .. }),
            "the ending was {:?}, not a lag",
            endings[0]
        );
        let StreamMessage::Lagged { delivered_through } = endings[0] else {
            unreachable!("checked immediately above");
        };
        assert_eq!(
            delivered_through,
            u64::try_from(frames).expect("a small count"),
            "the resume cursor must name the last frame actually delivered"
        );

        // And the slot is released, so the ceiling is not consumed by a peer
        // nobody is serving any more.
        eventually("the lagged subscriber's slot to be released", || {
            endpoint.hub.subscriber_count() == 0
        });
    }

    /// The lag ending is not the run's own ending, and neither is the other one.
    #[test]
    fn the_three_endings_are_three_different_things() {
        let lagged = StreamMessage::Lagged {
            delivered_through: 7,
        };
        let retired = StreamMessage::Retired {
            delivered_through: 7,
        };
        let run_end = StreamMessage::Frame(run_terminal(7));
        assert_ne!(lagged.kind(), retired.kind());
        assert_ne!(lagged.kind(), run_end.kind());
        assert_ne!(retired.kind(), run_end.kind());
        // The transport's two endings end the connection; the run's does not.
        assert!(lagged.is_terminal());
        assert!(retired.is_terminal());
        assert!(!run_end.is_terminal());
    }
}

/// Claim 2: a reconnection with a cursor is a continuation, not a re-read.
mod resumption {
    use super::*;

    /// Half the frames over one connection, half over the next, and the join
    /// checked against the durable record rather than against itself.
    #[test]
    fn a_reconnection_resumes_byte_exactly_against_the_spool() {
        let endpoint = Endpoint::start();
        let spool_root = private_directory();
        let mut spool = Spool::open(spool_root.path(), RUN, 1 << 20).expect("a spool");
        spool
            .append(SpoolKind::Started, SpoolAuthority::Authoritative, b"{}")
            .expect("a started event");

        // Appended to the durable record and published as the same bytes at the
        // same position, which is what the execution lane does: the spool owns
        // the sequence and the hub echoes the event it just wrote. `started`
        // took position one, so the frames run from two.
        let mut published = Vec::new();
        for sequence in 2..=11 {
            let stamped = frame(sequence, &format!("frame {sequence}"));
            let payload = stamped.to_canonical_bytes().expect("it encodes");
            let event = spool
                .append(SpoolKind::AdapterEvent, SpoolAuthority::Synthetic, &payload)
                .expect("an adapter event");
            assert_eq!(
                event.sequence(),
                sequence,
                "a frame must be stamped with the position the spool gave it"
            );
            publish(&endpoint.hub, &stamped);
            published.push(stamped);
        }

        let mut first = endpoint.connect();
        assert_eq!(first.attach(RUN, 1), 2);
        let mut received = Vec::new();
        for _ in 0..4 {
            match first.read() {
                Some(StreamMessage::Frame(frame)) => received.push(frame),
                other => panic!("expected a frame, got {other:?}"),
            }
        }
        let cursor = received.last().expect("four frames").sequence();
        // The disconnect: no goodbye, no cancellation, just a closed socket.
        drop(first);
        eventually("the first subscriber's slot to be released", || {
            endpoint.hub.subscriber_count() == 0
        });

        let mut second = endpoint.connect();
        assert_eq!(second.attach(RUN, cursor), cursor + 1);
        endpoint.hub.retire(RUN);
        while let Some(message) = second.read() {
            match message {
                StreamMessage::Frame(frame) => received.push(frame),
                StreamMessage::Retired { delivered_through } => {
                    assert_eq!(delivered_through, 11);
                }
                other => panic!("expected frames then a retirement, got {other:?}"),
            }
        }

        // THE CHECK: what two connections delivered, against what the
        // hash-chained record holds. `read_events` verifies the chain, so a
        // record this disagrees with is a record that did not verify.
        let events =
            automonique_runner::read_events(spool_root.path(), RUN).expect("a valid chain");
        let recorded: Vec<Vec<u8>> = events
            .iter()
            .filter(|event| event.kind() == SpoolKind::AdapterEvent)
            .map(|event| event.payload().to_vec())
            .collect();
        let delivered: Vec<Vec<u8>> = received
            .iter()
            .map(|frame| frame.to_canonical_bytes().expect("it encodes"))
            .collect();
        assert_eq!(delivered.len(), 10, "a frame was lost or delivered twice");
        assert_eq!(
            delivered,
            published
                .iter()
                .map(|frame| frame.to_canonical_bytes().expect("it encodes"))
                .collect::<Vec<_>>(),
            "the two connections did not join into the sequence that was published"
        );
        assert_eq!(
            recorded.len(),
            delivered.len(),
            "the record and the stream hold different numbers of frames"
        );
        // Every sequence the stream delivered is a sequence the chain holds, in
        // the same order: the cursor means one thing in both tiers.
        let recorded_sequences: Vec<u64> = events
            .iter()
            .filter(|event| event.kind() == SpoolKind::AdapterEvent)
            .map(automonique_runner::Event::sequence)
            .collect();
        assert_eq!(
            recorded_sequences,
            received
                .iter()
                .map(ProgressFrame::sequence)
                .collect::<Vec<_>>()
        );
    }
}

/// Claim 3: a cursor outside the window is told which window it left.
mod cursor_too_old {
    use super::*;

    #[test]
    fn a_cursor_below_the_window_is_refused_with_the_window() {
        let endpoint = Endpoint::start();
        // Publish enough that the ring has evicted its own beginning.
        let text = "y".repeat(4 * 1024);
        for sequence in 1..=400 {
            publish(&endpoint.hub, &frame(sequence, &text));
        }
        let oldest = endpoint
            .hub
            .oldest_retained(RUN)
            .expect("the ring retains something");
        assert!(oldest > 1, "the ring did not evict anything to fall out of");

        let mut client = endpoint.connect();
        assert_eq!(client.greeting(), ADMIN_CAPABILITY);
        match client.subscribe(RUN, 0) {
            StreamMessage::ResyncRequired {
                snapshot_from,
                snapshot_to,
            } => {
                assert_eq!(snapshot_from, oldest);
                assert_eq!(snapshot_to, 400);
            }
            other => panic!("expected a resync, got {other:?}"),
        }
        // A resync is terminal: the endpoint has nothing further to say and the
        // spool does.
        assert!(client.read().is_none());

        // The boundary, exactly: the cursor naming the frame *before* the oldest
        // retained one still resumes, because the frame it wants next is held.
        let mut boundary = endpoint.connect();
        assert_eq!(boundary.attach(RUN, oldest - 1), oldest);
    }

    /// An attempt this hub knows nothing about is a resync with an empty window.
    #[test]
    fn an_unknown_attempt_is_an_empty_window_for_a_cursor_that_claims_progress() {
        let endpoint = Endpoint::start();
        let mut client = endpoint.connect();
        assert_eq!(client.greeting(), ADMIN_CAPABILITY);
        match client.subscribe(RUN, 12) {
            StreamMessage::ResyncRequired {
                snapshot_from,
                snapshot_to,
            } => {
                assert_eq!((snapshot_from, snapshot_to), (0, 0));
            }
            other => panic!("expected an empty-window resync, got {other:?}"),
        }

        // A subscriber that has seen nothing is asking for everything there is,
        // and nothing is a truthful answer to that: it attaches and waits.
        let mut fresh = endpoint.connect();
        assert_eq!(fresh.attach(RUN, 0), 1);
    }
}

/// Claim 4: nothing here stops a run.
mod disconnect_is_not_cancellation {
    use super::*;

    #[test]
    fn a_disconnected_subscriber_leaves_the_attempt_running() {
        let endpoint = Endpoint::start();
        let mut client = endpoint.connect();
        assert_eq!(client.attach(RUN, 0), 1);
        publish(&endpoint.hub, &frame(1, "before the disconnect"));
        assert!(matches!(client.read(), Some(StreamMessage::Frame(_))));

        drop(client);
        // The attempt keeps producing, the hub keeps retaining, and the run
        // reaches its own terminal — none of which a transport event touched.
        for sequence in 2..=5 {
            publish(&endpoint.hub, &frame(sequence, "after the disconnect"));
        }
        let terminal = run_terminal(6);
        publish(&endpoint.hub, &terminal);
        assert_eq!(endpoint.hub.frames_after(RUN, 0).len(), 6);
        assert_eq!(endpoint.hub.frames_after(RUN, 5), vec![terminal]);
        eventually("the disconnected subscriber's slot to be released", || {
            endpoint.hub.subscriber_count() == 0
        });

        // And a new subscriber sees the whole run, including everything
        // published after the first one went away.
        let mut watcher = endpoint.connect();
        assert_eq!(watcher.attach(RUN, 0), 1);
        let mut kinds = Vec::new();
        endpoint.hub.retire(RUN);
        while let Some(message) = watcher.read() {
            match message {
                StreamMessage::Frame(frame) => kinds.push(frame.kind()),
                StreamMessage::Retired { .. } => break,
                other => panic!("expected frames then a retirement, got {other:?}"),
            }
        }
        assert_eq!(kinds.len(), 6);
        assert_eq!(kinds.last(), Some(&EventKind::RunTerminal));
    }

    /// Shutting the whole endpoint down is not a cancellation either.
    #[test]
    fn shutting_the_endpoint_down_leaves_the_hub_and_its_attempts_intact() {
        let mut endpoint = Endpoint::start();
        let mut client = endpoint.connect();
        assert_eq!(client.attach(RUN, 0), 1);
        publish(&endpoint.hub, &frame(1, "still here"));

        endpoint.shutdown();
        // The socket is gone and the writer joined, and the retained window is
        // exactly what it was: the endpoint is a way to read the hub, not a
        // participant in the run.
        assert_eq!(endpoint.hub.frames_after(RUN, 0).len(), 1);
        assert_eq!(endpoint.hub.subscriber_count(), 0);
        publish(&endpoint.hub, &frame(2, "and still producing"));
        assert_eq!(endpoint.hub.frames_after(RUN, 0).len(), 2);
    }
}

/// Claim 5: the capability is in the greeting, and the ceiling is real.
mod admission {
    use super::*;

    #[test]
    fn the_greeting_carries_the_capability_before_any_request_is_read() {
        let endpoint = Endpoint::start();
        let mut client = endpoint.connect();
        // Read before writing anything at all: the endpoint states what it is
        // without being asked.
        assert_eq!(client.greeting(), ADMIN_CAPABILITY);
    }

    #[test]
    fn the_ninth_subscriber_is_refused_rather_than_served() {
        let endpoint = Endpoint::start();
        let mut attached = Vec::new();
        for _ in 0..HUB_SUBSCRIBERS {
            let mut client = endpoint.connect();
            client.attach(RUN, 0);
            attached.push(client);
        }
        eventually("every admitted subscriber to attach", || {
            endpoint.hub.subscriber_count() == HUB_SUBSCRIBERS
        });

        let mut extra = endpoint.connect();
        assert_eq!(extra.greeting(), ADMIN_CAPABILITY);
        assert_eq!(
            extra.read(),
            Some(StreamMessage::Refused {
                refusal: StreamRefusal::SubscriberLimit
            })
        );
        assert!(extra.read().is_none(), "a refusal is terminal");
        assert_eq!(
            endpoint.hub.subscriber_count(),
            HUB_SUBSCRIBERS,
            "a refused peer must not consume a slot"
        );

        // A seat freed by a disconnect is a seat the next peer gets.
        drop(attached.pop());
        publish(&endpoint.hub, &frame(1, "wake the writers"));
        eventually("the freed slot to be reclaimed", || {
            endpoint.hub.subscriber_count() == HUB_SUBSCRIBERS - 1
        });
        let mut ninth = endpoint.connect();
        assert_eq!(ninth.greeting(), ADMIN_CAPABILITY);
        assert!(
            matches!(
                ninth.subscribe(RUN, 0),
                StreamMessage::Live { .. } | StreamMessage::ResyncRequired { .. }
            ),
            "the ceiling stayed closed after a subscriber left"
        );
    }

    /// A peer that sends something other than a subscription is told so.
    #[test]
    fn a_request_that_is_not_a_subscription_is_refused_without_attaching() {
        let endpoint = Endpoint::start();
        let mut client = endpoint.connect();
        assert_eq!(client.greeting(), ADMIN_CAPABILITY);
        let mut framed = Vec::new();
        encode_frame(b"{\"not\":\"a subscription\"}", &mut framed).expect("it frames");
        client.stream.write_all(&framed).expect("a writable stream");
        client.stream.flush().expect("a flushable stream");
        assert_eq!(
            client.read(),
            Some(StreamMessage::Refused {
                refusal: StreamRefusal::FieldInvalid
            })
        );
        assert_eq!(endpoint.hub.subscriber_count(), 0);
    }
}

/// Claim 6: what the hub saw reaches the projection.
mod metrics {
    use super::*;

    #[test]
    fn a_lag_is_visible_in_the_observability_snapshot() {
        let endpoint = Endpoint::start();

        // Nothing has happened yet, and the snapshot says so with zeroes rather
        // than with an absence: the hub is present and has counted nothing.
        let quiet = endpoint.hub.observation();
        assert_eq!(quiet.frames_dropped, 0);
        assert_eq!(quiet.lag_disconnects, 0);
        assert_eq!(quiet.oldest_retained_age_ms, 0);

        let mut client = endpoint.connect();
        client.attach(RUN, 0);
        eventually("the subscriber to attach", || {
            endpoint.hub.subscriber_count() == 1
        });
        let text = "z".repeat(8 * 1024);
        for sequence in 1..=200 {
            publish(&endpoint.hub, &frame(sequence, &text));
        }
        eventually("the lag to be counted", || {
            endpoint.hub.observation().lag_disconnects == 1
        });

        let observation = endpoint.hub.observation();
        assert_eq!(observation.lag_disconnects, 1);
        assert!(observation.frames_dropped > 0);
        assert!(
            observation.queue_high_water_bytes > u64::try_from(SUBSCRIBER_QUEUE_BYTES).unwrap(),
            "the high-water mark must be the fullest the queue got, which is past its bound"
        );

        // The projection carries exactly what was observed, and the four samples
        // are measured rather than unavailable.
        let projection = automonique_observability::StoreProjection::from_status(&store_status())
            .expect("a projection")
            .with_progress(observation)
            .expect("the hub's observation attaches");
        let metrics = projection.metrics();
        assert_eq!(
            metrics.value(MetricName::ProgressLagDisconnects),
            MetricValue::Measured(1)
        );
        assert_eq!(
            metrics.value(MetricName::ProgressFramesDropped),
            MetricValue::Measured(observation.frames_dropped)
        );
        assert_eq!(
            metrics.value(MetricName::ProgressQueueHighWaterBytes),
            MetricValue::Measured(observation.queue_high_water_bytes)
        );
        // A second attachment is refused: a projection is one reading, not two.
        assert!(
            automonique_observability::StoreProjection::from_status(&store_status())
                .expect("a projection")
                .with_progress(observation)
                .expect("the first attaches")
                .with_progress(observation)
                .is_err()
        );
    }

    /// One real store snapshot, which is what the projection is derived from.
    fn store_status() -> automonique_store::StatusSnapshot {
        let directory = private_directory();
        let mut store =
            automonique_store::Store::open(directory.path().join("automonique.sqlite3"))
                .expect("a store");
        store
            .acquire_generation_lease(automonique_store::LeaseRequest {
                generation_id: "progress-metrics",
                holder_id: "progress-metrics-test",
                now_ms: 1_700_000_000_000,
                ttl_ms: 60_000,
            })
            .expect("a lease");
        store
            .status_snapshot_at("progress-metrics", 1_700_000_000_000)
            .expect("a snapshot")
    }
}
