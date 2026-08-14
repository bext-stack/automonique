// SPDX-License-Identifier: Elastic-2.0

//! Moving opaque bytes between a client and a destination, in both directions,
//! under a deadline.
//!
//! # Blind by construction
//!
//! The relay reads into a fixed buffer and writes what it read. It does not
//! parse, frame, buffer whole messages, inspect, log, or retain the bytes: the
//! only thing it derives from them is how many there were. That is what makes
//! it safe for the broker to sit inside a TLS session it has no key for — the
//! workload's TLS is established end to end with the real destination, so the
//! broker sees ciphertext, cannot decrypt it, needs no certificate authority of
//! its own, and cannot silently become a man in the middle without the change
//! being visible as "this crate suddenly needs a TLS library".
//!
//! # Every wait is bounded
//!
//! Both sockets carry a read and a write timeout. A destination that accepts a
//! connection and then never speaks, and a client that stops reading while the
//! destination keeps sending, both end as an idle expiry rather than as a
//! thread parked forever. The timeout is per-operation, not per-connection: a
//! healthy long-lived tunnel (a streaming model response, a websocket) resets
//! it on every chunk, which is the behaviour a provider session needs.
//!
//! # Half-close is propagated
//!
//! When one direction reaches end of stream, the relay shuts down only the
//! matching write half and lets the other direction finish. TLS peers routinely
//! close one way first; tearing the whole tunnel down on the first `EOF` would
//! truncate the final records of the other direction.

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::thread;
use std::time::Duration;

/// Size of the per-direction relay buffer.
///
/// One buffer per direction, allocated once per tunnel, never grown. The
/// tunnel's *volume* is deliberately unbounded — a provider session moves
/// megabytes and cutting it off at an arbitrary count would be a broken proxy,
/// not a security control — but its *memory* is this, twice.
pub const RELAY_BUFFER_BYTES: usize = 16 * 1024;

/// How much moved, in each direction, before a tunnel ended.
///
/// Byte counts only: this is the entire observation the broker makes of a
/// tunnel's contents.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelayOutcome {
    /// Bytes carried from the client to the destination.
    pub to_destination: u64,
    /// Bytes carried from the destination to the client.
    pub to_client: u64,
}

/// Why one direction of a tunnel stopped. Kept for the tunnel's own bookkeeping;
/// none of these is reported to the client, which by then owns a tunnel that has
/// simply closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectionEnd {
    /// The source reached end of stream. The peer's write half was shut down.
    EndOfStream,
    /// A read or write exceeded the idle deadline.
    Idle,
    /// The socket failed.
    Failed,
}

/// Install the idle deadline on both sockets.
///
/// A timeout is a property of the socket rather than of a particular descriptor,
/// so setting it once per socket covers both directions' use of it. Returns an
/// error if the kernel refuses, because a relay that could not install its
/// deadline is a relay that can hang, and starting it anyway would be the
/// silent downgrade this crate refuses everywhere else.
pub fn install_deadlines(
    client: &TcpStream,
    destination: &TcpStream,
    idle: Duration,
) -> std::io::Result<()> {
    for socket in [client, destination] {
        socket.set_read_timeout(Some(idle))?;
        socket.set_write_timeout(Some(idle))?;
    }
    Ok(())
}

/// Relay until both directions end, then return the byte counts.
///
/// Blocks the calling thread on the destination-to-client direction and runs
/// the client-to-destination direction on one spawned thread, so a tunnel costs
/// two threads and no polling.
pub fn relay(client: TcpStream, destination: TcpStream) -> std::io::Result<RelayOutcome> {
    let client_source = client.try_clone()?;
    let destination_sink = destination.try_clone()?;
    let outbound = thread::spawn(move || pump(&client_source, &destination_sink));
    let to_client = pump(&destination, &client);
    // A failure in either direction leaves the other blocked on a peer that
    // will never speak again; shutting both sockets down wakes it now rather
    // than at the idle deadline.
    if to_client.1 != DirectionEnd::EndOfStream {
        let _ = client.shutdown(Shutdown::Both);
        let _ = destination.shutdown(Shutdown::Both);
    }
    let to_destination = outbound
        .join()
        .map_err(|_| std::io::Error::other("relay direction panicked"))?;
    Ok(RelayOutcome {
        to_destination: to_destination.0,
        to_client: to_client.0,
    })
}

/// Copy `source` into `sink` until either ends, returning the byte count and
/// why it stopped.
fn pump(source: &TcpStream, sink: &TcpStream) -> (u64, DirectionEnd) {
    let mut buffer = [0u8; RELAY_BUFFER_BYTES];
    let mut moved = 0u64;
    let mut reader = source;
    let mut writer = sink;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => {
                // End of stream one way only: the peer may still have bytes to
                // send back, so only this direction is closed.
                let _ = sink.shutdown(Shutdown::Write);
                return (moved, DirectionEnd::EndOfStream);
            }
            Ok(read) => read,
            Err(error) => return (moved, classify(&error)),
        };
        if let Err(error) = writer.write_all(&buffer[..read]) {
            return (moved, classify(&error));
        }
        moved += read as u64;
    }
}

/// An expired socket timeout surfaces as `WouldBlock` or `TimedOut` depending on
/// the platform's spelling; both mean the deadline fired.
fn classify(error: &std::io::Error) -> DirectionEnd {
    match error.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => DirectionEnd::Idle,
        _ => DirectionEnd::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::{DirectionEnd, RELAY_BUFFER_BYTES, classify, install_deadlines, relay};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::{Duration, Instant};

    /// A payload longer than one relay buffer, covering every byte value, so a
    /// relay that truncated at a buffer boundary or mangled a byte is visible.
    fn payload(seed: u8) -> Vec<u8> {
        (0..RELAY_BUFFER_BYTES * 2 + 37)
            .map(|index| (index as u8).wrapping_add(seed))
            .collect()
    }

    #[test]
    fn both_directions_are_carried_byte_exact_across_buffer_boundaries() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        // The far side of the relay: reads everything, replies with its own.
        let far = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut received = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                match socket.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => received.extend_from_slice(&buffer[..read]),
                    Err(error) => panic!("far side read: {error}"),
                }
            }
            socket.write_all(&payload(7)).unwrap();
            socket.shutdown(std::net::Shutdown::Write).unwrap();
            received
        });

        let (near_client, mut client_end) = pair();
        let destination = TcpStream::connect(address).unwrap();
        install_deadlines(&near_client, &destination, Duration::from_secs(5)).unwrap();
        let relaying = thread::spawn(move || relay(near_client, destination).unwrap());

        let sent = payload(0);
        let writer = {
            let mut end = client_end.try_clone().unwrap();
            let sent = sent.clone();
            thread::spawn(move || {
                end.write_all(&sent).unwrap();
                end.shutdown(std::net::Shutdown::Write).unwrap();
            })
        };
        let mut back = Vec::new();
        client_end.read_to_end(&mut back).unwrap();
        writer.join().unwrap();

        let received = far.join().unwrap();
        let outcome = relaying.join().unwrap();
        assert_eq!(received, sent, "client to destination must be byte-exact");
        assert_eq!(back, payload(7), "destination to client must be byte-exact");
        assert_eq!(outcome.to_destination, sent.len() as u64);
        assert_eq!(outcome.to_client, payload(7).len() as u64);
    }

    #[test]
    fn a_destination_that_never_speaks_ends_at_the_deadline_rather_than_hanging() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let far = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            // Accept and then do nothing at all, holding the socket open.
            thread::sleep(Duration::from_secs(3));
            drop(socket);
        });

        let (near_client, _client_end) = pair();
        let destination = TcpStream::connect(address).unwrap();
        install_deadlines(&near_client, &destination, Duration::from_millis(300)).unwrap();

        // The relay is driven on its own thread and waited for with a bound,
        // because the failure this test exists to catch is a relay that never
        // returns. Calling it inline would turn a lost deadline into a hung
        // test run — which is how a missing bound hides — rather than a
        // failure, so the bound lives on this side of the call too.
        let (finished, wait) = std::sync::mpsc::channel();
        let started = Instant::now();
        let relaying = thread::spawn(move || {
            let outcome = relay(near_client, destination);
            let _ = finished.send(());
            outcome
        });
        wait.recv_timeout(Duration::from_secs(2))
            .expect("the relay must end at its deadline, not hang");
        let outcome = relaying.join().unwrap().unwrap();
        let elapsed = started.elapsed();

        assert_eq!(outcome.to_client, 0);
        assert!(
            elapsed < Duration::from_secs(2),
            "the relay must end at its deadline, not hang: took {elapsed:?}"
        );
        far.join().unwrap();
    }

    #[test]
    fn a_timeout_is_recognized_under_either_platform_spelling() {
        assert_eq!(
            classify(&std::io::Error::from(std::io::ErrorKind::WouldBlock)),
            DirectionEnd::Idle
        );
        assert_eq!(
            classify(&std::io::Error::from(std::io::ErrorKind::TimedOut)),
            DirectionEnd::Idle
        );
        assert_eq!(
            classify(&std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
            DirectionEnd::Failed
        );
    }

    /// A connected loopback socket pair, standing in for an accepted client.
    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let dialer = thread::spawn(move || TcpStream::connect(address).unwrap());
        let (accepted, _) = listener.accept().unwrap();
        (accepted, dialer.join().unwrap())
    }
}
