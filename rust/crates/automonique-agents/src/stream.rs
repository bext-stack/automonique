// SPDX-License-Identifier: Elastic-2.0

//! Incremental, strictly bounded parser for provider stdout event lines.
//!
//! A provider writes one JSON object per line to its stdout. This module turns
//! those bytes — arriving in arbitrary chunks, split anywhere, including mid
//! multi-byte character — into the crate's existing normalized event
//! vocabulary ([`crate::NormalizedEvent`]), one line at a time, without ever
//! buffering the whole transcript.
//!
//! # It is a function of bytes, and nothing else
//!
//! [`ProviderEventStream`] performs no I/O. It does not open a pipe, read a
//! descriptor, poll, wait on a child, or know that a process exists. The caller
//! hands it bytes it obtained from somewhere; the runner's backend owns the
//! process, its descriptors, and its lifetime. That separation is deliberate:
//! parsing is the part that must be exhaustively testable from fixture bytes,
//! and a parser that also owned a pipe could not be.
//!
//! It is also the same vocabulary as the whole-buffer path. [`crate::normalize_jsonl`]
//! and this stream accept exactly the same events with exactly the same
//! ordering rules, because both drive the one normalizer in
//! [`crate::normalize`]. There is deliberately no second, looser grammar for
//! "live" output.
//!
//! # Bounds, all of them refusals
//!
//! - one line may not exceed [`crate::MAX_JSONL_LINE_BYTES`], checked both when
//!   a line completes and after every chunk on the bytes still held, so a
//!   provider that never emits a newline is refused rather than buffered;
//! - the whole stream may not exceed [`crate::MAX_JSONL_TOTAL_BYTES`];
//! - the stream may not accept more than [`MAX_STREAM_EVENTS`] events.
//!
//! Each is a typed refusal. None of them truncates, drops, or summarizes.
//!
//! # Unknown kinds are refusals, not skips
//!
//! An event kind outside the accepted vocabulary refuses the stream and names
//! the offending kind ([`crate::UnknownEventKind`]) — the kind token only,
//! never the line, because the line is provider output that may carry prompt
//! or workspace content. Skipping unknown events would be worse than the
//! refusal it replaces: the resulting transcript would silently be a subset of
//! what the provider did, and nothing downstream could tell.
//!
//! # A refused stream stays refused
//!
//! The first refusal is remembered. Every later call returns that same refusal
//! rather than resuming, because after a rejected line the parser's view of the
//! provider's state and the provider's own view have diverged, and nothing in
//! the byte stream can resynchronize them.
//!
//! # A truncated final line is refused, not salvaged
//!
//! Bytes with no terminating newline are *held*: more may still arrive, and
//! feeding the rest completes the line normally. But [`ProviderEventStream::finish`]
//! refuses while any partial line is held. A provider killed mid-write leaves a
//! prefix that may parse as valid JSON while meaning something else entirely —
//! a truncated `"text"` value is still a string — so a held remainder is
//! evidence the transcript is incomplete, and completeness is exactly what
//! `finish` claims.
//!
//! # What this module does **not** establish
//!
//! - It is not proof the provider ran, exited, or produced these bytes. It
//!   parses what it is given; provenance is the caller's problem.
//! - A [`crate::ProviderDisposition`] is what the provider *said*, not a run
//!   terminal. Only a supervisor holding trusted exit status and enforcement
//!   evidence can combine the two.

use crate::normalize::{NormalizedRun, Normalizer};
use crate::types::{
    AdapterError, ExecutionMode, MAX_JSONL_LINE_BYTES, MAX_JSONL_TOTAL_BYTES, NormalizedEvent,
    NormalizedTranscript, RunCoordinates,
};

/// Largest number of normalized events one stream may accept.
///
/// The byte bounds already cap a stream, but only jointly with line length; an
/// explicit event ceiling is what a consumer sizing a buffer can actually rely
/// on.
pub const MAX_STREAM_EVENTS: usize = 4096;

/// How an incremental stream handles malformed NDJSON lines.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum StreamPolicy {
    /// Any malformed line permanently refuses the stream.
    #[default]
    Strict,
    /// Invalid JSON or UTF-8 warns and continues at the next newline.
    Session,
}

/// Incremental parser over one provider process's stdout bytes.
///
/// Construction is free and starts no work. The parser *copies* the run
/// coordinates and execution mode it normalizes against, so the events it
/// produces carry the caller's run and turn identity rather than anything the
/// provider claimed about itself — and so a stream can be moved onto the reader
/// thread that drains a live process, which a borrowing one could not be.
pub struct ProviderEventStream {
    normalizer: Normalizer,
    pending: Vec<u8>,
    total_bytes: usize,
    refusal: Option<AdapterError>,
    policy: StreamPolicy,
    warning_count: u64,
}

impl ProviderEventStream {
    /// Start a stream for one turn.
    #[must_use]
    pub fn new(coordinates: &RunCoordinates, mode: &ExecutionMode) -> Self {
        Self {
            normalizer: Normalizer::new(coordinates, mode),
            pending: Vec::new(),
            total_bytes: 0,
            refusal: None,
            policy: StreamPolicy::Strict,
            warning_count: 0,
        }
    }

    /// Start a stream under an explicitly selected malformed-line policy.
    #[must_use]
    pub fn with_policy(
        coordinates: &RunCoordinates,
        mode: &ExecutionMode,
        policy: StreamPolicy,
    ) -> Self {
        let mut stream = Self::new(coordinates, mode);
        stream.policy = policy;
        stream
    }

    /// Feed the next chunk of provider stdout.
    ///
    /// Returns how many normalized events this chunk completed, which may be
    /// zero for a chunk that does not finish a line. On refusal the stream is
    /// permanently refused.
    pub fn push_bytes(&mut self, chunk: &[u8]) -> Result<usize, AdapterError> {
        if let Some(refusal) = &self.refusal {
            return Err(refusal.clone());
        }
        let before = self.normalizer.events().len();
        match self.consume(chunk) {
            Ok(()) => Ok(self.normalizer.events().len() - before),
            Err(error) => {
                self.refusal = Some(error.clone());
                Err(error)
            }
        }
    }

    /// Events accepted so far, in acceptance order.
    #[must_use]
    pub fn events(&self) -> &[NormalizedEvent] {
        self.normalizer.events()
    }

    /// Bytes currently held from a line that has no terminator yet.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.pending.len()
    }

    /// Total bytes fed to this stream, accepted or held.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Invalid lines skipped by [`StreamPolicy::Session`].
    #[must_use]
    pub const fn warning_count(&self) -> u64 {
        self.warning_count
    }

    /// Complete the stream and produce the whole transcript.
    ///
    /// Refuses a stream that was already refused, one holding a partial final
    /// line, and one whose events never reached a provider disposition.
    pub fn finish(self) -> Result<NormalizedTranscript, AdapterError> {
        if let Some(refusal) = self.refusal {
            return Err(refusal);
        }
        if !self.pending.is_empty() {
            return Err(AdapterError::IncompleteFinalLine);
        }
        let NormalizedRun {
            binding,
            events,
            disposition,
        } = self.normalizer.finish()?;
        Ok(NormalizedTranscript {
            binding,
            events,
            disposition,
            warning_count: self.warning_count,
        })
    }

    /// Finish a session process after its trusted supervisor observed exit.
    ///
    /// A non-zero exit, truncated final line, or EOF without a provider
    /// terminal becomes a failed disposition. Strict streams retain their
    /// ordinary refusal behavior.
    pub fn finish_session(
        mut self,
        exit_success: bool,
    ) -> Result<NormalizedTranscript, AdapterError> {
        if self.policy != StreamPolicy::Session {
            return self.finish();
        }
        if let Some(refusal) = self.refusal {
            return Err(refusal);
        }
        if !self.pending.is_empty() {
            self.pending.clear();
            self.warning_count = self.warning_count.saturating_add(1);
        }
        let normalized = if exit_success && self.normalizer.is_terminal() {
            self.normalizer.finish()?
        } else {
            self.normalizer.finish_failed()?
        };
        Ok(NormalizedTranscript {
            binding: normalized.binding,
            events: normalized.events,
            disposition: normalized.disposition,
            warning_count: self.warning_count,
        })
    }

    fn consume(&mut self, chunk: &[u8]) -> Result<(), AdapterError> {
        self.total_bytes = self
            .total_bytes
            .checked_add(chunk.len())
            .ok_or(AdapterError::OutputTooLarge)?;
        if self.total_bytes > MAX_JSONL_TOTAL_BYTES {
            return Err(AdapterError::OutputTooLarge);
        }
        let mut rest = chunk;
        while let Some(index) = rest.iter().position(|byte| *byte == b'\n') {
            let (head, tail) = rest.split_at(index);
            self.pending.extend_from_slice(head);
            // `tail` still begins with the newline itself.
            rest = &tail[1..];
            let line = std::mem::take(&mut self.pending);
            if let Err(error) = self.accept_line(&line) {
                if self.policy == StreamPolicy::Session
                    && matches!(error, AdapterError::InvalidJson | AdapterError::InvalidUtf8)
                {
                    self.warning_count = self.warning_count.saturating_add(1);
                } else {
                    return Err(error);
                }
            }
        }
        self.pending.extend_from_slice(rest);
        // The line bound applies to what is held, not only to what completed:
        // otherwise a provider that never writes a newline is unbounded.
        if self.pending.len() > MAX_JSONL_LINE_BYTES {
            return Err(AdapterError::OutputTooLarge);
        }
        Ok(())
    }

    fn accept_line(&mut self, line: &[u8]) -> Result<(), AdapterError> {
        if line.len() > MAX_JSONL_LINE_BYTES {
            return Err(AdapterError::OutputTooLarge);
        }
        if line.is_empty() {
            // A blank line is not a neutral separator here: the grammar is one
            // object per line, so a blank one means the writer lost framing.
            return Err(AdapterError::InvalidJson);
        }
        let line = std::str::from_utf8(line).map_err(|_| AdapterError::InvalidUtf8)?;
        self.normalizer.push(line)?;
        if self.normalizer.events().len() > MAX_STREAM_EVENTS {
            return Err(AdapterError::TooManyEvents);
        }
        Ok(())
    }
}
