// SPDX-License-Identifier: Elastic-2.0

//! The golden-trace format, and the hermetic replay that turns one into a
//! verdict.
//!
//! A trace is an ordered file of canonical-JSON *lines* (`.cjson`): one header,
//! then records. It carries everything one comparison needs and nothing else —
//! the inbound events that provoked the decisions, the canned provider
//! interactions that stand in for a model, and both engines' intended-action
//! envelopes as they were recorded.
//!
//! ```text
//! {"category":"happy","parity_row":"…","provenance":"synthetic","schema":"automonique.parity-trace/v1","scope":"…","workspace":{…}}
//! {"app_mention":false,"channel":"C…","event_id":"Ev1","record":"inbound-event","text":"…","thread_ts":"…","user":"U…"}
//! {"engine":"legacy-observed","envelope":{…},"record":"envelope"}
//! ```
//!
//! # Why lines, and why integers
//!
//! One record per line means a trace can be appended to during capture and read
//! back without holding the whole corpus in memory, and it means a diff of two
//! traces is a diff of records. Each line is *canonical* JSON on
//! [`automonique_protocol::wire`], so one record has exactly one byte spelling —
//! which is what makes the determinism test below meaningful.
//!
//! That canonical form admits integers only. Any latency, score or duration a
//! trace ever carries must therefore be a whole number of milliseconds or basis
//! points; a float cannot round-trip and is refused rather than rounded.
//!
//! # Refusal, not best effort
//!
//! An unknown `schema`, an unknown `record` kind, a missing member, an extra
//! member or a non-canonical line is a refusal. A trace that was best-effort
//! parsed would silently drop the record that mattered, and the whole corpus
//! exists to catch exactly the case nobody thought of.
//!
//! # What replay is, and what it is not
//!
//! [`replay`] builds the real [`crate::slack`] router with the #10 shadow
//! surfaces and a fixed clock, feeds it the trace's inbound events, and diffs
//! the envelopes it produces against the ones the trace recorded for the
//! reference engine. It opens no socket, reads no clock, touches no database and
//! reaches no network — the whole thing is values.
//!
//! It is not a claim that the candidate is correct. It is a claim that, on this
//! input, the candidate decided what the trace says the reference engine
//! decided, or differed in a way the registry already accounts for.
//!
//! # The provider lane
//!
//! [`ReplayRunLane`] is the deterministic stand-in for a model: it answers from
//! the trace's canned interactions, keyed by the digest of the task text, and
//! refuses anything it was not given an answer for. No new seam was needed —
//! [`crate::telegram_bridge::RunLane`] is already a public trait that tests
//! inject into.
//!
//! The Slack ticket-routing scope this milestone traces holds its GitHub action
//! engine over a *concrete* lane type, so a replay of that scope builds the
//! router with no action engine at all and a trace that declares provider
//! interactions for it is refused as inconsistent rather than quietly ignored.
//! When a scope whose lane is injectable is traced, the same
//! [`ReplayRunLane`] serves it unchanged.

use automonique_protocol::digest::Sha256;
use automonique_protocol::parity::{
    Category, Classification, Comparison, ComparisonVerdict, DeviationRegistry,
    IntendedActionEnvelope, PARITY_TRACE_SCHEMA_V1, ParityEngine, compare,
};
use automonique_protocol::wire::{JsonValue, parse_canonical};

use crate::shadow::{MemorySink, ShadowClock, SharedRecorder};
use crate::telegram_bridge::{QuestionProfile, RunFailure, RunLane};

/// Largest number of records one trace may carry.
pub const MAX_TRACE_RECORDS: usize = 4_096;

/// Largest canonical bytes of one trace line.
pub const MAX_TRACE_LINE_BYTES: usize = 64 * 1024;

/// The fixed clock every replay runs under.
///
/// A constant rather than a parameter: two replays of one trace must produce
/// byte-identical envelopes, and a caller-chosen clock would make that a
/// property of the caller rather than of the trace.
pub const REPLAY_CLOCK_MS: i64 = 1_700_000_000_000;

/// A refusal while reading, writing or replaying a trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TraceError {
    /// A line was not canonical JSON, or was over the line ceiling.
    Line {
        /// One-based line number that was refused.
        line: usize,
    },
    /// The file had no header line.
    HeaderAbsent,
    /// The header declared a schema this build does not serve.
    UnknownSchema,
    /// A member was absent, of the wrong type, or unexpected.
    Body {
        /// One-based line number that was refused.
        line: usize,
    },
    /// A record named a kind this build does not define.
    UnknownRecord {
        /// One-based line number that was refused.
        line: usize,
    },
    /// The trace carried more records than [`MAX_TRACE_RECORDS`].
    TooManyRecords,
    /// The trace declared provider interactions no lane in this scope consumes.
    ProviderInteractionUnconsumed,
    /// A workspace coordinate or event field was outside its grammar.
    Field(&'static str),
    /// The scope named has no replay binding in this build.
    UnknownScope,
}

impl TraceError {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Line { .. } => "line",
            Self::HeaderAbsent => "header_absent",
            Self::UnknownSchema => "unknown_schema",
            Self::Body { .. } => "body",
            Self::UnknownRecord { .. } => "unknown_record",
            Self::TooManyRecords => "too_many_records",
            Self::ProviderInteractionUnconsumed => "provider_interaction_unconsumed",
            Self::Field(_) => "field",
            Self::UnknownScope => "unknown_scope",
        }
    }
}

impl std::fmt::Display for TraceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Line { line } => write!(formatter, "line {line} is not canonical JSON"),
            Self::HeaderAbsent => formatter.write_str("trace has no header line"),
            Self::UnknownSchema => formatter.write_str("trace declares an unserved schema"),
            Self::Body { line } => write!(formatter, "line {line} is not the shape it claims"),
            Self::UnknownRecord { line } => {
                write!(formatter, "line {line} names an undefined record kind")
            }
            Self::TooManyRecords => write!(formatter, "trace exceeds {MAX_TRACE_RECORDS} records"),
            Self::ProviderInteractionUnconsumed => formatter
                .write_str("trace declares provider interactions this scope cannot consume"),
            Self::Field(field) => write!(formatter, "field {field} is outside its grammar"),
            Self::UnknownScope => formatter.write_str("no replay binding for this scope"),
        }
    }
}

impl std::error::Error for TraceError {}

/// The anonymized workspace coordinates a replay reconstructs the router from.
///
/// Synthetic by construction: capture rewrites every real identifier into a
/// stable synthetic token before a trace is ever written, so these values are
/// the shape of a workspace and never one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceWorkspace {
    /// Synthetic team identifier.
    pub team: String,
    /// Synthetic identifier of the one configured channel.
    pub channel: String,
    /// Synthetic administrator identifiers.
    pub admins: Vec<String>,
    /// Synthetic member identifiers.
    pub members: Vec<String>,
}

/// A trace's header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceHeader {
    /// Parity scope this trace belongs to.
    pub scope: String,
    /// The `plan/ledgers/parity.json` entry key this trace is evidence for.
    pub parity_row: String,
    /// How representative this trace is, for the weighted score.
    ///
    /// Human judgement, reviewed with the fixture. The scorer reads it; it never
    /// derives it.
    pub category: Category,
    /// Where the trace came from: `synthetic` or `captured`.
    pub provenance: String,
    /// The workspace to reconstruct.
    pub workspace: TraceWorkspace,
}

/// One inbound event a trace replays.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceEvent {
    /// Synthetic event identifier; the source key is derived from it.
    pub event_id: String,
    /// Synthetic channel identifier.
    pub channel: String,
    /// Synthetic author identifier.
    pub user: String,
    /// The message text.
    pub text: String,
    /// The thread this message belongs to.
    pub thread_ts: String,
    /// Whether the message mentioned the app.
    pub app_mention: bool,
}

/// One record in a trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TraceRecord {
    /// An event to feed the router.
    InboundEvent(TraceEvent),
    /// A canned provider answer, keyed by the digest of the task text.
    ProviderInteraction {
        /// SHA-256 of the task text, as 64 lowercase hexadecimal digits.
        prompt_digest: String,
        /// The answer the lane returns for it.
        response: String,
    },
    /// An envelope one engine recorded.
    Envelope(IntendedActionEnvelope),
}

impl TraceRecord {
    fn kind(&self) -> &'static str {
        match self {
            Self::InboundEvent(_) => "inbound-event",
            Self::ProviderInteraction { .. } => "provider-interaction",
            Self::Envelope(_) => "envelope",
        }
    }
}

/// One golden trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Trace {
    header: TraceHeader,
    records: Vec<TraceRecord>,
}

impl Trace {
    /// Assemble a trace from a header and its records.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::TooManyRecords`] above [`MAX_TRACE_RECORDS`].
    pub fn new(header: TraceHeader, records: Vec<TraceRecord>) -> Result<Self, TraceError> {
        if records.len() > MAX_TRACE_RECORDS {
            return Err(TraceError::TooManyRecords);
        }
        Ok(Self { header, records })
    }

    /// The header.
    #[must_use]
    pub const fn header(&self) -> &TraceHeader {
        &self.header
    }

    /// The records, in file order.
    #[must_use]
    pub fn records(&self) -> &[TraceRecord] {
        &self.records
    }

    /// The inbound events, in file order.
    #[must_use]
    pub fn events(&self) -> Vec<&TraceEvent> {
        self.records
            .iter()
            .filter_map(|record| match record {
                TraceRecord::InboundEvent(event) => Some(event),
                _ => None,
            })
            .collect()
    }

    /// The envelopes one engine recorded, in file order.
    #[must_use]
    pub fn envelopes(&self, engine: ParityEngine) -> Vec<&IntendedActionEnvelope> {
        self.records
            .iter()
            .filter_map(|record| match record {
                TraceRecord::Envelope(envelope) if envelope.engine() == engine => Some(envelope),
                _ => None,
            })
            .collect()
    }

    /// The canned provider interactions, in file order.
    #[must_use]
    pub fn provider_interactions(&self) -> Vec<(&str, &str)> {
        self.records
            .iter()
            .filter_map(|record| match record {
                TraceRecord::ProviderInteraction {
                    prompt_digest,
                    response,
                } => Some((prompt_digest.as_str(), response.as_str())),
                _ => None,
            })
            .collect()
    }

    /// Render the trace to canonical-JSON lines.
    #[must_use]
    pub fn to_lines(&self) -> Vec<u8> {
        let mut out = header_document(&self.header).to_canonical_bytes();
        out.push(b'\n');
        for record in &self.records {
            out.extend_from_slice(&record_document(record).to_canonical_bytes());
            out.push(b'\n');
        }
        out
    }

    /// Parse a trace from canonical-JSON lines.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::HeaderAbsent`] for an empty file,
    /// [`TraceError::Line`] for a line that is not canonical JSON or is over the
    /// ceiling, [`TraceError::UnknownSchema`] for a schema this build does not
    /// serve, [`TraceError::UnknownRecord`] for a record kind it does not
    /// define, and [`TraceError::Body`] for a line that is not the shape it
    /// claims.
    pub fn from_lines(payload: &[u8]) -> Result<Self, TraceError> {
        let text = core::str::from_utf8(payload).map_err(|_| TraceError::Line { line: 1 })?;
        let mut lines = text.lines().enumerate();
        let (_, first) = lines.next().ok_or(TraceError::HeaderAbsent)?;
        if first.is_empty() {
            return Err(TraceError::HeaderAbsent);
        }
        let header = parse_header(&parse_line(first, 1)?)?;
        let mut records = Vec::new();
        for (index, line) in lines {
            let number = index + 1;
            if line.is_empty() {
                continue;
            }
            if records.len() >= MAX_TRACE_RECORDS {
                return Err(TraceError::TooManyRecords);
            }
            records.push(parse_record(&parse_line(line, number)?, number)?);
        }
        Ok(Self { header, records })
    }
}

fn parse_line(line: &str, number: usize) -> Result<JsonValue, TraceError> {
    if line.len() > MAX_TRACE_LINE_BYTES {
        return Err(TraceError::Line { line: number });
    }
    parse_canonical(line.as_bytes()).map_err(|_| TraceError::Line { line: number })
}

fn header_document(header: &TraceHeader) -> JsonValue {
    JsonValue::Object(vec![
        (
            "category".to_owned(),
            JsonValue::String(header.category.as_str().to_owned()),
        ),
        (
            "parity_row".to_owned(),
            JsonValue::String(header.parity_row.clone()),
        ),
        (
            "provenance".to_owned(),
            JsonValue::String(header.provenance.clone()),
        ),
        (
            "schema".to_owned(),
            JsonValue::String(PARITY_TRACE_SCHEMA_V1.to_owned()),
        ),
        ("scope".to_owned(), JsonValue::String(header.scope.clone())),
        (
            "workspace".to_owned(),
            JsonValue::Object(vec![
                (
                    "admins".to_owned(),
                    JsonValue::Array(
                        header
                            .workspace
                            .admins
                            .iter()
                            .map(|admin| JsonValue::String(admin.clone()))
                            .collect(),
                    ),
                ),
                (
                    "channel".to_owned(),
                    JsonValue::String(header.workspace.channel.clone()),
                ),
                (
                    "members".to_owned(),
                    JsonValue::Array(
                        header
                            .workspace
                            .members
                            .iter()
                            .map(|member| JsonValue::String(member.clone()))
                            .collect(),
                    ),
                ),
                (
                    "team".to_owned(),
                    JsonValue::String(header.workspace.team.clone()),
                ),
            ]),
        ),
    ])
}

fn parse_header(body: &JsonValue) -> Result<TraceHeader, TraceError> {
    exact(
        body,
        &[
            "category",
            "parity_row",
            "provenance",
            "schema",
            "scope",
            "workspace",
        ],
        1,
    )?;
    if string(body, "schema", 1)? != PARITY_TRACE_SCHEMA_V1 {
        return Err(TraceError::UnknownSchema);
    }
    let workspace = body.get("workspace").ok_or(TraceError::Body { line: 1 })?;
    exact(workspace, &["admins", "channel", "members", "team"], 1)?;
    let spelling = string(body, "category", 1)?;
    let category = Category::ALL
        .into_iter()
        .find(|category| category.as_str() == spelling)
        .ok_or(TraceError::Field("category"))?;
    Ok(TraceHeader {
        scope: string(body, "scope", 1)?,
        parity_row: string(body, "parity_row", 1)?,
        category,
        provenance: string(body, "provenance", 1)?,
        workspace: TraceWorkspace {
            team: string(workspace, "team", 1)?,
            channel: string(workspace, "channel", 1)?,
            admins: strings(workspace, "admins", 1)?,
            members: strings(workspace, "members", 1)?,
        },
    })
}

fn record_document(record: &TraceRecord) -> JsonValue {
    let mut entries = vec![(
        "record".to_owned(),
        JsonValue::String(record.kind().to_owned()),
    )];
    match record {
        TraceRecord::InboundEvent(event) => {
            entries.push(("app_mention".to_owned(), JsonValue::Bool(event.app_mention)));
            entries.push((
                "channel".to_owned(),
                JsonValue::String(event.channel.clone()),
            ));
            entries.push((
                "event_id".to_owned(),
                JsonValue::String(event.event_id.clone()),
            ));
            entries.push(("text".to_owned(), JsonValue::String(event.text.clone())));
            entries.push((
                "thread_ts".to_owned(),
                JsonValue::String(event.thread_ts.clone()),
            ));
            entries.push(("user".to_owned(), JsonValue::String(event.user.clone())));
        }
        TraceRecord::ProviderInteraction {
            prompt_digest,
            response,
        } => {
            entries.push((
                "prompt_digest".to_owned(),
                JsonValue::String(prompt_digest.clone()),
            ));
            entries.push(("response".to_owned(), JsonValue::String(response.clone())));
        }
        TraceRecord::Envelope(envelope) => {
            entries.push(("envelope".to_owned(), envelope.to_document()));
        }
    }
    JsonValue::Object(entries)
}

fn parse_record(body: &JsonValue, line: usize) -> Result<TraceRecord, TraceError> {
    match string(body, "record", line)?.as_str() {
        "inbound-event" => {
            exact(
                body,
                &[
                    "app_mention",
                    "channel",
                    "event_id",
                    "record",
                    "text",
                    "thread_ts",
                    "user",
                ],
                line,
            )?;
            let JsonValue::Bool(app_mention) =
                body.get("app_mention").ok_or(TraceError::Body { line })?
            else {
                return Err(TraceError::Body { line });
            };
            Ok(TraceRecord::InboundEvent(TraceEvent {
                event_id: string(body, "event_id", line)?,
                channel: string(body, "channel", line)?,
                user: string(body, "user", line)?,
                text: string(body, "text", line)?,
                thread_ts: string(body, "thread_ts", line)?,
                app_mention: *app_mention,
            }))
        }
        "provider-interaction" => {
            exact(body, &["prompt_digest", "record", "response"], line)?;
            Ok(TraceRecord::ProviderInteraction {
                prompt_digest: string(body, "prompt_digest", line)?,
                response: string(body, "response", line)?,
            })
        }
        "envelope" => {
            exact(body, &["envelope", "record"], line)?;
            let envelope = IntendedActionEnvelope::from_document(
                body.get("envelope").ok_or(TraceError::Body { line })?,
            )
            .map_err(|_| TraceError::Body { line })?;
            Ok(TraceRecord::Envelope(envelope))
        }
        _ => Err(TraceError::UnknownRecord { line }),
    }
}

fn exact(body: &JsonValue, fields: &[&str], line: usize) -> Result<(), TraceError> {
    let JsonValue::Object(entries) = body else {
        return Err(TraceError::Body { line });
    };
    if entries.len() != fields.len()
        || !fields
            .iter()
            .all(|field| entries.iter().any(|(name, _)| name == field))
    {
        return Err(TraceError::Body { line });
    }
    Ok(())
}

fn string(body: &JsonValue, field: &str, line: usize) -> Result<String, TraceError> {
    body.get(field)
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
        .ok_or(TraceError::Body { line })
}

fn strings(body: &JsonValue, field: &str, line: usize) -> Result<Vec<String>, TraceError> {
    let JsonValue::Array(items) = body.get(field).ok_or(TraceError::Body { line })? else {
        return Err(TraceError::Body { line });
    };
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or(TraceError::Body { line })
        })
        .collect()
}

/// A deterministic provider lane fed from a trace's canned interactions.
///
/// Answers are keyed by the SHA-256 of the task text rather than by position, so
/// a change in the order the candidate asks its questions is a mismatch on the
/// question rather than a silently reordered set of answers. A task the trace
/// has no answer for is [`RunFailure::NotConfigured`] — the honest reading of
/// "this lane was never given a response for that" — and never an invented one.
#[derive(Clone, Debug, Default)]
pub struct ReplayRunLane {
    answers: Vec<(String, String)>,
    asked: Vec<String>,
}

impl ReplayRunLane {
    /// Build a lane from a trace's canned interactions.
    #[must_use]
    pub fn new(interactions: &[(&str, &str)]) -> Self {
        Self {
            answers: interactions
                .iter()
                .map(|(digest, response)| ((*digest).to_owned(), (*response).to_owned()))
                .collect(),
            asked: Vec::new(),
        }
    }

    /// The digest of one task text, as a trace spells it.
    #[must_use]
    pub fn prompt_digest(task: &str) -> String {
        Sha256::digest(task.as_bytes()).to_hex()
    }

    /// The prompt digests this lane was asked for, in order.
    #[must_use]
    pub fn asked(&self) -> &[String] {
        &self.asked
    }
}

impl RunLane for ReplayRunLane {
    fn run(&mut self, task: &str) -> Result<String, RunFailure> {
        let digest = Self::prompt_digest(task);
        let answer = self
            .answers
            .iter()
            .find(|(recorded, _)| *recorded == digest)
            .map(|(_, response)| response.clone());
        self.asked.push(digest);
        answer.ok_or(RunFailure::NotConfigured)
    }

    fn run_question(
        &mut self,
        task: &str,
        _profile: QuestionProfile,
    ) -> Result<String, RunFailure> {
        self.run(task)
    }
}

/// One position's verdict from a replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayDifference {
    /// The source key the position belongs to.
    pub source_key: String,
    /// The position within that source key's streams.
    pub sequence: u32,
    /// The comparison itself.
    pub comparison: Comparison,
    /// How the comparison was accounted for.
    pub classification: Classification,
    /// Registry entries that explained it, when it was a known deviation.
    pub deviations: Vec<String>,
}

/// What one replay produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayOutcome {
    /// Every envelope the candidate decided, in order.
    pub candidate: Vec<IntendedActionEnvelope>,
    /// One entry per compared position.
    pub differences: Vec<ReplayDifference>,
}

impl ReplayOutcome {
    /// Positions the registry could not account for.
    #[must_use]
    pub fn regressions(&self) -> Vec<&ReplayDifference> {
        self.differences
            .iter()
            .filter(|difference| difference.classification == Classification::Regression)
            .collect()
    }

    /// Whether every position classified parity or known-deviation.
    #[must_use]
    pub fn accounted(&self) -> bool {
        self.regressions().is_empty()
    }

    /// Positions where the two engines agreed exactly.
    #[must_use]
    pub fn matches(&self) -> usize {
        self.differences
            .iter()
            .filter(|difference| difference.comparison.verdict() == ComparisonVerdict::Match)
            .count()
    }
}

/// Replay one trace and classify every position against the registry.
///
/// Hermetic: no socket, no database, no network, and a fixed clock, so two
/// replays of one trace produce byte-identical envelopes.
///
/// # Errors
///
/// Returns [`TraceError::UnknownScope`] for a scope this build has no replay
/// binding for, [`TraceError::ProviderInteractionUnconsumed`] for a trace whose
/// canned interactions nothing in the scope can consume, and
/// [`TraceError::Field`] for a workspace coordinate outside its grammar.
pub fn replay(trace: &Trace, registry: &DeviationRegistry) -> Result<ReplayOutcome, TraceError> {
    let candidate = crate::slack::replay_slack_trace(trace)?;
    let recorded = trace.envelopes(ParityEngine::LegacyObserved);

    // Pair position by position within each source key. A key present on only
    // one side still produces comparisons, because a candidate that decided
    // nothing where the reference engine acted is the finding, not a gap.
    let mut keys: Vec<String> = Vec::new();
    for key in candidate
        .iter()
        .map(IntendedActionEnvelope::source_key)
        .chain(recorded.iter().map(|envelope| envelope.source_key()))
    {
        if !keys.iter().any(|existing| existing == key) {
            keys.push(key.to_owned());
        }
    }

    let mut differences = Vec::new();
    for key in keys {
        let ours: Vec<&IntendedActionEnvelope> = candidate
            .iter()
            .filter(|envelope| envelope.source_key() == key)
            .collect();
        let theirs: Vec<&IntendedActionEnvelope> = recorded
            .iter()
            .copied()
            .filter(|envelope| envelope.source_key() == key)
            .collect();
        for position in 0..ours.len().max(theirs.len()) {
            let mine = ours.get(position).copied();
            let other = theirs.get(position).copied();
            let comparison = compare(mine, other);
            let kind = mine.or(other).map(|envelope| envelope.action().kind());
            let (classification, deviations) = match kind {
                Some(kind) => registry.classify(&trace.header.scope, kind, &comparison),
                None => (Classification::Parity, Vec::new()),
            };
            let sequence = u32::try_from(position).map_err(|_| TraceError::Field("sequence"))?;
            differences.push(ReplayDifference {
                source_key: key.clone(),
                sequence,
                comparison,
                classification,
                deviations,
            });
        }
    }
    Ok(ReplayOutcome {
        candidate,
        differences,
    })
}

/// The recorder a scope's replay records into.
///
/// Fixed clock and in-memory sink: a replay must be byte-identical run to run,
/// and it must leave nothing durable behind.
pub(crate) fn replay_recorder(scope: &str) -> SharedRecorder<MemorySink> {
    SharedRecorder::opened(
        scope,
        ParityEngine::ShadowCandidate,
        ShadowClock::Fixed(REPLAY_CLOCK_MS),
        MemorySink::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use automonique_protocol::parity::{ActionKind, IntendedAction};

    fn header() -> TraceHeader {
        TraceHeader {
            scope: String::from("slack-ticket-routing"),
            parity_row: String::from(
                "slack-socket-mode-messages-mentions-threads-commands-and-actions",
            ),
            category: Category::Happy,
            provenance: String::from("synthetic"),
            workspace: TraceWorkspace {
                team: String::from("T0TRACE0001"),
                channel: String::from("C0TRACE0001"),
                admins: vec![String::from("U0TRACEADM1")],
                members: vec![String::from("U0TRACEADM1")],
            },
        }
    }

    fn event() -> TraceEvent {
        TraceEvent {
            event_id: String::from("Ev0000000001"),
            channel: String::from("C0TRACE0001"),
            user: String::from("U0TRACEUSR1"),
            text: String::from("please handle https://example.invalid/issues/1"),
            thread_ts: String::from("1700000000.000100"),
            app_mention: false,
        }
    }

    fn envelope() -> IntendedActionEnvelope {
        IntendedActionEnvelope::new(
            "slack-ticket-routing",
            "slack:T0TRACE0001:event:Ev0000000001",
            ParityEngine::LegacyObserved,
            0,
            IntendedAction::new(
                ActionKind::SlackThreadReply,
                vec![
                    String::from("C0TRACE0001"),
                    String::from("1700000000.000100"),
                    String::from("on it"),
                ],
            )
            .expect("valid action"),
            REPLAY_CLOCK_MS,
        )
        .expect("valid envelope")
    }

    fn trace() -> Trace {
        Trace::new(
            header(),
            vec![
                TraceRecord::InboundEvent(event()),
                TraceRecord::Envelope(envelope()),
            ],
        )
        .expect("valid trace")
    }

    #[test]
    fn round_trips_through_canonical_lines() {
        let original = trace();
        let bytes = original.to_lines();
        assert_eq!(Trace::from_lines(&bytes).expect("decodes"), original);
        assert_eq!(
            Trace::from_lines(&bytes).expect("decodes").to_lines(),
            bytes
        );
    }

    #[test]
    fn every_line_is_canonical_on_its_own() {
        let bytes = trace().to_lines();
        let text = String::from_utf8(bytes).expect("utf-8");
        for line in text.lines() {
            parse_canonical(line.as_bytes()).expect("each line is canonical on its own");
        }
    }

    #[test]
    fn an_empty_file_has_no_header() {
        assert_eq!(Trace::from_lines(b""), Err(TraceError::HeaderAbsent));
    }

    #[test]
    fn a_foreign_schema_is_refused_rather_than_best_effort_parsed() {
        let text = String::from_utf8(trace().to_lines()).expect("utf-8");
        let foreign = text.replace(PARITY_TRACE_SCHEMA_V1, "automonique.parity-trace/v2");
        assert_eq!(
            Trace::from_lines(foreign.as_bytes()),
            Err(TraceError::UnknownSchema)
        );
    }

    #[test]
    fn an_undefined_record_kind_is_refused() {
        let text = String::from_utf8(trace().to_lines()).expect("utf-8");
        let foreign = text.replace("\"inbound-event\"", "\"inbound-events\"");
        assert_eq!(
            Trace::from_lines(foreign.as_bytes()),
            Err(TraceError::UnknownRecord { line: 2 })
        );
    }

    #[test]
    fn a_non_canonical_line_is_refused_with_its_number() {
        let text = String::from_utf8(trace().to_lines()).expect("utf-8");
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        lines[1] = lines[1].replace("\":", "\" :");
        assert_eq!(
            Trace::from_lines(lines.join("\n").as_bytes()),
            Err(TraceError::Line { line: 2 })
        );
    }

    #[test]
    fn an_extra_member_on_a_record_is_refused() {
        let text = String::from_utf8(trace().to_lines()).expect("utf-8");
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        lines[1] = lines[1].replacen('{', "{\"aaa\":1,", 1);
        assert_eq!(
            Trace::from_lines(lines.join("\n").as_bytes()),
            Err(TraceError::Body { line: 2 })
        );
    }

    #[test]
    fn a_category_outside_the_closed_set_is_refused() {
        let text = String::from_utf8(trace().to_lines()).expect("utf-8");
        let foreign = text.replacen("\"happy\"", "\"cheerful\"", 1);
        assert_eq!(
            Trace::from_lines(foreign.as_bytes()),
            Err(TraceError::Field("category"))
        );
    }

    #[test]
    fn engines_are_read_back_separately() {
        let trace = trace();
        assert_eq!(trace.envelopes(ParityEngine::LegacyObserved).len(), 1);
        assert!(trace.envelopes(ParityEngine::ShadowCandidate).is_empty());
        assert_eq!(trace.events().len(), 1);
    }

    #[test]
    fn the_replay_lane_answers_only_what_it_was_given() {
        let known = "what is the status";
        let digest = ReplayRunLane::prompt_digest(known);
        let mut lane = ReplayRunLane::new(&[(digest.as_str(), "it is fine")]);
        assert_eq!(lane.run(known), Ok(String::from("it is fine")));
        assert_eq!(
            lane.run("something else entirely"),
            Err(RunFailure::NotConfigured)
        );
        assert_eq!(lane.asked().len(), 2);
        assert_eq!(lane.asked()[0], digest);
    }

    #[test]
    fn the_replay_lane_is_keyed_by_content_not_by_position() {
        let first = ReplayRunLane::prompt_digest("first");
        let second = ReplayRunLane::prompt_digest("second");
        let mut lane = ReplayRunLane::new(&[(first.as_str(), "one"), (second.as_str(), "two")]);
        assert_eq!(lane.run("second"), Ok(String::from("two")));
        assert_eq!(lane.run("first"), Ok(String::from("one")));
    }

    #[test]
    fn a_question_uses_the_same_canned_answers_as_a_run() {
        let digest = ReplayRunLane::prompt_digest("ask");
        let mut lane = ReplayRunLane::new(&[(digest.as_str(), "answered")]);
        assert_eq!(
            lane.run_question("ask", QuestionProfile::Conversation),
            Ok(String::from("answered"))
        );
    }
}
