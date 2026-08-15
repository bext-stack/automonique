// SPDX-License-Identifier: Elastic-2.0

//! Offline verification of a hash-chained audit database.
//!
//! ```text
//! automonique audit verify <database>
//! ```
//!
//! **Local, like the parity verbs and for the same reason.** A chain is
//! verified from bytes already durable on this host, so routing the check
//! through the administration lane would add a failure mode without adding a
//! fact — and it would make verification unavailable exactly when the daemon is
//! the thing under suspicion. A verifier that has to ask the suspect is not a
//! verifier.
//!
//! # Both halves, in one pass
//!
//! Verification is two checks that catch different lies, and this verb runs
//! both because either alone is misleading:
//!
//! - `AuditChain::verify_structure` is the store's own structural walk:
//!   positions contiguous from one, the genesis link 64 zeros, each
//!   `prev_hash` its predecessor's `record_hash`. It catches a deleted record
//!   and a reordering. It cannot catch an edited body, because it computes no
//!   hash.
//! - `automonique_protocol::audit::verify_chain` recomputes every
//!   `record_hash` from the stored bytes and every `record_id` from that hash,
//!   and re-reads `seq` and `prev_hash` out of the body to check them against
//!   the columns beside them. That is what catches an edited body — and the
//!   `record_hash` column edited to match it, since the body is what is hashed.
//!
//! Whichever fails first names the exact `seq` it failed at and what was wrong
//! with it. Nothing is repaired: a verifier that fixed what it found would
//! destroy the evidence it was run to produce.
//!
//! # What a passing verification does not say
//!
//! It does not say the records are **true**. A chain proves nothing has changed
//! since it was written, not that what was written was so.
//!
//! It does not say the chain is **complete**. Deleting a suffix leaves a valid
//! shorter chain, and detecting that needs an external witness to the head
//! hash, which nothing in this product keeps yet. The head hash is printed on
//! success precisely so an operator can keep one.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};

use automonique_protocol::audit::{AuditLink, verify_chain};
use automonique_store::audit_chain::{AuditChain, AuditEntry, MAX_AUDIT_PAGE};

/// One audit operation named on the command line.
#[derive(Clone)]
pub(crate) enum Operation {
    /// Walk the chain, recomputing every hash, and report the first break.
    Verify {
        /// Path to the audit chain database.
        database: OsString,
    },
}

/// A refusal from an audit verb, with a stable category.
#[derive(Debug)]
enum AuditCliError {
    /// An argument was not valid filesystem data or was outside its grammar.
    Argument(&'static str),
    /// The chain database refused an operation, or holds a row it would not
    /// have written.
    Store(String),
    /// The chain does not verify. This is the finding, not a malfunction.
    Broken(String),
}

impl AuditCliError {
    const fn category(&self) -> &'static str {
        match self {
            Self::Argument(_) => "invalid_argument",
            Self::Store(_) => "store",
            Self::Broken(_) => "chain_broken",
        }
    }

    fn detail(&self) -> &str {
        match self {
            Self::Argument(detail) => detail,
            Self::Store(detail) | Self::Broken(detail) => detail,
        }
    }

    /// Usage-shaped failures exit 2 like the rest of this CLI; a store refusal
    /// and a broken chain both exit 1, because both are answers rather than
    /// mistakes the operator made.
    const fn exit_code(&self) -> u8 {
        match self {
            Self::Argument(_) => 2,
            Self::Store(_) | Self::Broken(_) => 1,
        }
    }
}

/// Answer one audit operation, writing rendered output only on success.
pub(crate) fn run<W: Write, E: Write>(operation: &Operation, stdout: &mut W, stderr: &mut E) -> u8 {
    let rendered = match operation {
        Operation::Verify { database } => verify_verb(database),
    };
    match rendered {
        Ok(text) => {
            if stdout.write_all(text.as_bytes()).is_err() {
                return 1;
            }
            0
        }
        Err(error) => {
            let _ = writeln!(
                stderr,
                "automonique audit refused: {} ({})",
                error.category(),
                error.detail()
            );
            error.exit_code()
        }
    }
}

fn verify_verb(database: &OsStr) -> Result<String, AuditCliError> {
    let path = database_path(database)?;
    let chain = AuditChain::open(&path).map_err(|error| store(&error))?;

    // Structure first: it is the cheaper walk, and a gap it finds is a better
    // description of a deletion than the hash mismatch the same deletion also
    // produces.
    let structural = chain
        .verify_structure()
        .map_err(|error| broken_or_store(&error))?;

    let entries = read_all(&chain)?;
    let links: Vec<AuditLink<'_>> = entries.iter().map(link).collect();
    let verified = verify_chain(links).map_err(|error| AuditCliError::Broken(error.to_string()))?;

    let head = entries.last().map_or_else(
        || String::from("(empty chain)"),
        |entry| entry.record_hash.clone(),
    );
    Ok(format!(
        "chain {}\nrecords {verified}\nstructure {structural}\nhead {head}\nverdict intact\n",
        path.display()
    ))
}

/// Every record in `seq` order.
///
/// Read as pages rather than as one statement so the chain's own cursor bound
/// is the ceiling on a single allocation, and so a chain far larger than a page
/// verifies without a special case.
fn read_all(chain: &AuditChain) -> Result<Vec<AuditEntry>, AuditCliError> {
    let mut entries = Vec::new();
    let mut cursor = 0_u64;
    loop {
        let page = chain
            .page(cursor, MAX_AUDIT_PAGE)
            .map_err(|error| broken_or_store(&error))?;
        let next = page.next_cursor;
        entries.extend(page.entries);
        match next {
            Some(next) => cursor = next,
            None => return Ok(entries),
        }
    }
}

fn link(entry: &AuditEntry) -> AuditLink<'_> {
    AuditLink {
        seq: entry.seq,
        record_id: &entry.record_id,
        body: &entry.body,
        prev_hash: &entry.prev_hash,
        record_hash: &entry.record_hash,
    }
}

/// A store refusal, reported by its stable category and message.
fn store(error: &automonique_store::audit_chain::AuditChainError) -> AuditCliError {
    AuditCliError::Store(format!("{}: {error}", error.category()))
}

/// Corruption the store found is a broken chain, not a malfunctioning store.
///
/// The store's read paths refuse a row this API would not have written, and on
/// an audit chain that refusal *is* the finding an operator ran this verb to
/// get. Reporting it as a store failure would file the answer under the wrong
/// heading.
fn broken_or_store(error: &automonique_store::audit_chain::AuditChainError) -> AuditCliError {
    match error {
        automonique_store::audit_chain::AuditChainError::Corrupt(_) => {
            AuditCliError::Broken(format!("{}: {error}", error.category()))
        }
        other => store(other),
    }
}

fn database_path(value: &OsStr) -> Result<PathBuf, AuditCliError> {
    if value.is_empty() {
        return Err(AuditCliError::Argument("database"));
    }
    let path = PathBuf::from(value);
    if !Path::new(&path).is_absolute() {
        return Err(AuditCliError::Argument("database_not_absolute"));
    }
    Ok(path)
}
