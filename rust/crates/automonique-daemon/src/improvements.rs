// SPDX-License-Identifier: Elastic-2.0

//! Telegram-facing coordination primitives for self-improvement plans.
//!
//! This module owns no GitHub credential and performs no merge. It turns one
//! explicit owner request into durable state, renders the canonical private
//! plan document a GitHub broker publishes, and converts exact Telegram button
//! callbacks into the store's actor/chat/revision/digest-bound decisions.

use std::error::Error;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use automonique_store::improvements::{
    ApprovalAttempt, ApprovalKind, ImprovementRecord, ImprovementState, ImprovementStore,
    ImprovementStoreError, NewApprovalChallenge, NewImprovement, PlanSubmission, PreparedPlan,
    ReleaseSubmission, StateTransition,
};
use automonique_transport_runtime::{ApprovalKeyboard, SendMessageRequest};
use sha2::{Digest, Sha256};

const CHALLENGE_LIFETIME_MS: i64 = 15 * 60 * 1_000;
const CALLBACK_VERSION: &str = "im1";
const MAX_PLAN_ITEMS: usize = 64;
const MAX_PLAN_ITEM_BYTES: usize = 1_024;
const MAX_PLAN_DOCUMENT_BYTES: usize = 64 * 1_024;
pub const SOURCE_REPOSITORY: &str = "bext-stack/automonique";
pub const PLANNING_REPOSITORY: &str = "bext-stack/automonique-plans";
const STORE_NAME: &str = "improvements.sqlite3";
const CALLBACK_KEY_NAME: &str = "improvement-callback.key";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImprovementIntent {
    pub request: String,
}

impl ImprovementIntent {
    /// Recognize an explicit request to change Automonique. Ordinary questions
    /// about its current capabilities do not become write intents.
    #[must_use]
    pub fn recognize(message: &str) -> Option<Self> {
        let trimmed = message.trim();
        if trimmed.is_empty() || trimmed.starts_with('/') {
            return None;
        }
        let normalized = trimmed.to_lowercase();
        let names_product = ["automonique", "monique", "yourself", "your self"]
            .iter()
            .any(|term| normalized.contains(term));
        let asks_change = [
            "improve",
            "change yourself",
            "add support",
            "add a feature",
            "teach yourself",
            "améliore",
            "ameliore",
            "ajoute",
            "modifie-toi",
        ]
        .iter()
        .any(|term| normalized.contains(term));
        let capability_question = normalized.starts_with("can ")
            || normalized.starts_with("could ")
            || normalized.starts_with("what ")
            || normalized.starts_with("how ")
            || normalized.starts_with("est-ce que");
        (names_product && asks_change && !capability_question).then(|| Self {
            request: trimmed.to_owned(),
        })
    }

    /// Recognize chat guidance for an existing draft, such as
    /// `IMP-000123: keep the database schema unchanged`.
    #[must_use]
    pub fn revision(message: &str) -> Option<(i64, Self)> {
        let trimmed = message.trim();
        let marker = trimmed.get(..10)?;
        if !marker.starts_with("IMP-") || !marker[4..].bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let separator = trimmed.get(10..)?.trim_start();
        let guidance = separator
            .strip_prefix(':')
            .or_else(|| separator.strip_prefix('-'))?
            .trim();
        if guidance.is_empty() {
            return None;
        }
        let improvement_id = marker[4..].parse().ok()?;
        Some((
            improvement_id,
            Self {
                request: guidance.to_owned(),
            },
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImprovementPlan {
    pub title: String,
    pub intent: String,
    pub scope: Vec<String>,
    pub exclusions: Vec<String>,
    pub acceptance: Vec<String>,
    pub risks: Vec<String>,
    pub activation: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderedPlan {
    pub repository_path: String,
    pub markdown: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRenderedPlan {
    pub source_base_sha: String,
    pub plan: RenderedPlan,
}

impl ImprovementPlan {
    /// Render the sole canonical plan artifact committed to the private plan
    /// repository. Chat revision produces a new document digest and therefore
    /// invalidates any earlier approval button.
    pub fn render(
        &self,
        improvement: &ImprovementRecord,
    ) -> Result<RenderedPlan, ImprovementError> {
        self.render_with_source_base(
            improvement,
            improvement
                .source_base_sha
                .as_deref()
                .unwrap_or("to-be-pinned"),
        )
    }

    pub fn render_with_source_base(
        &self,
        improvement: &ImprovementRecord,
        source_base_sha: &str,
    ) -> Result<RenderedPlan, ImprovementError> {
        validate_text(&self.title, "title", 256)?;
        validate_text(&self.intent, "intent", 8_192)?;
        for (items, field) in [
            (&self.scope, "scope"),
            (&self.exclusions, "exclusions"),
            (&self.acceptance, "acceptance"),
            (&self.risks, "risks"),
            (&self.activation, "activation"),
        ] {
            validate_items(items, field)?;
        }
        let public_id = improvement.public_id();
        let mut markdown = format!(
            "# {} — {}\n\nStatus: proposed  \nPlan-ID: {}  \nSource repository: `{}`  \nSource base: `{}`\n\n## Intent\n\n{}\n",
            public_id, self.title, public_id, improvement.source_repo, source_base_sha, self.intent,
        );
        append_section(&mut markdown, "Scope", &self.scope);
        append_section(&mut markdown, "Out of scope", &self.exclusions);
        append_section(&mut markdown, "Acceptance criteria", &self.acceptance);
        append_section(&mut markdown, "Risks and rollback", &self.risks);
        append_section(&mut markdown, "Activation", &self.activation);
        markdown.push_str(
            "\n## Approval contract\n\nApproving this plan authorizes implementation of this exact plan digest only. It does not authorize release or activation; those require a second approval bound to the tested implementation SHA and release manifest.\n",
        );
        if markdown.len() > MAX_PLAN_DOCUMENT_BYTES {
            return Err(ImprovementError::InvalidField("plan_document"));
        }
        let sha256 = encode_hex(&Sha256::digest(markdown.as_bytes()));
        Ok(RenderedPlan {
            repository_path: format!("plans/{public_id}.md"),
            markdown,
            sha256: format!("sha256:{sha256}"),
        })
    }
}

fn append_section(output: &mut String, heading: &str, items: &[String]) {
    output.push_str("\n## ");
    output.push_str(heading);
    output.push_str("\n\n");
    for item in items {
        output.push_str("- ");
        output.push_str(item);
        output.push('\n');
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateDecision {
    Approve,
    RequestChanges,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatePresentation {
    pub message: SendMessageRequest,
    pub challenge_key: String,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateOutcome {
    pub decision: GateDecision,
    pub improvement: ImprovementRecord,
}

pub struct ImprovementCoordinator {
    store: ImprovementStore,
    source_repo: String,
    planning_repo: String,
    callback_key: [u8; 32],
}

impl ImprovementCoordinator {
    /// Open the owner-selected repositories and a private persistent callback
    /// key. The key is created from the kernel CSPRNG once and never leaves the
    /// state directory.
    pub fn open_default(state_dir: &Path) -> Result<Self, ImprovementError> {
        let metadata = fs::symlink_metadata(state_dir).map_err(ImprovementError::Io)?;
        if !state_dir.is_absolute()
            || !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(ImprovementError::InvalidField("state_dir"));
        }
        let callback_key = load_or_create_key(&state_dir.join(CALLBACK_KEY_NAME))?;
        let store = ImprovementStore::open(state_dir.join(STORE_NAME))?;
        Self::new(store, SOURCE_REPOSITORY, PLANNING_REPOSITORY, &callback_key)
    }

    pub fn new(
        store: ImprovementStore,
        source_repo: &str,
        planning_repo: &str,
        callback_key: &[u8],
    ) -> Result<Self, ImprovementError> {
        validate_text(source_repo, "source_repo", 256)?;
        validate_text(planning_repo, "planning_repo", 256)?;
        if callback_key.len() < 32 || callback_key.len() > 4_096 {
            return Err(ImprovementError::InvalidField("callback_key"));
        }
        let mut key = [0_u8; 32];
        key.copy_from_slice(&Sha256::digest(callback_key));
        Ok(Self {
            store,
            source_repo: source_repo.to_owned(),
            planning_repo: planning_repo.to_owned(),
            callback_key: key,
        })
    }

    pub fn capture(
        &mut self,
        source_key: &str,
        actor_id: i64,
        chat_id: i64,
        intent: &ImprovementIntent,
        now_ms: i64,
    ) -> Result<ImprovementRecord, ImprovementError> {
        if actor_id <= 0 || chat_id == 0 {
            return Err(ImprovementError::InvalidField("telegram_principal"));
        }
        self.store
            .create(NewImprovement {
                request_key: source_key,
                actor_id: &actor(actor_id),
                chat_id: &chat(chat_id),
                summary: &intent.request,
                source_repo: &self.source_repo,
                planning_repo: &self.planning_repo,
                now_ms,
            })
            .map_err(ImprovementError::Store)
    }

    pub fn revise(
        &mut self,
        improvement_id: i64,
        guidance: &ImprovementIntent,
        actor_id: i64,
        now_ms: i64,
    ) -> Result<ImprovementRecord, ImprovementError> {
        let current = self
            .store
            .get(improvement_id)?
            .ok_or(ImprovementError::InvalidField("improvement_id"))?;
        let summary = format!(
            "{}\n\nOwner revision guidance: {}",
            current.summary, guidance.request
        );
        self.store
            .revise_draft(
                improvement_id,
                current.revision,
                &summary,
                &actor(actor_id),
                now_ms,
            )
            .map_err(ImprovementError::Store)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn present_gate(
        &mut self,
        improvement_id: i64,
        expected_revision: u64,
        kind: ApprovalKind,
        actor_id: i64,
        chat_id: i64,
        now_ms: i64,
        text: impl Into<String>,
    ) -> Result<GatePresentation, ImprovementError> {
        if actor_id <= 0 || chat_id == 0 || now_ms < 0 {
            return Err(ImprovementError::InvalidField("telegram_principal"));
        }
        let expires_at_ms = now_ms
            .checked_add(CHALLENGE_LIFETIME_MS)
            .ok_or(ImprovementError::InvalidField("expires_at_ms"))?;
        let challenge_key = self.challenge_key(
            improvement_id,
            expected_revision,
            kind,
            actor_id,
            chat_id,
            expires_at_ms,
        );
        self.store.issue_challenge(NewApprovalChallenge {
            challenge_key: &challenge_key,
            improvement_id,
            expected_revision,
            kind,
            actor_id: &actor(actor_id),
            chat_id: &chat(chat_id),
            created_at_ms: now_ms,
            expires_at_ms,
        })?;
        let approve = callback(GateDecision::Approve, &challenge_key);
        let revise = callback(GateDecision::RequestChanges, &challenge_key);
        let keyboard = ApprovalKeyboard::new(approve, revise)
            .map_err(|_| ImprovementError::InvalidField("approval_keyboard"))?;
        let message = SendMessageRequest::new(chat_id, text, None)
            .map_err(|_| ImprovementError::InvalidField("gate_message"))?
            .with_approval_keyboard(keyboard);
        Ok(GatePresentation {
            message,
            challenge_key,
            expires_at_ms,
        })
    }

    pub fn handle_callback(
        &mut self,
        callback_data: &str,
        actor_id: i64,
        chat_id: i64,
        now_ms: i64,
    ) -> Result<GateOutcome, ImprovementError> {
        let (decision, challenge_key) = parse_callback(callback_data)?;
        let attempt = ApprovalAttempt {
            challenge_key,
            actor_id: &actor(actor_id),
            chat_id: &chat(chat_id),
            now_ms,
        };
        let improvement = match decision {
            GateDecision::Approve => self.store.approve(attempt)?,
            GateDecision::RequestChanges => self.store.request_changes(attempt)?,
        };
        Ok(GateOutcome {
            decision,
            improvement,
        })
    }

    #[must_use]
    pub fn store(&self) -> &ImprovementStore {
        &self.store
    }

    pub fn prepared_plan(
        &self,
        improvement_id: i64,
        revision: u64,
    ) -> Result<Option<PreparedRenderedPlan>, ImprovementError> {
        self.store
            .prepared_plan(improvement_id, revision)
            .map(|prepared| {
                prepared.map(|value| PreparedRenderedPlan {
                    source_base_sha: value.source_base_sha.clone(),
                    plan: rendered_from_prepared(improvement_id, value),
                })
            })
            .map_err(ImprovementError::Store)
    }

    pub fn approved_plan(
        &self,
        improvement: &ImprovementRecord,
    ) -> Result<PreparedRenderedPlan, ImprovementError> {
        let source = improvement
            .source_base_sha
            .as_deref()
            .ok_or(ImprovementError::InvalidField("source_base_sha"))?;
        let digest = improvement
            .plan_digest
            .as_deref()
            .ok_or(ImprovementError::InvalidField("plan_digest"))?;
        self.store
            .prepared_plan_for_artifact(improvement.entry_id, source, digest)?
            .map(|prepared| PreparedRenderedPlan {
                source_base_sha: prepared.source_base_sha.clone(),
                plan: rendered_from_prepared(improvement.entry_id, prepared),
            })
            .ok_or(ImprovementError::InvalidField("prepared_plan"))
    }

    pub fn prepare_plan(
        &mut self,
        improvement_id: i64,
        revision: u64,
        source_base_sha: &str,
        plan: &RenderedPlan,
        now_ms: i64,
    ) -> Result<(), ImprovementError> {
        self.store
            .prepare_plan(
                improvement_id,
                revision,
                source_base_sha,
                &plan.sha256,
                &plan.markdown,
                now_ms,
            )
            .map(drop)
            .map_err(ImprovementError::Store)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_plan_publication(
        &mut self,
        improvement_id: i64,
        revision: u64,
        plan: &RenderedPlan,
        plan_head_sha: &str,
        source_base_sha: &str,
        issue_number: u64,
        issue_url: &str,
        plan_pr_number: u64,
        plan_pr_url: &str,
        now_ms: i64,
    ) -> Result<ImprovementRecord, ImprovementError> {
        self.store
            .submit_plan(PlanSubmission {
                improvement_id,
                expected_revision: revision,
                actor: "automonique:planner",
                plan_digest: &plan.sha256,
                plan_head_sha,
                source_base_sha,
                issue_number,
                issue_url,
                plan_pr_number,
                plan_pr_url,
                now_ms,
            })
            .map_err(ImprovementError::Store)
    }

    pub fn start_implementation(
        &mut self,
        improvement_id: i64,
        expected_revision: u64,
        now_ms: i64,
    ) -> Result<ImprovementRecord, ImprovementError> {
        self.transition(
            improvement_id,
            expected_revision,
            ImprovementState::Implementing,
            "automonique:lab",
            None,
            None,
            now_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_release_candidate(
        &mut self,
        improvement_id: i64,
        expected_revision: u64,
        implementation_head_sha: &str,
        implementation_tree_sha: &str,
        release_manifest_digest: &str,
        implementation_pr_number: u64,
        implementation_pr_url: &str,
        now_ms: i64,
    ) -> Result<ImprovementRecord, ImprovementError> {
        self.store
            .submit_release(ReleaseSubmission {
                improvement_id,
                expected_revision,
                actor: "automonique:lab",
                implementation_head_sha,
                implementation_tree_sha,
                release_manifest_digest,
                implementation_pr_number,
                implementation_pr_url,
                now_ms,
            })
            .map_err(ImprovementError::Store)
    }

    pub fn start_activation(
        &mut self,
        improvement_id: i64,
        expected_revision: u64,
        now_ms: i64,
    ) -> Result<ImprovementRecord, ImprovementError> {
        self.transition(
            improvement_id,
            expected_revision,
            ImprovementState::Activating,
            "automonique:activator",
            None,
            None,
            now_ms,
        )
    }

    pub fn complete_activation(
        &mut self,
        improvement_id: i64,
        expected_revision: u64,
        release_manifest_digest: &str,
        now_ms: i64,
    ) -> Result<ImprovementRecord, ImprovementError> {
        self.transition(
            improvement_id,
            expected_revision,
            ImprovementState::Completed,
            "automonique:activator",
            Some(release_manifest_digest),
            None,
            now_ms,
        )
    }

    pub fn fail(
        &mut self,
        improvement_id: i64,
        expected_revision: u64,
        reason: &str,
        now_ms: i64,
    ) -> Result<ImprovementRecord, ImprovementError> {
        self.transition(
            improvement_id,
            expected_revision,
            ImprovementState::Failed,
            "automonique:controller",
            None,
            Some(reason),
            now_ms,
        )
    }

    pub fn rolled_back(
        &mut self,
        improvement_id: i64,
        expected_revision: u64,
        reason: &str,
        now_ms: i64,
    ) -> Result<ImprovementRecord, ImprovementError> {
        self.transition(
            improvement_id,
            expected_revision,
            ImprovementState::RolledBack,
            "automonique:activator",
            None,
            Some(reason),
            now_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn transition(
        &mut self,
        improvement_id: i64,
        expected_revision: u64,
        to: ImprovementState,
        actor: &str,
        active_release_digest: Option<&str>,
        failure_reason: Option<&str>,
        now_ms: i64,
    ) -> Result<ImprovementRecord, ImprovementError> {
        self.store
            .transition(StateTransition {
                improvement_id,
                expected_revision,
                to,
                actor,
                active_release_digest,
                failure_reason,
                now_ms,
            })
            .map_err(ImprovementError::Store)
    }

    fn challenge_key(
        &self,
        improvement_id: i64,
        revision: u64,
        kind: ApprovalKind,
        actor_id: i64,
        chat_id: i64,
        expires_at_ms: i64,
    ) -> String {
        let mut message = Vec::new();
        message.extend_from_slice(&improvement_id.to_be_bytes());
        message.extend_from_slice(&revision.to_be_bytes());
        message.extend_from_slice(kind.as_str().as_bytes());
        message.extend_from_slice(&actor_id.to_be_bytes());
        message.extend_from_slice(&chat_id.to_be_bytes());
        message.extend_from_slice(&expires_at_ms.to_be_bytes());
        encode_hex(&hmac_sha256(&self.callback_key, &message)[..24])
    }
}

fn rendered_from_prepared(improvement_id: i64, prepared: PreparedPlan) -> RenderedPlan {
    RenderedPlan {
        repository_path: format!("plans/IMP-{improvement_id:06}.md"),
        markdown: prepared.markdown,
        sha256: prepared.plan_digest,
    }
}

fn load_or_create_key(path: &Path) -> Result<Vec<u8>, ImprovementError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != nix::unistd::geteuid().as_raw()
                || metadata.permissions().mode() & 0o077 != 0
                || metadata.len() != 32
            {
                return Err(ImprovementError::InvalidField("callback_key_file"));
            }
            let mut bytes = Vec::new();
            fs::File::open(path)
                .and_then(|mut file| file.read_to_end(&mut bytes))
                .map_err(ImprovementError::Io)?;
            Ok(bytes)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut bytes = vec![0_u8; 32];
            fs::File::open("/dev/urandom")
                .and_then(|mut random| random.read_exact(&mut bytes))
                .map_err(ImprovementError::Io)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(ImprovementError::Io)?;
            file.write_all(&bytes).map_err(ImprovementError::Io)?;
            file.sync_all().map_err(ImprovementError::Io)?;
            Ok(bytes)
        }
        Err(error) => Err(ImprovementError::Io(error)),
    }
}

fn callback(decision: GateDecision, challenge_key: &str) -> String {
    let action = match decision {
        GateDecision::Approve => "a",
        GateDecision::RequestChanges => "r",
    };
    format!("{CALLBACK_VERSION}:{action}:{challenge_key}")
}

fn parse_callback(value: &str) -> Result<(GateDecision, &str), ImprovementError> {
    let mut parts = value.split(':');
    if parts.next() != Some(CALLBACK_VERSION) {
        return Err(ImprovementError::UnknownCallback);
    }
    let decision = match parts.next() {
        Some("a") => GateDecision::Approve,
        Some("r") => GateDecision::RequestChanges,
        _ => return Err(ImprovementError::UnknownCallback),
    };
    let challenge = parts.next().ok_or(ImprovementError::UnknownCallback)?;
    if parts.next().is_some()
        || challenge.len() != 48
        || !challenge.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ImprovementError::UnknownCallback);
    }
    Ok((decision, challenge))
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for index in 0..64 {
        inner_pad[index] ^= block[index];
        outer_pad[index] ^= block[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn actor(id: i64) -> String {
    format!("telegram:user:{id}")
}

fn chat(id: i64) -> String {
    format!("telegram:chat:{id}")
}

fn validate_items(items: &[String], field: &'static str) -> Result<(), ImprovementError> {
    if items.is_empty() || items.len() > MAX_PLAN_ITEMS {
        return Err(ImprovementError::InvalidField(field));
    }
    for item in items {
        validate_text(item, field, MAX_PLAN_ITEM_BYTES)?;
        if item.contains('\n') {
            return Err(ImprovementError::InvalidField(field));
        }
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<(), ImprovementError> {
    if value.trim().is_empty() || value.len() > max || value.contains('\0') {
        return Err(ImprovementError::InvalidField(field));
    }
    Ok(())
}

#[derive(Debug)]
pub enum ImprovementError {
    InvalidField(&'static str),
    UnknownCallback,
    Store(ImprovementStoreError),
    Io(std::io::Error),
}

impl fmt::Display for ImprovementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(formatter, "invalid improvement field: {field}"),
            Self::UnknownCallback => formatter.write_str("unknown improvement callback"),
            Self::Store(error) => write!(formatter, "improvement state refused: {error}"),
            Self::Io(error) => write!(formatter, "improvement I/O error: {error}"),
        }
    }
}

impl Error for ImprovementError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ImprovementStoreError> for ImprovementError {
    fn from(error: ImprovementStoreError) -> Self {
        Self::Store(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use automonique_store::improvements::PlanSubmission;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn coordinator() -> (tempfile::TempDir, ImprovementCoordinator) {
        let directory = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("private");
        let store =
            ImprovementStore::open(directory.path().join("improvements.sqlite3")).expect("store");
        let coordinator = ImprovementCoordinator::new(
            store,
            "bext-stack/automonique",
            "bext-stack/automonique-plans",
            &[7_u8; 32],
        )
        .expect("coordinator");
        (directory, coordinator)
    }

    #[test]
    fn explicit_self_change_is_recognized_but_capability_questions_are_not() {
        assert!(
            ImprovementIntent::recognize("Improve Automonique by adding plan review").is_some()
        );
        assert!(ImprovementIntent::recognize("Can Monique improve herself?").is_none());
        assert!(ImprovementIntent::recognize("summarize this issue").is_none());
        assert_eq!(
            ImprovementIntent::revision("IMP-000123: keep this skill-only")
                .map(|(id, intent)| (id, intent.request)),
            Some((123, "keep this skill-only".to_owned()))
        );
        assert!(ImprovementIntent::revision("please revise the plan").is_none());
    }

    #[test]
    fn plan_buttons_drive_the_bound_store_gate() {
        let (_directory, mut coordinator) = coordinator();
        let intent =
            ImprovementIntent::recognize("Improve Automonique with a status view").expect("intent");
        let draft = coordinator
            .capture("telegram:update:1", 7, -9, &intent, 1_000)
            .expect("capture");
        coordinator
            .store
            .prepare_plan(
                draft.entry_id,
                1,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "sha256:plan",
                "# Prepared plan\n",
                1_500,
            )
            .expect("prepare");
        let plan = coordinator
            .store
            .submit_plan(PlanSubmission {
                improvement_id: draft.entry_id,
                expected_revision: 1,
                actor: "automonique:planner",
                plan_digest: "sha256:plan",
                plan_head_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                source_base_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                issue_number: 1,
                issue_url: "https://github.com/bext-stack/automonique-plans/issues/1",
                plan_pr_number: 2,
                plan_pr_url: "https://github.com/bext-stack/automonique-plans/pull/2",
                now_ms: 2_000,
            })
            .expect("plan");
        let gate = coordinator
            .present_gate(
                plan.entry_id,
                plan.revision,
                ApprovalKind::Plan,
                7,
                -9,
                3_000,
                "Plan ready",
            )
            .expect("gate");
        let callback = gate
            .message
            .approval_keyboard()
            .expect("keyboard")
            .approve_callback()
            .to_owned();
        let outcome = coordinator
            .handle_callback(&callback, 7, -9, 3_500)
            .expect("approve");
        assert_eq!(outcome.decision, GateDecision::Approve);
        assert_eq!(
            outcome.improvement.state,
            automonique_store::improvements::ImprovementState::PlanApproved
        );
        assert!(matches!(
            coordinator.handle_callback(&callback, 7, -9, 3_600),
            Err(ImprovementError::Store(
                ImprovementStoreError::ChallengeConsumed
            ))
        ));
    }

    #[test]
    fn canonical_plan_states_that_release_needs_a_second_gate() {
        let (_directory, mut coordinator) = coordinator();
        let intent = ImprovementIntent {
            request: "Improve Automonique".to_owned(),
        };
        let draft = coordinator
            .capture("telegram:update:2", 7, -9, &intent, 1_000)
            .expect("capture");
        let plan = ImprovementPlan {
            title: "Durable self-improvements".to_owned(),
            intent: intent.request,
            scope: vec!["Persist a plan".to_owned()],
            exclusions: vec!["No repository administration".to_owned()],
            acceptance: vec!["Approval is revision-bound".to_owned()],
            risks: vec!["Rollback to the prior release".to_owned()],
            activation: vec!["Restart only after release approval".to_owned()],
        }
        .render(&draft)
        .expect("render");
        assert_eq!(plan.repository_path, "plans/IMP-000001.md");
        assert!(plan.markdown.contains("require a second approval"));
        assert!(plan.sha256.starts_with("sha256:"));
    }
}
