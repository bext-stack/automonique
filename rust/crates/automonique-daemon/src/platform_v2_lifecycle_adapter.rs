// SPDX-License-Identifier: Elastic-2.0

//! Production Platform v2 lifecycle effects.
//!
//! Public requests contain only opaque selectors.  This module is the sole
//! place where those selectors are resolved to local paths and git refs.  The
//! registry is an operator-owned, generation-fenced 0600 file; the effect
//! journal is a daemon-owned 0600 file.  Neither representation crosses the
//! protocol boundary.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use automonique_protocol::digest::{Sha256, Sha256Digest};
use automonique_protocol::platform::IdempotencyKey;
use automonique_protocol::platform_v2::{CheckoutKind, HostSetupKind, WorkContextIdentity};
use automonique_protocol::platform_v2_lifecycle::WorkContextMutationIntent;
use serde::{Deserialize, Serialize};

use crate::platform_v2_host::{
    PlatformV2EffectExecution, PlatformV2EffectReconciliation, PlatformV2LifecycleEffectAdapter,
};

pub const LIFECYCLE_REGISTRY_FILE_NAME: &str = "platform-v2-lifecycle-registry.json";
pub const LIFECYCLE_JOURNAL_FILE_NAME: &str = "platform-v2-lifecycle-effects.json";

const MAX_REGISTRY_BYTES: u64 = 512 * 1024;
const MAX_JOURNAL_BYTES: u64 = 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_GIT_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_CHECKOUT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_CHECKOUT_ENTRIES: usize = 20_000;
const GIT_TIMEOUT: Duration = Duration::from_secs(15);
const GIT_PROGRAM: &str = "/usr/bin/git";

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileGeneration {
    device: u64,
    inode: u64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    length: u64,
    digest: Sha256Digest,
}

#[derive(Debug)]
struct PrivateSnapshot {
    bytes: Vec<u8>,
    generation: FileGeneration,
}

#[derive(Clone, Copy, Debug)]
struct JournalPersistError {
    category: &'static str,
    installed: bool,
}

#[derive(Clone, Copy, Debug)]
struct AtomicWriteError {
    category: &'static str,
    installed: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryDocument {
    version: u8,
    generation: String,
    #[serde(default)]
    host_setups: Vec<HostSetupBinding>,
    #[serde(default)]
    checkouts: Vec<CheckoutBinding>,
    #[serde(default)]
    workspaces: Vec<WorkspaceBinding>,
    #[serde(default)]
    task_selectors: Vec<TaskSelectorBinding>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostSetupBinding {
    selector: String,
    host_setup: Option<String>,
    project: String,
    setup_kind: String,
    canonical_root: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckoutBinding {
    selector: String,
    checkout: Option<String>,
    project: String,
    host_setup: String,
    repository_authority: String,
    repository: String,
    checkout_kind: String,
    canonical_root: PathBuf,
    repository_root: Option<PathBuf>,
    base_commit: Option<String>,
    branch_ref: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceBinding {
    workspace: String,
    project: String,
    checkout: String,
    canonical_root: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskSelectorBinding {
    base_selector: String,
    branch_selector: String,
    project: String,
    workspace: String,
    checkout: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalDocument {
    version: u8,
    registry_generation: JournalGeneration,
    entries: BTreeMap<String, JournalEntry>,
    #[serde(default)]
    host_setups: BTreeMap<String, JournalHostSetup>,
    #[serde(default)]
    checkouts: BTreeMap<String, JournalCheckout>,
    workspaces: BTreeMap<String, JournalWorkspace>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalGeneration {
    device: u64,
    inode: u64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    length: u64,
    digest: String,
}

impl From<&FileGeneration> for JournalGeneration {
    fn from(value: &FileGeneration) -> Self {
        Self {
            device: value.device,
            inode: value.inode,
            changed_seconds: value.changed_seconds,
            changed_nanoseconds: value.changed_nanoseconds,
            modified_seconds: value.modified_seconds,
            modified_nanoseconds: value.modified_nanoseconds,
            length: value.length,
            digest: hex(value.digest.as_bytes()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalEntry {
    digest: String,
    state: String,
    effect_kind: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalWorkspace {
    project: String,
    checkout: String,
    root_digest: String,
    archived: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalHostSetup {
    selector: String,
    project: String,
    root_digest: String,
    archived: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalCheckout {
    selector: String,
    project: String,
    host_setup: String,
    repository_authority: String,
    repository: String,
    root_digest: String,
    archived: bool,
}

/// Operator-registry-backed local lifecycle adapter.
///
/// Opening returns `None` when no registry is installed.  An installed but
/// insecure or malformed registry is an error, so production cannot silently
/// fall back to weaker selector handling.
pub struct ProductionLifecycleEffectAdapter {
    registry_path: PathBuf,
    registry_generation: FileGeneration,
    expected_uid: u32,
    registry: RegistryDocument,
    journal_path: PathBuf,
    journal_generation: Option<FileGeneration>,
    journal: JournalDocument,
}

impl ProductionLifecycleEffectAdapter {
    pub fn open(
        registry_path: &Path,
        journal_path: &Path,
        expected_uid: u32,
    ) -> Result<Option<Self>, &'static str> {
        let Some(snapshot) = read_private_file(registry_path, expected_uid, MAX_REGISTRY_BYTES)?
        else {
            return Ok(None);
        };
        let registry: RegistryDocument = serde_json::from_slice(&snapshot.bytes)
            .map_err(|_| "platform_v2_lifecycle_registry_invalid")?;
        validate_registry(&registry, expected_uid)?;
        let journal_snapshot = read_private_file(journal_path, expected_uid, MAX_JOURNAL_BYTES)?;
        let journal = match journal_snapshot.as_ref() {
            Some(value) => serde_json::from_slice(&value.bytes)
                .map_err(|_| "platform_v2_lifecycle_journal_invalid")?,
            None => JournalDocument {
                version: 1,
                registry_generation: JournalGeneration::from(&snapshot.generation),
                entries: BTreeMap::new(),
                host_setups: BTreeMap::new(),
                checkouts: BTreeMap::new(),
                workspaces: BTreeMap::new(),
            },
        };
        if journal.version != 1
            || !valid_digest(&journal.registry_generation.digest)
            || journal.entries.len() > MAX_ENTRIES
            || journal.host_setups.len() > MAX_ENTRIES
            || journal.checkouts.len() > MAX_ENTRIES
            || journal.workspaces.len() > MAX_ENTRIES
            || journal.entries.iter().any(|(key, value)| {
                !safe_token(key)
                    || !valid_digest(&value.digest)
                    || !matches!(value.state.as_str(), "prepared" | "completed")
                    || !safe_token(&value.effect_kind)
            })
            || journal.workspaces.iter().any(|(workspace, value)| {
                !safe_token(workspace)
                    || !safe_token(&value.project)
                    || !safe_token(&value.checkout)
                    || !valid_digest(&value.root_digest)
            })
            || journal.host_setups.iter().any(|(identity, value)| {
                !safe_token(identity)
                    || !safe_token(&value.selector)
                    || !safe_token(&value.project)
                    || !valid_digest(&value.root_digest)
            })
            || journal.checkouts.iter().any(|(identity, value)| {
                !safe_token(identity)
                    || !safe_token(&value.selector)
                    || !safe_token(&value.project)
                    || !safe_token(&value.host_setup)
                    || !safe_token(&value.repository_authority)
                    || !safe_coordinate(&value.repository)
                    || !valid_digest(&value.root_digest)
            })
        {
            return Err("platform_v2_lifecycle_journal_invalid");
        }
        let loaded_generation = JournalGeneration::from(&snapshot.generation);
        if journal.registry_generation != loaded_generation
            && journal
                .entries
                .values()
                .any(|entry| entry.state == "prepared")
        {
            return Err("platform_v2_lifecycle_registry_recovery_required");
        }
        if journal.host_setups.values().any(|stored| {
            registry
                .host_setups
                .iter()
                .find(|binding| binding.selector == stored.selector)
                .is_none_or(|binding| {
                    binding.project != stored.project
                        || binding.setup_kind != HostSetupKind::Local.as_str()
                        || binding
                            .canonical_root
                            .as_deref()
                            .is_none_or(|root| path_digest(root) != stored.root_digest)
                })
        }) || journal.checkouts.values().any(|stored| {
            registry
                .checkouts
                .iter()
                .find(|binding| binding.selector == stored.selector)
                .is_none_or(|binding| {
                    binding.project != stored.project
                        || binding.host_setup != stored.host_setup
                        || binding.repository_authority != stored.repository_authority
                        || binding.repository != stored.repository
                        || path_digest(&binding.canonical_root) != stored.root_digest
                })
        }) || journal.workspaces.values().any(|stored| {
            let checkout = journal
                .checkouts
                .get(&stored.checkout)
                .and_then(|value| {
                    registry
                        .checkouts
                        .iter()
                        .find(|binding| binding.selector == value.selector)
                })
                .or_else(|| {
                    registry
                        .checkouts
                        .iter()
                        .find(|binding| binding.checkout.as_deref() == Some(&stored.checkout))
                });
            checkout.is_none_or(|binding| {
                binding.project != stored.project
                    || path_digest(&binding.canonical_root) != stored.root_digest
            })
        }) {
            return Err("platform_v2_lifecycle_journal_invalid");
        }
        let result = Self {
            registry_path: registry_path.to_path_buf(),
            registry_generation: snapshot.generation,
            expected_uid,
            registry,
            journal_path: journal_path.to_path_buf(),
            journal_generation: journal_snapshot.map(|value| value.generation),
            journal,
        };
        Ok(Some(result))
    }

    fn verify_registry(&self) -> Result<(), &'static str> {
        let current =
            read_private_file(&self.registry_path, self.expected_uid, MAX_REGISTRY_BYTES)?
                .ok_or("platform_v2_lifecycle_registry_changed")?;
        if current.generation != self.registry_generation {
            return Err("platform_v2_lifecycle_registry_changed");
        }
        Ok(())
    }

    pub fn preflight(&self, intent: &WorkContextMutationIntent) -> Result<(), &'static str> {
        self.verify_registry()?;
        match intent {
            WorkContextMutationIntent::CreateHostSetup(value) => {
                let binding = self.host_setup(value.registry().as_str())?;
                if binding.project != value.project().identity().id()
                    || binding.setup_kind != value.setup_kind().as_str()
                {
                    return Err("platform_v2_lifecycle_selector_mismatch");
                }
                if value.setup_kind() != HostSetupKind::Local {
                    return Err("platform_v2_remote_host_unsupported");
                }
                validate_private_root_and_parent(
                    binding
                        .canonical_root
                        .as_deref()
                        .ok_or("platform_v2_lifecycle_registry_invalid")?,
                    self.expected_uid,
                )
            }
            WorkContextMutationIntent::CreateCheckout(value) => {
                let binding = self.checkout(value.registry().as_str())?;
                let host = self.host_setup_by_identity(&binding.host_setup)?;
                if binding.project != value.project().identity().id()
                    || binding.host_setup != value.host_setup().identity().id()
                    || !repository_matches(
                        value.repository().identity(),
                        &binding.repository_authority,
                        &binding.repository,
                    )
                    || binding.checkout_kind != value.checkout_kind().as_str()
                    || host.project != binding.project
                    || host.setup_kind != HostSetupKind::Local.as_str()
                {
                    return Err("platform_v2_lifecycle_selector_mismatch");
                }
                preflight_checkout_effect(binding, self.expected_uid)
            }
            WorkContextMutationIntent::CreateUserWorkspace(value) => self
                .checkout_by_identity(value.checkout().identity().id())
                .map(|_| ()),
            WorkContextMutationIntent::ArchiveHostSetup(value) => self
                .host_setup_by_identity(value.target().identity().id())
                .map(|_| ()),
            WorkContextMutationIntent::ArchiveCheckout(value) => self
                .checkout_by_identity(value.target().identity().id())
                .map(|_| ()),
            WorkContextMutationIntent::ArchiveUserWorkspace(value) => self
                .workspace_root(value.target().identity().id())
                .map(|_| ()),
            WorkContextMutationIntent::CreateAttemptWorkspace(_)
            | WorkContextMutationIntent::ResumeAttemptWorkspace(_)
            | WorkContextMutationIntent::ResumeSession(_) => Ok(()),
            WorkContextMutationIntent::CreateProject(_)
            | WorkContextMutationIntent::ArchiveProject(_) => Ok(()),
        }
    }

    pub fn preflight_submission(
        &self,
        intent: &WorkContextMutationIntent,
        resulting_identity: &WorkContextIdentity,
    ) -> Result<(), &'static str> {
        self.preflight(intent)?;
        match intent {
            WorkContextMutationIntent::CreateHostSetup(value) => {
                let binding = self.host_setup(value.registry().as_str())?;
                if binding
                    .host_setup
                    .as_deref()
                    .is_some_and(|identity| identity != resulting_identity.id())
                    || self.journal.host_setups.iter().any(|(identity, entry)| {
                        entry.selector == binding.selector && identity != resulting_identity.id()
                    })
                {
                    return Err("platform_v2_lifecycle_selector_consumed");
                }
            }
            WorkContextMutationIntent::CreateCheckout(value) => {
                let binding = self.checkout(value.registry().as_str())?;
                if binding
                    .checkout
                    .as_deref()
                    .is_some_and(|identity| identity != resulting_identity.id())
                    || self.journal.checkouts.iter().any(|(identity, entry)| {
                        entry.selector == binding.selector && identity != resulting_identity.id()
                    })
                {
                    return Err("platform_v2_lifecycle_selector_consumed");
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn host_setup(&self, selector: &str) -> Result<&HostSetupBinding, &'static str> {
        self.registry
            .host_setups
            .iter()
            .find(|entry| entry.selector == selector)
            .ok_or("platform_v2_lifecycle_selector_unknown")
    }

    fn checkout(&self, selector: &str) -> Result<&CheckoutBinding, &'static str> {
        self.registry
            .checkouts
            .iter()
            .find(|entry| entry.selector == selector)
            .ok_or("platform_v2_lifecycle_selector_unknown")
    }

    fn checkout_by_identity(&self, identity: &str) -> Result<&CheckoutBinding, &'static str> {
        let selector = self
            .journal
            .checkouts
            .get(identity)
            .map(|value| value.selector.as_str());
        match selector {
            Some(selector) => self.checkout(selector),
            None => self
                .registry
                .checkouts
                .iter()
                .find(|entry| entry.checkout.as_deref() == Some(identity))
                .ok_or("platform_v2_lifecycle_checkout_unknown"),
        }
    }

    fn host_setup_by_identity(&self, identity: &str) -> Result<&HostSetupBinding, &'static str> {
        let selector = self
            .journal
            .host_setups
            .get(identity)
            .map(|value| value.selector.as_str());
        match selector {
            Some(selector) => self.host_setup(selector),
            None => self
                .registry
                .host_setups
                .iter()
                .find(|entry| entry.host_setup.as_deref() == Some(identity))
                .ok_or("platform_v2_lifecycle_host_setup_unknown"),
        }
    }

    fn workspace(&self, identity: &str) -> Result<&WorkspaceBinding, &'static str> {
        self.registry
            .workspaces
            .iter()
            .find(|entry| entry.workspace == identity)
            .ok_or("platform_v2_lifecycle_workspace_unknown")
    }

    fn workspace_root(&self, identity: &str) -> Result<PathBuf, &'static str> {
        if let Ok(binding) = self.workspace(identity) {
            return Ok(binding.canonical_root.clone());
        }
        let stored = self
            .journal
            .workspaces
            .get(identity)
            .ok_or("platform_v2_lifecycle_workspace_unknown")?;
        let checkout = self.checkout_by_identity(&stored.checkout)?;
        if stored.root_digest != path_digest(&checkout.canonical_root) {
            return Err("platform_v2_lifecycle_workspace_mismatch");
        }
        Ok(checkout.canonical_root.clone())
    }

    fn verify_journal_generation(&self) -> Result<(), &'static str> {
        let current = read_private_file(&self.journal_path, self.expected_uid, MAX_JOURNAL_BYTES)?;
        if current.as_ref().map(|value| &value.generation) != self.journal_generation.as_ref() {
            return Err("platform_v2_lifecycle_journal_changed");
        }
        Ok(())
    }

    fn persist_journal(&mut self) -> Result<(), JournalPersistError> {
        self.verify_registry()
            .map_err(|category| JournalPersistError {
                category,
                installed: false,
            })?;
        self.verify_journal_generation()
            .map_err(|category| JournalPersistError {
                category,
                installed: false,
            })?;
        self.journal.registry_generation = JournalGeneration::from(&self.registry_generation);
        let bytes = serde_json::to_vec(&self.journal).map_err(|_| JournalPersistError {
            category: "platform_v2_lifecycle_journal_invalid",
            installed: false,
        })?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(JournalPersistError {
                category: "platform_v2_lifecycle_journal_full",
                installed: false,
            });
        }
        let write_result = write_private_atomic(&self.journal_path, self.expected_uid, &bytes);
        match read_private_file(&self.journal_path, self.expected_uid, MAX_JOURNAL_BYTES) {
            Ok(Some(snapshot)) if snapshot.generation.digest == Sha256::digest(&bytes) => {
                self.journal_generation = Some(snapshot.generation);
            }
            Ok(_) if write_result.is_ok() => {
                return Err(JournalPersistError {
                    category: "platform_v2_lifecycle_journal_changed",
                    installed: true,
                });
            }
            Err(category) if write_result.is_ok() => {
                return Err(JournalPersistError {
                    category,
                    installed: true,
                });
            }
            _ => {}
        }
        write_result.map_err(|error| JournalPersistError {
            category: error.category,
            installed: error.installed,
        })
    }

    #[cfg(test)]
    fn insert_prepared(
        &mut self,
        key: String,
        digest: String,
        effect_kind: &str,
    ) -> Result<(), &'static str> {
        if self.journal.entries.len() >= MAX_ENTRIES {
            return Err("platform_v2_lifecycle_journal_full");
        }
        let previous = self.journal.clone();
        self.journal.entries.insert(
            key,
            JournalEntry {
                digest,
                state: "prepared".to_owned(),
                effect_kind: effect_kind.to_owned(),
            },
        );
        if let Err(error) = self.persist_journal() {
            if !error.installed {
                self.journal = previous;
            }
            return Err(error.category);
        }
        Ok(())
    }

    fn mark_completed(&mut self, key: &str) -> Result<(), &'static str> {
        let previous = self.journal.clone();
        self.journal
            .entries
            .get_mut(key)
            .ok_or("platform_v2_lifecycle_journal_invalid")?
            .state = "completed".to_owned();
        if let Err(error) = self.persist_journal() {
            if !error.installed {
                self.journal = previous;
            }
            return Err(error.category);
        }
        Ok(())
    }

    fn tombstone_not_started(
        &mut self,
        key: &str,
        intent: &WorkContextMutationIntent,
        resulting_identity: &WorkContextIdentity,
    ) -> Result<(), &'static str> {
        let previous = self.journal.clone();
        self.journal.entries.remove(key);
        match intent {
            WorkContextMutationIntent::CreateHostSetup(_) => {
                self.journal.host_setups.remove(resulting_identity.id());
            }
            WorkContextMutationIntent::CreateCheckout(_) => {
                self.journal.checkouts.remove(resulting_identity.id());
            }
            _ => {}
        }
        if let Err(error) = self.persist_journal() {
            if !error.installed {
                self.journal = previous;
            }
            return Err(error.category);
        }
        Ok(())
    }

    fn insert_lifecycle_prepared(
        &mut self,
        key: String,
        digest: String,
        intent: &WorkContextMutationIntent,
        resulting_identity: &WorkContextIdentity,
    ) -> Result<(), &'static str> {
        self.preflight_submission(intent, resulting_identity)?;
        if self.journal.entries.len() >= MAX_ENTRIES {
            return Err("platform_v2_lifecycle_journal_full");
        }
        let previous = self.journal.clone();
        self.journal.entries.insert(
            key,
            JournalEntry {
                digest,
                state: "prepared".to_owned(),
                effect_kind: intent.kind().to_owned(),
            },
        );
        match intent {
            WorkContextMutationIntent::CreateHostSetup(value) => {
                let binding = self.host_setup(value.registry().as_str())?;
                let root = binding
                    .canonical_root
                    .as_deref()
                    .ok_or("platform_v2_lifecycle_registry_invalid")?;
                self.journal.host_setups.insert(
                    resulting_identity.id().to_owned(),
                    JournalHostSetup {
                        selector: binding.selector.clone(),
                        project: binding.project.clone(),
                        root_digest: path_digest(root),
                        archived: false,
                    },
                );
            }
            WorkContextMutationIntent::CreateCheckout(value) => {
                let binding = self.checkout(value.registry().as_str())?;
                self.journal.checkouts.insert(
                    resulting_identity.id().to_owned(),
                    JournalCheckout {
                        selector: binding.selector.clone(),
                        project: binding.project.clone(),
                        host_setup: binding.host_setup.clone(),
                        repository_authority: binding.repository_authority.clone(),
                        repository: binding.repository.clone(),
                        root_digest: path_digest(&binding.canonical_root),
                        archived: false,
                    },
                );
            }
            _ => {}
        }
        if let Err(error) = self.persist_journal() {
            if !error.installed {
                self.journal = previous;
            }
            return Err(error.category);
        }
        Ok(())
    }
}

impl PlatformV2LifecycleEffectAdapter for ProductionLifecycleEffectAdapter {
    fn supported_effect_kinds(&self) -> std::collections::BTreeSet<String> {
        ["create_host_setup", "create_checkout"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    fn preflight(&self, intent: &WorkContextMutationIntent) -> Result<(), &'static str> {
        Self::preflight(self, intent)
    }

    fn preflight_submission(
        &self,
        intent: &WorkContextMutationIntent,
        resulting_identity: &WorkContextIdentity,
    ) -> Result<(), &'static str> {
        Self::preflight_submission(self, intent, resulting_identity)
    }

    fn verify_generation(&self) -> Result<(), &'static str> {
        self.verify_registry()
    }

    fn execute(
        &mut self,
        intent: &WorkContextMutationIntent,
        resulting_identity: &WorkContextIdentity,
        idempotency_key: &IdempotencyKey,
    ) -> PlatformV2EffectExecution {
        if !self.supported_effect_kinds().contains(intent.kind())
            || self.verify_registry().is_err()
            || self.preflight(intent).is_err()
        {
            return PlatformV2EffectExecution::NotStarted;
        }
        let key = format!("lifecycle:{}", idempotency_key.as_str());
        let digest = lifecycle_digest(intent, resulting_identity);
        match self.journal.entries.get(&key) {
            Some(entry) if entry.digest != digest => return PlatformV2EffectExecution::Unknown,
            Some(entry) if entry.state == "completed" => {
                return PlatformV2EffectExecution::Completed;
            }
            Some(_) => return PlatformV2EffectExecution::Unknown,
            None => {}
        }
        if self
            .insert_lifecycle_prepared(key.clone(), digest, intent, resulting_identity)
            .is_err()
        {
            return PlatformV2EffectExecution::NotStarted;
        }
        if self.apply_lifecycle(intent, resulting_identity).is_err() {
            if self.definitely_not_started(intent, resulting_identity)
                && self
                    .tombstone_not_started(&key, intent, resulting_identity)
                    .is_ok()
            {
                return PlatformV2EffectExecution::NotStarted;
            }
            return PlatformV2EffectExecution::Unknown;
        }
        if self.mark_completed(&key).is_err() {
            return PlatformV2EffectExecution::Unknown;
        }
        PlatformV2EffectExecution::Completed
    }

    fn reconcile(
        &mut self,
        intent: &WorkContextMutationIntent,
        resulting_identity: &WorkContextIdentity,
        idempotency_key: &IdempotencyKey,
    ) -> PlatformV2EffectReconciliation {
        let key = format!("lifecycle:{}", idempotency_key.as_str());
        let digest = lifecycle_digest(intent, resulting_identity);
        let evidence = || format!("v1:{digest}").into_bytes();
        if !self.supported_effect_kinds().contains(intent.kind()) || self.verify_registry().is_err()
        {
            return PlatformV2EffectReconciliation::Unknown(evidence());
        }
        let Some(entry) = self.journal.entries.get(&key) else {
            return PlatformV2EffectReconciliation::VerifiedNotStarted(evidence());
        };
        if entry.digest != digest {
            return PlatformV2EffectReconciliation::Unknown(evidence());
        }
        if entry.state == "completed" || self.inspect_lifecycle(intent, resulting_identity) {
            if entry.state != "completed" && self.mark_completed(&key).is_err() {
                return PlatformV2EffectReconciliation::Unknown(evidence());
            }
            PlatformV2EffectReconciliation::Completed(evidence())
        } else if self.definitely_not_started(intent, resulting_identity) {
            if self
                .tombstone_not_started(&key, intent, resulting_identity)
                .is_err()
            {
                PlatformV2EffectReconciliation::Unknown(evidence())
            } else {
                PlatformV2EffectReconciliation::VerifiedNotStarted(evidence())
            }
        } else {
            PlatformV2EffectReconciliation::Unknown(evidence())
        }
    }
}

impl ProductionLifecycleEffectAdapter {
    fn apply_lifecycle(
        &mut self,
        intent: &WorkContextMutationIntent,
        _resulting_identity: &WorkContextIdentity,
    ) -> Result<(), &'static str> {
        match intent {
            WorkContextMutationIntent::CreateHostSetup(value) => {
                let binding = self.host_setup(value.registry().as_str())?.clone();
                let root = binding
                    .canonical_root
                    .as_deref()
                    .ok_or("platform_v2_lifecycle_registry_invalid")?;
                validate_private_root_and_parent(root, self.expected_uid)?;
                Ok(())
            }
            WorkContextMutationIntent::CreateCheckout(value) => {
                let binding = self.checkout(value.registry().as_str())?.clone();
                materialize_checkout(&binding, self.expected_uid)
            }
            _ => Err("platform_v2_execution_adapter_unavailable"),
        }
    }

    fn inspect_lifecycle(
        &self,
        intent: &WorkContextMutationIntent,
        _resulting_identity: &WorkContextIdentity,
    ) -> bool {
        match intent {
            WorkContextMutationIntent::CreateHostSetup(value) => self
                .host_setup(value.registry().as_str())
                .is_ok_and(|binding| {
                    binding.canonical_root.as_deref().is_some_and(|root| {
                        validate_private_root_and_parent(root, self.expected_uid).is_ok()
                    })
                }),
            WorkContextMutationIntent::CreateCheckout(value) => self
                .checkout(value.registry().as_str())
                .is_ok_and(|binding| {
                    validate_checkout_materialized(binding, self.expected_uid).is_ok()
                }),
            _ => false,
        }
    }

    fn definitely_not_started(
        &self,
        intent: &WorkContextMutationIntent,
        _resulting_identity: &WorkContextIdentity,
    ) -> bool {
        match intent {
            WorkContextMutationIntent::CreateHostSetup(_) => true,
            WorkContextMutationIntent::CreateCheckout(value) => self
                .checkout(value.registry().as_str())
                .is_ok_and(
                    |binding| match CheckoutKind::parse(&binding.checkout_kind) {
                        Ok(CheckoutKind::AuthorizedFolder) => true,
                        Ok(CheckoutKind::GitWorktree) => {
                            !binding.canonical_root.exists()
                                && binding
                                    .repository_root
                                    .as_deref()
                                    .zip(binding.branch_ref.as_deref())
                                    .is_some_and(|(repository, branch)| {
                                        git_status(
                                            repository,
                                            &["show-ref", "--verify", "--quiet", branch],
                                        ) == Ok(false)
                                    })
                        }
                        Err(_) => false,
                    },
                ),
            _ => false,
        }
    }
}

fn validate_registry(document: &RegistryDocument, expected_uid: u32) -> Result<(), &'static str> {
    if document.version != 1
        || !safe_token(&document.generation)
        || document.host_setups.len() > MAX_ENTRIES
        || document.checkouts.len() > MAX_ENTRIES
        || document.workspaces.len() > MAX_ENTRIES
        || document.task_selectors.len() > MAX_ENTRIES
    {
        return Err("platform_v2_lifecycle_registry_invalid");
    }
    let unique = |mut values: Vec<String>| {
        values.sort();
        !values.windows(2).any(|pair| pair[0] == pair[1])
    };
    if !unique(
        document
            .host_setups
            .iter()
            .map(|v| v.selector.clone())
            .collect(),
    ) || !unique(
        document
            .checkouts
            .iter()
            .map(|v| v.selector.clone())
            .collect(),
    ) || !unique(
        document
            .workspaces
            .iter()
            .map(|v| v.workspace.clone())
            .collect(),
    ) || !unique(
        document
            .task_selectors
            .iter()
            .map(|v| format!("{}\0{}", v.base_selector, v.branch_selector))
            .collect(),
    ) {
        return Err("platform_v2_lifecycle_registry_invalid");
    }
    if !unique(
        document
            .host_setups
            .iter()
            .filter_map(|value| value.host_setup.clone())
            .collect(),
    ) || !unique(
        document
            .checkouts
            .iter()
            .filter_map(|value| value.checkout.clone())
            .collect(),
    ) {
        return Err("platform_v2_lifecycle_registry_invalid");
    }
    for host in &document.host_setups {
        let kind = HostSetupKind::parse(&host.setup_kind)
            .map_err(|_| "platform_v2_lifecycle_registry_invalid")?;
        if !safe_token(&host.selector)
            || host
                .host_setup
                .as_deref()
                .is_some_and(|value| !safe_token(value))
            || !safe_token(&host.project)
            || (kind == HostSetupKind::Local) != host.canonical_root.is_some()
        {
            return Err("platform_v2_lifecycle_registry_invalid");
        }
        if let Some(root) = &host.canonical_root {
            validate_private_root_and_parent(root, expected_uid)?;
        }
    }
    for checkout in &document.checkouts {
        if !safe_token(&checkout.selector)
            || checkout
                .checkout
                .as_deref()
                .is_some_and(|value| !safe_token(value))
            || !safe_token(&checkout.project)
            || !safe_token(&checkout.host_setup)
            || !safe_token(&checkout.repository_authority)
            || !safe_coordinate(&checkout.repository)
            || CheckoutKind::parse(&checkout.checkout_kind).is_err()
        {
            return Err("platform_v2_lifecycle_registry_invalid");
        }
        validate_checkout_binding(checkout, expected_uid)?;
    }
    for workspace in &document.workspaces {
        if !safe_token(&workspace.workspace)
            || !safe_token(&workspace.project)
            || !safe_token(&workspace.checkout)
            || !document.checkouts.iter().any(|value| {
                value.checkout.as_deref() == Some(workspace.checkout.as_str())
                    && value.project == workspace.project
                    && value.canonical_root == workspace.canonical_root
            })
        {
            return Err("platform_v2_lifecycle_registry_invalid");
        }
    }
    for selector in &document.task_selectors {
        if !safe_token(&selector.base_selector)
            || !safe_token(&selector.branch_selector)
            || !safe_token(&selector.project)
            || !safe_token(&selector.workspace)
            || !safe_token(&selector.checkout)
            || !document.workspaces.iter().any(|workspace| {
                workspace.workspace == selector.workspace
                    && workspace.project == selector.project
                    && workspace.checkout == selector.checkout
            })
        {
            return Err("platform_v2_lifecycle_registry_invalid");
        }
    }
    Ok(())
}

fn validate_checkout_binding(
    binding: &CheckoutBinding,
    expected_uid: u32,
) -> Result<(), &'static str> {
    match CheckoutKind::parse(&binding.checkout_kind)
        .map_err(|_| "platform_v2_lifecycle_registry_invalid")?
    {
        CheckoutKind::AuthorizedFolder => {
            if binding.repository_root.is_some()
                || binding.base_commit.is_some()
                || binding.branch_ref.is_some()
            {
                return Err("platform_v2_lifecycle_registry_invalid");
            }
            validate_private_root_and_parent(&binding.canonical_root, expected_uid)
        }
        CheckoutKind::GitWorktree => {
            let repository = binding
                .repository_root
                .as_ref()
                .ok_or("platform_v2_lifecycle_registry_invalid")?;
            let base = binding
                .base_commit
                .as_deref()
                .ok_or("platform_v2_lifecycle_registry_invalid")?;
            let branch = binding
                .branch_ref
                .as_deref()
                .ok_or("platform_v2_lifecycle_registry_invalid")?;
            validate_repository_root(repository, expected_uid)?;
            if !valid_object_id(base)
                || !valid_branch_ref(branch)
                || !binding.canonical_root.is_absolute()
                || binding
                    .canonical_root
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_none_or(|value| !safe_token(value))
                || binding.canonical_root.exists()
                    && fs::symlink_metadata(&binding.canonical_root)
                        .map(|metadata| metadata.file_type().is_symlink())
                        .unwrap_or(true)
            {
                return Err("platform_v2_lifecycle_registry_invalid");
            }
            let parent = binding
                .canonical_root
                .parent()
                .ok_or("platform_v2_lifecycle_registry_invalid")?;
            validate_existing_private_root(parent, expected_uid)?;
            let repository = fs::canonicalize(repository)
                .map_err(|_| "platform_v2_lifecycle_registry_invalid")?;
            let parent =
                fs::canonicalize(parent).map_err(|_| "platform_v2_lifecycle_registry_invalid")?;
            if parent.starts_with(&repository) || repository.starts_with(&parent) {
                return Err("platform_v2_lifecycle_registry_invalid");
            }
            Ok(())
        }
    }
}

fn materialize_checkout(binding: &CheckoutBinding, expected_uid: u32) -> Result<(), &'static str> {
    match CheckoutKind::parse(&binding.checkout_kind)
        .map_err(|_| "platform_v2_lifecycle_registry_invalid")?
    {
        CheckoutKind::AuthorizedFolder => {
            validate_private_root_and_parent(&binding.canonical_root, expected_uid)
        }
        CheckoutKind::GitWorktree => {
            if validate_checkout_materialized(binding, expected_uid).is_ok() {
                return Ok(());
            }
            if binding.canonical_root.exists() {
                return Err("platform_v2_lifecycle_effect_ambiguous");
            }
            let repository = binding.repository_root.as_ref().unwrap();
            let base = binding.base_commit.as_deref().unwrap();
            let branch_ref = binding.branch_ref.as_deref().unwrap();
            let resolved = git_text(
                repository,
                &["rev-parse", "--verify", &format!("{base}^{{commit}}")],
            )?;
            if resolved != base {
                return Err("platform_v2_lifecycle_base_mismatch");
            }
            if git_status(repository, &["show-ref", "--verify", "--quiet", branch_ref])? {
                return Err("platform_v2_lifecycle_branch_conflict");
            }
            validate_checkout_tree_bounds(repository, base, &binding.canonical_root)?;
            let branch = branch_ref
                .strip_prefix("refs/heads/")
                .ok_or("platform_v2_lifecycle_registry_invalid")?;
            let mut command = safe_git_command(repository)?;
            command
                .args(["worktree", "add", "-b"])
                .arg(branch)
                .arg(&binding.canonical_root)
                .arg(base);
            let output = bounded_output(&mut command)?;
            if !output.status.success() {
                return Err("platform_v2_lifecycle_git_failed");
            }
            fs::set_permissions(&binding.canonical_root, fs::Permissions::from_mode(0o700))
                .map_err(|_| "platform_v2_lifecycle_path_insecure")?;
            fs::set_permissions(
                binding.canonical_root.join(".git"),
                fs::Permissions::from_mode(0o600),
            )
            .map_err(|_| "platform_v2_lifecycle_path_insecure")?;
            validate_checkout_materialized(binding, expected_uid)
        }
    }
}

fn preflight_checkout_effect(
    binding: &CheckoutBinding,
    expected_uid: u32,
) -> Result<(), &'static str> {
    validate_checkout_binding(binding, expected_uid)?;
    if CheckoutKind::parse(&binding.checkout_kind).ok() != Some(CheckoutKind::GitWorktree) {
        return Ok(());
    }
    if binding.canonical_root.exists() {
        return validate_checkout_materialized(binding, expected_uid);
    }
    let repository = binding.repository_root.as_ref().unwrap();
    let base = binding.base_commit.as_deref().unwrap();
    let branch = binding.branch_ref.as_deref().unwrap();
    if git_text(
        repository,
        &["rev-parse", "--verify", &format!("{base}^{{commit}}")],
    )? != base
    {
        return Err("platform_v2_lifecycle_base_mismatch");
    }
    if git_status(repository, &["show-ref", "--verify", "--quiet", branch])? {
        return Err("platform_v2_lifecycle_branch_conflict");
    }
    validate_checkout_tree_bounds(repository, base, &binding.canonical_root)
}

fn validate_checkout_materialized(
    binding: &CheckoutBinding,
    expected_uid: u32,
) -> Result<(), &'static str> {
    validate_private_root_and_parent(&binding.canonical_root, expected_uid)?;
    if CheckoutKind::parse(&binding.checkout_kind).ok() == Some(CheckoutKind::GitWorktree) {
        let repository = binding.repository_root.as_ref().unwrap();
        validate_repository_root(repository, expected_uid)?;
        validate_worktree_git_file(&binding.canonical_root, repository, expected_uid)?;
        let expected_repository =
            fs::canonicalize(repository).map_err(|_| "platform_v2_lifecycle_checkout_mismatch")?;
        let expected_common = fs::canonicalize(repository.join(".git"))
            .map_err(|_| "platform_v2_lifecycle_checkout_mismatch")?;
        let actual_root = canonical_git_path(
            &binding.canonical_root,
            &git_text(&binding.canonical_root, &["rev-parse", "--show-toplevel"])?,
        )?;
        let actual_common = canonical_git_path(
            &binding.canonical_root,
            &git_text(&binding.canonical_root, &["rev-parse", "--git-common-dir"])?,
        )?;
        let base = binding.base_commit.as_deref().unwrap();
        let branch = binding.branch_ref.as_deref().unwrap();
        if actual_root != binding.canonical_root
            || expected_repository != repository.as_path()
            || actual_common != expected_common
            || git_text(&binding.canonical_root, &["rev-parse", "HEAD"])? != base
            || git_text(&binding.canonical_root, &["symbolic-ref", "-q", "HEAD"])? != branch
        {
            return Err("platform_v2_lifecycle_checkout_mismatch");
        }
    };
    Ok(())
}

fn validate_repository_root(path: &Path, expected_uid: u32) -> Result<(), &'static str> {
    validate_private_root_and_parent(path, expected_uid)?;
    let git = path.join(".git");
    let metadata =
        fs::symlink_metadata(&git).map_err(|_| "platform_v2_lifecycle_repository_mismatch")?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o022 != 0
        || fs::canonicalize(&git).ok().as_deref() != Some(git.as_path())
    {
        return Err("platform_v2_lifecycle_repository_mismatch");
    }
    let top = canonical_git_path(path, &git_text(path, &["rev-parse", "--show-toplevel"])?)?;
    let common = canonical_git_path(path, &git_text(path, &["rev-parse", "--git-common-dir"])?)?;
    if top != path || common != git {
        return Err("platform_v2_lifecycle_repository_mismatch");
    }
    Ok(())
}

fn validate_worktree_git_file(
    worktree: &Path,
    repository: &Path,
    expected_uid: u32,
) -> Result<(), &'static str> {
    let git_file = worktree.join(".git");
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(&git_file)
        .map_err(|_| "platform_v2_lifecycle_checkout_mismatch")?;
    let metadata = file
        .metadata()
        .map_err(|_| "platform_v2_lifecycle_checkout_mismatch")?;
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
        || metadata.len() > 4096
    {
        return Err("platform_v2_lifecycle_checkout_mismatch");
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| "platform_v2_lifecycle_checkout_mismatch")?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| "platform_v2_lifecycle_checkout_mismatch")?
        .trim();
    let target = value
        .strip_prefix("gitdir: ")
        .ok_or("platform_v2_lifecycle_checkout_mismatch")?;
    let target = canonical_git_path(worktree, target)?;
    let common = fs::canonicalize(repository.join(".git"))
        .map_err(|_| "platform_v2_lifecycle_checkout_mismatch")?;
    let worktree_records = common.join("worktrees");
    if !target.starts_with(&worktree_records)
        || target.parent() != Some(worktree_records.as_path())
        || canonical_git_path(worktree, &git_text(worktree, &["rev-parse", "--git-dir"])?)?
            != target
    {
        return Err("platform_v2_lifecycle_checkout_mismatch");
    }
    Ok(())
}

fn canonical_git_path(base: &Path, value: &str) -> Result<PathBuf, &'static str> {
    let value = Path::new(value);
    fs::canonicalize(if value.is_absolute() {
        value.to_path_buf()
    } else {
        base.join(value)
    })
    .map_err(|_| "platform_v2_lifecycle_checkout_mismatch")
}

fn validate_checkout_tree_bounds(
    repository: &Path,
    base: &str,
    target: &Path,
) -> Result<(), &'static str> {
    let mut command = safe_git_command(repository)?;
    command.args(["ls-tree", "-rlz", "--full-tree", base]);
    let output = bounded_output(&mut command)?;
    if !output.status.success() {
        return Err("platform_v2_lifecycle_git_failed");
    }
    let mut total = 0_u64;
    let mut entries = 0_usize;
    for record in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|value| !value.is_empty())
    {
        let header = record
            .splitn(2, |byte| *byte == b'\t')
            .next()
            .ok_or("platform_v2_lifecycle_git_failed")?;
        let header = std::str::from_utf8(header).map_err(|_| "platform_v2_lifecycle_git_failed")?;
        let mut fields = header.split_ascii_whitespace();
        let mode = fields.next().ok_or("platform_v2_lifecycle_git_failed")?;
        let kind = fields.next().ok_or("platform_v2_lifecycle_git_failed")?;
        let _object = fields.next().ok_or("platform_v2_lifecycle_git_failed")?;
        let size = fields.next().ok_or("platform_v2_lifecycle_git_failed")?;
        if mode == "120000" || mode == "160000" || kind != "blob" {
            return Err("platform_v2_lifecycle_checkout_tree_unsafe");
        }
        total = total
            .checked_add(
                size.parse::<u64>()
                    .map_err(|_| "platform_v2_lifecycle_git_failed")?,
            )
            .ok_or("platform_v2_lifecycle_checkout_too_large")?;
        entries += 1;
        if entries > MAX_CHECKOUT_ENTRIES || total > MAX_CHECKOUT_BYTES {
            return Err("platform_v2_lifecycle_checkout_too_large");
        }
    }
    let parent = target
        .parent()
        .ok_or("platform_v2_lifecycle_path_insecure")?;
    let capacity =
        nix::sys::statvfs::statvfs(parent).map_err(|_| "platform_v2_lifecycle_path_unavailable")?;
    let available = capacity
        .blocks_available()
        .saturating_mul(capacity.fragment_size());
    if total.saturating_add(64 * 1024 * 1024) > available {
        return Err("platform_v2_lifecycle_checkout_disk_insufficient");
    }
    Ok(())
}

fn validate_existing_private_root(path: &Path, expected_uid: u32) -> Result<(), &'static str> {
    if !path.is_absolute() {
        return Err("platform_v2_lifecycle_path_insecure");
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "platform_v2_lifecycle_path_unavailable")?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err("platform_v2_lifecycle_path_insecure");
    }
    let canonical = fs::canonicalize(path).map_err(|_| "platform_v2_lifecycle_path_unavailable")?;
    if canonical != path {
        return Err("platform_v2_lifecycle_path_insecure");
    }
    Ok(())
}

fn validate_private_root_and_parent(path: &Path, expected_uid: u32) -> Result<(), &'static str> {
    validate_existing_private_root(path, expected_uid)?;
    let parent = path
        .parent()
        .filter(|parent| *parent != path)
        .ok_or("platform_v2_lifecycle_path_insecure")?;
    validate_existing_private_root(parent, expected_uid)
}

fn read_private_file(
    path: &Path,
    expected_uid: u32,
    limit: u64,
) -> Result<Option<PrivateSnapshot>, &'static str> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("platform_v2_lifecycle_private_file_insecure"),
    };
    let metadata = file
        .metadata()
        .map_err(|_| "platform_v2_lifecycle_private_file_insecure")?;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > limit
    {
        return Err("platform_v2_lifecycle_private_file_insecure");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "platform_v2_lifecycle_private_file_insecure")?;
    if bytes.len() as u64 > limit {
        return Err("platform_v2_lifecycle_private_file_insecure");
    }
    Ok(Some(PrivateSnapshot {
        generation: FileGeneration {
            device: metadata.dev(),
            inode: metadata.ino(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            length: metadata.len(),
            digest: Sha256::digest(&bytes),
        },
        bytes,
    }))
}

fn write_private_atomic(
    path: &Path,
    expected_uid: u32,
    bytes: &[u8],
) -> Result<(), AtomicWriteError> {
    write_private_atomic_with(path, expected_uid, bytes, || Ok(()))
}

fn write_private_atomic_with<F>(
    path: &Path,
    expected_uid: u32,
    bytes: &[u8],
    after_rename: F,
) -> Result<(), AtomicWriteError>
where
    F: FnOnce() -> Result<(), &'static str>,
{
    let before = |category| AtomicWriteError {
        category,
        installed: false,
    };
    let after = |category| AtomicWriteError {
        category,
        installed: true,
    };
    let parent = path
        .parent()
        .ok_or_else(|| before("platform_v2_lifecycle_journal_insecure"))?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|_| before("platform_v2_lifecycle_journal_insecure"))?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != expected_uid
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(before("platform_v2_lifecycle_journal_insecure"));
    }
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != expected_uid
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1)
    {
        return Err(before("platform_v2_lifecycle_journal_insecure"));
    }
    let mut nonce = [0_u8; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut nonce))
        .map_err(|_| before("platform_v2_lifecycle_journal_io"))?;
    let temporary = parent.join(format!(".platform-v2-lifecycle-{}.tmp", hex(&nonce)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|_| before("platform_v2_lifecycle_journal_io"))?;
    if file.write_all(bytes).and_then(|_| file.sync_all()).is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(before("platform_v2_lifecycle_journal_io"));
    }
    if fs::rename(&temporary, path).is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(before("platform_v2_lifecycle_journal_io"));
    }
    after_rename().map_err(after)?;
    let directory =
        fs::File::open(parent).map_err(|_| after("platform_v2_lifecycle_journal_io"))?;
    directory
        .sync_all()
        .map_err(|_| after("platform_v2_lifecycle_journal_io"))
}

struct BoundedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
}

fn bounded_output(command: &mut Command) -> Result<BoundedOutput, &'static str> {
    bounded_output_with_timeout(command, GIT_TIMEOUT)
}

fn bounded_output_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> Result<BoundedOutput, &'static str> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0");
    command.process_group(0);
    let mut child = command
        .spawn()
        .map_err(|_| "platform_v2_lifecycle_git_unavailable")?;

    let total = Arc::new(AtomicUsize::new(0));
    let exceeded = Arc::new(AtomicBool::new(false));
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let stdout_done = Arc::new(AtomicBool::new(false));
    let stderr_done = Arc::new(AtomicBool::new(false));
    let stdout_reader = spawn_bounded_reader(
        child
            .stdout
            .take()
            .ok_or("platform_v2_lifecycle_git_unavailable")?,
        Arc::clone(&total),
        Arc::clone(&exceeded),
        Some(Arc::clone(&stdout)),
        Arc::clone(&stdout_done),
    );
    let stderr_reader = spawn_bounded_reader(
        child
            .stderr
            .take()
            .ok_or("platform_v2_lifecycle_git_unavailable")?,
        Arc::clone(&total),
        Arc::clone(&exceeded),
        None,
        Arc::clone(&stderr_done),
    );
    let started = Instant::now();
    let mut status = None;
    loop {
        if exceeded.load(Ordering::Acquire) {
            kill_process_group(&mut child);
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err("platform_v2_lifecycle_git_output_exceeded");
        }
        if started.elapsed() >= timeout {
            kill_process_group(&mut child);
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err("platform_v2_lifecycle_git_timeout");
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(value)) => status = Some(value),
                Ok(None) => {}
                Err(_) => {
                    kill_process_group(&mut child);
                    let _ = stdout_reader.join();
                    let _ = stderr_reader.join();
                    return Err("platform_v2_lifecycle_git_failed");
                }
            }
        }
        if status.is_some()
            && stdout_done.load(Ordering::Acquire)
            && stderr_done.load(Ordering::Acquire)
        {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    stdout_reader
        .join()
        .map_err(|_| "platform_v2_lifecycle_git_failed")??;
    stderr_reader
        .join()
        .map_err(|_| "platform_v2_lifecycle_git_failed")??;
    if exceeded.load(Ordering::Acquire) {
        return Err("platform_v2_lifecycle_git_output_exceeded");
    }
    let stdout = Arc::try_unwrap(stdout)
        .map_err(|_| "platform_v2_lifecycle_git_failed")?
        .into_inner()
        .map_err(|_| "platform_v2_lifecycle_git_failed")?;
    Ok(BoundedOutput {
        status: status.ok_or("platform_v2_lifecycle_git_failed")?,
        stdout,
    })
}

fn spawn_bounded_reader<R>(
    mut reader: R,
    total: Arc<AtomicUsize>,
    exceeded: Arc<AtomicBool>,
    capture: Option<Arc<Mutex<Vec<u8>>>>,
    done: Arc<AtomicBool>,
) -> thread::JoinHandle<Result<(), &'static str>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let result = (|| {
            let mut buffer = [0_u8; 8192];
            loop {
                let count = reader
                    .read(&mut buffer)
                    .map_err(|_| "platform_v2_lifecycle_git_failed")?;
                if count == 0 {
                    return Ok(());
                }
                let prior = total.fetch_add(count, Ordering::AcqRel);
                if prior.saturating_add(count) > MAX_GIT_OUTPUT_BYTES {
                    exceeded.store(true, Ordering::Release);
                    continue;
                }
                if let Some(capture) = &capture {
                    capture
                        .lock()
                        .map_err(|_| "platform_v2_lifecycle_git_failed")?
                        .extend_from_slice(&buffer[..count]);
                }
            }
        })();
        done.store(true, Ordering::Release);
        result
    })
}

fn kill_process_group(child: &mut std::process::Child) {
    if let Ok(raw_pid) = i32::try_from(child.id()) {
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(raw_pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn safe_git_command(path: &Path) -> Result<Command, &'static str> {
    let mut query = Command::new(GIT_PROGRAM);
    query
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.file.allow=never",
        ])
        .arg("-C")
        .arg(path)
        .args([
            "config",
            "--local",
            "--no-includes",
            "--null",
            "--name-only",
            "--list",
        ]);
    let output = bounded_output(&mut query)?;
    if !output.status.success() {
        return Err("platform_v2_lifecycle_git_failed");
    }
    let mut filters = Vec::new();
    for key in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|value| !value.is_empty())
    {
        let key = std::str::from_utf8(key).map_err(|_| "platform_v2_lifecycle_git_failed")?;
        let normalized = key.to_ascii_lowercase();
        if normalized.starts_with("include.") || normalized.starts_with("includeif.") {
            return Err("platform_v2_lifecycle_git_include_unsafe");
        }
        let Some(normalized_tail) = normalized.strip_prefix("filter.") else {
            continue;
        };
        let Some((_, property)) = normalized_tail.rsplit_once('.') else {
            continue;
        };
        if !matches!(property, "process" | "smudge" | "clean" | "required") {
            continue;
        }
        // Git's section and variable names are case-insensitive, but subsection
        // names are case-sensitive. Preserve the exact subsection spelling so
        // the command-line override applies to the configured filter.
        let Some((name, _)) = key["filter.".len()..].rsplit_once('.') else {
            continue;
        };
        if !safe_filter_name(name) {
            return Err("platform_v2_lifecycle_filter_unsafe");
        }
        if !filters.iter().any(|existing| existing == name) {
            filters.push(name.to_owned());
        }
    }
    if filters.len() > 64 {
        return Err("platform_v2_lifecycle_filter_unsafe");
    }
    let mut command = Command::new(GIT_PROGRAM);
    command.args([
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "protocol.file.allow=never",
    ]);
    for filter in filters {
        command
            .arg("-c")
            .arg(format!("filter.{filter}.process="))
            .arg("-c")
            .arg(format!("filter.{filter}.smudge=cat"))
            .arg("-c")
            .arg(format!("filter.{filter}.clean=cat"))
            .arg("-c")
            .arg(format!("filter.{filter}.required=false"));
    }
    command.arg("-C").arg(path);
    Ok(command)
}

fn safe_filter_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn git_text(path: &Path, args: &[&str]) -> Result<String, &'static str> {
    let mut command = safe_git_command(path)?;
    command.args(args);
    let output = bounded_output(&mut command)?;
    if !output.status.success() {
        return Err("platform_v2_lifecycle_git_failed");
    }
    let value = std::str::from_utf8(&output.stdout)
        .map_err(|_| "platform_v2_lifecycle_git_failed")?
        .trim();
    if value.is_empty() || value.len() > 256 {
        return Err("platform_v2_lifecycle_git_failed");
    }
    Ok(value.to_owned())
}

fn git_status(path: &Path, args: &[&str]) -> Result<bool, &'static str> {
    let mut command = safe_git_command(path)?;
    command.args(args);
    let output = bounded_output(&mut command)?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err("platform_v2_lifecycle_git_failed"),
    }
}

fn safe_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with(['.', ':', '-'])
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn safe_coordinate(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn repository_matches(identity: &WorkContextIdentity, authority: &str, id: &str) -> bool {
    match identity {
        WorkContextIdentity::Repository(value) => {
            value.coordinate().authority.as_str() == authority
                && value.coordinate().id.as_str() == id
        }
        _ => false,
    }
}

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_branch_ref(value: &str) -> bool {
    let Some(branch) = value.strip_prefix("refs/heads/") else {
        return false;
    };
    !branch.is_empty()
        && branch.len() <= 200
        && !branch.starts_with(['.', '-', '/'])
        && !branch.ends_with(['.', '/'])
        && !branch.contains("..")
        && !branch.contains("@{")
        && !branch.bytes().any(|byte| {
            byte <= 0x20
                || byte == 0x7f
                || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn path_digest(path: &Path) -> String {
    hex(Sha256::digest(path.as_os_str().as_encoded_bytes()).as_bytes())
}

fn lifecycle_digest(intent: &WorkContextMutationIntent, identity: &WorkContextIdentity) -> String {
    let value = format!(
        "v1\0{}\0{}\0{}\0{intent:?}",
        intent.kind(),
        identity.kind().as_str(),
        identity.id()
    );
    hex(Sha256::digest(value.as_bytes()).as_bytes())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use automonique_protocol::platform::{
        ResourceAuthority, ResourceCoordinate, ResourceId, ResourceKind,
    };
    use automonique_protocol::platform_v2::{
        HostSetupId, ProjectId, V1RepositoryRef, WorkContextLabel,
    };
    use automonique_protocol::platform_v2_lifecycle::{
        CreateCheckoutIntent, CreateHostSetupIntent, ExpectedWorkContext,
        WorkContextRegistrySelector,
    };
    use automonique_protocol::primitives::Revision;

    fn private_directory(path: &Path) {
        fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn write_registry(path: &Path, value: &serde_json::Value) {
        fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn authorized_registry(root: &Path) -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "generation": "generation-one",
            "host_setups": [{
                "selector": "host-local", "host_setup": "host-one",
                "project": "project-test",
                "setup_kind": "local", "canonical_root": root
            }],
            "checkouts": [{
                "selector": "checkout-one", "checkout": "checkout-one",
                "project": "project-test",
                "host_setup": "host-one", "repository_authority": "github",
                "repository": "owner/repository", "checkout_kind": "authorized_folder",
                "canonical_root": root, "repository_root": null,
                "base_commit": null, "branch_ref": null
            }],
            "workspaces": [{
                "workspace": "workspace-one", "project": "project-test",
                "checkout": "checkout-one", "canonical_root": root
            }],
            "task_selectors": [{
                "base_selector": "base-one", "branch_selector": "branch-one",
                "project": "project-test", "workspace": "workspace-one",
                "checkout": "checkout-one"
            }]
        })
    }

    #[test]
    fn branch_injection_and_revision_expressions_are_refused() {
        assert!(valid_branch_ref("refs/heads/work/issue-166"));
        for value in [
            "-c core.fsmonitor=x",
            "refs/heads/-unsafe",
            "refs/heads/main..other",
            "refs/heads/main@{1}",
            "refs/heads/main^{}",
            "refs/remotes/origin/main",
        ] {
            assert!(!valid_branch_ref(value), "accepted {value}");
        }
        assert!(valid_object_id(&"a".repeat(40)));
        assert!(!valid_object_id("main^{commit}"));
    }

    #[test]
    fn private_file_refuses_symlinks_and_permissive_modes() {
        let root = tempfile::tempdir().unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        let target = root.path().join("target");
        fs::write(&target, b"{}").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_private_file(&link, uid, 100).is_err());
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_private_file(&target, uid, 100).is_err());

        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let hardlink = root.path().join("hardlink");
        fs::hard_link(&target, &hardlink).unwrap();
        assert!(read_private_file(&target, uid, 100).is_err());
        assert!(read_private_file(&hardlink, uid, 100).is_err());
    }

    #[test]
    fn bounded_child_is_killed_on_timeout_and_output_limit() {
        let started = Instant::now();
        assert_eq!(
            bounded_output_with_timeout(
                Command::new("/bin/sh").args(["-c", "sleep 30"]),
                Duration::from_millis(50),
            )
            .err(),
            Some("platform_v2_lifecycle_git_timeout")
        );
        assert!(started.elapsed() < Duration::from_secs(2));

        let started = Instant::now();
        assert_eq!(
            bounded_output_with_timeout(
                Command::new("/bin/sh").args(["-c", "sleep 30 & exit 0"]),
                Duration::from_millis(50),
            )
            .err(),
            Some("platform_v2_lifecycle_git_timeout")
        );
        assert!(started.elapsed() < Duration::from_secs(2));

        assert_eq!(
            bounded_output_with_timeout(
                Command::new("/bin/sh").args([
                    "-c",
                    "while :; do printf '012345678901234567890123456789'; done",
                ]),
                Duration::from_secs(2),
            )
            .err(),
            Some("platform_v2_lifecycle_git_output_exceeded")
        );
    }

    #[test]
    fn atomic_write_reports_installed_after_post_rename_failure() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        private_directory(&state);
        let journal = state.join("journal");
        let error = write_private_atomic_with(
            &journal,
            nix::unistd::geteuid().as_raw(),
            b"new-generation",
            || Err("forced_post_rename_failure"),
        )
        .unwrap_err();
        assert!(error.installed);
        assert_eq!(error.category, "forced_post_rename_failure");
        assert_eq!(fs::read(journal).unwrap(), b"new-generation");
    }

    #[test]
    fn remote_host_is_typed_but_explicitly_unsupported() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        private_directory(&state);
        let registry_path = state.join(LIFECYCLE_REGISTRY_FILE_NAME);
        write_registry(
            &registry_path,
            &serde_json::json!({
                "version": 1, "generation": "generation-remote",
                "host_setups": [{
                    "selector": "remote-one", "host_setup": null,
                    "project": "project-test", "setup_kind": "remote_runtime",
                    "canonical_root": null
                }],
                "checkouts": [], "workspaces": [], "task_selectors": []
            }),
        );
        let adapter = ProductionLifecycleEffectAdapter::open(
            &registry_path,
            &state.join(LIFECYCLE_JOURNAL_FILE_NAME),
            nix::unistd::geteuid().as_raw(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            adapter.supported_effect_kinds(),
            std::collections::BTreeSet::from([
                String::from("create_host_setup"),
                String::from("create_checkout"),
            ])
        );
        let intent = WorkContextMutationIntent::CreateHostSetup(
            CreateHostSetupIntent::new(
                WorkContextLabel::new("Remote host").unwrap(),
                ExpectedWorkContext::new(
                    WorkContextIdentity::Project(ProjectId::new("project-test").unwrap()),
                    Revision::FIRST,
                ),
                HostSetupKind::RemoteRuntime,
                WorkContextRegistrySelector::new("remote-one").unwrap(),
            )
            .unwrap(),
        );
        assert_eq!(
            adapter.preflight(&intent),
            Err("platform_v2_remote_host_unsupported")
        );
    }

    #[test]
    fn selector_registry_refuses_a_symlinked_authorized_root() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        let target = directory.path().join("target");
        let linked = directory.path().join("linked");
        private_directory(&state);
        private_directory(&target);
        std::os::unix::fs::symlink(&target, &linked).unwrap();
        let registry_path = state.join(LIFECYCLE_REGISTRY_FILE_NAME);
        write_registry(&registry_path, &authorized_registry(&linked));
        assert!(matches!(
            ProductionLifecycleEffectAdapter::open(
                &registry_path,
                &state.join(LIFECYCLE_JOURNAL_FILE_NAME),
                nix::unistd::geteuid().as_raw(),
            ),
            Err("platform_v2_lifecycle_path_insecure")
        ));
    }

    #[test]
    fn selector_registry_refuses_a_permissive_authorized_root_parent() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        let permissive_parent = directory.path().join("permissive");
        let root = permissive_parent.join("authorized");
        private_directory(&state);
        private_directory(&permissive_parent);
        private_directory(&root);
        fs::set_permissions(&permissive_parent, fs::Permissions::from_mode(0o770)).unwrap();
        let registry_path = state.join(LIFECYCLE_REGISTRY_FILE_NAME);
        write_registry(&registry_path, &authorized_registry(&root));
        assert!(matches!(
            ProductionLifecycleEffectAdapter::open(
                &registry_path,
                &state.join(LIFECYCLE_JOURNAL_FILE_NAME),
                nix::unistd::geteuid().as_raw(),
            ),
            Err("platform_v2_lifecycle_path_insecure")
        ));
    }

    #[test]
    fn completed_effect_survives_restart_and_live_registry_swap_refuses() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        let root = directory.path().join("authorized");
        private_directory(&state);
        private_directory(&root);
        let registry_path = state.join(LIFECYCLE_REGISTRY_FILE_NAME);
        let journal_path = state.join(LIFECYCLE_JOURNAL_FILE_NAME);
        let document = authorized_registry(&root);
        write_registry(&registry_path, &document);
        let uid = nix::unistd::geteuid().as_raw();
        let mut adapter =
            ProductionLifecycleEffectAdapter::open(&registry_path, &journal_path, uid)
                .unwrap()
                .unwrap();
        let project = ExpectedWorkContext::new(
            WorkContextIdentity::Project(ProjectId::new("project-test").unwrap()),
            Revision::FIRST,
        );
        let intent = WorkContextMutationIntent::CreateHostSetup(
            CreateHostSetupIntent::new(
                WorkContextLabel::new("Local host").unwrap(),
                project,
                HostSetupKind::Local,
                WorkContextRegistrySelector::new("host-local").unwrap(),
            )
            .unwrap(),
        );
        let resulting = WorkContextIdentity::HostSetup(HostSetupId::new("host-one").unwrap());
        let key = IdempotencyKey::new("effect-one").unwrap();
        assert_eq!(
            adapter.execute(&intent, &resulting, &key),
            PlatformV2EffectExecution::Completed
        );
        assert_eq!(
            adapter.preflight_submission(
                &intent,
                &WorkContextIdentity::HostSetup(HostSetupId::new("host-other").unwrap()),
            ),
            Err("platform_v2_lifecycle_selector_consumed")
        );
        drop(adapter);

        let mut restarted =
            ProductionLifecycleEffectAdapter::open(&registry_path, &journal_path, uid)
                .unwrap()
                .unwrap();
        assert_eq!(
            restarted.execute(&intent, &resulting, &key),
            PlatformV2EffectExecution::Completed
        );

        let replacement = state.join("replacement.json");
        write_registry(&replacement, &document);
        fs::rename(&replacement, &registry_path).unwrap();
        assert!(matches!(
            restarted.reconcile(&intent, &resulting, &key),
            PlatformV2EffectReconciliation::Unknown(_)
        ));
    }

    #[test]
    fn validation_only_prepared_effects_are_tombstoned_and_do_not_block_rotation() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        let root = directory.path().join("authorized");
        private_directory(&state);
        private_directory(&root);
        let registry_path = state.join(LIFECYCLE_REGISTRY_FILE_NAME);
        let journal_path = state.join(LIFECYCLE_JOURNAL_FILE_NAME);
        let mut document = authorized_registry(&root);
        write_registry(&registry_path, &document);
        let uid = nix::unistd::geteuid().as_raw();
        let mut adapter =
            ProductionLifecycleEffectAdapter::open(&registry_path, &journal_path, uid)
                .unwrap()
                .unwrap();
        let project = ExpectedWorkContext::new(
            WorkContextIdentity::Project(ProjectId::new("project-test").unwrap()),
            Revision::FIRST,
        );
        let host_intent = WorkContextMutationIntent::CreateHostSetup(
            CreateHostSetupIntent::new(
                WorkContextLabel::new("Local host").unwrap(),
                project.clone(),
                HostSetupKind::Local,
                WorkContextRegistrySelector::new("host-local").unwrap(),
            )
            .unwrap(),
        );
        let host_result = WorkContextIdentity::HostSetup(HostSetupId::new("host-one").unwrap());
        let host_key = IdempotencyKey::new("host-validation-only").unwrap();
        adapter
            .insert_lifecycle_prepared(
                format!("lifecycle:{}", host_key.as_str()),
                lifecycle_digest(&host_intent, &host_result),
                &host_intent,
                &host_result,
            )
            .unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(matches!(
            adapter.reconcile(&host_intent, &host_result, &host_key),
            PlatformV2EffectReconciliation::VerifiedNotStarted(_)
        ));
        assert!(adapter.journal.entries.is_empty());
        assert!(adapter.journal.host_setups.is_empty());

        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let repository = WorkContextIdentity::Repository(
            V1RepositoryRef::new(ResourceCoordinate::new(
                ResourceAuthority::GitHub,
                ResourceKind::Repository,
                ResourceId::new("owner/repository").unwrap(),
            ))
            .unwrap(),
        );
        let checkout_intent = WorkContextMutationIntent::CreateCheckout(
            CreateCheckoutIntent::new(
                WorkContextLabel::new("Authorized checkout").unwrap(),
                project,
                ExpectedWorkContext::new(host_result.clone(), Revision::FIRST),
                ExpectedWorkContext::new(repository, Revision::FIRST),
                CheckoutKind::AuthorizedFolder,
                WorkContextRegistrySelector::new("checkout-one").unwrap(),
            )
            .unwrap(),
        );
        let checkout_result = WorkContextIdentity::Checkout(
            automonique_protocol::platform_v2::CheckoutId::new("checkout-one").unwrap(),
        );
        let checkout_key = IdempotencyKey::new("checkout-validation-only").unwrap();
        adapter
            .insert_lifecycle_prepared(
                format!("lifecycle:{}", checkout_key.as_str()),
                lifecycle_digest(&checkout_intent, &checkout_result),
                &checkout_intent,
                &checkout_result,
            )
            .unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(matches!(
            adapter.reconcile(&checkout_intent, &checkout_result, &checkout_key),
            PlatformV2EffectReconciliation::VerifiedNotStarted(_)
        ));
        assert!(adapter.journal.entries.is_empty());
        assert!(adapter.journal.checkouts.is_empty());
        drop(adapter);

        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        document["generation"] = serde_json::Value::String("generation-two".to_owned());
        let replacement = state.join("replacement.json");
        write_registry(&replacement, &document);
        fs::rename(&replacement, &registry_path).unwrap();
        assert!(
            ProductionLifecycleEffectAdapter::open(&registry_path, &journal_path, uid)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn restart_refuses_to_reconcile_prepared_effect_under_replaced_registry_generation() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        let root = directory.path().join("authorized");
        private_directory(&state);
        private_directory(&root);
        let registry_path = state.join(LIFECYCLE_REGISTRY_FILE_NAME);
        let journal_path = state.join(LIFECYCLE_JOURNAL_FILE_NAME);
        let document = authorized_registry(&root);
        write_registry(&registry_path, &document);
        let uid = nix::unistd::geteuid().as_raw();
        let mut adapter =
            ProductionLifecycleEffectAdapter::open(&registry_path, &journal_path, uid)
                .unwrap()
                .unwrap();
        adapter
            .insert_prepared(
                "lifecycle:effect-prepared".to_owned(),
                "a".repeat(64),
                "create_checkout",
            )
            .unwrap();
        drop(adapter);

        let replacement = state.join("replacement.json");
        write_registry(&replacement, &document);
        fs::rename(&replacement, &registry_path).unwrap();
        assert!(matches!(
            ProductionLifecycleEffectAdapter::open(&registry_path, &journal_path, uid),
            Err("platform_v2_lifecycle_registry_recovery_required")
        ));
    }

    #[test]
    fn journal_generation_is_fenced_before_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        let root = directory.path().join("authorized");
        private_directory(&state);
        private_directory(&root);
        let registry_path = state.join(LIFECYCLE_REGISTRY_FILE_NAME);
        let journal_path = state.join(LIFECYCLE_JOURNAL_FILE_NAME);
        write_registry(&registry_path, &authorized_registry(&root));
        let uid = nix::unistd::geteuid().as_raw();
        let mut adapter =
            ProductionLifecycleEffectAdapter::open(&registry_path, &journal_path, uid)
                .unwrap()
                .unwrap();
        adapter
            .insert_prepared(
                "lifecycle:first".to_owned(),
                "a".repeat(64),
                "create_checkout",
            )
            .unwrap();
        let replacement = state.join("replacement-journal");
        fs::copy(&journal_path, &replacement).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement, &journal_path).unwrap();
        let installed = fs::read(&journal_path).unwrap();
        assert_eq!(
            adapter.insert_prepared(
                "lifecycle:second".to_owned(),
                "b".repeat(64),
                "create_checkout",
            ),
            Err("platform_v2_lifecycle_journal_changed")
        );
        assert_eq!(fs::read(&journal_path).unwrap(), installed);
    }

    #[test]
    fn git_worktree_uses_exact_commit_and_branch_and_replays_idempotently() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        let repository = directory.path().join("repository");
        let worktrees = directory.path().join("worktrees");
        private_directory(&state);
        private_directory(&repository);
        private_directory(&worktrees);
        let run = |arguments: &[&str]| {
            let output = Command::new("git")
                .arg("-C")
                .arg(&repository)
                .args(arguments)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .output()
                .unwrap();
            assert!(output.status.success(), "{:?}", output.stderr);
        };
        run(&["init", "--quiet"]);
        fs::set_permissions(repository.join(".git"), fs::Permissions::from_mode(0o700)).unwrap();
        run(&["config", "user.name", "Fixture"]);
        run(&["config", "user.email", "fixture@example.invalid"]);
        fs::write(repository.join("README"), b"fixture\n").unwrap();
        fs::write(
            repository.join(".gitattributes"),
            b"*.payload filter=MiXeD\n",
        )
        .unwrap();
        fs::write(repository.join("fixture.payload"), b"payload\n").unwrap();
        run(&["add", "README", ".gitattributes", "fixture.payload"]);
        run(&["commit", "--quiet", "-m", "fixture"]);
        let hook_marker = directory.path().join("hook-ran");
        let hook = repository.join(".git/hooks/post-checkout");
        fs::write(
            &hook,
            format!("#!/bin/sh\nprintf ran > '{}'\n", hook_marker.display()),
        )
        .unwrap();
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();
        let filter_marker = directory.path().join("filter-ran");
        let filter = directory.path().join("filter.sh");
        fs::write(
            &filter,
            format!(
                "#!/bin/sh\nprintf ran > '{}'\nexit 1\n",
                filter_marker.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&filter, fs::Permissions::from_mode(0o700)).unwrap();
        run(&["config", "filter.MiXeD.smudge", filter.to_str().unwrap()]);
        run(&["config", "filter.MiXeD.required", "true"]);
        let base = git_text(&repository, &["rev-parse", "HEAD"]).unwrap();
        let target = worktrees.join("issue-166");
        let registry_path = state.join(LIFECYCLE_REGISTRY_FILE_NAME);
        let journal_path = state.join(LIFECYCLE_JOURNAL_FILE_NAME);
        write_registry(
            &registry_path,
            &serde_json::json!({
                "version": 1, "generation": "generation-git",
                "host_setups": [{
                    "selector": "host-local", "host_setup": "host-one",
                    "project": "project-test",
                    "setup_kind": "local", "canonical_root": repository
                }],
                "checkouts": [{
                    "selector": "checkout-git", "checkout": null,
                    "project": "project-test",
                    "host_setup": "host-one", "repository_authority": "github",
                    "repository": "owner/repository", "checkout_kind": "git_worktree",
                    "canonical_root": target, "repository_root": repository,
                    "base_commit": base, "branch_ref": "refs/heads/work/issue-166"
                }],
                "workspaces": [], "task_selectors": []
            }),
        );
        let uid = nix::unistd::geteuid().as_raw();
        let mut adapter =
            ProductionLifecycleEffectAdapter::open(&registry_path, &journal_path, uid)
                .unwrap()
                .unwrap();
        let project = ExpectedWorkContext::new(
            WorkContextIdentity::Project(ProjectId::new("project-test").unwrap()),
            Revision::FIRST,
        );
        let host = ExpectedWorkContext::new(
            WorkContextIdentity::HostSetup(HostSetupId::new("host-one").unwrap()),
            Revision::FIRST,
        );
        let repository_identity = WorkContextIdentity::Repository(
            V1RepositoryRef::new(ResourceCoordinate::new(
                ResourceAuthority::GitHub,
                ResourceKind::Repository,
                ResourceId::new("owner/repository").unwrap(),
            ))
            .unwrap(),
        );
        let checkout = WorkContextMutationIntent::CreateCheckout(
            CreateCheckoutIntent::new(
                WorkContextLabel::new("Issue worktree").unwrap(),
                project,
                host,
                ExpectedWorkContext::new(repository_identity, Revision::FIRST),
                CheckoutKind::GitWorktree,
                WorkContextRegistrySelector::new("checkout-git").unwrap(),
            )
            .unwrap(),
        );
        let resulting = WorkContextIdentity::Checkout(
            automonique_protocol::platform_v2::CheckoutId::new("checkout-created").unwrap(),
        );
        run(&["branch", "work/issue-166", &base]);
        assert_eq!(
            adapter.execute(
                &checkout,
                &resulting,
                &IdempotencyKey::new("git-effect-conflict").unwrap(),
            ),
            PlatformV2EffectExecution::NotStarted
        );
        assert!(adapter.journal.entries.is_empty());
        run(&["branch", "-D", "work/issue-166"]);

        let partial_key = IdempotencyKey::new("git-effect-partial").unwrap();
        adapter
            .insert_prepared(
                format!("lifecycle:{}", partial_key.as_str()),
                lifecycle_digest(&checkout, &resulting),
                checkout.kind(),
            )
            .unwrap();
        run(&["branch", "work/issue-166", &base]);
        drop(adapter);
        let mut adapter =
            ProductionLifecycleEffectAdapter::open(&registry_path, &journal_path, uid)
                .unwrap()
                .unwrap();
        assert!(matches!(
            adapter.reconcile(&checkout, &resulting, &partial_key),
            PlatformV2EffectReconciliation::Unknown(_)
        ));
        run(&["branch", "-D", "work/issue-166"]);

        let key = IdempotencyKey::new("git-effect-one").unwrap();
        assert_eq!(
            adapter.execute(&checkout, &resulting, &key),
            PlatformV2EffectExecution::Completed
        );
        assert_eq!(
            fs::symlink_metadata(target.join(".git")).unwrap().mode() & 0o777,
            0o600
        );
        assert_eq!(git_text(&target, &["rev-parse", "HEAD"]).unwrap(), base);
        assert_eq!(
            git_text(&target, &["symbolic-ref", "-q", "HEAD"]).unwrap(),
            "refs/heads/work/issue-166"
        );
        assert!(!hook_marker.exists(), "repository hook was executed");
        assert!(!filter_marker.exists(), "repository filter was executed");
        assert_eq!(
            adapter.execute(&checkout, &resulting, &key),
            PlatformV2EffectExecution::Completed
        );

        let independent = directory.path().join("independent");
        let forged = worktrees.join("forged");
        let output = Command::new("git")
            .args(["clone", "--quiet", "--no-hardlinks"])
            .arg(&repository)
            .arg(&independent)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        fs::set_permissions(&independent, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(independent.join(".git"), fs::Permissions::from_mode(0o700)).unwrap();
        let output = Command::new("git")
            .arg("-C")
            .arg(&independent)
            .args(["worktree", "add", "--quiet", "-b", "work/forged"])
            .arg(&forged)
            .arg(&base)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        fs::set_permissions(&forged, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(forged.join(".git"), fs::Permissions::from_mode(0o600)).unwrap();
        let mut forged_binding = adapter.checkout("checkout-git").unwrap().clone();
        forged_binding.canonical_root = forged;
        forged_binding.branch_ref = Some("refs/heads/work/forged".to_owned());
        assert_eq!(
            validate_checkout_materialized(&forged_binding, uid),
            Err("platform_v2_lifecycle_checkout_mismatch")
        );

        fs::set_permissions(target.join(".git"), fs::Permissions::from_mode(0o660)).unwrap();
        assert_eq!(
            validate_checkout_materialized(adapter.checkout("checkout-git").unwrap(), uid),
            Err("platform_v2_lifecycle_checkout_mismatch")
        );
        fs::set_permissions(target.join(".git"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(repository.join(".git"), fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(
            validate_repository_root(&repository, uid),
            Err("platform_v2_lifecycle_repository_mismatch")
        );
        fs::set_permissions(repository.join(".git"), fs::Permissions::from_mode(0o700)).unwrap();

        let included = directory.path().join("included-git-config");
        fs::write(&included, "[filter \"included\"]\n\tprocess = /bin/false\n").unwrap();
        run(&["config", "include.path", included.to_str().unwrap()]);
        assert_eq!(
            git_text(&repository, &["rev-parse", "HEAD"]),
            Err("platform_v2_lifecycle_git_include_unsafe")
        );
    }
}
