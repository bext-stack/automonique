// SPDX-License-Identifier: Elastic-2.0

//! Private operator bootstrap registry for authoritative attention sources.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use automonique_protocol::digest::{Sha256, Sha256Digest};
use automonique_protocol::platform_v2_attention::{AttentionReadRequest, AttentionSourceSnapshot};
use automonique_protocol::platform_v2_attention_api::{
    decode_attention_source_snapshot, encode_attention_source_snapshot,
};
use automonique_store::attention_store::AttentionStore;
use nix::libc;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

pub const ATTENTION_REGISTRY_FILE_NAME: &str = "platform-v2-attention-registry.json";
pub const ATTENTION_STORE_FILE_NAME: &str = "platform-v2-attention.sqlite3";

const MAX_REGISTRY_BYTES: u64 = 2 * 1024 * 1024;
const MAX_SNAPSHOTS: usize = 4096;
const MAX_GENERATION_BYTES: usize = 256;

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

struct PrivateSnapshot {
    bytes: Vec<u8>,
    generation: FileGeneration,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryDocument {
    version: u8,
    generation: String,
    snapshots: Vec<StrictJson>,
}

#[derive(Debug)]
struct StrictJson(serde_json::Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictJson;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON without duplicate object fields")
            }
            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictJson(serde_json::Value::Bool(value)))
            }
            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictJson(serde_json::Value::Number(value.into())))
            }
            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictJson(serde_json::Value::Number(value.into())))
            }
            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(serde_json::Value::Number)
                    .map(StrictJson)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictJson(serde_json::Value::String(value.to_owned())))
            }
            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictJson(serde_json::Value::String(value)))
            }
            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(StrictJson(serde_json::Value::Null))
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictJson(serde_json::Value::Null))
            }
            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictJson>()? {
                    values.push(value.0);
                }
                Ok(StrictJson(serde_json::Value::Array(values)))
            }
            fn visit_map<A>(self, mut fields: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = serde_json::Map::new();
                while let Some((key, value)) = fields.next_entry::<String, StrictJson>()? {
                    if values.insert(key, value.0).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON object field"));
                    }
                }
                Ok(StrictJson(serde_json::Value::Object(values)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

#[derive(Default)]
pub(crate) struct AttentionRegistry {
    installed: Option<InstalledRegistry>,
}

struct InstalledRegistry {
    path: PathBuf,
    expected_uid: u32,
    generation: FileGeneration,
    snapshots: Vec<AttentionSourceSnapshot>,
}

impl std::fmt::Debug for AttentionRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (state, snapshot_count) = self.installed.as_ref().map_or(("unavailable", 0), |value| {
            ("installed", value.snapshots.len())
        });
        formatter
            .debug_struct("AttentionRegistry")
            .field("state", &state)
            .field("snapshot_count", &snapshot_count)
            .finish()
    }
}

impl std::fmt::Debug for InstalledRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstalledRegistry")
            .field("state", &"installed")
            .field("snapshot_count", &self.snapshots.len())
            .finish()
    }
}

impl AttentionRegistry {
    pub(crate) fn open(
        path: &Path,
        expected_uid: u32,
        store: &mut AttentionStore,
        mut source_reserved: impl FnMut(&AttentionSourceSnapshot) -> bool,
    ) -> Result<Self, &'static str> {
        let Some(private) = read_private_file(path, expected_uid)? else {
            return Ok(Self::default());
        };
        let document: RegistryDocument = serde_json::from_slice(&private.bytes)
            .map_err(|_| "platform_v2_attention_registry_invalid")?;
        if document.version != 1
            || !safe_generation(&document.generation)
            || document.snapshots.len() > MAX_SNAPSHOTS
        {
            return Err("platform_v2_attention_registry_invalid");
        }
        let mut keys = BTreeSet::new();
        let mut snapshots = Vec::with_capacity(document.snapshots.len());
        for raw in document.snapshots {
            let bytes =
                serde_json::to_vec(&raw.0).map_err(|_| "platform_v2_attention_registry_invalid")?;
            let snapshot = decode_attention_source_snapshot(&bytes)
                .map_err(|_| "platform_v2_attention_registry_invalid")?;
            let key = (
                snapshot.source().kind().as_str().to_owned(),
                snapshot.source().id().as_str().to_owned(),
                snapshot.project().as_str().to_owned(),
                snapshot.user_workspace().as_str().to_owned(),
            );
            if !keys.insert(key) {
                return Err("platform_v2_attention_registry_invalid");
            }
            if source_reserved(&snapshot) {
                return Err("platform_v2_attention_registry_runtime_collision");
            }
            snapshots.push(snapshot);
        }
        store
            .put_snapshots(&snapshots)
            .map_err(|_| "platform_v2_attention_store_refused")?;
        Ok(Self {
            installed: Some(InstalledRegistry {
                path: path.to_path_buf(),
                expected_uid,
                generation: private.generation,
                snapshots,
            }),
        })
    }

    pub(crate) fn snapshot(
        &self,
        request: &AttentionReadRequest,
        store: &AttentionStore,
    ) -> Result<AttentionSourceSnapshot, &'static str> {
        let installed = self
            .installed
            .as_ref()
            .ok_or("platform_v2_attention_registry_unavailable")?;
        installed.verify_generation()?;
        let registered = installed
            .snapshots
            .iter()
            .find(|snapshot| {
                snapshot.source() == request.source()
                    && snapshot.project() == request.project()
                    && snapshot.user_workspace() == request.user_workspace()
            })
            .ok_or("platform_v2_attention_not_found")?;
        let stored = store
            .snapshot(
                request.source(),
                request.project(),
                request.user_workspace(),
            )
            .map_err(|_| "platform_v2_attention_store_refused")?
            .ok_or("platform_v2_attention_store_refused")?;
        let stored_document = encode_attention_source_snapshot(&stored)
            .map_err(|_| "platform_v2_attention_store_refused")?;
        let registered_document = encode_attention_source_snapshot(registered)
            .map_err(|_| "platform_v2_attention_registry_invalid")?;
        if stored_document != registered_document {
            return Err("platform_v2_attention_store_refused");
        }
        Ok(stored)
    }

    pub(crate) fn contains(&self, request: &AttentionReadRequest) -> bool {
        self.installed.as_ref().is_some_and(|installed| {
            installed.snapshots.iter().any(|snapshot| {
                snapshot.source() == request.source()
                    && snapshot.project() == request.project()
                    && snapshot.user_workspace() == request.user_workspace()
            })
        })
    }
}

impl InstalledRegistry {
    fn verify_generation(&self) -> Result<(), &'static str> {
        let current = read_private_file(&self.path, self.expected_uid)?
            .ok_or("platform_v2_attention_registry_changed")?;
        if current.generation != self.generation {
            return Err("platform_v2_attention_registry_changed");
        }
        Ok(())
    }
}

fn read_private_file(
    path: &Path,
    expected_uid: u32,
) -> Result<Option<PrivateSnapshot>, &'static str> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("platform_v2_attention_registry_insecure"),
    };
    let before = file
        .metadata()
        .map_err(|_| "platform_v2_attention_registry_insecure")?;
    validate_metadata(&before, expected_uid)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_REGISTRY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "platform_v2_attention_registry_insecure")?;
    if bytes.len() as u64 > MAX_REGISTRY_BYTES {
        return Err("platform_v2_attention_registry_invalid");
    }
    let after = file
        .metadata()
        .map_err(|_| "platform_v2_attention_registry_insecure")?;
    validate_metadata(&after, expected_uid)?;
    let before_generation = generation(&before, &bytes);
    let after_generation = generation(&after, &bytes);
    if before_generation != after_generation {
        return Err("platform_v2_attention_registry_changed");
    }
    Ok(Some(PrivateSnapshot {
        bytes,
        generation: after_generation,
    }))
}

fn validate_metadata(metadata: &fs::Metadata, expected_uid: u32) -> Result<(), &'static str> {
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.len() > MAX_REGISTRY_BYTES
    {
        return Err("platform_v2_attention_registry_insecure");
    }
    Ok(())
}

fn generation(metadata: &fs::Metadata, bytes: &[u8]) -> FileGeneration {
    FileGeneration {
        device: metadata.dev(),
        inode: metadata.ino(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        length: metadata.len(),
        digest: Sha256::digest(bytes),
    }
}

fn safe_generation(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_GENERATION_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
        && !value.starts_with('-')
        && !value.contains("..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use automonique_protocol::platform_v2_attention::AttentionReadRequest;
    use std::os::unix::fs::PermissionsExt;

    fn uid() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    fn fixture() -> serde_json::Value {
        serde_json::from_slice(include_bytes!(
            "../../automonique-protocol/fixtures/platform-v2-attention-v1.json"
        ))
        .unwrap()
    }

    fn private_directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn write_registry(path: &Path, snapshots: Vec<serde_json::Value>, generation: &str) {
        let document = serde_json::json!({
            "version": 1,
            "generation": generation,
            "snapshots": snapshots,
        });
        fs::write(path, serde_json::to_vec(&document).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn store(directory: &Path) -> AttentionStore {
        AttentionStore::open_scoped(directory.join("attention.sqlite3"), "tenant").unwrap()
    }

    #[test]
    fn absent_registry_refuses_instead_of_projecting_empty_attention() {
        let directory = private_directory();
        let mut store = store(directory.path());
        let registry = AttentionRegistry::open(
            &directory.path().join("absent.json"),
            uid(),
            &mut store,
            |_| false,
        )
        .unwrap();
        let snapshot = decode_attention_source_snapshot(include_bytes!(
            "../../automonique-protocol/fixtures/platform-v2-attention-v1.json"
        ))
        .unwrap();
        let request = AttentionReadRequest::new(
            snapshot.source().clone(),
            snapshot.project().clone(),
            snapshot.user_workspace().clone(),
        );
        assert_eq!(
            registry.snapshot(&request, &store),
            Err("platform_v2_attention_registry_unavailable")
        );
    }

    #[test]
    fn registry_debug_is_count_only_and_never_projects_private_coordinates() {
        let directory = private_directory();
        let path = directory.path().join("attention-secret-registry.json");
        let mut snapshot = fixture();
        snapshot["source"]["id"] = serde_json::json!("source-secret-value");
        snapshot["project"] = serde_json::json!("project-secret-value");
        snapshot["user_workspace"] = serde_json::json!("workspace-secret-value");
        snapshot["items"][0]["id"] = serde_json::json!("item-secret-value");
        snapshot["items"][0]["nested_agent_path"] = serde_json::json!(["agent-secret-value"]);
        snapshot["items"][0]["platform_session"]["id"] = serde_json::json!("session-secret-value");
        write_registry(&path, vec![snapshot], "attention-secret-generation");
        let mut store = store(directory.path());
        let registry = AttentionRegistry::open(&path, uid(), &mut store, |_| false).unwrap();
        assert_eq!(
            format!("{registry:?}"),
            "AttentionRegistry { state: \"installed\", snapshot_count: 1 }"
        );
        assert_eq!(
            format!("{:?}", registry.installed.as_ref().unwrap()),
            "InstalledRegistry { state: \"installed\", snapshot_count: 1 }"
        );
        for forbidden in [
            "attention-secret-registry",
            "attention-secret-generation",
            "source-secret-value",
            "project-secret-value",
            "workspace-secret-value",
            "item-secret-value",
            "agent-secret-value",
            "session-secret-value",
        ] {
            assert!(!format!("{registry:?}").contains(forbidden));
            assert!(!format!("{:?}", registry.installed.as_ref().unwrap()).contains(forbidden));
        }

        assert_eq!(
            format!("{:?}", AttentionRegistry::default()),
            "AttentionRegistry { state: \"unavailable\", snapshot_count: 0 }"
        );
    }

    #[test]
    fn installed_registry_persists_and_returns_only_the_exact_tuple() {
        let directory = private_directory();
        let path = directory.path().join("registry.json");
        write_registry(&path, vec![fixture()], "generation-1");
        let mut store = store(directory.path());
        let registry = AttentionRegistry::open(&path, uid(), &mut store, |_| false).unwrap();
        let expected = decode_attention_source_snapshot(include_bytes!(
            "../../automonique-protocol/fixtures/platform-v2-attention-v1.json"
        ))
        .unwrap();
        let request = AttentionReadRequest::new(
            expected.source().clone(),
            expected.project().clone(),
            expected.user_workspace().clone(),
        );
        assert_eq!(registry.snapshot(&request, &store), Ok(expected.clone()));
        let foreign = AttentionReadRequest::new(
            expected.source().clone(),
            automonique_protocol::platform_v2::ProjectId::new("foreign").unwrap(),
            expected.user_workspace().clone(),
        );
        assert_eq!(
            registry.snapshot(&foreign, &store),
            Err("platform_v2_attention_not_found")
        );
        let foreign_source = AttentionReadRequest::new(
            automonique_protocol::platform_v2_attention::AttentionSource::new(
                expected.source().kind(),
                automonique_protocol::platform_v2_attention::AttentionSourceId::new("foreign")
                    .unwrap(),
            ),
            expected.project().clone(),
            expected.user_workspace().clone(),
        );
        assert_eq!(
            registry.snapshot(&foreign_source, &store),
            Err("platform_v2_attention_not_found")
        );
        let foreign_workspace = AttentionReadRequest::new(
            expected.source().clone(),
            expected.project().clone(),
            automonique_protocol::platform_v2::UserWorkspaceId::new("foreign").unwrap(),
        );
        assert_eq!(
            registry.snapshot(&foreign_workspace, &store),
            Err("platform_v2_attention_not_found")
        );
    }

    #[test]
    fn a_stale_registry_generation_cannot_replace_persisted_source_authority() {
        let directory = private_directory();
        let path = directory.path().join("registry.json");
        write_registry(&path, vec![fixture()], "generation-7");
        let mut store = store(directory.path());
        AttentionRegistry::open(&path, uid(), &mut store, |_| false).unwrap();

        let mut stale = fixture();
        stale["revision"] = serde_json::json!(6);
        stale["previous_revision"] = serde_json::json!(5);
        stale["observed_at_ms"] = serde_json::json!(1_900);
        stale["items"][0]["observed_at_ms"] = serde_json::json!(1_890);
        write_registry(&path, vec![stale], "generation-6");
        assert_eq!(
            AttentionRegistry::open(&path, uid(), &mut store, |_| false).unwrap_err(),
            "platform_v2_attention_store_refused"
        );
    }

    #[test]
    fn runtime_owned_collision_is_rejected_before_import_and_again_after_restart() {
        let directory = private_directory();
        let path = directory.path().join("registry.json");
        let original_raw = fixture();
        write_registry(&path, vec![original_raw.clone()], "collision-generation");
        let original = decode_attention_source_snapshot(
            &serde_json::to_vec(&original_raw).expect("snapshot JSON"),
        )
        .unwrap();
        let mut successor_raw = original_raw;
        successor_raw["revision"] = serde_json::json!(8);
        successor_raw["previous_revision"] = serde_json::json!(7);
        successor_raw["observed_at_ms"] = serde_json::json!(2_100);
        successor_raw["items"][0]["revision"] = serde_json::json!(8);
        successor_raw["items"][0]["observed_at_ms"] = serde_json::json!(2_090);
        let successor = decode_attention_source_snapshot(
            &serde_json::to_vec(&successor_raw).expect("snapshot JSON"),
        )
        .unwrap();
        let mut attention = store(directory.path());
        attention.put_snapshot(&original).unwrap();
        attention.put_snapshot(&successor).unwrap();

        for _restart in 0..2 {
            assert_eq!(
                AttentionRegistry::open(&path, uid(), &mut attention, |_| true).unwrap_err(),
                "platform_v2_attention_registry_runtime_collision"
            );
            assert_eq!(
                attention
                    .snapshot(
                        successor.source(),
                        successor.project(),
                        successor.user_workspace(),
                    )
                    .unwrap(),
                Some(successor.clone()),
                "collision refusal must not re-import or shadow runtime custody"
            );
            drop(attention);
            attention = store(directory.path());
        }
    }

    #[test]
    fn a_later_tuple_conflict_rolls_back_the_complete_registry_import() {
        let directory = private_directory();
        let path = directory.path().join("registry.json");
        let mut current_a = fixture();
        current_a["project"] = serde_json::json!("project-a");
        let mut current_b = fixture();
        current_b["project"] = serde_json::json!("project-b");
        current_b["source"]["id"] = serde_json::json!("provider-feed-2");
        write_registry(
            &path,
            vec![current_a.clone(), current_b.clone()],
            "generation-1",
        );
        let mut store = store(directory.path());
        AttentionRegistry::open(&path, uid(), &mut store, |_| false).unwrap();

        let mut successor_a = current_a.clone();
        successor_a["revision"] = serde_json::json!(8);
        successor_a["previous_revision"] = serde_json::json!(7);
        successor_a["observed_at_ms"] = serde_json::json!(2_100);
        successor_a["items"][0]["revision"] = serde_json::json!(8);
        successor_a["items"][0]["observed_at_ms"] = serde_json::json!(2_090);
        let mut wrong_predecessor_b = current_b.clone();
        wrong_predecessor_b["revision"] = serde_json::json!(9);
        wrong_predecessor_b["previous_revision"] = serde_json::json!(8);
        wrong_predecessor_b["observed_at_ms"] = serde_json::json!(2_200);
        wrong_predecessor_b["items"][0]["revision"] = serde_json::json!(9);
        wrong_predecessor_b["items"][0]["observed_at_ms"] = serde_json::json!(2_190);
        write_registry(
            &path,
            vec![successor_a, wrong_predecessor_b],
            "generation-2",
        );
        assert_eq!(
            AttentionRegistry::open(&path, uid(), &mut store, |_| false).unwrap_err(),
            "platform_v2_attention_store_refused"
        );

        for raw in [current_a, current_b] {
            let expected =
                decode_attention_source_snapshot(&serde_json::to_vec(&raw).expect("snapshot JSON"))
                    .unwrap();
            assert_eq!(
                store
                    .snapshot(
                        expected.source(),
                        expected.project(),
                        expected.user_workspace(),
                    )
                    .unwrap(),
                Some(expected)
            );
        }
    }

    #[test]
    fn registry_drift_duplicates_and_insecure_permissions_fail_closed() {
        let directory = private_directory();
        let path = directory.path().join("registry.json");
        write_registry(&path, vec![fixture()], "generation-1");
        let mut store = store(directory.path());
        let registry = AttentionRegistry::open(&path, uid(), &mut store, |_| false).unwrap();
        let expected = decode_attention_source_snapshot(include_bytes!(
            "../../automonique-protocol/fixtures/platform-v2-attention-v1.json"
        ))
        .unwrap();
        let request = AttentionReadRequest::new(
            expected.source().clone(),
            expected.project().clone(),
            expected.user_workspace().clone(),
        );
        write_registry(&path, vec![fixture()], "generation-2");
        assert_eq!(
            registry.snapshot(&request, &store),
            Err("platform_v2_attention_registry_changed")
        );

        write_registry(&path, vec![fixture(), fixture()], "generation-3");
        assert!(matches!(
            AttentionRegistry::open(&path, uid(), &mut store, |_| false),
            Err("platform_v2_attention_registry_invalid")
        ));
        write_registry(&path, vec![fixture()], "generation-4");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            AttentionRegistry::open(&path, uid(), &mut store, |_| false),
            Err("platform_v2_attention_registry_insecure")
        ));

        let duplicated = std::str::from_utf8(include_bytes!(
            "../../automonique-protocol/fixtures/platform-v2-attention-v1.json"
        ))
        .unwrap()
        .replacen(
            "\"schema\":",
            "\"schema\":\"automonique.platform/attention/v1\",\"schema\":",
            1,
        );
        fs::write(
            &path,
            format!(
                "{{\"generation\":\"generation-5\",\"snapshots\":[{duplicated}],\"version\":1}}"
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            AttentionRegistry::open(&path, uid(), &mut store, |_| false),
            Err("platform_v2_attention_registry_invalid")
        ));
    }
}
