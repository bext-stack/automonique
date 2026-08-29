// SPDX-License-Identifier: Elastic-2.0

//! Server-owned credentials and authorization for untrusted mobile clients.
//!
//! Secrets are random bearer values. Only domain-separated SHA-256 digests are
//! retained. An access credential resolves to the complete actor authorization
//! descriptor before a Platform request is admitted; request method presence is
//! never treated as authority.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::time::Duration;

use automonique_protocol::codegen::supported_mobile_protocol_versions;
use automonique_protocol::platform::{
    PlatformRequest, ResourceAuthority, ResourceKind, SessionCommandState, SessionList,
};
use automonique_protocol::platform_v2::{ProjectId, WorkContextIdentity};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Deserializer, Serialize, de};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub const MOBILE_AUTH_PROTOCOL: &str = "automonique.mobile-auth";
pub const MOBILE_AUTH_SCHEMA_V1: &str = "automonique.mobile-auth/v1";
pub const MOBILE_AUTH_MEDIA_TYPE: &str = "application/vnd.automonique.mobile-auth.v1+json";
pub const MOBILE_PLATFORM_V2_AUTH_SCHEMA: &str = "automonique.mobile-platform-v2-authorization/v1";
pub const MOBILE_PLATFORM_V2_AUTH_MEDIA_TYPE: &str =
    "application/vnd.automonique.mobile-platform-v2-authorization.v1+json";
pub const MAX_MOBILE_ACTIONS: usize = 4;
pub const MAX_MOBILE_PLATFORM_V2_ACTIONS: usize = MobilePlatformV2Action::ALL.len();
pub const MAX_MOBILE_V2_PROJECT_ROOTS: usize = 32;
const MAX_MOBILE_V2_RECEIPT_CUSTODY: usize = 128;
pub(crate) const MOBILE_V2_DISPATCH_LEASE_MILLIS: i64 = 10_000;
pub const MAX_MOBILE_SESSIONS: usize = 100;
pub const MAX_PAGE_EVENTS: u16 = 512;
pub const MAX_FOLLOW_UP_BYTES: u32 = 65_536;
pub const ACCESS_TTL_MILLIS: i64 = 15 * 60 * 1_000;
pub const REFRESH_TTL_MILLIS: i64 = 30 * 24 * 60 * 60 * 1_000;
pub const REVOKED_FAMILY_RETENTION_MILLIS: i64 = 30 * 24 * 60 * 60 * 1_000;
pub const MAX_CREDENTIAL_REVISIONS: u64 = 4_096;
pub const PAIRING_TTL_MILLIS: i64 = 5 * 60 * 1_000;
pub const PAIRING_RETENTION_MILLIS: i64 = 24 * 60 * 60 * 1_000;
pub const MAX_OUTSTANDING_PAIRINGS: u64 = 32;
pub const MAX_CREDENTIAL_PAGE_SIZE: u16 = 100;

const TOKEN_BYTES: usize = 32;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_SAFE_JSON_INTEGER: i64 = 9_007_199_254_740_991;
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS mobile_server_identity (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  origin TEXT NOT NULL UNIQUE CHECK(length(origin) BETWEEN 9 AND 2048),
  server_identity TEXT NOT NULL UNIQUE CHECK(length(server_identity) = 71)
) STRICT;
CREATE TABLE IF NOT EXISTS mobile_credentials (
  credential_id TEXT PRIMARY KEY CHECK(length(credential_id) = 46),
  access_sha256 BLOB NOT NULL UNIQUE CHECK(length(access_sha256) = 32),
  refresh_sha256 BLOB NOT NULL UNIQUE CHECK(length(refresh_sha256) = 32),
  actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 256),
  server_identity TEXT NOT NULL CHECK(length(server_identity) = 71),
  credential_revision INTEGER NOT NULL
    CHECK(credential_revision BETWEEN 1 AND 4096),
  authorization_revision INTEGER NOT NULL
    CHECK(authorization_revision BETWEEN 1 AND 9007199254740991),
  issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms BETWEEN 0 AND 9007199254740991),
  access_expires_at_ms INTEGER NOT NULL
    CHECK(access_expires_at_ms BETWEEN 0 AND 9007199254740991),
  refresh_expires_at_ms INTEGER NOT NULL
    CHECK(refresh_expires_at_ms BETWEEN 0 AND 9007199254740991),
  revoked_at_ms INTEGER CHECK(revoked_at_ms BETWEEN 0 AND 9007199254740991),
  actions_json TEXT NOT NULL CHECK(length(actions_json) BETWEEN 1 AND 128),
  sessions_json TEXT NOT NULL CHECK(length(sessions_json) BETWEEN 2 AND 26000),
  max_page_events INTEGER NOT NULL CHECK(max_page_events BETWEEN 1 AND 512),
  max_follow_up_bytes INTEGER NOT NULL CHECK(max_follow_up_bytes BETWEEN 1 AND 65536)
) STRICT;
CREATE TABLE IF NOT EXISTS mobile_refresh_history (
  refresh_sha256 BLOB PRIMARY KEY CHECK(length(refresh_sha256) = 32),
  credential_id TEXT NOT NULL CHECK(length(credential_id) = 46),
  credential_revision INTEGER NOT NULL CHECK(credential_revision BETWEEN 1 AND 4096),
  rotated_at_ms INTEGER NOT NULL CHECK(rotated_at_ms BETWEEN 0 AND 9007199254740991),
  UNIQUE(credential_id, credential_revision),
  FOREIGN KEY(credential_id) REFERENCES mobile_credentials(credential_id) ON DELETE CASCADE
) STRICT;
CREATE TABLE IF NOT EXISTS mobile_pairings (
  pairing_id TEXT PRIMARY KEY CHECK(length(pairing_id) = 46),
  pairing_sha256 BLOB NOT NULL UNIQUE CHECK(length(pairing_sha256) = 32),
  actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 256),
  server_identity TEXT NOT NULL CHECK(length(server_identity) = 71),
  created_at_ms INTEGER NOT NULL CHECK(created_at_ms BETWEEN 0 AND 9007199254740991),
  expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms BETWEEN 0 AND 9007199254740991),
  consumed_at_ms INTEGER CHECK(consumed_at_ms BETWEEN 0 AND 9007199254740991),
  actions_json TEXT NOT NULL CHECK(length(actions_json) BETWEEN 1 AND 128),
  sessions_json TEXT NOT NULL CHECK(length(sessions_json) BETWEEN 2 AND 26000),
  max_page_events INTEGER NOT NULL CHECK(max_page_events BETWEEN 1 AND 512),
  max_follow_up_bytes INTEGER NOT NULL CHECK(max_follow_up_bytes BETWEEN 1 AND 65536)
) STRICT;
CREATE TABLE IF NOT EXISTS mobile_platform_v2_authorizations (
  credential_id TEXT PRIMARY KEY CHECK(length(credential_id) = 46),
  credential_revision INTEGER NOT NULL
    CHECK(credential_revision BETWEEN 1 AND 4096),
  authorization_revision INTEGER NOT NULL
    CHECK(authorization_revision BETWEEN 1 AND 9007199254740991),
  principal_generation INTEGER NOT NULL
    CHECK(principal_generation BETWEEN 1 AND 9007199254740991),
  delegation_id TEXT NOT NULL UNIQUE CHECK(length(delegation_id) = 46),
  tenant_id TEXT NOT NULL CHECK(length(tenant_id) BETWEEN 1 AND 256),
  actor_id TEXT NOT NULL CHECK(length(actor_id) BETWEEN 1 AND 256),
  issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms BETWEEN 0 AND 9007199254740991),
  expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms BETWEEN 0 AND 9007199254740991),
  revoked_at_ms INTEGER CHECK(revoked_at_ms BETWEEN 0 AND 9007199254740991),
  project_roots_json TEXT NOT NULL CHECK(length(project_roots_json) BETWEEN 3 AND 8192),
  actions_json TEXT NOT NULL CHECK(length(actions_json) BETWEEN 3 AND 512),
  FOREIGN KEY(credential_id) REFERENCES mobile_credentials(credential_id) ON DELETE CASCADE
) STRICT;
CREATE TABLE IF NOT EXISTS mobile_platform_v2_receipt_custody (
  project_id TEXT NOT NULL CHECK(length(project_id) BETWEEN 1 AND 128),
  idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),
  credential_id TEXT NOT NULL CHECK(length(credential_id) = 46),
  delegation_id TEXT NOT NULL CHECK(length(delegation_id) = 46),
  principal_generation INTEGER NOT NULL
    CHECK(principal_generation BETWEEN 1 AND 9007199254740991),
  created_at_ms INTEGER NOT NULL CHECK(created_at_ms BETWEEN 0 AND 9007199254740991),
  expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms BETWEEN 0 AND 9007199254740991),
  PRIMARY KEY(project_id,idempotency_key),
  FOREIGN KEY(credential_id) REFERENCES mobile_credentials(credential_id) ON DELETE CASCADE
) STRICT;
CREATE TABLE IF NOT EXISTS mobile_platform_v2_receipt_requests (
  project_id TEXT NOT NULL CHECK(length(project_id) BETWEEN 1 AND 128),
  idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),
  request_sha256 BLOB NOT NULL CHECK(length(request_sha256) = 32),
  PRIMARY KEY(project_id,idempotency_key),
  FOREIGN KEY(project_id,idempotency_key)
    REFERENCES mobile_platform_v2_receipt_custody(project_id,idempotency_key)
    ON DELETE CASCADE
) STRICT;
CREATE TABLE IF NOT EXISTS mobile_platform_v2_exact_receipt_custody (
  receipt_family TEXT NOT NULL CHECK(receipt_family IN ('mutation','review')),
  project_id TEXT NOT NULL CHECK(length(project_id) BETWEEN 1 AND 128),
  workspace_kind TEXT NOT NULL CHECK(length(workspace_kind) BETWEEN 0 AND 32),
  workspace_id TEXT NOT NULL CHECK(length(workspace_id) BETWEEN 0 AND 256),
  idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),
  credential_id TEXT NOT NULL CHECK(length(credential_id) = 46),
  delegation_id TEXT NOT NULL CHECK(length(delegation_id) = 46),
  principal_generation INTEGER NOT NULL
    CHECK(principal_generation BETWEEN 1 AND 9007199254740991),
  request_sha256 BLOB NOT NULL CHECK(length(request_sha256) = 32),
  receipt_correlation_digest TEXT CHECK(
    receipt_correlation_digest IS NULL OR
    (length(receipt_correlation_digest) = 64 AND receipt_correlation_digest = lower(receipt_correlation_digest))
  ),
  created_at_ms INTEGER NOT NULL CHECK(created_at_ms BETWEEN 0 AND 9007199254740991),
  expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms BETWEEN 0 AND 9007199254740991),
  CHECK(
    (receipt_family = 'mutation' AND workspace_kind = '' AND workspace_id = '') OR
    (receipt_family = 'review' AND length(workspace_kind) > 0 AND length(workspace_id) > 0)
  ),
  PRIMARY KEY(receipt_family,project_id,workspace_kind,workspace_id,idempotency_key),
  FOREIGN KEY(credential_id) REFERENCES mobile_credentials(credential_id) ON DELETE CASCADE
) STRICT;
CREATE TABLE IF NOT EXISTS mobile_platform_v2_dispatch_leases (
  credential_id TEXT PRIMARY KEY CHECK(length(credential_id) = 46),
  lease_id TEXT NOT NULL UNIQUE CHECK(length(lease_id) = 46),
  delegation_id TEXT NOT NULL CHECK(length(delegation_id) = 46),
  principal_generation INTEGER NOT NULL
    CHECK(principal_generation BETWEEN 1 AND 9007199254740991),
  request_sha256 BLOB NOT NULL CHECK(length(request_sha256) = 32),
  acquired_at_ms INTEGER NOT NULL CHECK(acquired_at_ms BETWEEN 0 AND 9007199254740991),
  expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms BETWEEN 0 AND 9007199254740991),
  FOREIGN KEY(credential_id) REFERENCES mobile_credentials(credential_id) ON DELETE CASCADE
) STRICT;
"#;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileAction {
    Attach,
    FollowUp,
    DecideApproval,
    StopRun,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MobilePlatformV2Action {
    QueryWorkContexts,
    GetLineage,
    PrepareMutation,
    DecideMutation,
    SubmitMutation,
    GetMutationReceipt,
    SubmitWorkspaceIntent,
    GetWorkspaceIntent,
    GetReview,
    GetAttentionSourceSnapshot,
    GetReviewCapabilities,
    ExecuteReviewAction,
    RerunCheck,
    GetReviewReceipt,
    // Three members, not one pull-request member, because they are withheld
    // independently. A merge moves code into a protected branch and can
    // trigger a deploy, so a delegation that may open and update a pull
    // request must still be unable to land it.
    //
    // These are live grants: `authorize_mobile_request` maps each
    // pull-request review action onto its own member here, so a delegation
    // carrying one of them can drive that write from a phone. They are the
    // first delegated authority that writes outside the daemon's trust
    // boundary, and nothing confers them implicitly — `admit_platform_v2_scope`
    // takes exactly the set an operator named, there is no default and no
    // "everything" shorthand, and the broader `ExecuteReviewAction` grant
    // reaches none of the three.
    //
    // Holding one is still not enough to write. The installed GitHub
    // credential must separately carry `pull_request_write`, and a merge
    // needs `pull_request_merge` on top; that fence lives in the daemon and
    // neither side subsumes the other.
    OpenPullRequest,
    UpdatePullRequest,
    MergePullRequest,
}

impl MobilePlatformV2Action {
    pub const ALL: [Self; 17] = [
        Self::QueryWorkContexts,
        Self::GetLineage,
        Self::PrepareMutation,
        Self::DecideMutation,
        Self::SubmitMutation,
        Self::GetMutationReceipt,
        Self::SubmitWorkspaceIntent,
        Self::GetWorkspaceIntent,
        Self::GetReview,
        Self::GetAttentionSourceSnapshot,
        Self::GetReviewCapabilities,
        Self::ExecuteReviewAction,
        Self::RerunCheck,
        Self::GetReviewReceipt,
        Self::OpenPullRequest,
        Self::UpdatePullRequest,
        Self::MergePullRequest,
    ];
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MobilePlatformV2GrantRequest {
    pub credential_id: String,
    pub project_roots: Vec<String>,
    pub actions: Vec<MobilePlatformV2Action>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MobilePlatformV2Authorization {
    pub actions: Vec<MobilePlatformV2Action>,
    pub actor_id: String,
    pub authorization_revision: u64,
    pub credential_id: String,
    pub credential_revision: u64,
    pub delegation_id: String,
    pub expires_at_ms: i64,
    pub issued_at_ms: i64,
    pub principal_generation: u64,
    pub project_roots: Vec<String>,
    pub schema: &'static str,
    pub server_identity: String,
    pub tenant_id: String,
}

impl MobilePlatformV2Authorization {
    pub fn allows(&self, action: MobilePlatformV2Action) -> bool {
        self.actions.binary_search(&action).is_ok()
    }

    pub fn allows_project(&self, project: &ProjectId) -> bool {
        self.project_roots
            .binary_search_by(|candidate| candidate.as_str().cmp(project.as_str()))
            .is_ok()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MobileLimits {
    pub max_follow_up_bytes: u32,
    pub max_page_events: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MobileAuthorization {
    pub actions: Vec<MobileAction>,
    pub actor: String,
    pub authorization_revision: u64,
    pub credential_id: String,
    pub credential_revision: u64,
    pub expires_at_ms: i64,
    pub issued_at_ms: i64,
    pub limits: MobileLimits,
    pub schema: &'static str,
    pub server_identity: String,
    pub session_scope: Vec<String>,
}

impl MobileAuthorization {
    pub fn allows(&self, action: MobileAction) -> bool {
        self.actions.binary_search(&action).is_ok()
    }

    pub fn allows_session(&self, session_id: &str) -> bool {
        self.session_scope
            .binary_search_by(|candidate| candidate.as_str().cmp(session_id))
            .is_ok()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MobileDiscovery {
    pub credential_inventory_endpoint: String,
    pub credential_revoke_endpoint: String,
    pub operator_provision_endpoint: String,
    pub origin: String,
    pub pairing_create_endpoint: String,
    pub pairing_exchange_endpoint: String,
    pub platform_endpoint: String,
    pub protocol: &'static str,
    pub schema: &'static str,
    pub server_identity: String,
    pub supported_versions: Vec<u16>,
}

#[derive(Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MobilePairingOffer {
    pub exchange_endpoint: String,
    pub expires_at_ms: i64,
    pub origin: String,
    pub pairing_id: String,
    pub pairing_token: String,
    pub schema: &'static str,
    pub server_identity: String,
}

impl Drop for MobilePairingOffer {
    fn drop(&mut self) {
        self.pairing_token.zeroize();
    }
}

impl std::fmt::Debug for MobilePairingOffer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MobilePairingOffer")
            .field("exchange_endpoint", &self.exchange_endpoint)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("origin", &self.origin)
            .field("pairing_id", &self.pairing_id)
            .field("pairing_token", &"<redacted>")
            .field("schema", &self.schema)
            .field("server_identity", &self.server_identity)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MobilePairingExchangeRequest {
    pub pairing_id: String,
    pub pairing_token: String,
    pub server_identity: String,
}

impl Drop for MobilePairingExchangeRequest {
    fn drop(&mut self) {
        self.pairing_token.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MobileCredentialInventoryRequest {
    pub cursor: Option<String>,
    pub page_size: u16,
}

impl<'de> Deserialize<'de> for MobileCredentialInventoryRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            cursor: serde_json::Value,
            page_size: u16,
        }
        let wire = Wire::deserialize(deserializer)?;
        let cursor = match wire.cursor {
            serde_json::Value::Null => None,
            serde_json::Value::String(value) => Some(value),
            _ => return Err(de::Error::custom("cursor must be a string or null")),
        };
        Ok(Self {
            cursor,
            page_size: wire.page_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MobileCredentialRevokeRequest {
    pub credential_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MobileCredentialSummary {
    pub authorization: MobileAuthorization,
    pub refresh_expires_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MobileCredentialInventory {
    pub credentials: Vec<MobileCredentialSummary>,
    pub next_cursor: Option<String>,
    pub schema: &'static str,
}

#[derive(Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedMobileCredentials {
    pub access_token: String,
    pub authorization: MobileAuthorization,
    pub refresh_token: String,
}

impl Drop for IssuedMobileCredentials {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

impl std::fmt::Debug for IssuedMobileCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedMobileCredentials")
            .field("access_token", &"<redacted>")
            .field("authorization", &self.authorization)
            .field("refresh_token", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MobileOperatorProvisionRequest {
    pub actions: Vec<MobileAction>,
    pub session_scope: Vec<String>,
    pub limits: MobileLimits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MobileRefreshRequest {
    pub refresh_token: String,
    pub server_identity: String,
}

impl Drop for MobileRefreshRequest {
    fn drop(&mut self) {
        self.refresh_token.zeroize();
    }
}

impl std::fmt::Debug for MobileRefreshRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MobileRefreshRequest")
            .field("refresh_token", &"<redacted>")
            .field("server_identity", &self.server_identity)
            .finish()
    }
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MobileRevocation {
    pub revoked: bool,
    pub schema: &'static str,
}

#[derive(Debug)]
pub enum MobileAuthError {
    InvalidOrigin,
    InvalidRequest,
    InvalidCredential,
    DispatchBusy,
    InvalidPairing,
    PairingLimit,
    Expired,
    Revoked,
    ServerIdentityMismatch,
    InsecurePath,
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
}

impl MobileAuthError {
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InvalidOrigin => "mobile_origin_invalid",
            Self::InvalidRequest => "mobile_request_invalid",
            Self::InvalidCredential => "mobile_credential_invalid",
            Self::DispatchBusy => "mobile_platform_v2_dispatch_busy",
            Self::InvalidPairing => "mobile_pairing_invalid",
            Self::PairingLimit => "mobile_pairing_limit",
            Self::Expired => "mobile_credential_expired",
            Self::Revoked => "mobile_credential_revoked",
            Self::ServerIdentityMismatch => "mobile_server_identity_mismatch",
            Self::InsecurePath => "mobile_credential_store_insecure",
            Self::Io(_) => "mobile_credential_store_io",
            Self::Sqlite(_) => "mobile_credential_store_sqlite",
            Self::Json(_) => "mobile_credential_store_corrupt",
        }
    }
}

impl std::fmt::Display for MobileAuthError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.category())
    }
}

impl std::error::Error for MobileAuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::InvalidOrigin
            | Self::InvalidRequest
            | Self::InvalidCredential
            | Self::DispatchBusy
            | Self::InvalidPairing
            | Self::PairingLimit
            | Self::Expired
            | Self::Revoked
            | Self::ServerIdentityMismatch
            | Self::InsecurePath => None,
        }
    }
}

impl From<std::io::Error> for MobileAuthError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for MobileAuthError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<serde_json::Error> for MobileAuthError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[derive(Debug)]
pub struct MobileCredentialAuthority {
    #[cfg(test)]
    path: PathBuf,
    connection: Connection,
    discovery: MobileDiscovery,
    tenant: String,
    actor: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MobilePlatformV2DispatchLease {
    credential_id: String,
    lease_id: String,
}

pub(crate) enum MobilePlatformV2ReceiptCustody<'coordinate> {
    None,
    BindMutation {
        project: &'coordinate ProjectId,
        idempotency_key: &'coordinate str,
    },
    ReadMutation {
        project: &'coordinate ProjectId,
        idempotency_key: &'coordinate str,
    },
    BindReview {
        project: &'coordinate ProjectId,
        workspace: &'coordinate WorkContextIdentity,
        idempotency_key: &'coordinate str,
        receipt_correlation_digest: Option<&'coordinate str>,
    },
    ReadReview {
        project: &'coordinate ProjectId,
        workspace: &'coordinate WorkContextIdentity,
        idempotency_key: &'coordinate str,
        receipt_correlation_digest: Option<&'coordinate str>,
    },
}

struct ReceiptCustodyCoordinate<'coordinate> {
    receipt_family: &'static str,
    project: &'coordinate ProjectId,
    workspace_kind: &'coordinate str,
    workspace_id: &'coordinate str,
    idempotency_key: &'coordinate str,
}

impl<'coordinate> ReceiptCustodyCoordinate<'coordinate> {
    fn mutation(project: &'coordinate ProjectId, idempotency_key: &'coordinate str) -> Self {
        Self {
            receipt_family: "mutation",
            project,
            workspace_kind: "",
            workspace_id: "",
            idempotency_key,
        }
    }

    fn review(
        project: &'coordinate ProjectId,
        workspace: &'coordinate WorkContextIdentity,
        idempotency_key: &'coordinate str,
    ) -> Self {
        Self {
            receipt_family: "review",
            project,
            workspace_kind: workspace.kind().as_str(),
            workspace_id: workspace.id(),
            idempotency_key,
        }
    }
}

impl MobileCredentialAuthority {
    #[cfg(test)]
    pub fn open(
        path: impl AsRef<Path>,
        canonical_host: &str,
        actor: &str,
    ) -> Result<Self, MobileAuthError> {
        Self::open_scoped(path, canonical_host, actor, actor)
    }

    pub fn open_scoped(
        path: impl AsRef<Path>,
        canonical_host: &str,
        tenant: &str,
        actor: &str,
    ) -> Result<Self, MobileAuthError> {
        validate_identifier(tenant)?;
        validate_identifier(actor)?;
        validate_host(canonical_host)?;
        let path = path.as_ref();
        secure_database_path(path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(path, flags)?;
        connection.busy_timeout(Duration::from_secs(3))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.execute_batch(SCHEMA)?;
        ensure_review_receipt_correlation_column(&connection)?;
        let origin = format!("https://{canonical_host}");
        let server_identity = load_or_create_server_identity(&connection, &origin)?;
        let discovery = MobileDiscovery {
            protocol: MOBILE_AUTH_PROTOCOL,
            schema: MOBILE_AUTH_SCHEMA_V1,
            platform_endpoint: format!("{origin}/api/platform"),
            operator_provision_endpoint: format!("{origin}/api/mobile/operator-provision"),
            pairing_create_endpoint: format!("{origin}/api/mobile/pairings"),
            pairing_exchange_endpoint: format!("{origin}/api/mobile/pairings/exchange"),
            credential_inventory_endpoint: format!("{origin}/api/mobile/credentials/list"),
            credential_revoke_endpoint: format!("{origin}/api/mobile/credentials/revoke"),
            origin,
            server_identity,
            supported_versions: supported_mobile_protocol_versions(),
        };
        Ok(Self {
            #[cfg(test)]
            path: path.to_path_buf(),
            connection,
            discovery,
            tenant: tenant.to_owned(),
            actor: actor.to_owned(),
        })
    }

    pub fn discovery(&self) -> &MobileDiscovery {
        &self.discovery
    }

    pub fn operator_provision(
        &mut self,
        request: MobileOperatorProvisionRequest,
        now_ms: i64,
    ) -> Result<IssuedMobileCredentials, MobileAuthError> {
        validate_time(now_ms)?;
        cleanup_retired_families(&self.connection, now_ms)?;
        let (actions, sessions) = admit_scope(request.actions, request.session_scope)?;
        validate_limits(&request.limits)?;
        issue_credential(
            &self.connection,
            &self.discovery.server_identity,
            &self.actor,
            actions,
            sessions,
            request.limits,
            now_ms,
        )
    }

    pub fn create_pairing(
        &mut self,
        request: MobileOperatorProvisionRequest,
        now_ms: i64,
    ) -> Result<MobilePairingOffer, MobileAuthError> {
        validate_time(now_ms)?;
        let (actions, sessions) = admit_scope(request.actions, request.session_scope)?;
        validate_limits(&request.limits)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        cleanup_pairings(&transaction, now_ms)?;
        let outstanding = transaction.query_row(
            "SELECT COUNT(*) FROM mobile_pairings
             WHERE consumed_at_ms IS NULL AND expires_at_ms > ?1",
            params![now_ms],
            |row| row.get::<_, u64>(0),
        )?;
        if outstanding >= MAX_OUTSTANDING_PAIRINGS {
            return Err(MobileAuthError::PairingLimit);
        }
        let pairing_id = random_token("pi")?;
        let mut pairing_token = random_secret_token("mp")?;
        let pairing_digest = token_digest(
            b"automonique.mobile-pairing/v1\0",
            &self.discovery.server_identity,
            &pairing_token,
        );
        let expires_at_ms = now_ms
            .checked_add(PAIRING_TTL_MILLIS)
            .ok_or(MobileAuthError::InvalidRequest)?;
        validate_time(expires_at_ms)?;
        transaction.execute(
            "INSERT INTO mobile_pairings(
               pairing_id,pairing_sha256,actor,server_identity,created_at_ms,expires_at_ms,
               consumed_at_ms,actions_json,sessions_json,max_page_events,max_follow_up_bytes
             ) VALUES(?1,?2,?3,?4,?5,?6,NULL,?7,?8,?9,?10)",
            params![
                pairing_id,
                pairing_digest.as_slice(),
                self.actor,
                self.discovery.server_identity,
                now_ms,
                expires_at_ms,
                serde_json::to_string(&actions)?,
                serde_json::to_string(&sessions)?,
                request.limits.max_page_events,
                request.limits.max_follow_up_bytes,
            ],
        )?;
        transaction.commit()?;
        Ok(MobilePairingOffer {
            exchange_endpoint: self.discovery.pairing_exchange_endpoint.clone(),
            expires_at_ms,
            origin: self.discovery.origin.clone(),
            pairing_id,
            pairing_token: std::mem::take(&mut *pairing_token),
            schema: MOBILE_AUTH_SCHEMA_V1,
            server_identity: self.discovery.server_identity.clone(),
        })
    }

    pub fn exchange_pairing(
        &mut self,
        request: &mut MobilePairingExchangeRequest,
        now_ms: i64,
    ) -> Result<IssuedMobileCredentials, MobileAuthError> {
        let token = take_secret(&mut request.pairing_token);
        validate_time(now_ms).map_err(|_| MobileAuthError::InvalidPairing)?;
        validate_token(&request.pairing_id, "pi").map_err(|_| MobileAuthError::InvalidPairing)?;
        validate_token(&token, "mp").map_err(|_| MobileAuthError::InvalidPairing)?;
        if request.server_identity != self.discovery.server_identity {
            return Err(MobileAuthError::InvalidPairing);
        }
        let digest = token_digest(
            b"automonique.mobile-pairing/v1\0",
            &self.discovery.server_identity,
            &token,
        );
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = transaction
            .query_row(
                "SELECT actor,actions_json,sessions_json,max_page_events,max_follow_up_bytes
                 FROM mobile_pairings
                 WHERE pairing_id=?1 AND pairing_sha256=?2 AND server_identity=?3
                   AND consumed_at_ms IS NULL AND expires_at_ms > ?4",
                params![
                    request.pairing_id,
                    digest.as_slice(),
                    self.discovery.server_identity,
                    now_ms
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or(MobileAuthError::InvalidPairing)?;
        validate_identifier(&row.0).map_err(|_| MobileAuthError::InvalidPairing)?;
        if row.0 != self.actor {
            return Err(MobileAuthError::InvalidPairing);
        }
        let actions = serde_json::from_str::<Vec<MobileAction>>(&row.1)
            .map_err(|_| MobileAuthError::InvalidPairing)?;
        let sessions = serde_json::from_str::<Vec<String>>(&row.2)
            .map_err(|_| MobileAuthError::InvalidPairing)?;
        let (actions, sessions) =
            admit_scope(actions, sessions).map_err(|_| MobileAuthError::InvalidPairing)?;
        let limits = MobileLimits {
            max_page_events: u16::try_from(row.3).map_err(|_| MobileAuthError::InvalidPairing)?,
            max_follow_up_bytes: u32::try_from(row.4)
                .map_err(|_| MobileAuthError::InvalidPairing)?,
        };
        validate_limits(&limits).map_err(|_| MobileAuthError::InvalidPairing)?;
        let issued = issue_credential(
            &transaction,
            &self.discovery.server_identity,
            &row.0,
            actions,
            sessions,
            limits,
            now_ms,
        )?;
        let consumed = transaction.execute(
            "UPDATE mobile_pairings SET consumed_at_ms=?1
             WHERE pairing_id=?2 AND pairing_sha256=?3 AND consumed_at_ms IS NULL
               AND expires_at_ms > ?1",
            params![now_ms, request.pairing_id, digest.as_slice()],
        )?;
        if consumed != 1 {
            return Err(MobileAuthError::InvalidPairing);
        }
        transaction.commit()?;
        Ok(issued)
    }

    pub fn credential_inventory(
        &mut self,
        request: MobileCredentialInventoryRequest,
        now_ms: i64,
    ) -> Result<MobileCredentialInventory, MobileAuthError> {
        validate_time(now_ms)?;
        cleanup_retired_families(&self.connection, now_ms)?;
        if request.page_size == 0 || request.page_size > MAX_CREDENTIAL_PAGE_SIZE {
            return Err(MobileAuthError::InvalidRequest);
        }
        if let Some(cursor) = request.cursor.as_deref() {
            validate_token(cursor, "mc")?;
        }
        let cursor = request.cursor.unwrap_or_default();
        let query_limit = u64::from(request.page_size) + 1;
        let mut statement = self.connection.prepare(
            "SELECT credential_id,access_sha256 FROM mobile_credentials
             WHERE credential_id > ?1 ORDER BY credential_id ASC LIMIT ?2",
        )?;
        let candidates = statement
            .query_map(params![cursor, query_limit], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = candidates.len() > usize::from(request.page_size);
        let mut credentials = Vec::with_capacity(usize::from(request.page_size));
        for (_, digest) in candidates.into_iter().take(usize::from(request.page_size)) {
            let digest: [u8; 32] = digest
                .try_into()
                .map_err(|_| MobileAuthError::InvalidRequest)?;
            let row = read_by_digest(&self.connection, "access_sha256", &digest)?
                .ok_or(MobileAuthError::InvalidRequest)?;
            credentials.push(MobileCredentialSummary {
                authorization: row.descriptor(),
                refresh_expires_at_ms: row.refresh_expires_at_ms,
                revoked_at_ms: row.revoked_at_ms,
            });
        }
        let next_cursor = has_more
            .then(|| {
                credentials
                    .last()
                    .map(|value| value.authorization.credential_id.clone())
            })
            .flatten();
        Ok(MobileCredentialInventory {
            credentials,
            next_cursor,
            schema: MOBILE_AUTH_SCHEMA_V1,
        })
    }

    pub fn revoke_credential_id(
        &mut self,
        request: MobileCredentialRevokeRequest,
        now_ms: i64,
    ) -> Result<MobileRevocation, MobileAuthError> {
        validate_time(now_ms)?;
        validate_token(&request.credential_id, "mc")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        refuse_active_platform_v2_dispatch_on(&transaction, &request.credential_id, now_ms)?;
        let changed = transaction.execute(
            "UPDATE mobile_credentials SET revoked_at_ms=COALESCE(revoked_at_ms,?1)
             WHERE credential_id=?2",
            params![now_ms, request.credential_id],
        )?;
        if changed != 1 {
            return Err(MobileAuthError::InvalidRequest);
        }
        revoke_platform_v2(&transaction, &request.credential_id, now_ms)?;
        transaction.commit()?;
        Ok(MobileRevocation {
            revoked: true,
            schema: MOBILE_AUTH_SCHEMA_V1,
        })
    }

    pub fn authorize_access(
        &self,
        token: &str,
        expected_server_identity: &str,
        now_ms: i64,
    ) -> Result<MobileAuthorization, MobileAuthError> {
        validate_time(now_ms)?;
        validate_token(token, "ma")?;
        if expected_server_identity != self.discovery.server_identity {
            return Err(MobileAuthError::ServerIdentityMismatch);
        }
        let digest = token_digest(
            b"automonique.mobile-access/v1\0",
            &self.discovery.server_identity,
            token,
        );
        let row = read_by_digest(&self.connection, "access_sha256", &digest)?
            .ok_or(MobileAuthError::InvalidCredential)?;
        row.authorization(&self.discovery.server_identity, now_ms, false)
    }

    pub fn grant_platform_v2(
        &mut self,
        request: MobilePlatformV2GrantRequest,
        now_ms: i64,
    ) -> Result<MobilePlatformV2Authorization, MobileAuthError> {
        validate_time(now_ms)?;
        validate_token(&request.credential_id, "mc")?;
        let (project_roots, actions) =
            admit_platform_v2_scope(request.project_roots, request.actions)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let credential = read_by_id(&transaction, &request.credential_id)?
            .ok_or(MobileAuthError::InvalidCredential)?;
        refuse_active_platform_v2_dispatch_on(&transaction, &request.credential_id, now_ms)?;
        let credential_authorization =
            credential.authorization(&self.discovery.server_identity, now_ms, false)?;
        if credential_authorization.actor != self.actor {
            return Err(MobileAuthError::InvalidCredential);
        }
        let current_generation = transaction
            .query_row(
                "SELECT principal_generation FROM mobile_platform_v2_authorizations
                 WHERE credential_id=?1",
                params![request.credential_id],
                |row| row.get::<_, u64>(0),
            )
            .optional()?
            .unwrap_or(0);
        let principal_generation = current_generation
            .checked_add(1)
            .filter(|value| *value <= MAX_SAFE_JSON_INTEGER as u64)
            .ok_or(MobileAuthError::InvalidRequest)?;
        let authorization_revision = credential.authorization_revision;
        let delegation_id = random_token("md")?;
        transaction.execute(
            "DELETE FROM mobile_platform_v2_receipt_custody WHERE credential_id=?1",
            params![request.credential_id],
        )?;
        transaction.execute(
            "DELETE FROM mobile_platform_v2_exact_receipt_custody WHERE credential_id=?1",
            params![request.credential_id],
        )?;
        transaction.execute(
            "INSERT INTO mobile_platform_v2_authorizations(
               credential_id,credential_revision,authorization_revision,
               principal_generation,delegation_id,tenant_id,actor_id,issued_at_ms,
               expires_at_ms,revoked_at_ms,project_roots_json,actions_json
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,NULL,?10,?11)
             ON CONFLICT(credential_id) DO UPDATE SET
               credential_revision=excluded.credential_revision,
               authorization_revision=excluded.authorization_revision,
               principal_generation=excluded.principal_generation,
               delegation_id=excluded.delegation_id,
               tenant_id=excluded.tenant_id,actor_id=excluded.actor_id,
               issued_at_ms=excluded.issued_at_ms,expires_at_ms=excluded.expires_at_ms,
               revoked_at_ms=NULL,project_roots_json=excluded.project_roots_json,
               actions_json=excluded.actions_json",
            params![
                request.credential_id,
                credential.credential_revision,
                authorization_revision,
                principal_generation,
                delegation_id,
                self.tenant,
                self.actor,
                now_ms,
                credential.access_expires_at_ms,
                serde_json::to_string(&project_roots)?,
                serde_json::to_string(&actions)?,
            ],
        )?;
        transaction.commit()?;
        Ok(MobilePlatformV2Authorization {
            schema: MOBILE_PLATFORM_V2_AUTH_SCHEMA,
            server_identity: self.discovery.server_identity.clone(),
            credential_id: request.credential_id,
            credential_revision: credential.credential_revision,
            authorization_revision,
            principal_generation,
            delegation_id,
            tenant_id: self.tenant.clone(),
            actor_id: self.actor.clone(),
            issued_at_ms: now_ms,
            expires_at_ms: credential.access_expires_at_ms,
            project_roots,
            actions,
        })
    }

    pub fn authorize_platform_v2(
        &self,
        token: &str,
        now_ms: i64,
    ) -> Result<MobilePlatformV2Authorization, MobileAuthError> {
        let authorization =
            self.authorize_access(token, &self.discovery.server_identity, now_ms)?;
        let mut descriptor = read_platform_v2(&self.connection, &authorization.credential_id)?
            .ok_or(MobileAuthError::InvalidCredential)?;
        descriptor.server_identity = self.discovery.server_identity.clone();
        validate_platform_v2_descriptor(
            &descriptor,
            &authorization,
            &self.discovery.server_identity,
            &self.tenant,
            &self.actor,
            now_ms,
        )?;
        Ok(descriptor)
    }

    #[cfg(test)]
    pub fn reauthorize_platform_v2(
        &self,
        expected: &MobilePlatformV2Authorization,
        now_ms: i64,
    ) -> Result<(), MobileAuthError> {
        reauthorize_platform_v2_on(
            &self.connection,
            expected,
            &self.discovery.server_identity,
            &self.tenant,
            &self.actor,
            now_ms,
        )
    }

    pub(crate) fn acquire_platform_v2_dispatch(
        &mut self,
        expected: &MobilePlatformV2Authorization,
        custody: MobilePlatformV2ReceiptCustody<'_>,
        canonical_request: &[u8],
        now_ms: i64,
    ) -> Result<MobilePlatformV2DispatchLease, MobileAuthError> {
        let server_identity = self.discovery.server_identity.clone();
        let tenant = self.tenant.clone();
        let actor = self.actor.clone();
        let lease_id = random_token("ml")?;
        let request_sha256 = dispatch_request_digest(canonical_request);
        let expires_at_ms = now_ms
            .checked_add(MOBILE_V2_DISPATCH_LEASE_MILLIS)
            .filter(|value| *value <= MAX_SAFE_JSON_INTEGER)
            .ok_or(MobileAuthError::InvalidRequest)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM mobile_platform_v2_dispatch_leases WHERE expires_at_ms<=?1",
            params![now_ms],
        )?;
        refuse_active_platform_v2_dispatch_on(&transaction, &expected.credential_id, now_ms)?;
        reauthorize_platform_v2_on(
            &transaction,
            expected,
            &server_identity,
            &tenant,
            &actor,
            now_ms,
        )?;
        match custody {
            MobilePlatformV2ReceiptCustody::None => {}
            MobilePlatformV2ReceiptCustody::BindMutation {
                project,
                idempotency_key,
            } => bind_receipt_custody_on(
                &transaction,
                expected,
                ReceiptCustodyCoordinate::mutation(project, idempotency_key),
                &request_sha256,
                None,
                now_ms,
            )?,
            MobilePlatformV2ReceiptCustody::ReadMutation {
                project,
                idempotency_key,
            } => authorize_receipt_custody_on(
                &transaction,
                expected,
                ReceiptCustodyCoordinate::mutation(project, idempotency_key),
                None,
                now_ms,
            )?,
            MobilePlatformV2ReceiptCustody::BindReview {
                project,
                workspace,
                idempotency_key,
                receipt_correlation_digest,
            } => bind_receipt_custody_on(
                &transaction,
                expected,
                ReceiptCustodyCoordinate::review(project, workspace, idempotency_key),
                &request_sha256,
                receipt_correlation_digest,
                now_ms,
            )?,
            MobilePlatformV2ReceiptCustody::ReadReview {
                project,
                workspace,
                idempotency_key,
                receipt_correlation_digest,
            } => authorize_receipt_custody_on(
                &transaction,
                expected,
                ReceiptCustodyCoordinate::review(project, workspace, idempotency_key),
                receipt_correlation_digest,
                now_ms,
            )?,
        }
        transaction.execute(
            "INSERT INTO mobile_platform_v2_dispatch_leases(
               credential_id,lease_id,delegation_id,principal_generation,request_sha256,
               acquired_at_ms,expires_at_ms
             ) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                expected.credential_id,
                lease_id,
                expected.delegation_id,
                expected.principal_generation,
                request_sha256.as_slice(),
                now_ms,
                expires_at_ms,
            ],
        )?;
        transaction.commit()?;
        Ok(MobilePlatformV2DispatchLease {
            credential_id: expected.credential_id.clone(),
            lease_id,
        })
    }

    pub(crate) fn release_platform_v2_dispatch(
        &mut self,
        lease: &MobilePlatformV2DispatchLease,
    ) -> Result<(), MobileAuthError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM mobile_platform_v2_dispatch_leases
             WHERE credential_id=?1 AND lease_id=?2",
            params![lease.credential_id, lease.lease_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub fn bind_platform_v2_receipt_custody(
        &mut self,
        authorization: &MobilePlatformV2Authorization,
        project: &ProjectId,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<(), MobileAuthError> {
        let lease = self.acquire_platform_v2_dispatch(
            authorization,
            MobilePlatformV2ReceiptCustody::BindMutation {
                project,
                idempotency_key,
            },
            idempotency_key.as_bytes(),
            now_ms,
        )?;
        self.release_platform_v2_dispatch(&lease)
    }

    #[cfg(test)]
    pub fn authorize_platform_v2_receipt_custody(
        &mut self,
        authorization: &MobilePlatformV2Authorization,
        project: &ProjectId,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<(), MobileAuthError> {
        let lease = self.acquire_platform_v2_dispatch(
            authorization,
            MobilePlatformV2ReceiptCustody::ReadMutation {
                project,
                idempotency_key,
            },
            idempotency_key.as_bytes(),
            now_ms,
        )?;
        self.release_platform_v2_dispatch(&lease)
    }

    #[cfg(test)]
    pub fn bind_platform_v2_review_receipt_custody(
        &mut self,
        authorization: &MobilePlatformV2Authorization,
        project: &ProjectId,
        workspace: &WorkContextIdentity,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<(), MobileAuthError> {
        let lease = self.acquire_platform_v2_dispatch(
            authorization,
            MobilePlatformV2ReceiptCustody::BindReview {
                project,
                workspace,
                idempotency_key,
                receipt_correlation_digest: None,
            },
            idempotency_key.as_bytes(),
            now_ms,
        )?;
        self.release_platform_v2_dispatch(&lease)
    }

    #[cfg(test)]
    pub fn authorize_platform_v2_review_receipt_custody(
        &mut self,
        authorization: &MobilePlatformV2Authorization,
        project: &ProjectId,
        workspace: &WorkContextIdentity,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<(), MobileAuthError> {
        let lease = self.acquire_platform_v2_dispatch(
            authorization,
            MobilePlatformV2ReceiptCustody::ReadReview {
                project,
                workspace,
                idempotency_key,
                receipt_correlation_digest: None,
            },
            idempotency_key.as_bytes(),
            now_ms,
        )?;
        self.release_platform_v2_dispatch(&lease)
    }

    pub fn refresh(
        &mut self,
        token: &mut String,
        expected_server_identity: &str,
        now_ms: i64,
    ) -> Result<IssuedMobileCredentials, MobileAuthError> {
        let token = take_secret(token);
        validate_time(now_ms)?;
        validate_token(&token, "mr")?;
        if expected_server_identity != self.discovery.server_identity {
            return Err(MobileAuthError::ServerIdentityMismatch);
        }
        let digest = token_digest(
            b"automonique.mobile-refresh/v1\0",
            &self.discovery.server_identity,
            &token,
        );
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = match read_by_digest(&transaction, "refresh_sha256", &digest)? {
            Some(row) => row,
            None => {
                let replayed_credential = transaction
                    .query_row(
                        "SELECT credential_id FROM mobile_refresh_history WHERE refresh_sha256=?1",
                        params![digest.as_slice()],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?;
                let Some(credential_id) = replayed_credential else {
                    return Err(MobileAuthError::InvalidCredential);
                };
                refuse_active_platform_v2_dispatch_on(&transaction, &credential_id, now_ms)?;
                transaction.execute(
                    "UPDATE mobile_credentials SET revoked_at_ms=COALESCE(revoked_at_ms,?1)
                     WHERE credential_id=?2",
                    params![now_ms, credential_id],
                )?;
                revoke_platform_v2(&transaction, &credential_id, now_ms)?;
                transaction.commit()?;
                return Err(MobileAuthError::InvalidCredential);
            }
        };
        refuse_active_platform_v2_dispatch_on(&transaction, &row.credential_id, now_ms)?;
        let _ = row.authorization(&self.discovery.server_identity, now_ms, true)?;
        let requested_access_expiry = now_ms
            .checked_add(ACCESS_TTL_MILLIS)
            .ok_or(MobileAuthError::InvalidRequest)?;
        let access_expires_at_ms = requested_access_expiry.min(row.refresh_expires_at_ms);
        validate_time(access_expires_at_ms)?;
        if access_expires_at_ms <= now_ms {
            return Err(MobileAuthError::Expired);
        }
        if row.credential_revision >= MAX_CREDENTIAL_REVISIONS {
            transaction.execute(
                "UPDATE mobile_credentials SET revoked_at_ms=COALESCE(revoked_at_ms,?1)
                 WHERE credential_id=?2",
                params![now_ms, row.credential_id],
            )?;
            revoke_platform_v2(&transaction, &row.credential_id, now_ms)?;
            transaction.commit()?;
            return Err(MobileAuthError::InvalidCredential);
        }
        let mut access = random_secret_token("ma")?;
        let mut refresh = random_secret_token("mr")?;
        let access_digest = token_digest(
            b"automonique.mobile-access/v1\0",
            &self.discovery.server_identity,
            &access,
        );
        let refresh_digest = token_digest(
            b"automonique.mobile-refresh/v1\0",
            &self.discovery.server_identity,
            &refresh,
        );
        let revision = row
            .credential_revision
            .checked_add(1)
            .ok_or(MobileAuthError::InvalidRequest)?;
        let next_platform_v2_generation = transaction
            .query_row(
                "SELECT principal_generation FROM mobile_platform_v2_authorizations
                 WHERE credential_id=?1 AND revoked_at_ms IS NULL",
                params![row.credential_id],
                |row| row.get::<_, u64>(0),
            )
            .optional()?
            .map(|generation| {
                generation
                    .checked_add(1)
                    .filter(|value| *value <= MAX_SAFE_JSON_INTEGER as u64)
                    .ok_or(MobileAuthError::InvalidCredential)
            })
            .transpose()?;
        transaction.execute(
            "INSERT INTO mobile_refresh_history(
               refresh_sha256,credential_id,credential_revision,rotated_at_ms
             ) VALUES(?1,?2,?3,?4)",
            params![
                digest.as_slice(),
                row.credential_id,
                row.credential_revision,
                now_ms
            ],
        )?;
        let updated = transaction.execute(
            "UPDATE mobile_credentials SET access_sha256=?1,refresh_sha256=?2,
               credential_revision=?3,issued_at_ms=?4,access_expires_at_ms=?5
             WHERE credential_id=?6 AND refresh_sha256=?7
               AND credential_revision=?8 AND revoked_at_ms IS NULL",
            params![
                access_digest.as_slice(),
                refresh_digest.as_slice(),
                revision,
                now_ms,
                access_expires_at_ms,
                row.credential_id,
                digest.as_slice(),
                row.credential_revision,
            ],
        )?;
        if updated != 1 {
            return Err(MobileAuthError::InvalidCredential);
        }
        if let Some(principal_generation) = next_platform_v2_generation {
            let updated = transaction.execute(
                "UPDATE mobile_platform_v2_authorizations SET
                   credential_revision=?1,principal_generation=?2,
                   issued_at_ms=?3,expires_at_ms=?4
                 WHERE credential_id=?5 AND credential_revision=?6
                   AND authorization_revision=?7 AND revoked_at_ms IS NULL",
                params![
                    revision,
                    principal_generation,
                    now_ms,
                    access_expires_at_ms,
                    row.credential_id,
                    row.credential_revision,
                    row.authorization_revision,
                ],
            )?;
            if updated != 1 {
                return Err(MobileAuthError::InvalidCredential);
            }
            transaction.execute(
                "UPDATE mobile_platform_v2_receipt_custody SET expires_at_ms=?1
                 WHERE credential_id=?2",
                params![access_expires_at_ms, row.credential_id],
            )?;
            transaction.execute(
                "UPDATE mobile_platform_v2_exact_receipt_custody SET expires_at_ms=?1
                 WHERE credential_id=?2",
                params![access_expires_at_ms, row.credential_id],
            )?;
        }
        transaction.commit()?;
        Ok(IssuedMobileCredentials {
            access_token: std::mem::take(&mut *access),
            refresh_token: std::mem::take(&mut *refresh),
            authorization: MobileAuthorization {
                schema: MOBILE_AUTH_SCHEMA_V1,
                server_identity: self.discovery.server_identity.clone(),
                actor: row.actor,
                credential_id: row.credential_id,
                credential_revision: revision,
                authorization_revision: row.authorization_revision,
                issued_at_ms: now_ms,
                expires_at_ms: access_expires_at_ms,
                actions: row.actions,
                session_scope: row.sessions,
                limits: row.limits,
            },
        })
    }

    pub fn revoke(
        &mut self,
        token: &mut String,
        expected_server_identity: &str,
        now_ms: i64,
    ) -> Result<(), MobileAuthError> {
        let token = take_secret(token);
        validate_time(now_ms)?;
        validate_token(&token, "mr")?;
        if expected_server_identity != self.discovery.server_identity {
            return Err(MobileAuthError::ServerIdentityMismatch);
        }
        let digest = token_digest(
            b"automonique.mobile-refresh/v1\0",
            &self.discovery.server_identity,
            &token,
        );
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current_credential = transaction
            .query_row(
                "SELECT credential_id FROM mobile_credentials WHERE refresh_sha256=?1",
                params![digest.as_slice()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let credential_id = match current_credential {
            Some(credential_id) => credential_id,
            None => transaction
                .query_row(
                    "SELECT credential_id FROM mobile_refresh_history WHERE refresh_sha256=?1",
                    params![digest.as_slice()],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or(MobileAuthError::InvalidCredential)?,
        };
        refuse_active_platform_v2_dispatch_on(&transaction, &credential_id, now_ms)?;
        let changed = transaction.execute(
            "UPDATE mobile_credentials SET revoked_at_ms=?1
             WHERE credential_id=?2 AND revoked_at_ms IS NULL",
            params![now_ms, credential_id],
        )?;
        if changed != 1 {
            return Err(MobileAuthError::InvalidCredential);
        }
        revoke_platform_v2(&transaction, &credential_id, now_ms)?;
        transaction.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn ensure_review_receipt_correlation_column(
    connection: &Connection,
) -> Result<(), MobileAuthError> {
    let mut statement = connection.prepare(
        "SELECT name FROM pragma_table_info('mobile_platform_v2_exact_receipt_custody')",
    )?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<BTreeSet<_>, _>>()?;
    if !columns.contains("receipt_correlation_digest") {
        connection.execute_batch(
            "ALTER TABLE mobile_platform_v2_exact_receipt_custody
             ADD COLUMN receipt_correlation_digest TEXT CHECK(
               receipt_correlation_digest IS NULL OR
               (length(receipt_correlation_digest) = 64 AND receipt_correlation_digest = lower(receipt_correlation_digest))
             );",
        )?;
    }
    Ok(())
}

fn issue_credential(
    connection: &Connection,
    server_identity: &str,
    actor: &str,
    actions: Vec<MobileAction>,
    sessions: Vec<String>,
    limits: MobileLimits,
    now_ms: i64,
) -> Result<IssuedMobileCredentials, MobileAuthError> {
    let mut access = random_secret_token("ma")?;
    let mut refresh = random_secret_token("mr")?;
    let credential_id = random_token("mc")?;
    let access_digest = token_digest(b"automonique.mobile-access/v1\0", server_identity, &access);
    let refresh_digest = token_digest(
        b"automonique.mobile-refresh/v1\0",
        server_identity,
        &refresh,
    );
    let access_expires_at_ms = now_ms
        .checked_add(ACCESS_TTL_MILLIS)
        .ok_or(MobileAuthError::InvalidRequest)?;
    let refresh_expires_at_ms = now_ms
        .checked_add(REFRESH_TTL_MILLIS)
        .ok_or(MobileAuthError::InvalidRequest)?;
    validate_time(access_expires_at_ms)?;
    validate_time(refresh_expires_at_ms)?;
    connection.execute(
        "INSERT INTO mobile_credentials(
           credential_id,access_sha256,refresh_sha256,actor,server_identity,
           credential_revision,authorization_revision,issued_at_ms,
           access_expires_at_ms,refresh_expires_at_ms,revoked_at_ms,
           actions_json,sessions_json,max_page_events,max_follow_up_bytes
         ) VALUES(?1,?2,?3,?4,?5,1,1,?6,?7,?8,NULL,?9,?10,?11,?12)",
        params![
            credential_id,
            access_digest.as_slice(),
            refresh_digest.as_slice(),
            actor,
            server_identity,
            now_ms,
            access_expires_at_ms,
            refresh_expires_at_ms,
            serde_json::to_string(&actions)?,
            serde_json::to_string(&sessions)?,
            limits.max_page_events,
            limits.max_follow_up_bytes,
        ],
    )?;
    Ok(IssuedMobileCredentials {
        access_token: std::mem::take(&mut *access),
        refresh_token: std::mem::take(&mut *refresh),
        authorization: MobileAuthorization {
            schema: MOBILE_AUTH_SCHEMA_V1,
            server_identity: server_identity.to_owned(),
            actor: actor.to_owned(),
            credential_id,
            credential_revision: 1,
            authorization_revision: 1,
            issued_at_ms: now_ms,
            expires_at_ms: access_expires_at_ms,
            actions,
            session_scope: sessions,
            limits,
        },
    })
}

#[derive(Debug)]
struct CredentialRow {
    credential_id: String,
    actor: String,
    server_identity: String,
    credential_revision: u64,
    authorization_revision: u64,
    issued_at_ms: i64,
    access_expires_at_ms: i64,
    refresh_expires_at_ms: i64,
    revoked_at_ms: Option<i64>,
    actions: Vec<MobileAction>,
    sessions: Vec<String>,
    limits: MobileLimits,
}

impl CredentialRow {
    fn descriptor(&self) -> MobileAuthorization {
        MobileAuthorization {
            schema: MOBILE_AUTH_SCHEMA_V1,
            server_identity: self.server_identity.clone(),
            actor: self.actor.clone(),
            credential_id: self.credential_id.clone(),
            credential_revision: self.credential_revision,
            authorization_revision: self.authorization_revision,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.access_expires_at_ms,
            actions: self.actions.clone(),
            session_scope: self.sessions.clone(),
            limits: self.limits.clone(),
        }
    }

    fn authorization(
        &self,
        server_identity: &str,
        now_ms: i64,
        refresh: bool,
    ) -> Result<MobileAuthorization, MobileAuthError> {
        if self.server_identity != server_identity {
            return Err(MobileAuthError::ServerIdentityMismatch);
        }
        if self.revoked_at_ms.is_some() {
            return Err(MobileAuthError::Revoked);
        }
        let expiry = if refresh {
            self.refresh_expires_at_ms
        } else {
            self.access_expires_at_ms
        };
        if expiry <= now_ms {
            return Err(MobileAuthError::Expired);
        }
        Ok(self.descriptor())
    }
}

fn read_by_digest(
    connection: &Connection,
    column: &str,
    digest: &[u8; 32],
) -> Result<Option<CredentialRow>, MobileAuthError> {
    if !matches!(column, "access_sha256" | "refresh_sha256") {
        return Err(MobileAuthError::InvalidRequest);
    }
    let sql = format!(
        "SELECT credential_id,actor,server_identity,credential_revision,
          authorization_revision,issued_at_ms,access_expires_at_ms,
          refresh_expires_at_ms,revoked_at_ms,actions_json,sessions_json,
          max_page_events,max_follow_up_bytes FROM mobile_credentials WHERE {column}=?1"
    );
    let raw = connection
        .query_row(&sql, params![digest.as_slice()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, i64>(12)?,
            ))
        })
        .optional()?;
    raw.map(|raw| {
        let credential_revision =
            u64::try_from(raw.3).map_err(|_| MobileAuthError::InvalidRequest)?;
        let authorization_revision =
            u64::try_from(raw.4).map_err(|_| MobileAuthError::InvalidRequest)?;
        if credential_revision > MAX_SAFE_JSON_INTEGER as u64
            || authorization_revision > MAX_SAFE_JSON_INTEGER as u64
        {
            return Err(MobileAuthError::InvalidRequest);
        }
        validate_token(&raw.0, "mc")?;
        validate_identifier(&raw.1)?;
        validate_server_identity(&raw.2)?;
        validate_time(raw.5)?;
        validate_time(raw.6)?;
        validate_time(raw.7)?;
        if raw.6 <= raw.5 || raw.7 < raw.6 {
            return Err(MobileAuthError::InvalidRequest);
        }
        if let Some(revoked_at_ms) = raw.8 {
            validate_time(revoked_at_ms)?;
        }
        let actions: Vec<MobileAction> = serde_json::from_str(&raw.9)?;
        let sessions: Vec<String> = serde_json::from_str(&raw.10)?;
        let (actions, sessions) = admit_scope(actions, sessions)?;
        let limits = MobileLimits {
            max_page_events: u16::try_from(raw.11).map_err(|_| MobileAuthError::InvalidRequest)?,
            max_follow_up_bytes: u32::try_from(raw.12)
                .map_err(|_| MobileAuthError::InvalidRequest)?,
        };
        validate_limits(&limits)?;
        Ok(CredentialRow {
            credential_id: raw.0,
            actor: raw.1,
            server_identity: raw.2,
            credential_revision,
            authorization_revision,
            issued_at_ms: raw.5,
            access_expires_at_ms: raw.6,
            refresh_expires_at_ms: raw.7,
            revoked_at_ms: raw.8,
            actions,
            sessions,
            limits,
        })
    })
    .transpose()
}

fn read_by_id(
    connection: &Connection,
    credential_id: &str,
) -> Result<Option<CredentialRow>, MobileAuthError> {
    let digest = connection
        .query_row(
            "SELECT access_sha256 FROM mobile_credentials WHERE credential_id=?1",
            params![credential_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let Some(digest) = digest else {
        return Ok(None);
    };
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| MobileAuthError::InvalidRequest)?;
    read_by_digest(connection, "access_sha256", &digest)
}

fn read_platform_v2(
    connection: &Connection,
    credential_id: &str,
) -> Result<Option<MobilePlatformV2Authorization>, MobileAuthError> {
    let raw = connection
        .query_row(
            "SELECT credential_revision,authorization_revision,principal_generation,
               delegation_id,tenant_id,actor_id,issued_at_ms,expires_at_ms,revoked_at_ms,
               project_roots_json,actions_json
             FROM mobile_platform_v2_authorizations WHERE credential_id=?1",
            params![credential_id],
            |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                ))
            },
        )
        .optional()?;
    raw.map(|raw| {
        if raw.0 == 0
            || raw.0 > MAX_CREDENTIAL_REVISIONS
            || raw.1 == 0
            || raw.1 > MAX_SAFE_JSON_INTEGER as u64
            || raw.2 == 0
            || raw.2 > MAX_SAFE_JSON_INTEGER as u64
            || raw.8.is_some()
        {
            return Err(MobileAuthError::InvalidCredential);
        }
        validate_token(credential_id, "mc")?;
        validate_token(&raw.3, "md")?;
        validate_identifier(&raw.4)?;
        validate_identifier(&raw.5)?;
        validate_time(raw.6)?;
        validate_time(raw.7)?;
        if raw.6 >= raw.7 {
            return Err(MobileAuthError::InvalidCredential);
        }
        let project_roots = serde_json::from_str::<Vec<String>>(&raw.9)?;
        let actions = serde_json::from_str::<Vec<MobilePlatformV2Action>>(&raw.10)?;
        let (project_roots, actions) = admit_platform_v2_scope(project_roots, actions)?;
        Ok(MobilePlatformV2Authorization {
            schema: MOBILE_PLATFORM_V2_AUTH_SCHEMA,
            server_identity: String::new(),
            credential_id: credential_id.to_owned(),
            credential_revision: raw.0,
            authorization_revision: raw.1,
            principal_generation: raw.2,
            delegation_id: raw.3,
            tenant_id: raw.4,
            actor_id: raw.5,
            issued_at_ms: raw.6,
            expires_at_ms: raw.7,
            project_roots,
            actions,
        })
    })
    .transpose()
}

fn validate_platform_v2_descriptor(
    descriptor: &MobilePlatformV2Authorization,
    authorization: &MobileAuthorization,
    server_identity: &str,
    tenant: &str,
    actor: &str,
    now_ms: i64,
) -> Result<(), MobileAuthError> {
    if descriptor.credential_id != authorization.credential_id
        || descriptor.credential_revision != authorization.credential_revision
        || descriptor.authorization_revision != authorization.authorization_revision
        || descriptor.tenant_id != tenant
        || descriptor.actor_id != actor
        || descriptor.issued_at_ms > now_ms
        || descriptor.expires_at_ms != authorization.expires_at_ms
        || descriptor.expires_at_ms <= now_ms
    {
        return Err(MobileAuthError::InvalidCredential);
    }
    // The identity is derived from the authority's origin-bound singleton,
    // never trusted from the persisted grant row.
    if descriptor.server_identity != server_identity {
        return Err(MobileAuthError::ServerIdentityMismatch);
    }
    Ok(())
}

fn reauthorize_platform_v2_on(
    connection: &Connection,
    expected: &MobilePlatformV2Authorization,
    server_identity: &str,
    tenant: &str,
    actor: &str,
    now_ms: i64,
) -> Result<(), MobileAuthError> {
    validate_time(now_ms)?;
    let credential = read_by_id(connection, &expected.credential_id)?
        .ok_or(MobileAuthError::InvalidCredential)?;
    let authorization = credential.authorization(server_identity, now_ms, false)?;
    let mut current = read_platform_v2(connection, &expected.credential_id)?
        .ok_or(MobileAuthError::InvalidCredential)?;
    current.server_identity = server_identity.to_owned();
    validate_platform_v2_descriptor(
        &current,
        &authorization,
        server_identity,
        tenant,
        actor,
        now_ms,
    )?;
    (current == *expected)
        .then_some(())
        .ok_or(MobileAuthError::InvalidCredential)
}

fn bind_receipt_custody_on(
    connection: &Connection,
    authorization: &MobilePlatformV2Authorization,
    coordinate: ReceiptCustodyCoordinate<'_>,
    request_sha256: &[u8; 32],
    receipt_correlation_digest: Option<&str>,
    now_ms: i64,
) -> Result<(), MobileAuthError> {
    validate_receipt_coordinate(coordinate.idempotency_key)?;
    connection.execute(
        "DELETE FROM mobile_platform_v2_exact_receipt_custody WHERE expires_at_ms<=?1",
        params![now_ms],
    )?;
    let existing = connection
        .query_row(
            "SELECT credential_id,delegation_id,principal_generation,request_sha256,receipt_correlation_digest
             FROM mobile_platform_v2_exact_receipt_custody
             WHERE receipt_family=?1 AND project_id=?2 AND workspace_kind=?3
               AND workspace_id=?4 AND idempotency_key=?5",
            params![
                coordinate.receipt_family,
                coordinate.project.as_str(),
                coordinate.workspace_kind,
                coordinate.workspace_id,
                coordinate.idempotency_key
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()?;
    if let Some((credential_id, delegation_id, generation, bound_digest, bound_correlation)) =
        existing
    {
        if credential_id != authorization.credential_id
            || delegation_id != authorization.delegation_id
            || generation != authorization.principal_generation
        {
            return Err(MobileAuthError::InvalidCredential);
        }
        return (bound_digest.as_slice() == request_sha256
            && bound_correlation.as_deref() == receipt_correlation_digest)
            .then_some(())
            .ok_or(MobileAuthError::InvalidCredential);
    }
    let count = connection.query_row(
        "SELECT COUNT(*) FROM mobile_platform_v2_exact_receipt_custody
         WHERE credential_id=?1",
        params![authorization.credential_id],
        |row| row.get::<_, u64>(0),
    )?;
    if count >= MAX_MOBILE_V2_RECEIPT_CUSTODY as u64 {
        return Err(MobileAuthError::InvalidRequest);
    }
    connection.execute(
        "INSERT INTO mobile_platform_v2_exact_receipt_custody(
           receipt_family,project_id,workspace_kind,workspace_id,idempotency_key,
           credential_id,delegation_id,principal_generation,request_sha256,
           created_at_ms,expires_at_ms,receipt_correlation_digest
         ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        params![
            coordinate.receipt_family,
            coordinate.project.as_str(),
            coordinate.workspace_kind,
            coordinate.workspace_id,
            coordinate.idempotency_key,
            authorization.credential_id,
            authorization.delegation_id,
            authorization.principal_generation,
            request_sha256.as_slice(),
            now_ms,
            authorization.expires_at_ms,
            receipt_correlation_digest,
        ],
    )?;
    Ok(())
}

fn authorize_receipt_custody_on(
    connection: &Connection,
    authorization: &MobilePlatformV2Authorization,
    coordinate: ReceiptCustodyCoordinate<'_>,
    receipt_correlation_digest: Option<&str>,
    now_ms: i64,
) -> Result<(), MobileAuthError> {
    validate_receipt_coordinate(coordinate.idempotency_key)?;
    let custody = connection
        .query_row(
            "SELECT credential_id,delegation_id,principal_generation,expires_at_ms,receipt_correlation_digest
             FROM mobile_platform_v2_exact_receipt_custody
             WHERE receipt_family=?1 AND project_id=?2 AND workspace_kind=?3
               AND workspace_id=?4 AND idempotency_key=?5",
            params![
                coordinate.receipt_family,
                coordinate.project.as_str(),
                coordinate.workspace_kind,
                coordinate.workspace_id,
                coordinate.idempotency_key
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(MobileAuthError::InvalidCredential)?;
    (custody.0 == authorization.credential_id
        && custody.1 == authorization.delegation_id
        && custody.2 <= authorization.principal_generation
        && custody.3 > now_ms
        && custody.4.as_deref() == receipt_correlation_digest)
        .then_some(())
        .ok_or(MobileAuthError::InvalidCredential)
}

fn refuse_active_platform_v2_dispatch_on(
    connection: &Connection,
    credential_id: &str,
    now_ms: i64,
) -> Result<(), MobileAuthError> {
    connection.execute(
        "DELETE FROM mobile_platform_v2_dispatch_leases WHERE expires_at_ms<=?1",
        params![now_ms],
    )?;
    let active = connection.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM mobile_platform_v2_dispatch_leases
           WHERE credential_id=?1 AND expires_at_ms>?2
         )",
        params![credential_id, now_ms],
        |row| row.get::<_, bool>(0),
    )?;
    if active {
        return Err(MobileAuthError::DispatchBusy);
    }
    Ok(())
}

fn admit_platform_v2_scope(
    project_roots: Vec<String>,
    actions: Vec<MobilePlatformV2Action>,
) -> Result<(Vec<String>, Vec<MobilePlatformV2Action>), MobileAuthError> {
    if project_roots.is_empty()
        || project_roots.len() > MAX_MOBILE_V2_PROJECT_ROOTS
        || actions.is_empty()
        || actions.len() > MAX_MOBILE_PLATFORM_V2_ACTIONS
    {
        return Err(MobileAuthError::InvalidRequest);
    }
    let project_roots = project_roots
        .into_iter()
        .map(|value| {
            ProjectId::new(value.clone()).map_err(|_| MobileAuthError::InvalidRequest)?;
            Ok(value)
        })
        .collect::<Result<BTreeSet<_>, MobileAuthError>>()?;
    let actions = actions.into_iter().collect::<BTreeSet<_>>();
    if project_roots.is_empty()
        || project_roots.len() > MAX_MOBILE_V2_PROJECT_ROOTS
        || actions.is_empty()
        || actions.len() > MAX_MOBILE_PLATFORM_V2_ACTIONS
    {
        return Err(MobileAuthError::InvalidRequest);
    }
    Ok((
        project_roots.into_iter().collect(),
        actions.into_iter().collect(),
    ))
}

fn revoke_platform_v2(
    connection: &Connection,
    credential_id: &str,
    now_ms: i64,
) -> Result<(), MobileAuthError> {
    connection.execute(
        "DELETE FROM mobile_platform_v2_receipt_custody WHERE credential_id=?1",
        params![credential_id],
    )?;
    connection.execute(
        "DELETE FROM mobile_platform_v2_exact_receipt_custody WHERE credential_id=?1",
        params![credential_id],
    )?;
    let generation = connection
        .query_row(
            "SELECT principal_generation FROM mobile_platform_v2_authorizations
             WHERE credential_id=?1 AND revoked_at_ms IS NULL",
            params![credential_id],
            |row| row.get::<_, u64>(0),
        )
        .optional()?;
    if let Some(generation) = generation {
        let next = generation
            .checked_add(1)
            .filter(|value| *value <= MAX_SAFE_JSON_INTEGER as u64)
            .ok_or(MobileAuthError::InvalidCredential)?;
        let changed = connection.execute(
            "UPDATE mobile_platform_v2_authorizations
             SET revoked_at_ms=?1,principal_generation=?2
             WHERE credential_id=?3 AND revoked_at_ms IS NULL",
            params![now_ms, next, credential_id],
        )?;
        if changed != 1 {
            return Err(MobileAuthError::InvalidCredential);
        }
    }
    Ok(())
}

pub fn authorize_platform_request(
    authorization: &MobileAuthorization,
    request: &PlatformRequest,
    now_ms: i64,
) -> Result<(), MobileAuthError> {
    if authorization.expires_at_ms <= now_ms {
        return Err(MobileAuthError::Expired);
    }
    let allowed = match request {
        PlatformRequest::Capabilities => true,
        PlatformRequest::ListSessions(request) => {
            request.authority == ResourceAuthority::Automonique
                && authorization.allows(MobileAction::Attach)
        }
        PlatformRequest::Attach(request) => {
            authorization.allows(MobileAction::Attach)
                && request.session.authority == ResourceAuthority::Automonique
                && request.session.kind == ResourceKind::Session
                && authorization.allows_session(request.session.id.as_str())
                && request.client.as_str() == authorization.credential_id
        }
        PlatformRequest::Detach(request) => {
            authorization.allows(MobileAction::Attach)
                && request.session.authority == ResourceAuthority::Automonique
                && request.session.kind == ResourceKind::Session
                && authorization.allows_session(request.session.id.as_str())
                && request.client.as_str() == authorization.credential_id
        }
        // Mobile callers use only the dedicated session-bound commands below.
        // The generic action grammar remains available to local/operator
        // clients, but a mobile bearer can never acquire it.
        PlatformRequest::Execute(_) => false,
        PlatformRequest::GetReceipt(request) => request
            .client
            .as_ref()
            .is_some_and(|client| client.as_str() == authorization.credential_id),
        PlatformRequest::SessionHistorySnapshot(request) => {
            authorization.allows(MobileAction::Attach)
                && request.session.authority == ResourceAuthority::Automonique
                && request.session.kind == ResourceKind::Session
                && authorization.allows_session(request.session.id.as_str())
                && request.limit <= authorization.limits.max_page_events
        }
        PlatformRequest::SessionHistoryPage(request) => {
            authorization.allows(MobileAction::Attach)
                && request.session.authority == ResourceAuthority::Automonique
                && request.session.kind == ResourceKind::Session
                && authorization.allows_session(request.session.id.as_str())
                && request.limit <= authorization.limits.max_page_events
        }
        PlatformRequest::SessionCommandState(request) => {
            request.session.authority == ResourceAuthority::Automonique
                && request.session.kind == ResourceKind::Session
                && authorization.allows_session(request.session.id.as_str())
                && (authorization.allows(MobileAction::FollowUp)
                    || authorization.allows(MobileAction::StopRun)
                    || authorization.allows(MobileAction::DecideApproval))
        }
        PlatformRequest::SessionFollowUp(request) => {
            let text = request.text.as_str();
            authorization.allows(MobileAction::FollowUp)
                && request.client.as_str() == authorization.credential_id
                && request.session.authority == ResourceAuthority::Automonique
                && request.session.kind == ResourceKind::Session
                && authorization.allows_session(request.session.id.as_str())
                && !text.trim().is_empty()
                && text.len()
                    <= usize::try_from(authorization.limits.max_follow_up_bytes)
                        .unwrap_or(usize::MAX)
        }
        PlatformRequest::SessionRunStop(request) => {
            authorization.allows(MobileAction::StopRun)
                && request.client.as_str() == authorization.credential_id
                && request.session.authority == ResourceAuthority::Automonique
                && request.session.kind == ResourceKind::Session
                && authorization.allows_session(request.session.id.as_str())
                && request.run.authority == ResourceAuthority::Automonique
                && request.run.kind == ResourceKind::Run
        }
        PlatformRequest::SessionApprovalDecision(request) => {
            authorization.allows(MobileAction::DecideApproval)
                && request.client.as_str() == authorization.credential_id
                && request.session.authority == ResourceAuthority::Automonique
                && request.session.kind == ResourceKind::Session
                && authorization.allows_session(request.session.id.as_str())
                && request.approval.authority == ResourceAuthority::Automonique
                && request.approval.kind == ResourceKind::Approval
        }
        // These reads lack actor/session coordinates in Platform v1. They must
        // remain closed until the caller's receipt/cursor/resource ownership is
        // provable at this boundary.
        PlatformRequest::Snapshot(_)
        | PlatformRequest::Subscribe(_)
        | PlatformRequest::ClaimControl(_)
        | PlatformRequest::ReleaseControl(_) => false,
    };
    allowed.then_some(()).ok_or(MobileAuthError::InvalidRequest)
}

pub fn filter_sessions(
    authorization: &MobileAuthorization,
    mut sessions: SessionList,
) -> SessionList {
    sessions.sessions.retain(|session| {
        session.session.resource.authority == ResourceAuthority::Automonique
            && session.session.resource.kind == ResourceKind::Session
            && authorization.allows_session(session.session.resource.id.as_str())
    });
    sessions
}

/// Strip command targets that the admitted descriptor cannot operate. The
/// daemon proves ownership; this projection additionally prevents one action
/// grant from revealing targets belonging to another command capability.
pub fn filter_command_state(
    authorization: &MobileAuthorization,
    mut state: SessionCommandState,
) -> SessionCommandState {
    if !authorization.allows(MobileAction::StopRun) {
        state.run = None;
    }
    if !authorization.allows(MobileAction::DecideApproval) {
        state.pending_approvals.clear();
    }
    state
}

fn validate_time(value: i64) -> Result<(), MobileAuthError> {
    ((0..=MAX_SAFE_JSON_INTEGER).contains(&value))
        .then_some(())
        .ok_or(MobileAuthError::InvalidRequest)
}

fn cleanup_retired_families(connection: &Connection, now_ms: i64) -> Result<(), MobileAuthError> {
    let revoked_before = now_ms.saturating_sub(REVOKED_FAMILY_RETENTION_MILLIS);
    connection.execute(
        "DELETE FROM mobile_credentials
         WHERE (access_expires_at_ms <= ?1 AND refresh_expires_at_ms <= ?1)
            OR (revoked_at_ms IS NOT NULL AND revoked_at_ms <= ?2)",
        params![now_ms, revoked_before],
    )?;
    Ok(())
}

fn cleanup_pairings(connection: &Connection, now_ms: i64) -> Result<(), MobileAuthError> {
    let retained_after = now_ms.saturating_sub(PAIRING_RETENTION_MILLIS);
    connection.execute(
        "DELETE FROM mobile_pairings
         WHERE (consumed_at_ms IS NOT NULL AND consumed_at_ms <= ?1)
            OR (consumed_at_ms IS NULL AND expires_at_ms <= ?1)",
        params![retained_after],
    )?;
    Ok(())
}

fn validate_limits(value: &MobileLimits) -> Result<(), MobileAuthError> {
    ((1..=MAX_PAGE_EVENTS).contains(&value.max_page_events)
        && (1..=MAX_FOLLOW_UP_BYTES).contains(&value.max_follow_up_bytes))
    .then_some(())
    .ok_or(MobileAuthError::InvalidRequest)
}

fn admit_scope(
    actions: Vec<MobileAction>,
    sessions: Vec<String>,
) -> Result<(Vec<MobileAction>, Vec<String>), MobileAuthError> {
    if actions.is_empty()
        || actions.len() > MAX_MOBILE_ACTIONS
        || sessions.len() > MAX_MOBILE_SESSIONS
    {
        return Err(MobileAuthError::InvalidRequest);
    }
    let actions = actions.into_iter().collect::<BTreeSet<_>>();
    if actions.is_empty() || actions.len() > MAX_MOBILE_ACTIONS {
        return Err(MobileAuthError::InvalidRequest);
    }
    let sessions = sessions
        .into_iter()
        .map(|session| {
            validate_identifier(&session)?;
            Ok(session)
        })
        .collect::<Result<BTreeSet<_>, MobileAuthError>>()?;
    Ok((
        actions.into_iter().collect(),
        sessions.into_iter().collect(),
    ))
}

fn validate_identifier(value: &str) -> Result<(), MobileAuthError> {
    (!value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')))
    .then_some(())
    .ok_or(MobileAuthError::InvalidRequest)
}

fn validate_receipt_coordinate(value: &str) -> Result<(), MobileAuthError> {
    (!value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')))
    .then_some(())
    .ok_or(MobileAuthError::InvalidRequest)
}

fn validate_host(value: &str) -> Result<(), MobileAuthError> {
    if value.is_empty()
        || value.len() > 253
        || !value.is_ascii()
        || value.contains(['/', '\\', '@', ':'])
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                || !label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
    {
        return Err(MobileAuthError::InvalidOrigin);
    }
    Ok(())
}

fn validate_token(value: &str, prefix: &str) -> Result<(), MobileAuthError> {
    let encoded = value
        .strip_prefix(prefix)
        .and_then(|value| value.strip_prefix('_'))
        .ok_or(MobileAuthError::InvalidCredential)?;
    if encoded.len() != 43
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(MobileAuthError::InvalidCredential);
    }
    Ok(())
}

fn validate_server_identity(value: &str) -> Result<(), MobileAuthError> {
    let digest = value
        .strip_prefix("sha256:")
        .ok_or(MobileAuthError::ServerIdentityMismatch)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MobileAuthError::ServerIdentityMismatch);
    }
    Ok(())
}

fn random_token(prefix: &str) -> Result<String, MobileAuthError> {
    let mut bytes = random_bytes()?;
    let encoded = URL_SAFE_NO_PAD.encode(bytes);
    bytes.zeroize();
    Ok(format!("{prefix}_{encoded}"))
}

fn random_secret_token(prefix: &str) -> Result<Zeroizing<String>, MobileAuthError> {
    random_token(prefix).map(Zeroizing::new)
}

fn take_secret(value: &mut String) -> Zeroizing<String> {
    Zeroizing::new(std::mem::take(value))
}

fn random_bytes() -> Result<[u8; TOKEN_BYTES], MobileAuthError> {
    let mut bytes = [0_u8; TOKEN_BYTES];
    if let Err(error) =
        fs::File::open("/dev/urandom").and_then(|mut random| random.read_exact(&mut bytes))
    {
        bytes.zeroize();
        return Err(error.into());
    }
    Ok(bytes)
}

fn load_or_create_server_identity(
    connection: &Connection,
    origin: &str,
) -> Result<String, MobileAuthError> {
    let mut nonce = random_bytes()?;
    let mut digest = Sha256::new();
    digest.update(b"automonique.mobile-server/v1\0");
    digest.update(origin.as_bytes());
    digest.update(b"\0");
    digest.update(nonce);
    nonce.zeroize();
    let candidate = format!("sha256:{}", hex::encode(digest.finalize()));
    connection.execute(
        "INSERT OR IGNORE INTO mobile_server_identity(singleton,origin,server_identity)
         VALUES(1,?1,?2)",
        params![origin, candidate],
    )?;
    let (stored_origin, server_identity) = connection.query_row(
        "SELECT origin,server_identity FROM mobile_server_identity WHERE singleton=1",
        [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )?;
    if stored_origin != origin {
        return Err(MobileAuthError::ServerIdentityMismatch);
    }
    validate_server_identity(&server_identity)?;
    Ok(server_identity)
}

fn token_digest(domain: &[u8], server_identity: &str, token: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(server_identity.as_bytes());
    digest.update(b"\0");
    digest.update(token.as_bytes());
    digest.finalize().into()
}

fn dispatch_request_digest(canonical_request: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"automonique.mobile-platform-v2-dispatch/v1\0");
    digest.update(canonical_request);
    digest.finalize().into()
}

fn secure_database_path(path: &Path) -> Result<(), MobileAuthError> {
    let parent = path.parent().ok_or(MobileAuthError::InsecurePath)?;
    let metadata = fs::symlink_metadata(parent).map_err(MobileAuthError::Io)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(MobileAuthError::InsecurePath);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != nix::unistd::geteuid().as_raw()
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(MobileAuthError::InsecurePath);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(&[])?;
            file.sync_all()?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use automonique_protocol::platform::{
        AttachRequest, ClientId, CursorTopic, DetachRequest, ExecuteRequest, Freshness,
        FreshnessState, GetReceiptRequest, IdempotencyKey, PlatformAction, PlatformCursor,
        PlatformParameter, PlatformText, ReceiptId, ResourceCoordinate, ResourceId, ResourceRecord,
        SessionApprovalDecision, SessionApprovalDecisionRequest, SessionCommandState,
        SessionCommandStateRequest, SessionCommandTarget, SessionFollowUpRequest, SessionRecord,
        SessionRunStopRequest,
    };
    use automonique_protocol::primitives::{EpochMillis, Revision};
    use tempfile::TempDir;

    const NOW: i64 = 1_777_000_000_000;

    fn authority() -> (TempDir, MobileCredentialAuthority) {
        let root = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private");
        let auth = MobileCredentialAuthority::open(
            root.path().join("mobile.sqlite3"),
            "ops.example.test",
            "operator:mobile",
        )
        .expect("authority");
        (root, auth)
    }

    fn request() -> MobileOperatorProvisionRequest {
        MobileOperatorProvisionRequest {
            actions: vec![MobileAction::FollowUp, MobileAction::Attach],
            session_scope: vec!["session-b".to_owned(), "session-a".to_owned()],
            limits: MobileLimits {
                max_page_events: 128,
                max_follow_up_bytes: 4096,
            },
        }
    }

    fn platform_v2_grant(credential_id: &str) -> MobilePlatformV2GrantRequest {
        MobilePlatformV2GrantRequest {
            credential_id: credential_id.to_owned(),
            project_roots: vec!["project-b".to_owned(), "project-a".to_owned()],
            actions: vec![
                MobilePlatformV2Action::SubmitMutation,
                MobilePlatformV2Action::QueryWorkContexts,
                MobilePlatformV2Action::PrepareMutation,
                MobilePlatformV2Action::GetReviewReceipt,
                MobilePlatformV2Action::ExecuteReviewAction,
                MobilePlatformV2Action::RerunCheck,
                MobilePlatformV2Action::GetReviewCapabilities,
            ],
        }
    }

    #[test]
    fn platform_v2_grant_is_additive_sorted_bounded_and_v1_wire_stays_exact() {
        let (_root, mut auth) = authority();
        let issued = auth.operator_provision(request(), NOW).expect("provision");
        let before = serde_json::to_value(&issued).expect("v1 wire");
        let before_keys = before
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            before_keys,
            vec!["access_token", "authorization", "refresh_token"]
        );
        let descriptor = auth
            .grant_platform_v2(
                platform_v2_grant(&issued.authorization.credential_id),
                NOW + 1,
            )
            .expect("grant");
        assert_eq!(descriptor.schema, MOBILE_PLATFORM_V2_AUTH_SCHEMA);
        assert_eq!(descriptor.credential_id, issued.authorization.credential_id);
        assert_eq!(descriptor.credential_revision, 1);
        assert_eq!(descriptor.authorization_revision, 1);
        assert_eq!(descriptor.principal_generation, 1);
        assert_eq!(descriptor.tenant_id, "operator:mobile");
        assert_eq!(descriptor.actor_id, "operator:mobile");
        assert_eq!(descriptor.project_roots, vec!["project-a", "project-b"]);
        assert_eq!(
            descriptor.actions,
            vec![
                MobilePlatformV2Action::QueryWorkContexts,
                MobilePlatformV2Action::PrepareMutation,
                MobilePlatformV2Action::SubmitMutation,
                MobilePlatformV2Action::GetReviewCapabilities,
                MobilePlatformV2Action::ExecuteReviewAction,
                MobilePlatformV2Action::RerunCheck,
                MobilePlatformV2Action::GetReviewReceipt,
            ]
        );
        assert_eq!(
            auth.authorize_platform_v2(&issued.access_token, NOW + 1)
                .expect("bearer authorization"),
            descriptor
        );
        assert!(matches!(
            auth.authorize_platform_v2(&issued.access_token, descriptor.expires_at_ms),
            Err(MobileAuthError::Expired)
        ));
        assert_eq!(
            serde_json::to_value(
                auth.authorize_access(
                    &issued.access_token,
                    &issued.authorization.server_identity,
                    NOW + 1,
                )
                .expect("unchanged v1 authorization"),
            )
            .expect("v1 authorization wire"),
            before["authorization"],
        );
        assert!(matches!(
            auth.grant_platform_v2(
                MobilePlatformV2GrantRequest {
                    credential_id: issued.authorization.credential_id.clone(),
                    project_roots: (0..=MAX_MOBILE_V2_PROJECT_ROOTS)
                        .map(|index| format!("project-{index}"))
                        .collect(),
                    actions: vec![MobilePlatformV2Action::QueryWorkContexts],
                },
                NOW + 2,
            ),
            Err(MobileAuthError::InvalidRequest)
        ));
        assert_eq!(
            before["authorization"]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec![
                "actions",
                "actor",
                "authorization_revision",
                "credential_id",
                "credential_revision",
                "expires_at_ms",
                "issued_at_ms",
                "limits",
                "schema",
                "server_identity",
                "session_scope",
            ]
        );
    }

    #[test]
    fn every_platform_v2_action_remains_grantable_together() {
        let (_root, mut auth) = authority();
        let issued = auth.operator_provision(request(), NOW).expect("provision");
        let descriptor = auth
            .grant_platform_v2(
                MobilePlatformV2GrantRequest {
                    credential_id: issued.authorization.credential_id.clone(),
                    project_roots: vec!["project-a".to_owned()],
                    actions: MobilePlatformV2Action::ALL.to_vec(),
                },
                NOW + 1,
            )
            .expect("complete Platform v2 grant");
        assert_eq!(descriptor.actions, MobilePlatformV2Action::ALL.to_vec());
    }

    #[test]
    fn review_capability_and_rerun_grants_serde_persist_and_are_removed_by_narrow_regrant() {
        let (root, mut auth) = authority();
        let issued = auth.operator_provision(request(), NOW).unwrap();
        let granted = auth
            .grant_platform_v2(
                MobilePlatformV2GrantRequest {
                    credential_id: issued.authorization.credential_id.clone(),
                    project_roots: vec!["project-a".to_owned()],
                    actions: vec![
                        MobilePlatformV2Action::RerunCheck,
                        MobilePlatformV2Action::ExecuteReviewAction,
                        MobilePlatformV2Action::GetReviewCapabilities,
                    ],
                },
                NOW + 1,
            )
            .unwrap();
        assert_eq!(
            granted.actions,
            vec![
                MobilePlatformV2Action::GetReviewCapabilities,
                MobilePlatformV2Action::ExecuteReviewAction,
                MobilePlatformV2Action::RerunCheck,
            ]
        );
        let wire = serde_json::to_string(&granted).unwrap();
        assert!(wire.contains("get_review_capabilities"));
        assert!(wire.contains("rerun_check"));
        let decoded: serde_json::Value = serde_json::from_str(&wire).unwrap();
        let decoded_actions: Vec<MobilePlatformV2Action> =
            serde_json::from_value(decoded["actions"].clone()).unwrap();
        assert_eq!(decoded_actions, granted.actions);
        drop(auth);

        let mut auth = MobileCredentialAuthority::open(
            root.path().join("mobile.sqlite3"),
            "ops.example.test",
            "operator:mobile",
        )
        .unwrap();
        let reopened = auth
            .authorize_platform_v2(&issued.access_token, NOW + 2)
            .unwrap();
        assert!(reopened.allows(MobilePlatformV2Action::GetReviewCapabilities));
        assert!(reopened.allows(MobilePlatformV2Action::RerunCheck));

        let narrowed = auth
            .grant_platform_v2(
                MobilePlatformV2GrantRequest {
                    credential_id: issued.authorization.credential_id.clone(),
                    project_roots: vec!["project-a".to_owned()],
                    actions: vec![MobilePlatformV2Action::ExecuteReviewAction],
                },
                NOW + 3,
            )
            .unwrap();
        assert!(narrowed.allows(MobilePlatformV2Action::ExecuteReviewAction));
        assert!(!narrowed.allows(MobilePlatformV2Action::GetReviewCapabilities));
        assert!(!narrowed.allows(MobilePlatformV2Action::RerunCheck));
    }

    #[test]
    fn platform_v2_rotation_generation_regrant_and_revoke_are_fenced() {
        let (_root, mut auth) = authority();
        let issued = auth.operator_provision(request(), NOW).expect("provision");
        assert!(matches!(
            auth.authorize_platform_v2(&issued.access_token, NOW),
            Err(MobileAuthError::InvalidCredential)
        ));
        let first = auth
            .grant_platform_v2(
                platform_v2_grant(&issued.authorization.credential_id),
                NOW + 1,
            )
            .expect("grant");
        let mut refresh = issued.refresh_token.clone();
        let rotated = auth
            .refresh(&mut refresh, &issued.authorization.server_identity, NOW + 2)
            .expect("rotate");
        let second = auth
            .authorize_platform_v2(&rotated.access_token, NOW + 2)
            .expect("rotated descriptor");
        assert_eq!(second.credential_revision, 2);
        assert_eq!(second.authorization_revision, first.authorization_revision);
        assert_eq!(second.principal_generation, first.principal_generation + 1);
        assert_eq!(second.delegation_id, first.delegation_id);
        assert!(auth.reauthorize_platform_v2(&first, NOW + 2).is_err());

        let third = auth
            .grant_platform_v2(
                MobilePlatformV2GrantRequest {
                    credential_id: rotated.authorization.credential_id.clone(),
                    project_roots: vec!["project-a".to_owned()],
                    actions: vec![MobilePlatformV2Action::GetLineage],
                },
                NOW + 3,
            )
            .expect("regrant");
        assert_eq!(third.principal_generation, second.principal_generation + 1);
        assert_ne!(third.delegation_id, second.delegation_id);
        assert!(auth.reauthorize_platform_v2(&second, NOW + 3).is_err());

        auth.revoke_credential_id(
            MobileCredentialRevokeRequest {
                credential_id: rotated.authorization.credential_id.clone(),
            },
            NOW + 4,
        )
        .expect("revoke");
        assert!(matches!(
            auth.authorize_platform_v2(&rotated.access_token, NOW + 4),
            Err(MobileAuthError::Revoked)
        ));
    }

    #[test]
    fn platform_v2_receipt_custody_survives_restart_and_rotation_but_not_regrant() {
        let (root, mut auth) = authority();
        let first = auth.operator_provision(request(), NOW).expect("first");
        let first_descriptor = auth
            .grant_platform_v2(
                platform_v2_grant(&first.authorization.credential_id),
                NOW + 1,
            )
            .expect("first grant");
        let project = ProjectId::new("project-a").expect("project");
        auth.bind_platform_v2_receipt_custody(
            &first_descriptor,
            &project,
            "mobile:mutation:one",
            NOW + 2,
        )
        .expect("bind custody");
        let workspace = WorkContextIdentity::UserWorkspace(
            automonique_protocol::platform_v2::UserWorkspaceId::new("workspace-a").unwrap(),
        );
        let other_workspace = WorkContextIdentity::UserWorkspace(
            automonique_protocol::platform_v2::UserWorkspaceId::new("workspace-b").unwrap(),
        );
        assert!(
            auth.authorize_platform_v2_review_receipt_custody(
                &first_descriptor,
                &project,
                &workspace,
                "mobile:mutation:one",
                NOW + 2,
            )
            .is_err()
        );
        auth.bind_platform_v2_review_receipt_custody(
            &first_descriptor,
            &project,
            &workspace,
            "mobile:review:one",
            NOW + 2,
        )
        .expect("bind exact review custody");
        assert!(
            auth.authorize_platform_v2_review_receipt_custody(
                &first_descriptor,
                &project,
                &other_workspace,
                "mobile:review:one",
                NOW + 2,
            )
            .is_err()
        );
        assert!(matches!(
            auth.acquire_platform_v2_dispatch(
                &first_descriptor,
                MobilePlatformV2ReceiptCustody::BindMutation {
                    project: &project,
                    idempotency_key: "mobile:mutation:one",
                },
                b"different submit request",
                NOW + 2,
            ),
            Err(MobileAuthError::InvalidCredential)
        ));
        auth.authorize_platform_v2_receipt_custody(
            &first_descriptor,
            &project,
            "mobile:mutation:one",
            NOW + 2,
        )
        .expect("same generation owns custody");

        drop(auth);
        let mut auth = MobileCredentialAuthority::open(
            root.path().join("mobile.sqlite3"),
            "ops.example.test",
            "operator:mobile",
        )
        .expect("restart");
        auth.authorize_platform_v2_receipt_custody(
            &first_descriptor,
            &project,
            "mobile:mutation:one",
            NOW + 3,
        )
        .expect("durable custody");

        let second = auth.operator_provision(request(), NOW + 3).expect("second");
        let second_descriptor = auth
            .grant_platform_v2(
                platform_v2_grant(&second.authorization.credential_id),
                NOW + 4,
            )
            .expect("second grant");
        assert!(
            auth.authorize_platform_v2_receipt_custody(
                &second_descriptor,
                &project,
                "mobile:mutation:one",
                NOW + 4,
            )
            .is_err()
        );
        assert!(
            auth.authorize_platform_v2_review_receipt_custody(
                &second_descriptor,
                &project,
                &workspace,
                "mobile:review:one",
                NOW + 4,
            )
            .is_err()
        );

        let mut refresh = first.refresh_token.clone();
        let rotated = auth
            .refresh(&mut refresh, &first.authorization.server_identity, NOW + 5)
            .expect("rotate first");
        let rotated_descriptor = auth
            .authorize_platform_v2(&rotated.access_token, NOW + 5)
            .expect("rotated descriptor");
        assert_eq!(
            rotated_descriptor.principal_generation,
            first_descriptor.principal_generation + 1
        );
        auth.authorize_platform_v2_receipt_custody(
            &rotated_descriptor,
            &project,
            "mobile:mutation:one",
            NOW + 5,
        )
        .expect("same delegation rotation retains custody");

        let regranted = auth
            .grant_platform_v2(
                platform_v2_grant(&rotated.authorization.credential_id),
                NOW + 6,
            )
            .expect("regrant");
        assert_ne!(regranted.delegation_id, rotated_descriptor.delegation_id);
        assert!(
            auth.authorize_platform_v2_receipt_custody(
                &regranted,
                &project,
                "mobile:mutation:one",
                NOW + 6,
            )
            .is_err()
        );
        assert!(
            auth.authorize_platform_v2_review_receipt_custody(
                &regranted,
                &project,
                &workspace,
                "mobile:review:one",
                NOW + 6,
            )
            .is_err()
        );
        for index in 0..MAX_MOBILE_V2_RECEIPT_CUSTODY {
            auth.bind_platform_v2_receipt_custody(
                &regranted,
                &project,
                &format!("mobile:bounded:{index}"),
                NOW + 7,
            )
            .expect("bounded custody entry");
        }
        assert!(matches!(
            auth.bind_platform_v2_receipt_custody(
                &regranted,
                &project,
                "mobile:bounded:overflow",
                NOW + 7,
            ),
            Err(MobileAuthError::InvalidRequest)
        ));
        auth.revoke_credential_id(
            MobileCredentialRevokeRequest {
                credential_id: rotated.authorization.credential_id.clone(),
            },
            NOW + 8,
        )
        .expect("revoke");
        assert_eq!(
            auth.connection
                .query_row(
                    "SELECT COUNT(*) FROM mobile_platform_v2_exact_receipt_custody",
                    [],
                    |row| row.get::<_, u64>(0),
                )
                .expect("custody count"),
            0
        );
    }

    #[test]
    fn correlated_review_receipt_custody_survives_restart_and_refuses_substitution() {
        let (root, mut auth) = authority();
        let issued = auth.operator_provision(request(), NOW).expect("provision");
        let descriptor = auth
            .grant_platform_v2(
                platform_v2_grant(&issued.authorization.credential_id),
                NOW + 1,
            )
            .expect("grant");
        let project = ProjectId::new("project-a").unwrap();
        let workspace = WorkContextIdentity::UserWorkspace(
            automonique_protocol::platform_v2::UserWorkspaceId::new("workspace-a").unwrap(),
        );
        let correlation = "ab".repeat(32);
        let lease = auth
            .acquire_platform_v2_dispatch(
                &descriptor,
                MobilePlatformV2ReceiptCustody::BindReview {
                    project: &project,
                    workspace: &workspace,
                    idempotency_key: "mobile:review:correlated",
                    receipt_correlation_digest: Some(&correlation),
                },
                b"confirmed github request",
                NOW + 2,
            )
            .expect("bind correlated custody");
        auth.release_platform_v2_dispatch(&lease).unwrap();
        drop(auth);

        let mut auth = MobileCredentialAuthority::open(
            root.path().join("mobile.sqlite3"),
            "ops.example.test",
            "operator:mobile",
        )
        .unwrap();
        let descriptor = auth
            .authorize_platform_v2(&issued.access_token, NOW + 3)
            .unwrap();
        for substituted in [
            None,
            Some("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"),
        ] {
            assert!(matches!(
                auth.acquire_platform_v2_dispatch(
                    &descriptor,
                    MobilePlatformV2ReceiptCustody::ReadReview {
                        project: &project,
                        workspace: &workspace,
                        idempotency_key: "mobile:review:correlated",
                        receipt_correlation_digest: substituted,
                    },
                    b"lookup",
                    NOW + 3,
                ),
                Err(MobileAuthError::InvalidCredential)
            ));
        }
        let lease = auth
            .acquire_platform_v2_dispatch(
                &descriptor,
                MobilePlatformV2ReceiptCustody::ReadReview {
                    project: &project,
                    workspace: &workspace,
                    idempotency_key: "mobile:review:correlated",
                    receipt_correlation_digest: Some(&correlation),
                },
                b"lookup",
                NOW + 3,
            )
            .expect("exact correlated recovery");
        auth.release_platform_v2_dispatch(&lease).unwrap();
    }

    #[test]
    fn legacy_receipt_custody_rows_fail_closed_after_exact_schema_migration() {
        let (root, mut auth) = authority();
        let issued = auth.operator_provision(request(), NOW).expect("credential");
        let authorization = auth
            .grant_platform_v2(
                platform_v2_grant(&issued.authorization.credential_id),
                NOW + 1,
            )
            .expect("grant");
        let project = ProjectId::new("project-a").unwrap();
        auth.connection
            .execute(
                "INSERT INTO mobile_platform_v2_receipt_custody(
                   project_id,idempotency_key,credential_id,delegation_id,
                   principal_generation,created_at_ms,expires_at_ms
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![
                    project.as_str(),
                    "mobile:legacy:one",
                    authorization.credential_id,
                    authorization.delegation_id,
                    authorization.principal_generation,
                    NOW + 1,
                    authorization.expires_at_ms,
                ],
            )
            .expect("legacy custody");
        auth.connection
            .execute_batch("DROP TABLE mobile_platform_v2_exact_receipt_custody;")
            .expect("simulate prior schema");
        drop(auth);

        let mut reopened = MobileCredentialAuthority::open(
            root.path().join("mobile.sqlite3"),
            "ops.example.test",
            "operator:mobile",
        )
        .expect("restart-safe additive migration");
        assert!(
            reopened
                .authorize_platform_v2_receipt_custody(
                    &authorization,
                    &project,
                    "mobile:legacy:one",
                    NOW + 2,
                )
                .is_err()
        );
    }

    #[test]
    fn platform_v2_grant_rejects_a_v1_credential_owned_by_the_old_actor() {
        let (root, mut auth) = authority();
        let issued = auth.operator_provision(request(), NOW).expect("credential");
        drop(auth);

        let mut changed_actor = MobileCredentialAuthority::open(
            root.path().join("mobile.sqlite3"),
            "ops.example.test",
            "operator:replacement",
        )
        .expect("changed actor configuration");
        assert!(matches!(
            changed_actor.grant_platform_v2(
                platform_v2_grant(&issued.authorization.credential_id),
                NOW + 1,
            ),
            Err(MobileAuthError::InvalidCredential)
        ));
    }

    #[test]
    fn additive_platform_v2_table_is_bootstrapped_for_an_existing_v1_store() {
        let (root, mut auth) = authority();
        let issued = auth
            .operator_provision(request(), NOW)
            .expect("v1 credential");
        auth.connection
            .execute_batch(
                "DROP TABLE mobile_platform_v2_dispatch_leases;
                 DROP TABLE mobile_platform_v2_exact_receipt_custody;
                 DROP TABLE mobile_platform_v2_receipt_requests;
                 DROP TABLE mobile_platform_v2_receipt_custody;
                 DROP TABLE mobile_platform_v2_authorizations;",
            )
            .expect("simulate pre-v2 schema");
        drop(auth);
        let mut reopened = MobileCredentialAuthority::open(
            root.path().join("mobile.sqlite3"),
            "ops.example.test",
            "operator:mobile",
        )
        .expect("additive migration");
        reopened
            .grant_platform_v2(
                platform_v2_grant(&issued.authorization.credential_id),
                NOW + 1,
            )
            .expect("new table accepts existing v1 credential");
    }

    #[test]
    fn discovery_is_https_origin_bound_and_stable() {
        let (_root, auth) = authority();
        assert_eq!(auth.discovery().origin, "https://ops.example.test");
        assert_eq!(
            auth.discovery().platform_endpoint,
            "https://ops.example.test/api/platform"
        );
        assert_eq!(
            auth.discovery().operator_provision_endpoint,
            "https://ops.example.test/api/mobile/operator-provision"
        );
        assert_eq!(
            auth.discovery().pairing_create_endpoint,
            "https://ops.example.test/api/mobile/pairings"
        );
        assert_eq!(
            auth.discovery().pairing_exchange_endpoint,
            "https://ops.example.test/api/mobile/pairings/exchange"
        );
        assert_eq!(
            auth.discovery().credential_inventory_endpoint,
            "https://ops.example.test/api/mobile/credentials/list"
        );
        assert_eq!(
            auth.discovery().credential_revoke_endpoint,
            "https://ops.example.test/api/mobile/credentials/revoke"
        );
        assert!(auth.discovery().server_identity.starts_with("sha256:"));
        let first = auth.discovery().server_identity.clone();
        let deterministic_origin_hash = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                b"automonique.mobile-server/v1\0https://ops.example.test"
            ))
        );
        assert_ne!(first, deterministic_origin_hash);
        drop(auth);
        let auth = MobileCredentialAuthority::open(
            _root.path().join("mobile.sqlite3"),
            "ops.example.test",
            "operator:mobile",
        )
        .expect("reopen");
        assert_eq!(auth.discovery().server_identity, first);
        drop(auth);
        assert!(matches!(
            MobileCredentialAuthority::open(
                _root.path().join("mobile.sqlite3"),
                "other.example.test",
                "operator:mobile",
            ),
            Err(MobileAuthError::ServerIdentityMismatch)
        ));
    }

    /// What the server advertises is the shared support range, not a literal.
    ///
    /// A client admits this server on the highest version the two sets share,
    /// so the advertisement and the range a client intersects against have to
    /// be one fact. Written against the constants rather than against `[1]` so
    /// it keeps checking the rule once the protocol widens.
    #[test]
    fn discovery_advertises_every_version_this_build_speaks() {
        let (_root, auth) = authority();
        let advertised = &auth.discovery().supported_versions;
        assert_eq!(advertised, &supported_mobile_protocol_versions());
        assert!(!advertised.is_empty());
        assert_eq!(
            advertised.first().copied(),
            Some(automonique_protocol::codegen::MIN_SUPPORTED_MOBILE_PROTOCOL_VERSION)
        );
        assert_eq!(
            advertised.last().copied(),
            Some(automonique_protocol::codegen::MAX_SUPPORTED_MOBILE_PROTOCOL_VERSION)
        );
        assert!(advertised.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(advertised.len() <= automonique_protocol::codegen::MAX_MOBILE_PROTOCOL_VERSIONS);
        let encoded = serde_json::to_value(auth.discovery()).expect("discovery serializes");
        assert_eq!(
            encoded["supported_versions"],
            serde_json::json!(supported_mobile_protocol_versions())
        );
    }

    #[test]
    fn issue_stores_only_hashes_and_returns_an_exact_descriptor() {
        let (_root, mut auth) = authority();
        let issued = auth.operator_provision(request(), NOW).expect("provision");
        let debug = format!("{issued:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&issued.access_token));
        assert!(!debug.contains(&issued.refresh_token));
        let refresh_debug = format!(
            "{:?}",
            MobileRefreshRequest {
                refresh_token: issued.refresh_token.clone(),
                server_identity: issued.authorization.server_identity.clone(),
            }
        );
        assert!(refresh_debug.contains("<redacted>"));
        assert!(!refresh_debug.contains(&issued.refresh_token));
        assert_eq!(issued.authorization.actor, "operator:mobile");
        assert_eq!(issued.authorization.credential_revision, 1);
        assert_eq!(
            issued.authorization.actions,
            vec![MobileAction::Attach, MobileAction::FollowUp]
        );
        assert_eq!(
            issued.authorization.session_scope,
            vec!["session-a", "session-b"]
        );
        let bytes = fs::read(auth.path()).expect("database bytes");
        assert!(
            !bytes
                .windows(issued.access_token.len())
                .any(|window| window == issued.access_token.as_bytes())
        );
        assert!(
            !bytes
                .windows(issued.refresh_token.len())
                .any(|window| window == issued.refresh_token.as_bytes())
        );
        assert_eq!(
            auth.authorize_access(
                &issued.access_token,
                &issued.authorization.server_identity,
                NOW
            )
            .expect("authorize"),
            issued.authorization
        );
    }

    #[test]
    fn refresh_replay_revokes_the_rotated_successor_family() {
        let (_root, mut auth) = authority();
        let issued = auth.operator_provision(request(), NOW).expect("provision");
        let old_access = issued.access_token.clone();
        let mut old_refresh = issued.refresh_token.clone();
        let replay = issued.refresh_token.clone();
        let refreshed = auth
            .refresh(
                &mut old_refresh,
                &issued.authorization.server_identity,
                NOW + 1,
            )
            .expect("refresh");
        assert!(old_refresh.bytes().all(|byte| byte == 0));
        assert_eq!(refreshed.authorization.credential_revision, 2);
        assert!(matches!(
            auth.authorize_access(&old_access, &issued.authorization.server_identity, NOW + 1),
            Err(MobileAuthError::InvalidCredential)
        ));
        let mut unknown = random_token("mr").expect("unknown refresh");
        assert!(matches!(
            auth.refresh(&mut unknown, &issued.authorization.server_identity, NOW + 2),
            Err(MobileAuthError::InvalidCredential)
        ));
        assert!(
            auth.authorize_access(
                &refreshed.access_token,
                &issued.authorization.server_identity,
                NOW + 2
            )
            .is_ok()
        );
        let mut replay = replay;
        assert!(matches!(
            auth.refresh(&mut replay, &issued.authorization.server_identity, NOW + 3),
            Err(MobileAuthError::InvalidCredential)
        ));
        assert!(matches!(
            auth.authorize_access(
                &refreshed.access_token,
                &issued.authorization.server_identity,
                NOW + 3
            ),
            Err(MobileAuthError::Revoked)
        ));
    }

    #[test]
    fn concurrent_refresh_replay_yields_one_success_and_revokes_its_successor() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let (root, mut auth) = authority();
        let issued = auth.operator_provision(request(), NOW).expect("provision");
        let path = auth.path().to_path_buf();
        let server_identity = issued.authorization.server_identity.clone();
        let refresh = issued.refresh_token.clone();
        drop(auth);
        let barrier = Arc::new(Barrier::new(2));
        let workers = (0..2)
            .map(|offset| {
                let path = path.clone();
                let server_identity = server_identity.clone();
                let mut refresh = refresh.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut authority = MobileCredentialAuthority::open(
                        path,
                        "ops.example.test",
                        "operator:mobile",
                    )
                    .expect("authority");
                    barrier.wait();
                    authority.refresh(&mut refresh, &server_identity, NOW + offset + 1)
                })
            })
            .collect::<Vec<_>>();
        let mut successor = None;
        let mut replays = 0;
        for worker in workers {
            match worker.join().expect("worker") {
                Ok(issued) => successor = Some(issued),
                Err(MobileAuthError::InvalidCredential) => replays += 1,
                Err(error) => panic!("unexpected refresh result: {error}"),
            }
        }
        assert_eq!(replays, 1);
        let successor = successor.expect("one refresh succeeded");
        let authority = MobileCredentialAuthority::open(
            root.path().join("mobile.sqlite3"),
            "ops.example.test",
            "operator:mobile",
        )
        .expect("authority");
        assert!(matches!(
            authority.authorize_access(&successor.access_token, &server_identity, NOW + 3),
            Err(MobileAuthError::Revoked)
        ));
    }

    #[test]
    fn refresh_replay_tombstone_survives_authority_reopen() {
        let (root, mut auth) = authority();
        let issued = auth.operator_provision(request(), NOW).expect("provision");
        let server_identity = issued.authorization.server_identity.clone();
        let replay = issued.refresh_token.clone();
        let mut refresh = issued.refresh_token.clone();
        let successor = auth
            .refresh(&mut refresh, &server_identity, NOW + 1)
            .expect("rotate");
        drop(auth);

        let mut reopened = MobileCredentialAuthority::open(
            root.path().join("mobile.sqlite3"),
            "ops.example.test",
            "operator:mobile",
        )
        .expect("reopen");
        let mut replay = replay;
        assert!(matches!(
            reopened.refresh(&mut replay, &server_identity, NOW + 2),
            Err(MobileAuthError::InvalidCredential)
        ));
        assert!(matches!(
            reopened.authorize_access(&successor.access_token, &server_identity, NOW + 2),
            Err(MobileAuthError::Revoked)
        ));
    }

    #[test]
    fn refresh_expiry_is_absolute_and_retired_family_cleanup_cascades_history() {
        let (_root, mut auth) = authority();
        let issued = auth.operator_provision(request(), NOW).expect("provision");
        let mut first_refresh = issued.refresh_token.clone();
        let refreshed = auth
            .refresh(
                &mut first_refresh,
                &issued.authorization.server_identity,
                NOW + 1,
            )
            .expect("refresh");
        let mut at_original_boundary = refreshed.refresh_token.clone();
        assert!(matches!(
            auth.refresh(
                &mut at_original_boundary,
                &issued.authorization.server_identity,
                NOW + REFRESH_TTL_MILLIS,
            ),
            Err(MobileAuthError::Expired)
        ));

        let mut revoke = refreshed.refresh_token.clone();
        auth.revoke(&mut revoke, &issued.authorization.server_identity, NOW + 2)
            .expect("revoke");
        assert_eq!(
            auth.connection
                .query_row("SELECT COUNT(*) FROM mobile_refresh_history", [], |row| {
                    row.get::<_, u64>(0)
                })
                .expect("history count"),
            1
        );
        auth.operator_provision(request(), NOW + 3 + REVOKED_FAMILY_RETENTION_MILLIS)
            .expect("cleanup-triggering provision");
        assert_eq!(
            auth.connection
                .query_row("SELECT COUNT(*) FROM mobile_credentials", [], |row| {
                    row.get::<_, u64>(0)
                })
                .expect("credential count"),
            1
        );
        assert_eq!(
            auth.connection
                .query_row("SELECT COUNT(*) FROM mobile_refresh_history", [], |row| {
                    row.get::<_, u64>(0)
                })
                .expect("history count"),
            0
        );
    }

    #[test]
    fn refresh_near_the_absolute_boundary_caps_the_access_expiry() {
        let (_root, mut auth) = authority();
        let issued = auth.operator_provision(request(), NOW).expect("provision");
        let mut refresh = issued.refresh_token.clone();
        let near_boundary = NOW + REFRESH_TTL_MILLIS - 1;
        let refreshed = auth
            .refresh(
                &mut refresh,
                &issued.authorization.server_identity,
                near_boundary,
            )
            .expect("near-boundary refresh");
        assert_eq!(
            refreshed.authorization.expires_at_ms,
            NOW + REFRESH_TTL_MILLIS
        );
        assert!(
            auth.authorize_access(
                &refreshed.access_token,
                &issued.authorization.server_identity,
                near_boundary,
            )
            .is_ok()
        );
        assert!(matches!(
            auth.authorize_access(
                &refreshed.access_token,
                &issued.authorization.server_identity,
                NOW + REFRESH_TTL_MILLIS,
            ),
            Err(MobileAuthError::Expired)
        ));
    }

    #[test]
    fn expiry_identity_mismatch_and_revocation_fail_closed() {
        let (_root, mut auth) = authority();
        let issued = auth.operator_provision(request(), NOW).expect("provision");
        assert!(matches!(
            auth.authorize_access("malformed", &issued.authorization.server_identity, NOW),
            Err(MobileAuthError::InvalidCredential)
        ));
        let absent = random_token("ma").expect("random access token");
        assert!(matches!(
            auth.authorize_access(&absent, &issued.authorization.server_identity, NOW),
            Err(MobileAuthError::InvalidCredential)
        ));
        assert!(matches!(
            auth.authorize_access(&issued.access_token, "sha256:wrong", NOW),
            Err(MobileAuthError::ServerIdentityMismatch)
        ));
        assert!(matches!(
            auth.authorize_access(
                &issued.access_token,
                &issued.authorization.server_identity,
                NOW + ACCESS_TTL_MILLIS
            ),
            Err(MobileAuthError::Expired)
        ));
        let mut refresh = issued.refresh_token.clone();
        auth.revoke(&mut refresh, &issued.authorization.server_identity, NOW + 1)
            .expect("revoke");
        assert!(matches!(
            auth.authorize_access(
                &issued.access_token,
                &issued.authorization.server_identity,
                NOW + 1
            ),
            Err(MobileAuthError::Revoked)
        ));
    }

    #[test]
    fn lifecycle_secret_inputs_are_guarded_before_early_refusal() {
        fn requires_zeroizing_string(_: &Zeroizing<String>) {}

        let generated = random_secret_token("mr").expect("guarded generated secret");
        requires_zeroizing_string(&generated);

        let (_root, mut auth) = authority();
        let identity = auth.discovery().server_identity.clone();

        let mut malformed_refresh = String::from("malformed");
        assert!(matches!(
            auth.refresh(&mut malformed_refresh, &identity, NOW),
            Err(MobileAuthError::InvalidCredential)
        ));
        assert!(malformed_refresh.is_empty());

        let mut identity_mismatch = random_token("mr").expect("valid-shaped refresh");
        assert!(matches!(
            auth.refresh(
                &mut identity_mismatch,
                &format!("sha256:{}", "f".repeat(64)),
                NOW,
            ),
            Err(MobileAuthError::ServerIdentityMismatch)
        ));
        assert!(identity_mismatch.is_empty());

        let mut malformed_revoke = String::from("malformed");
        assert!(matches!(
            auth.revoke(&mut malformed_revoke, &identity, NOW),
            Err(MobileAuthError::InvalidCredential)
        ));
        assert!(malformed_revoke.is_empty());
    }

    #[test]
    fn malformed_duplicate_and_oversized_scope_is_refused() {
        let (_root, mut auth) = authority();
        let mut duplicate = request();
        duplicate.actions.push(MobileAction::Attach);
        assert!(
            auth.operator_provision(duplicate, NOW).is_ok(),
            "duplicate grants collapse"
        );
        let mut invalid = request();
        invalid.session_scope = vec!["bad/session".to_owned()];
        assert!(matches!(
            auth.operator_provision(invalid, NOW),
            Err(MobileAuthError::InvalidRequest)
        ));
        let mut oversized = request();
        oversized.limits.max_page_events = MAX_PAGE_EVENTS + 1;
        assert!(matches!(
            auth.operator_provision(oversized, NOW),
            Err(MobileAuthError::InvalidRequest)
        ));
        let mut dedicated = request();
        dedicated.actions = vec![MobileAction::StopRun, MobileAction::DecideApproval];
        assert!(auth.operator_provision(dedicated, NOW).is_ok());
    }

    #[test]
    fn platform_policy_is_per_action_per_session_and_fail_closed() {
        let (_root, mut auth) = authority();
        let mut all_commands = request();
        all_commands.actions = vec![
            MobileAction::Attach,
            MobileAction::FollowUp,
            MobileAction::StopRun,
            MobileAction::DecideApproval,
        ];
        let issued = auth
            .operator_provision(all_commands, NOW)
            .expect("provision");
        let session = |id: &str| {
            ResourceCoordinate::new(
                ResourceAuthority::Automonique,
                ResourceKind::Session,
                ResourceId::new(id).expect("id"),
            )
        };
        let attach = PlatformRequest::Attach(AttachRequest {
            session: session("session-a"),
            client: ClientId::new(&issued.authorization.credential_id).expect("client"),
        });
        assert!(authorize_platform_request(&issued.authorization, &attach, NOW).is_ok());
        let wrong_client = PlatformRequest::Attach(AttachRequest {
            session: session("session-a"),
            client: ClientId::new("mobile-1").expect("client"),
        });
        assert!(authorize_platform_request(&issued.authorization, &wrong_client, NOW).is_err());
        let wrong_authority = PlatformRequest::Attach(AttachRequest {
            session: ResourceCoordinate::new(
                ResourceAuthority::Provider,
                ResourceKind::Session,
                ResourceId::new("session-a").expect("id"),
            ),
            client: ClientId::new(&issued.authorization.credential_id).expect("client"),
        });
        assert!(authorize_platform_request(&issued.authorization, &wrong_authority, NOW).is_err());
        let detach = PlatformRequest::Detach(DetachRequest {
            session: session("session-a"),
            client: ClientId::new(&issued.authorization.credential_id).expect("client"),
        });
        assert!(authorize_platform_request(&issued.authorization, &detach, NOW).is_ok());
        let confused_detach = PlatformRequest::Detach(DetachRequest {
            session: ResourceCoordinate::new(
                ResourceAuthority::Provider,
                ResourceKind::Session,
                ResourceId::new("session-a").expect("id"),
            ),
            client: ClientId::new("mobile-1").expect("client"),
        });
        assert!(authorize_platform_request(&issued.authorization, &confused_detach, NOW).is_err());
        let other = PlatformRequest::Attach(AttachRequest {
            session: session("session-c"),
            client: ClientId::new(&issued.authorization.credential_id).expect("client"),
        });
        assert!(authorize_platform_request(&issued.authorization, &other, NOW).is_err());
        let follow_up = PlatformRequest::Execute(
            ExecuteRequest::new_with_parameter(
                PlatformAction::FollowUp,
                session("session-a"),
                IdempotencyKey::new("key-1").expect("key"),
                Some(Revision::new(1).expect("revision")),
                Some(PlatformParameter::new("continue").expect("parameter")),
            )
            .expect("execute")
            .with_client(ClientId::new(&issued.authorization.credential_id).expect("client")),
        );
        assert!(authorize_platform_request(&issued.authorization, &follow_up, NOW).is_err());

        let client = ClientId::new(&issued.authorization.credential_id).expect("client");
        let command_state = PlatformRequest::SessionCommandState(SessionCommandStateRequest {
            session: session("session-a"),
        });
        assert!(authorize_platform_request(&issued.authorization, &command_state, NOW).is_ok());
        let follow_up = PlatformRequest::SessionFollowUp(SessionFollowUpRequest {
            client: client.clone(),
            session: session("session-a"),
            expected_session_revision: Revision::new(1).expect("revision"),
            idempotency_key: IdempotencyKey::new("key-follow-up").expect("key"),
            text: PlatformParameter::new("continue").expect("text"),
        });
        assert!(authorize_platform_request(&issued.authorization, &follow_up, NOW).is_ok());
        let run = ResourceCoordinate::new(
            ResourceAuthority::Automonique,
            ResourceKind::Run,
            ResourceId::new("run-a").expect("run"),
        );
        let stop = PlatformRequest::SessionRunStop(SessionRunStopRequest {
            client: client.clone(),
            session: session("session-a"),
            expected_session_revision: Revision::new(1).expect("revision"),
            run,
            expected_run_revision: Revision::new(2).expect("revision"),
            idempotency_key: IdempotencyKey::new("key-stop").expect("key"),
        });
        assert!(authorize_platform_request(&issued.authorization, &stop, NOW).is_ok());
        let approval = ResourceCoordinate::new(
            ResourceAuthority::Automonique,
            ResourceKind::Approval,
            ResourceId::new("approval-a").expect("approval"),
        );
        let decide = PlatformRequest::SessionApprovalDecision(SessionApprovalDecisionRequest {
            client,
            session: session("session-a"),
            expected_session_revision: Revision::new(1).expect("revision"),
            approval,
            expected_approval_revision: Revision::new(3).expect("revision"),
            idempotency_key: IdempotencyKey::new("key-decide").expect("key"),
            decision: SessionApprovalDecision::Grant,
        });
        assert!(authorize_platform_request(&issued.authorization, &decide, NOW).is_ok());

        let receipt = |client: ClientId| {
            PlatformRequest::GetReceipt(GetReceiptRequest {
                client: Some(client),
                id: Some(ReceiptId::new("receipt-a").expect("receipt")),
                idempotency_key: None,
            })
        };
        assert!(
            authorize_platform_request(
                &issued.authorization,
                &receipt(
                    ClientId::new(&issued.authorization.credential_id).expect("credential client")
                ),
                NOW,
            )
            .is_ok()
        );
        assert!(
            authorize_platform_request(
                &issued.authorization,
                &receipt(ClientId::new("another-client").expect("foreign client")),
                NOW,
            )
            .is_err()
        );

        let mut restrictive = issued.authorization.clone();
        restrictive.limits.max_follow_up_bytes = 8;
        let oversized_follow_up = PlatformRequest::SessionFollowUp(SessionFollowUpRequest {
            client: ClientId::new(&issued.authorization.credential_id).expect("client"),
            session: session("session-a"),
            expected_session_revision: Revision::new(1).expect("revision"),
            idempotency_key: IdempotencyKey::new("key-2").expect("key"),
            text: PlatformParameter::new("continued").expect("bounded parameter"),
        });
        assert!(authorize_platform_request(&restrictive, &oversized_follow_up, NOW).is_err());
        assert!(
            authorize_platform_request(
                &issued.authorization,
                &PlatformRequest::Snapshot(
                    automonique_protocol::platform::SnapshotRequest::new(Vec::new())
                        .expect("snapshot")
                ),
                NOW
            )
            .is_err()
        );
    }

    #[test]
    fn session_discovery_is_filtered_to_the_exact_actor_scope() {
        let (_root, mut auth) = authority();
        let issued = auth.operator_provision(request(), NOW).expect("provision");
        let record = |authority: ResourceAuthority, id: &str, revision: u64| SessionRecord {
            session: ResourceRecord {
                resource: ResourceCoordinate::new(
                    authority,
                    ResourceKind::Session,
                    ResourceId::new(id).expect("id"),
                ),
                freshness: Freshness {
                    state: FreshnessState::Fresh,
                    observed_at: EpochMillis::from_millis(NOW),
                    revision: Revision::new(revision).expect("revision"),
                },
                summary: PlatformText::new("safe summary").expect("summary"),
            },
            run: None,
            attachable: true,
            controllable: false,
        };
        let sessions = SessionList::new(
            vec![
                record(ResourceAuthority::Automonique, "session-a", 1),
                record(ResourceAuthority::Provider, "session-a", 2),
                record(ResourceAuthority::Automonique, "session-c", 3),
            ],
            PlatformCursor {
                authority: ResourceAuthority::Automonique,
                topic: CursorTopic::new("sessions").expect("topic"),
                sequence: Revision::new(3).expect("revision"),
            },
        )
        .expect("session list");

        let filtered = filter_sessions(&issued.authorization, sessions);
        assert_eq!(filtered.sessions.len(), 1);
        assert_eq!(
            filtered.sessions[0].session.resource.id.as_str(),
            "session-a"
        );
    }

    #[test]
    fn dedicated_command_policy_enforces_client_scope_expiry_and_exact_utf8_bytes() {
        let (_root, mut auth) = authority();
        let mut provision = request();
        provision.actions = vec![MobileAction::FollowUp];
        provision.limits.max_follow_up_bytes = 4;
        let issued = auth.operator_provision(provision, NOW).expect("provision");
        let session = |id: &str| {
            ResourceCoordinate::new(
                ResourceAuthority::Automonique,
                ResourceKind::Session,
                ResourceId::new(id).expect("session"),
            )
        };
        let command = |client: ClientId, session: ResourceCoordinate, text: &str| {
            PlatformRequest::SessionFollowUp(SessionFollowUpRequest {
                client,
                session,
                expected_session_revision: Revision::new(1).expect("revision"),
                idempotency_key: IdempotencyKey::new(format!("key-{}", text.len())).expect("key"),
                text: PlatformParameter::new(text).expect("text"),
            })
        };
        let client = ClientId::new(&issued.authorization.credential_id).expect("client");
        assert!(
            authorize_platform_request(
                &issued.authorization,
                &command(client.clone(), session("session-a"), "éé"),
                NOW,
            )
            .is_ok()
        );
        assert!(
            authorize_platform_request(
                &issued.authorization,
                &command(client.clone(), session("session-a"), "ééa"),
                NOW,
            )
            .is_err()
        );
        assert!(
            authorize_platform_request(
                &issued.authorization,
                &command(client.clone(), session("session-a"), "   "),
                NOW,
            )
            .is_err()
        );
        assert!(
            authorize_platform_request(
                &issued.authorization,
                &command(
                    ClientId::new("different-client").expect("client"),
                    session("session-a"),
                    "ok",
                ),
                NOW,
            )
            .is_err()
        );
        assert!(
            authorize_platform_request(
                &issued.authorization,
                &command(client.clone(), session("session-c"), "ok"),
                NOW,
            )
            .is_err()
        );
        assert!(
            authorize_platform_request(
                &issued.authorization,
                &command(client, session("session-a"), "ok"),
                NOW + ACCESS_TTL_MILLIS,
            )
            .is_err()
        );
    }

    #[test]
    fn command_state_projection_hides_targets_without_their_independent_grants() {
        let (_root, mut auth) = authority();
        let issued = auth.operator_provision(request(), NOW).expect("provision");
        let coordinate = |kind: ResourceKind, id: &str| {
            ResourceCoordinate::new(
                ResourceAuthority::Automonique,
                kind,
                ResourceId::new(id).expect("id"),
            )
        };
        let state = SessionCommandState::new(
            ResourceRecord {
                resource: coordinate(ResourceKind::Session, "session-a"),
                freshness: Freshness {
                    state: FreshnessState::Fresh,
                    observed_at: EpochMillis::from_millis(NOW),
                    revision: Revision::new(1).expect("revision"),
                },
                summary: PlatformText::new("open").expect("summary"),
            },
            Some(SessionCommandTarget {
                target: coordinate(ResourceKind::Run, "run-a"),
                revision: Revision::new(2).expect("revision"),
            }),
            vec![SessionCommandTarget {
                target: coordinate(ResourceKind::Approval, "approval-a"),
                revision: Revision::new(3).expect("revision"),
            }],
        )
        .expect("state");
        let filtered = filter_command_state(&issued.authorization, state);
        assert!(filtered.run.is_none());
        assert!(filtered.pending_approvals.is_empty());
    }

    #[test]
    fn strict_request_json_rejects_unknown_fields() {
        let value = r#"{"actions":["attach"],"session_scope":[],"limits":{"max_page_events":1,"max_follow_up_bytes":1},"token":"secret"}"#;
        assert!(serde_json::from_str::<MobileOperatorProvisionRequest>(value).is_err());
        assert!(
            serde_json::from_str::<MobileCredentialInventoryRequest>(r#"{"page_size":10}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<MobileCredentialInventoryRequest>(
                r#"{"cursor":null,"page_size":10,"unexpected":true}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<MobilePairingExchangeRequest>(
                r#"{"pairing_id":"pi_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","pairing_token":"mp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","server_identity":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","unexpected":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn pairing_is_digest_only_restart_safe_single_use_and_boundary_exact() {
        let (root, mut auth) = authority();
        let offer = auth.create_pairing(request(), NOW).expect("pairing");
        assert_eq!(offer.expires_at_ms, NOW + PAIRING_TTL_MILLIS);
        assert_eq!(offer.origin, "https://ops.example.test");
        assert_eq!(
            offer.exchange_endpoint,
            "https://ops.example.test/api/mobile/pairings/exchange"
        );
        let token = offer.pairing_token.clone();
        let pairing_id = offer.pairing_id.clone();
        let identity = offer.server_identity.clone();
        let debug = format!("{offer:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&token));
        drop(auth);

        for entry in fs::read_dir(root.path()).expect("credential store files") {
            let entry = entry.expect("store entry");
            if entry.file_type().expect("entry type").is_file() {
                let bytes = fs::read(entry.path()).expect("store bytes");
                assert!(
                    !bytes
                        .windows(token.len())
                        .any(|window| window == token.as_bytes())
                );
            }
        }

        let mut changed_actor = MobileCredentialAuthority::open(
            root.path().join("mobile.sqlite3"),
            "ops.example.test",
            "operator:changed",
        )
        .expect("changed-actor reopen");
        let mut actor_confusion = MobilePairingExchangeRequest {
            pairing_id: pairing_id.clone(),
            pairing_token: token.clone(),
            server_identity: identity.clone(),
        };
        assert!(matches!(
            changed_actor.exchange_pairing(&mut actor_confusion, NOW + 1),
            Err(MobileAuthError::InvalidPairing)
        ));
        drop(changed_actor);

        let mut reopened = MobileCredentialAuthority::open(
            root.path().join("mobile.sqlite3"),
            "ops.example.test",
            "operator:mobile",
        )
        .expect("reopen");
        let mut exchange = MobilePairingExchangeRequest {
            pairing_id: pairing_id.clone(),
            pairing_token: token.clone(),
            server_identity: identity.clone(),
        };
        let issued = reopened
            .exchange_pairing(&mut exchange, NOW + 1)
            .expect("exchange after restart");
        assert!(exchange.pairing_token.is_empty());
        assert_eq!(
            issued.authorization.actions,
            vec![MobileAction::Attach, MobileAction::FollowUp]
        );
        let mut replay = MobilePairingExchangeRequest {
            pairing_id,
            pairing_token: token,
            server_identity: identity,
        };
        assert!(matches!(
            reopened.exchange_pairing(&mut replay, NOW + 2),
            Err(MobileAuthError::InvalidPairing)
        ));

        let boundary = reopened
            .create_pairing(request(), NOW)
            .expect("boundary pairing");
        let mut boundary_request = MobilePairingExchangeRequest {
            pairing_id: boundary.pairing_id.clone(),
            pairing_token: boundary.pairing_token.clone(),
            server_identity: boundary.server_identity.clone(),
        };
        assert!(matches!(
            reopened.exchange_pairing(&mut boundary_request, NOW + PAIRING_TTL_MILLIS),
            Err(MobileAuthError::InvalidPairing)
        ));
    }

    #[test]
    fn pairing_unknown_wrong_expired_and_consumed_are_indistinguishable() {
        let (_root, mut auth) = authority();
        let offer = auth.create_pairing(request(), NOW).expect("pairing");
        let identity = offer.server_identity.clone();
        let cases = [
            MobilePairingExchangeRequest {
                pairing_id: random_token("pi").expect("unknown id"),
                pairing_token: random_token("mp").expect("unknown token"),
                server_identity: identity.clone(),
            },
            MobilePairingExchangeRequest {
                pairing_id: offer.pairing_id.clone(),
                pairing_token: random_token("mp").expect("wrong token"),
                server_identity: identity.clone(),
            },
            MobilePairingExchangeRequest {
                pairing_id: offer.pairing_id.clone(),
                pairing_token: offer.pairing_token.clone(),
                server_identity: format!("sha256:{}", "f".repeat(64)),
            },
            MobilePairingExchangeRequest {
                pairing_id: offer.pairing_id.clone(),
                pairing_token: format!("mp_{}", "X".repeat(4096)),
                server_identity: identity.clone(),
            },
        ];
        for mut case in cases {
            let error = auth
                .exchange_pairing(&mut case, NOW + 1)
                .expect_err("refusal");
            assert_eq!(error.category(), "mobile_pairing_invalid");
            assert!(case.pairing_token.is_empty());
        }
        let mut expired = MobilePairingExchangeRequest {
            pairing_id: offer.pairing_id.clone(),
            pairing_token: offer.pairing_token.clone(),
            server_identity: identity,
        };
        assert_eq!(
            auth.exchange_pairing(&mut expired, NOW + PAIRING_TTL_MILLIS)
                .expect_err("expired")
                .category(),
            "mobile_pairing_invalid"
        );
    }

    #[test]
    fn pairing_credential_insert_failure_rolls_back_consumption() {
        let (_root, mut auth) = authority();
        let offer = auth.create_pairing(request(), NOW).expect("pairing");
        auth.connection
            .execute_batch(
                "CREATE TRIGGER fail_pairing_credential BEFORE INSERT ON mobile_credentials
                 BEGIN SELECT RAISE(ABORT, 'fixture insertion failure'); END;",
            )
            .expect("failure trigger");
        let mut first = MobilePairingExchangeRequest {
            pairing_id: offer.pairing_id.clone(),
            pairing_token: offer.pairing_token.clone(),
            server_identity: offer.server_identity.clone(),
        };
        assert!(matches!(
            auth.exchange_pairing(&mut first, NOW + 1),
            Err(MobileAuthError::Sqlite(_))
        ));
        auth.connection
            .execute_batch("DROP TRIGGER fail_pairing_credential;")
            .expect("drop trigger");
        let mut retry = MobilePairingExchangeRequest {
            pairing_id: offer.pairing_id.clone(),
            pairing_token: offer.pairing_token.clone(),
            server_identity: offer.server_identity.clone(),
        };
        auth.exchange_pairing(&mut retry, NOW + 2)
            .expect("unconsumed retry");
    }

    #[test]
    fn pairing_cap_cleanup_and_operator_inventory_revocation_are_bounded() {
        let (_root, mut auth) = authority();
        for _ in 0..MAX_OUTSTANDING_PAIRINGS {
            auth.create_pairing(request(), NOW)
                .expect("bounded pairing");
        }
        assert!(matches!(
            auth.create_pairing(request(), NOW),
            Err(MobileAuthError::PairingLimit)
        ));
        auth.create_pairing(request(), NOW + PAIRING_TTL_MILLIS)
            .expect("expired pairings do not consume outstanding capacity");
        auth.create_pairing(
            request(),
            NOW + PAIRING_TTL_MILLIS + PAIRING_RETENTION_MILLIS,
        )
        .expect("retained pairings are cleaned");
        assert!(
            auth.connection
                .query_row("SELECT COUNT(*) FROM mobile_pairings", [], |row| row
                    .get::<_, u64>(0))
                .expect("pairing count")
                <= 2
        );

        let first = auth.operator_provision(request(), NOW).expect("first");
        let second = auth.operator_provision(request(), NOW + 1).expect("second");
        let third = auth.operator_provision(request(), NOW + 2).expect("third");
        let page = auth
            .credential_inventory(
                MobileCredentialInventoryRequest {
                    cursor: None,
                    page_size: 2,
                },
                NOW + 3,
            )
            .expect("first page");
        assert_eq!(page.credentials.len(), 2);
        assert!(page.next_cursor.is_some());
        let next = auth
            .credential_inventory(
                MobileCredentialInventoryRequest {
                    cursor: page.next_cursor.clone(),
                    page_size: 2,
                },
                NOW + 3,
            )
            .expect("second page");
        assert_eq!(next.credentials.len(), 1);
        assert!(next.next_cursor.is_none());
        let serialized = serde_json::to_vec(&page).expect("inventory JSON");
        for secret in [
            &first.access_token,
            &first.refresh_token,
            &second.access_token,
            &third.refresh_token,
        ] {
            assert!(
                !serialized
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes())
            );
        }
        auth.revoke_credential_id(
            MobileCredentialRevokeRequest {
                credential_id: second.authorization.credential_id.clone(),
            },
            NOW + 4,
        )
        .expect("operator revoke");
        assert!(matches!(
            auth.authorize_access(
                &second.access_token,
                &second.authorization.server_identity,
                NOW + 4
            ),
            Err(MobileAuthError::Revoked)
        ));
    }

    #[test]
    fn consumed_pairings_are_retained_then_cleaned_at_the_exact_boundary() {
        let (_root, mut auth) = authority();
        let offer = auth.create_pairing(request(), NOW).expect("pairing");
        let mut exchange = MobilePairingExchangeRequest {
            pairing_id: offer.pairing_id.clone(),
            pairing_token: offer.pairing_token.clone(),
            server_identity: offer.server_identity.clone(),
        };
        auth.exchange_pairing(&mut exchange, NOW + 1)
            .expect("consume pairing");
        auth.create_pairing(request(), NOW + PAIRING_RETENTION_MILLIS)
            .expect("before cleanup boundary");
        assert_eq!(
            auth.connection
                .query_row(
                    "SELECT COUNT(*) FROM mobile_pairings WHERE pairing_id=?1",
                    params![offer.pairing_id],
                    |row| row.get::<_, u64>(0),
                )
                .expect("retained consumed pairing"),
            1
        );
        auth.create_pairing(request(), NOW + 1 + PAIRING_RETENTION_MILLIS)
            .expect("cleanup boundary");
        assert_eq!(
            auth.connection
                .query_row(
                    "SELECT COUNT(*) FROM mobile_pairings WHERE pairing_id=?1",
                    params![offer.pairing_id],
                    |row| row.get::<_, u64>(0),
                )
                .expect("cleaned consumed pairing"),
            0
        );
    }

    #[test]
    fn concurrent_pairing_exchange_has_exactly_one_winner() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let (root, mut auth) = authority();
        let offer = auth.create_pairing(request(), NOW).expect("pairing");
        let path = auth.path().to_path_buf();
        let barrier = Arc::new(Barrier::new(2));
        drop(auth);
        let workers = (0..2)
            .map(|offset| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                let pairing_id = offer.pairing_id.clone();
                let pairing_token = offer.pairing_token.clone();
                let server_identity = offer.server_identity.clone();
                thread::spawn(move || {
                    let mut auth = MobileCredentialAuthority::open(
                        path,
                        "ops.example.test",
                        "operator:mobile",
                    )
                    .expect("authority");
                    let mut exchange = MobilePairingExchangeRequest {
                        pairing_id,
                        pairing_token,
                        server_identity,
                    };
                    barrier.wait();
                    auth.exchange_pairing(&mut exchange, NOW + offset + 1)
                })
            })
            .collect::<Vec<_>>();
        let mut successes = 0;
        let mut refusals = 0;
        for worker in workers {
            match worker.join().expect("worker") {
                Ok(_) => successes += 1,
                Err(MobileAuthError::InvalidPairing) => refusals += 1,
                Err(error) => panic!("unexpected exchange error: {error}"),
            }
        }
        assert_eq!((successes, refusals), (1, 1));
        let reopened = MobileCredentialAuthority::open(
            root.path().join("mobile.sqlite3"),
            "ops.example.test",
            "operator:mobile",
        )
        .expect("reopen");
        assert_eq!(
            reopened
                .connection
                .query_row("SELECT COUNT(*) FROM mobile_credentials", [], |row| row
                    .get::<_, u64>(0))
                .expect("credential count"),
            1
        );
    }
}
