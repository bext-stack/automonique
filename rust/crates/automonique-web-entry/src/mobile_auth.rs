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

use automonique_protocol::platform::{
    PlatformAction, PlatformRequest, ResourceAuthority, ResourceKind, SessionList,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub const MOBILE_AUTH_PROTOCOL: &str = "automonique.mobile-auth";
pub const MOBILE_AUTH_SCHEMA_V1: &str = "automonique.mobile-auth/v1";
pub const MOBILE_AUTH_MEDIA_TYPE: &str = "application/vnd.automonique.mobile-auth.v1+json";
pub const MAX_MOBILE_ACTIONS: usize = 4;
pub const MAX_MOBILE_SESSIONS: usize = 100;
pub const MAX_PAGE_EVENTS: u16 = 512;
pub const MAX_FOLLOW_UP_BYTES: u32 = 65_536;
pub const ACCESS_TTL_MILLIS: i64 = 15 * 60 * 1_000;
pub const REFRESH_TTL_MILLIS: i64 = 30 * 24 * 60 * 60 * 1_000;
pub const REVOKED_FAMILY_RETENTION_MILLIS: i64 = 30 * 24 * 60 * 60 * 1_000;
pub const MAX_CREDENTIAL_REVISIONS: u64 = 4_096;

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
"#;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileAction {
    Attach,
    FollowUp,
    DecideApproval,
    StopRun,
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
    pub operator_provision_endpoint: String,
    pub origin: String,
    pub platform_endpoint: String,
    pub protocol: &'static str,
    pub schema: &'static str,
    pub server_identity: String,
    pub supported_versions: Vec<u16>,
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
    actor: String,
}

impl MobileCredentialAuthority {
    pub fn open(
        path: impl AsRef<Path>,
        canonical_host: &str,
        actor: &str,
    ) -> Result<Self, MobileAuthError> {
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
        let origin = format!("https://{canonical_host}");
        let server_identity = load_or_create_server_identity(&connection, &origin)?;
        let discovery = MobileDiscovery {
            protocol: MOBILE_AUTH_PROTOCOL,
            schema: MOBILE_AUTH_SCHEMA_V1,
            platform_endpoint: format!("{origin}/api/platform"),
            operator_provision_endpoint: format!("{origin}/api/mobile/operator-provision"),
            origin,
            server_identity,
            supported_versions: vec![1],
        };
        Ok(Self {
            #[cfg(test)]
            path: path.to_path_buf(),
            connection,
            discovery,
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
        let mut access = random_secret_token("ma")?;
        let mut refresh = random_secret_token("mr")?;
        let credential_id = random_token("mc")?;
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
        let actions_json = serde_json::to_string(&actions)?;
        let sessions_json = serde_json::to_string(&sessions)?;
        let access_expires_at_ms = now_ms
            .checked_add(ACCESS_TTL_MILLIS)
            .ok_or(MobileAuthError::InvalidRequest)?;
        let refresh_expires_at_ms = now_ms
            .checked_add(REFRESH_TTL_MILLIS)
            .ok_or(MobileAuthError::InvalidRequest)?;
        validate_time(access_expires_at_ms)?;
        validate_time(refresh_expires_at_ms)?;
        let inserted = self.connection.execute(
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
                self.actor,
                self.discovery.server_identity,
                now_ms,
                access_expires_at_ms,
                refresh_expires_at_ms,
                actions_json,
                sessions_json,
                request.limits.max_page_events,
                request.limits.max_follow_up_bytes,
            ],
        );
        inserted?;
        Ok(IssuedMobileCredentials {
            access_token: std::mem::take(&mut *access),
            refresh_token: std::mem::take(&mut *refresh),
            authorization: MobileAuthorization {
                schema: MOBILE_AUTH_SCHEMA_V1,
                server_identity: self.discovery.server_identity.clone(),
                actor: self.actor.clone(),
                credential_id,
                credential_revision: 1,
                authorization_revision: 1,
                issued_at_ms: now_ms,
                expires_at_ms: access_expires_at_ms,
                actions,
                session_scope: sessions,
                limits: request.limits,
            },
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
                transaction.execute(
                    "UPDATE mobile_credentials SET revoked_at_ms=COALESCE(revoked_at_ms,?1)
                     WHERE credential_id=?2",
                    params![now_ms, credential_id],
                )?;
                transaction.commit()?;
                return Err(MobileAuthError::InvalidCredential);
            }
        };
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
        let changed = transaction.execute(
            "UPDATE mobile_credentials SET revoked_at_ms=?1
             WHERE credential_id=?2 AND revoked_at_ms IS NULL",
            params![now_ms, credential_id],
        )?;
        if changed != 1 {
            return Err(MobileAuthError::InvalidCredential);
        }
        transaction.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }
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
        Ok(MobileAuthorization {
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
        })
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
        PlatformRequest::Execute(request) => match request.action {
            PlatformAction::FollowUp => {
                authorization.allows(MobileAction::FollowUp)
                    && request.target.authority == ResourceAuthority::Automonique
                    && request.target.kind == ResourceKind::Session
                    && authorization.allows_session(request.target.id.as_str())
                    && request.expected_revision.is_some()
                    && request.parameter.as_ref().is_some_and(|parameter| {
                        parameter.as_str().len()
                            <= usize::try_from(authorization.limits.max_follow_up_bytes)
                                .unwrap_or(usize::MAX)
                    })
            }
            // Platform v1 does not bind runs or approvals back to a session in
            // the request. A global action bit therefore cannot prove this
            // target is within the actor's session scope.
            PlatformAction::StopRun | PlatformAction::DecideApproval => false,
            PlatformAction::StartRun
            | PlatformAction::Steer
            | PlatformAction::SubmitRequest
            | PlatformAction::SubmitJob
            | PlatformAction::ApproveRelease
            | PlatformAction::RegisterNode => false,
        },
        // These reads lack actor/session coordinates in Platform v1. They must
        // remain closed until the caller's receipt/cursor/resource ownership is
        // provable at this boundary.
        PlatformRequest::Snapshot(_)
        | PlatformRequest::Subscribe(_)
        | PlatformRequest::GetReceipt(_)
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
    if actions.is_empty()
        || actions.len() > MAX_MOBILE_ACTIONS
        || actions
            .iter()
            .any(|action| !matches!(action, MobileAction::Attach | MobileAction::FollowUp))
    {
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
        FreshnessState, IdempotencyKey, PlatformCursor, PlatformParameter, PlatformText,
        ResourceCoordinate, ResourceId, ResourceRecord, SessionRecord,
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
        let mut unenforceable = request();
        unenforceable.actions = vec![MobileAction::StopRun];
        assert!(matches!(
            auth.operator_provision(unenforceable, NOW),
            Err(MobileAuthError::InvalidRequest)
        ));
    }

    #[test]
    fn platform_policy_is_per_action_per_session_and_fail_closed() {
        let (_root, mut auth) = authority();
        let issued = auth.operator_provision(request(), NOW).expect("provision");
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
            .expect("execute"),
        );
        assert!(authorize_platform_request(&issued.authorization, &follow_up, NOW).is_ok());
        let blind_follow_up = PlatformRequest::Execute(
            ExecuteRequest::new_with_parameter(
                PlatformAction::FollowUp,
                session("session-a"),
                IdempotencyKey::new("key-blind").expect("key"),
                None,
                Some(PlatformParameter::new("continue").expect("parameter")),
            )
            .expect("execute"),
        );
        assert!(authorize_platform_request(&issued.authorization, &blind_follow_up, NOW).is_err());
        let stale_shape = PlatformRequest::Execute(
            ExecuteRequest::new_with_parameter(
                PlatformAction::FollowUp,
                session("session-c"),
                IdempotencyKey::new("key-stale").expect("key"),
                Some(Revision::new(1).expect("revision")),
                Some(PlatformParameter::new("continue").expect("parameter")),
            )
            .expect("execute"),
        );
        assert!(authorize_platform_request(&issued.authorization, &stale_shape, NOW).is_err());
        let mut restrictive = issued.authorization.clone();
        restrictive.limits.max_follow_up_bytes = 8;
        let oversized_follow_up = PlatformRequest::Execute(
            ExecuteRequest::new_with_parameter(
                PlatformAction::FollowUp,
                session("session-a"),
                IdempotencyKey::new("key-2").expect("key"),
                Some(Revision::new(1).expect("revision")),
                Some(PlatformParameter::new("continued").expect("bounded parameter")),
            )
            .expect("execute"),
        );
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
    fn strict_request_json_rejects_unknown_fields() {
        let value = r#"{"actions":["attach"],"session_scope":[],"limits":{"max_page_events":1,"max_follow_up_bytes":1},"token":"secret"}"#;
        assert!(serde_json::from_str::<MobileOperatorProvisionRequest>(value).is_err());
    }
}
