// SPDX-License-Identifier: Elastic-2.0

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nix::unistd::geteuid;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const REGISTRY_SCHEMA: &str = "automonique.agent-accounts/v1";
const HEALTH_SCHEMA: &str = "automonique.provider-account-health/v1";
const VIEW_SCHEMA: &str = "automonique.dashboard.agent-accounts/v1";
const SESSION_LIFETIME: Duration = Duration::from_secs(10 * 60);
const SESSION_RETENTION: Duration = Duration::from_secs(30 * 60);
const OUTPUT_LIMIT: usize = 32 * 1024;
const REGISTRY_LIMIT: u64 = 128 * 1024;
const HEALTH_LIMIT: u64 = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Provider {
    Codex,
    Claude,
}

impl Provider {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "codex" => Some(Self::Codex),
            "claude" => Some(Self::Claude),
            _ => None,
        }
    }

    fn id(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
        }
    }

    fn display(self) -> &'static str {
        match self {
            Self::Codex => "Codex CLI",
            Self::Claude => "Claude Code",
        }
    }

    fn method(self) -> &'static str {
        match self {
            Self::Codex => "chatgpt",
            Self::Claude => "claude_ai",
        }
    }
}

#[derive(Clone, Debug)]
pub struct AgentAuthConfig {
    root: PathBuf,
    codex_binary: PathBuf,
    claude_binary: PathBuf,
}

impl AgentAuthConfig {
    pub fn new(
        root: PathBuf,
        codex_binary: PathBuf,
        claude_binary: PathBuf,
    ) -> Result<Self, &'static str> {
        let config = Self {
            root,
            codex_binary,
            claude_binary,
        };
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if !self.root.is_absolute()
            || !self.codex_binary.is_absolute()
            || !self.claude_binary.is_absolute()
        {
            return Err("agent authentication paths must be absolute");
        }
        for binary in [&self.codex_binary, &self.claude_binary] {
            let metadata = fs::metadata(binary).map_err(|_| "agent provider binary unavailable")?;
            if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
                return Err("agent provider binary unavailable");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccountRecord {
    id: String,
    provider: String,
    label: String,
    created_at_ms: u64,
    updated_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    schema: String,
    revision: u64,
    worker_provider: Option<String>,
    selected: BTreeMap<String, String>,
    accounts: Vec<AccountRecord>,
}

impl Registry {
    fn empty() -> Self {
        Self {
            schema: String::from(REGISTRY_SCHEMA),
            revision: 0,
            worker_provider: None,
            selected: BTreeMap::new(),
            accounts: Vec::new(),
        }
    }

    fn validate(&self) -> bool {
        if self.schema != REGISTRY_SCHEMA
            || self.revision > 9_007_199_254_740_991
            || self.accounts.len() > 64
            || self
                .worker_provider
                .as_deref()
                .is_some_and(|value| Provider::parse(value).is_none())
        {
            return false;
        }
        let mut ids = BTreeMap::new();
        for account in &self.accounts {
            if !valid_account_id(&account.id)
                || Provider::parse(&account.provider).is_none()
                || !valid_label(&account.label)
                || account.created_at_ms == 0
                || account.updated_at_ms < account.created_at_ms
                || ids
                    .insert(account.id.as_str(), account.provider.as_str())
                    .is_some()
            {
                return false;
            }
        }
        if self.selected.len() > 2 {
            return false;
        }
        self.selected.iter().all(|(provider, account_id)| {
            Provider::parse(provider).is_some()
                && ids.get(account_id.as_str()).copied() == Some(provider.as_str())
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HealthRecord {
    schema: String,
    provider: String,
    account_id: String,
    status: String,
    method: String,
    reason: String,
    observed_at_ms: u64,
    last_verified_at_ms: Option<u64>,
}

impl HealthRecord {
    fn valid(&self, account: &AccountRecord) -> bool {
        let status = matches!(
            self.status.as_str(),
            "authenticated"
                | "configured_unverified"
                | "authenticating"
                | "expired"
                | "signed_out"
                | "unavailable"
        );
        let reason = matches!(
            (self.status.as_str(), self.reason.as_str()),
            (
                "authenticated",
                "native_login_verified" | "execution_succeeded"
            ) | (
                "configured_unverified",
                "credentials_changed" | "local_session_present"
            ) | ("authenticating", "native_login_started")
                | ("expired", "refresh_token_rejected")
                | (
                    "signed_out",
                    "local_session_missing" | "operator_signed_out"
                )
                | (
                    "unavailable",
                    "provider_unavailable" | "native_login_failed"
                )
        );
        let method = Provider::parse(&account.provider)
            .is_some_and(|provider| self.method == provider.method());
        self.schema == HEALTH_SCHEMA
            && self.provider == account.provider
            && self.account_id == account.id
            && status
            && reason
            && method
            && self.observed_at_ms > 0
            && self.last_verified_at_ms.is_none_or(|verified| {
                verified > 0 && verified <= self.observed_at_ms && verified <= 9_007_199_254_740_991
            })
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct AgentAccountsView {
    schema: &'static str,
    providers: Vec<ProviderView>,
    worker_provider: Option<String>,
    accounts: Vec<AccountView>,
    login_sessions: Vec<LoginSessionView>,
}

impl AgentAccountsView {
    pub(crate) fn accounts(&self) -> &[AccountView] {
        &self.accounts
    }

    pub(crate) fn worker_provider(&self) -> Option<&str> {
        self.worker_provider.as_deref()
    }
}

#[derive(Clone, Debug, Serialize)]
struct ProviderView {
    id: &'static str,
    name: &'static str,
    native_subscription: &'static str,
    available: bool,
    account_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct AccountView {
    id: String,
    provider: String,
    provider_name: &'static str,
    label: String,
    selected: bool,
    worker_selected: bool,
    status: String,
    method: String,
    evidence: String,
    observed_at_ms: Option<u64>,
    last_verified_at_ms: Option<u64>,
}

impl AccountView {
    pub(crate) fn provider(&self) -> &str {
        &self.provider
    }

    pub(crate) fn provider_name(&self) -> &'static str {
        self.provider_name
    }

    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    pub(crate) fn worker_selected(&self) -> bool {
        self.worker_selected
    }

    pub(crate) fn status(&self) -> &str {
        &self.status
    }

    pub(crate) fn method(&self) -> &str {
        &self.method
    }

    pub(crate) fn evidence(&self) -> &str {
        &self.evidence
    }

    pub(crate) fn observed_at_ms(&self) -> Option<u64> {
        self.observed_at_ms
    }

    pub(crate) fn last_verified_at_ms(&self) -> Option<u64> {
        self.last_verified_at_ms
    }
}

#[derive(Clone, Debug, Serialize)]
struct LoginSessionView {
    id: String,
    account_id: String,
    provider: String,
    status: String,
    authorization_url: Option<String>,
    user_code: Option<String>,
    accepts_authorization_code: bool,
    created_at_ms: u64,
    expires_at_ms: u64,
}

struct LoginSession {
    id: String,
    account_id: String,
    provider: Provider,
    state: Arc<Mutex<String>>,
    output: Arc<Mutex<Vec<u8>>>,
    cancelled: Arc<AtomicBool>,
    input: Arc<Mutex<Option<ChildStdin>>>,
    created_at_ms: u64,
    expires_at_ms: u64,
}

struct LoginProcess {
    provider: Provider,
    binary: PathBuf,
    profile: PathBuf,
    account_id: String,
    health_path: PathBuf,
    output: Arc<Mutex<Vec<u8>>>,
    state: Arc<Mutex<String>>,
    cancelled: Arc<AtomicBool>,
    input: Arc<Mutex<Option<ChildStdin>>>,
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum AgentAuthAction {
    StartLogin {
        provider: String,
        label: String,
        account_id: Option<String>,
    },
    Select {
        account_id: String,
    },
    Refresh {
        account_id: String,
    },
    CancelLogin {
        session_id: String,
    },
    SubmitAuthorizationCode {
        session_id: String,
        code: String,
    },
    Logout {
        account_id: String,
        confirm: bool,
    },
    Remove {
        account_id: String,
        confirm: bool,
    },
}

pub(crate) struct AgentAuthManager {
    config: AgentAuthConfig,
    registry_lock: Mutex<()>,
    sessions: Arc<Mutex<BTreeMap<String, LoginSession>>>,
}

impl AgentAuthManager {
    pub(crate) fn open(config: AgentAuthConfig) -> Result<Self, &'static str> {
        config.validate()?;
        ensure_private_directory(&config.root)?;
        ensure_private_directory(&config.root.join("profiles"))?;
        ensure_private_directory(&config.root.join("health"))?;
        let manager = Self {
            config,
            registry_lock: Mutex::new(()),
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
        };
        if manager.registry_path().is_file() {
            manager.read_registry()?;
        }
        Ok(manager)
    }

    pub(crate) fn view(&self) -> Result<AgentAccountsView, &'static str> {
        let registry = self.read_registry()?;
        let mut accounts = Vec::with_capacity(registry.accounts.len());
        for account in &registry.accounts {
            let provider = Provider::parse(&account.provider).ok_or("agent_accounts_invalid")?;
            let health = self.read_health(account).unwrap_or_else(|| HealthRecord {
                schema: String::from(HEALTH_SCHEMA),
                provider: account.provider.clone(),
                account_id: account.id.clone(),
                status: String::from("unavailable"),
                method: String::from(provider.method()),
                reason: String::from("provider_unavailable"),
                observed_at_ms: account.updated_at_ms,
                last_verified_at_ms: None,
            });
            let selected = registry.selected.get(&account.provider) == Some(&account.id);
            accounts.push(AccountView {
                id: account.id.clone(),
                provider: account.provider.clone(),
                provider_name: provider.display(),
                label: account.label.clone(),
                selected,
                worker_selected: selected
                    && registry.worker_provider.as_deref() == Some(account.provider.as_str()),
                status: health.status,
                method: health.method,
                evidence: health.reason,
                observed_at_ms: Some(health.observed_at_ms),
                last_verified_at_ms: health.last_verified_at_ms,
            });
        }
        accounts.sort_by(|left, right| {
            left.provider
                .cmp(&right.provider)
                .then_with(|| left.label.cmp(&right.label))
        });
        let now = now_ms();
        let mut sessions = self.sessions.lock().map_err(|_| "agent_auth_busy")?;
        sessions.retain(|_, session| {
            now.saturating_sub(session.created_at_ms) <= SESSION_RETENTION.as_millis() as u64
        });
        let login_sessions = sessions.values().map(login_session_view).collect();
        let providers = [Provider::Codex, Provider::Claude]
            .into_iter()
            .map(|provider| ProviderView {
                id: provider.id(),
                name: provider.display(),
                native_subscription: match provider {
                    Provider::Codex => "ChatGPT subscription",
                    Provider::Claude => "Claude.ai subscription",
                },
                available: true,
                account_count: registry
                    .accounts
                    .iter()
                    .filter(|account| account.provider == provider.id())
                    .count(),
            })
            .collect();
        Ok(AgentAccountsView {
            schema: VIEW_SCHEMA,
            providers,
            worker_provider: registry.worker_provider,
            accounts,
            login_sessions,
        })
    }

    pub(crate) fn action(
        &self,
        action: AgentAuthAction,
    ) -> Result<AgentAccountsView, &'static str> {
        match action {
            AgentAuthAction::StartLogin {
                provider,
                label,
                account_id,
            } => self.start_login(&provider, &label, account_id.as_deref())?,
            AgentAuthAction::Select { account_id } => self.select(&account_id)?,
            AgentAuthAction::Refresh { account_id } => self.refresh(&account_id)?,
            AgentAuthAction::CancelLogin { session_id } => self.cancel_login(&session_id)?,
            AgentAuthAction::SubmitAuthorizationCode { session_id, code } => {
                self.submit_authorization_code(&session_id, &code)?;
            }
            AgentAuthAction::Logout {
                account_id,
                confirm,
            } => self.logout(&account_id, confirm)?,
            AgentAuthAction::Remove {
                account_id,
                confirm,
            } => self.remove(&account_id, confirm)?,
        }
        self.view()
    }

    fn start_login(
        &self,
        provider_value: &str,
        label_value: &str,
        existing_id: Option<&str>,
    ) -> Result<(), &'static str> {
        let provider = Provider::parse(provider_value).ok_or("provider_not_supported")?;
        let label = label_value.trim();
        if !valid_label(label) {
            return Err("account_label_invalid");
        }
        let _guard = self.registry_lock.lock().map_err(|_| "agent_auth_busy")?;
        let mut registry = self.read_registry_unlocked()?;
        let account_id = if let Some(account_id) = existing_id {
            let account = registry
                .accounts
                .iter_mut()
                .find(|account| account.id == account_id)
                .ok_or("account_not_found")?;
            if account.provider != provider.id() {
                return Err("account_provider_mismatch");
            }
            account.label = label.to_owned();
            account.updated_at_ms = now_ms();
            account.id.clone()
        } else {
            if registry.accounts.len() >= 64 {
                return Err("account_limit_reached");
            }
            let id = generate_id("acct")?;
            let now = now_ms();
            registry.accounts.push(AccountRecord {
                id: id.clone(),
                provider: String::from(provider.id()),
                label: label.to_owned(),
                created_at_ms: now,
                updated_at_ms: now,
            });
            id
        };
        let profile = self.profile_path(&account_id)?;
        ensure_private_directory(&profile)?;
        registry
            .selected
            .entry(String::from(provider.id()))
            .or_insert_with(|| account_id.clone());
        registry.revision = registry.revision.saturating_add(1);
        self.write_registry_unlocked(&registry)?;
        self.write_health(&HealthRecord {
            schema: String::from(HEALTH_SCHEMA),
            provider: String::from(provider.id()),
            account_id: account_id.clone(),
            status: String::from("authenticating"),
            method: String::from(provider.method()),
            reason: String::from("native_login_started"),
            observed_at_ms: now_ms(),
            last_verified_at_ms: self
                .read_health(
                    registry
                        .accounts
                        .iter()
                        .find(|account| account.id == account_id)
                        .ok_or("account_not_found")?,
                )
                .and_then(|health| health.last_verified_at_ms),
        })?;
        drop(_guard);

        let session_id = generate_id("login")?;
        let created_at_ms = now_ms();
        let output = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(Mutex::new(String::from("starting")));
        let cancelled = Arc::new(AtomicBool::new(false));
        let input = Arc::new(Mutex::new(None));
        let session = LoginSession {
            id: session_id.clone(),
            account_id: account_id.clone(),
            provider,
            state: Arc::clone(&state),
            output: Arc::clone(&output),
            cancelled: Arc::clone(&cancelled),
            input: Arc::clone(&input),
            created_at_ms,
            expires_at_ms: created_at_ms + SESSION_LIFETIME.as_millis() as u64,
        };
        self.sessions
            .lock()
            .map_err(|_| "agent_auth_busy")?
            .insert(session_id, session);
        let binary = self.binary(provider).to_path_buf();
        let health_path = self.health_path(&account_id)?;
        thread::Builder::new()
            .name(format!("agent-login-{}", provider.id()))
            .spawn(move || {
                run_login_process(LoginProcess {
                    provider,
                    binary,
                    profile,
                    account_id,
                    health_path,
                    output,
                    state,
                    cancelled,
                    input,
                });
            })
            .map_err(|_| "native_login_unavailable")?;
        Ok(())
    }

    fn select(&self, account_id: &str) -> Result<(), &'static str> {
        let _guard = self.registry_lock.lock().map_err(|_| "agent_auth_busy")?;
        let mut registry = self.read_registry_unlocked()?;
        let account = registry
            .accounts
            .iter()
            .find(|account| account.id == account_id)
            .cloned()
            .ok_or("account_not_found")?;
        let health = self.probe_and_write(&account)?;
        if !matches!(
            health.status.as_str(),
            "authenticated" | "configured_unverified"
        ) {
            return Err("account_not_authenticated");
        }
        registry
            .selected
            .insert(account.provider.clone(), account.id.clone());
        registry.worker_provider = Some(account.provider);
        registry.revision = registry.revision.saturating_add(1);
        self.write_registry_unlocked(&registry)
    }

    fn refresh(&self, account_id: &str) -> Result<(), &'static str> {
        let _guard = self.registry_lock.lock().map_err(|_| "agent_auth_busy")?;
        let registry = self.read_registry_unlocked()?;
        let account = registry
            .accounts
            .iter()
            .find(|account| account.id == account_id)
            .ok_or("account_not_found")?;
        self.probe_and_write(account).map(|_| ())
    }

    fn cancel_login(&self, session_id: &str) -> Result<(), &'static str> {
        if !valid_session_id(session_id) {
            return Err("login_session_invalid");
        }
        let sessions = self.sessions.lock().map_err(|_| "agent_auth_busy")?;
        let session = sessions.get(session_id).ok_or("login_session_not_found")?;
        session.cancelled.store(true, Ordering::Release);
        Ok(())
    }

    fn submit_authorization_code(
        &self,
        session_id: &str,
        code_value: &str,
    ) -> Result<(), &'static str> {
        if !valid_session_id(session_id) {
            return Err("login_session_invalid");
        }
        let code = code_value.trim();
        if code.is_empty()
            || code.len() > 4096
            || code.chars().any(|character| character.is_control())
        {
            return Err("authorization_code_invalid");
        }
        let sessions = self.sessions.lock().map_err(|_| "agent_auth_busy")?;
        let session = sessions.get(session_id).ok_or("login_session_not_found")?;
        if session.provider != Provider::Claude {
            return Err("authorization_code_not_supported");
        }
        let mut input = session.input.lock().map_err(|_| "agent_auth_busy")?;
        let writer = input.as_mut().ok_or("authorization_code_not_ready")?;
        writer
            .write_all(code.as_bytes())
            .and_then(|()| writer.write_all(b"\n"))
            .and_then(|()| writer.flush())
            .map_err(|_| "authorization_code_submit_failed")?;
        *input = None;
        set_session_state(&session.state, "verifying");
        Ok(())
    }

    fn logout(&self, account_id: &str, confirm: bool) -> Result<(), &'static str> {
        if !confirm {
            return Err("confirmation_required");
        }
        let _guard = self.registry_lock.lock().map_err(|_| "agent_auth_busy")?;
        let registry = self.read_registry_unlocked()?;
        let account = registry
            .accounts
            .iter()
            .find(|account| account.id == account_id)
            .ok_or("account_not_found")?;
        let provider = Provider::parse(&account.provider).ok_or("provider_not_supported")?;
        let profile = self.profile_path(account_id)?;
        let mut command = provider_command(provider, self.binary(provider), &profile);
        match provider {
            Provider::Codex => {
                command.arg("logout");
            }
            Provider::Claude => {
                command.args(["auth", "logout"]);
            }
        }
        let status = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| "native_logout_unavailable")?;
        if !status.success() {
            return Err("native_logout_failed");
        }
        self.write_health(&HealthRecord {
            schema: String::from(HEALTH_SCHEMA),
            provider: account.provider.clone(),
            account_id: account.id.clone(),
            status: String::from("signed_out"),
            method: String::from(provider.method()),
            reason: String::from("operator_signed_out"),
            observed_at_ms: now_ms(),
            last_verified_at_ms: self
                .read_health(account)
                .and_then(|health| health.last_verified_at_ms),
        })
    }

    fn remove(&self, account_id: &str, confirm: bool) -> Result<(), &'static str> {
        if !confirm {
            return Err("confirmation_required");
        }
        let _guard = self.registry_lock.lock().map_err(|_| "agent_auth_busy")?;
        let mut registry = self.read_registry_unlocked()?;
        let index = registry
            .accounts
            .iter()
            .position(|account| account.id == account_id)
            .ok_or("account_not_found")?;
        let account = registry.accounts[index].clone();
        if registry.worker_provider.as_deref() == Some(account.provider.as_str())
            && registry.selected.get(&account.provider) == Some(&account.id)
        {
            return Err("selected_account_cannot_be_removed");
        }
        let profile = self.profile_path(account_id)?;
        if profile.is_dir() {
            fs::remove_dir_all(&profile).map_err(|_| "account_remove_failed")?;
        }
        let health = self.health_path(account_id)?;
        if health.is_file() {
            fs::remove_file(&health).map_err(|_| "account_remove_failed")?;
        }
        registry.accounts.remove(index);
        if registry.selected.get(&account.provider) == Some(&account.id) {
            registry.selected.remove(&account.provider);
        }
        registry.revision = registry.revision.saturating_add(1);
        self.write_registry_unlocked(&registry)
    }

    fn probe_and_write(&self, account: &AccountRecord) -> Result<HealthRecord, &'static str> {
        let provider = Provider::parse(&account.provider).ok_or("provider_not_supported")?;
        let profile = self.profile_path(&account.id)?;
        let verified = probe_native_subscription(provider, self.binary(provider), &profile);
        let previous_health = self.read_health(account);
        let previous_verified = previous_health
            .as_ref()
            .and_then(|health| health.last_verified_at_ms);
        let execution_verified = previous_health
            .as_ref()
            .is_some_and(|health| health.status == "authenticated");
        let now = now_ms();
        let health = HealthRecord {
            schema: String::from(HEALTH_SCHEMA),
            provider: account.provider.clone(),
            account_id: account.id.clone(),
            status: String::from(if verified && execution_verified {
                "authenticated"
            } else if verified {
                "configured_unverified"
            } else {
                "signed_out"
            }),
            method: String::from(provider.method()),
            reason: String::from(if verified && execution_verified {
                previous_health
                    .as_ref()
                    .map_or("native_login_verified", |health| health.reason.as_str())
            } else if verified {
                "local_session_present"
            } else {
                "local_session_missing"
            }),
            observed_at_ms: now,
            last_verified_at_ms: previous_verified,
        };
        self.write_health(&health)?;
        Ok(health)
    }

    fn binary(&self, provider: Provider) -> &Path {
        match provider {
            Provider::Codex => &self.config.codex_binary,
            Provider::Claude => &self.config.claude_binary,
        }
    }

    fn registry_path(&self) -> PathBuf {
        self.config.root.join("accounts.json")
    }

    fn profile_path(&self, account_id: &str) -> Result<PathBuf, &'static str> {
        if !valid_account_id(account_id) {
            return Err("account_id_invalid");
        }
        Ok(self.config.root.join("profiles").join(account_id))
    }

    fn health_path(&self, account_id: &str) -> Result<PathBuf, &'static str> {
        if !valid_account_id(account_id) {
            return Err("account_id_invalid");
        }
        Ok(self
            .config
            .root
            .join("health")
            .join(format!("{account_id}.json")))
    }

    fn read_registry(&self) -> Result<Registry, &'static str> {
        let _guard = self.registry_lock.lock().map_err(|_| "agent_auth_busy")?;
        self.read_registry_unlocked()
    }

    fn read_registry_unlocked(&self) -> Result<Registry, &'static str> {
        let path = self.registry_path();
        if !path.exists() {
            return Ok(Registry::empty());
        }
        let bytes = read_private_file(&path, REGISTRY_LIMIT)?;
        let registry: Registry =
            serde_json::from_slice(&bytes).map_err(|_| "agent_accounts_invalid")?;
        if !registry.validate() {
            return Err("agent_accounts_invalid");
        }
        Ok(registry)
    }

    fn write_registry_unlocked(&self, registry: &Registry) -> Result<(), &'static str> {
        if !registry.validate() {
            return Err("agent_accounts_invalid");
        }
        write_private_json(&self.registry_path(), registry)
    }

    fn read_health(&self, account: &AccountRecord) -> Option<HealthRecord> {
        let path = self.health_path(&account.id).ok()?;
        let bytes = read_private_file(&path, HEALTH_LIMIT).ok()?;
        let health: HealthRecord = serde_json::from_slice(&bytes).ok()?;
        health.valid(account).then_some(health)
    }

    fn write_health(&self, health: &HealthRecord) -> Result<(), &'static str> {
        let account = AccountRecord {
            id: health.account_id.clone(),
            provider: health.provider.clone(),
            label: String::from("validation"),
            created_at_ms: 1,
            updated_at_ms: 1,
        };
        if !health.valid(&account) {
            return Err("agent_health_invalid");
        }
        write_private_json(&self.health_path(&health.account_id)?, health)
    }
}

fn run_login_process(process: LoginProcess) {
    let LoginProcess {
        provider,
        binary,
        profile,
        account_id,
        health_path,
        output,
        state,
        cancelled,
        input,
    } = process;
    let mut command = provider_command(provider, &binary, &profile);
    match provider {
        Provider::Codex => {
            command.args(["login", "--device-auth"]);
        }
        Provider::Claude => {
            command.args(["auth", "login", "--claudeai"]);
        }
    }
    let child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let Ok(mut child) = child else {
        set_session_state(&state, "failed");
        let _ = write_health_path(
            &health_path,
            provider,
            &account_id,
            "unavailable",
            "native_login_failed",
            None,
        );
        return;
    };
    if let Ok(mut writer) = input.lock() {
        *writer = child.stdin.take();
    }
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_reader = stdout.map(|stream| spawn_bounded_reader(stream, Arc::clone(&output)));
    let stderr_reader = stderr.map(|stream| spawn_bounded_reader(stream, Arc::clone(&output)));
    set_session_state(&state, "awaiting_user");
    let started = SystemTime::now();
    let success = loop {
        if cancelled.load(Ordering::Acquire)
            || started.elapsed().unwrap_or(SESSION_LIFETIME) >= SESSION_LIFETIME
        {
            let _ = child.kill();
            let _ = child.wait();
            break false;
        }
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) => thread::sleep(Duration::from_millis(200)),
            Err(_) => break false,
        }
    };
    if let Some(reader) = stdout_reader {
        let _ = reader.join();
    }
    if let Some(reader) = stderr_reader {
        let _ = reader.join();
    }
    let verified = success && probe_native_subscription(provider, &binary, &profile);
    if verified {
        set_session_state(&state, "authenticated");
        let now = now_ms();
        let _ = write_health_path(
            &health_path,
            provider,
            &account_id,
            "authenticated",
            "native_login_verified",
            Some(now),
        );
    } else if cancelled.load(Ordering::Acquire) {
        set_session_state(&state, "cancelled");
        let _ = write_health_path(
            &health_path,
            provider,
            &account_id,
            "signed_out",
            "local_session_missing",
            None,
        );
    } else {
        set_session_state(&state, "failed");
        let _ = write_health_path(
            &health_path,
            provider,
            &account_id,
            "unavailable",
            "native_login_failed",
            None,
        );
    }
}

fn provider_command(provider: Provider, binary: &Path, profile: &Path) -> Command {
    let mut command = Command::new(binary);
    command.current_dir(profile);
    command.env_remove("OPENAI_API_KEY");
    command.env_remove("ANTHROPIC_API_KEY");
    command.env_remove("CLAUDE_CODE_OAUTH_TOKEN");
    command.env_remove("CODEX_API_KEY");
    match provider {
        Provider::Codex => {
            command.env("CODEX_HOME", profile);
        }
        Provider::Claude => {
            command.env("CLAUDE_CONFIG_DIR", profile);
        }
    }
    command
}

fn probe_native_subscription(provider: Provider, binary: &Path, profile: &Path) -> bool {
    let mut command = provider_command(provider, binary, profile);
    match provider {
        Provider::Codex => {
            command.args(["login", "status"]);
            command
                .output()
                .ok()
                .filter(|output| output.status.success())
                .is_some_and(|output| {
                    let mut text = output.stdout;
                    text.extend_from_slice(&output.stderr);
                    String::from_utf8_lossy(&text).contains("Logged in using ChatGPT")
                })
        }
        Provider::Claude => {
            command.args(["auth", "status", "--json"]);
            command
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| serde_json::from_slice::<Value>(&output.stdout).ok())
                .is_some_and(|status| {
                    status.get("loggedIn").and_then(Value::as_bool) == Some(true)
                        && status.get("authMethod").and_then(Value::as_str) == Some("claude.ai")
                })
        }
    }
}

fn spawn_bounded_reader<R: Read + Send + 'static>(
    mut stream: R,
    output: Arc<Mutex<Vec<u8>>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut chunk = [0_u8; 1024];
        loop {
            let Ok(read) = stream.read(&mut chunk) else {
                return;
            };
            if read == 0 {
                return;
            }
            let Ok(mut buffer) = output.lock() else {
                return;
            };
            let remaining = OUTPUT_LIMIT.saturating_sub(buffer.len());
            if remaining == 0 {
                continue;
            }
            buffer.extend_from_slice(&chunk[..read.min(remaining)]);
        }
    })
}

fn login_session_view(session: &LoginSession) -> LoginSessionView {
    let output = session.output.lock().map_or_else(
        |_| String::new(),
        |output| strip_ansi(&String::from_utf8_lossy(&output)),
    );
    let authorization_url = extract_authorization_url(session.provider, &output);
    let user_code = (session.provider == Provider::Codex)
        .then(|| extract_codex_user_code(&output))
        .flatten();
    let mut status = session
        .state
        .lock()
        .map_or_else(|_| String::from("failed"), |state| state.clone());
    if status == "starting" && authorization_url.is_some() {
        status = String::from("awaiting_user");
    }
    let accepts_authorization_code = session.provider == Provider::Claude
        && matches!(status.as_str(), "starting" | "awaiting_user");
    LoginSessionView {
        id: session.id.clone(),
        account_id: session.account_id.clone(),
        provider: String::from(session.provider.id()),
        status,
        authorization_url,
        user_code,
        accepts_authorization_code,
        created_at_ms: session.created_at_ms,
        expires_at_ms: session.expires_at_ms,
    }
}

fn extract_authorization_url(provider: Provider, text: &str) -> Option<String> {
    for (index, _) in text.match_indices("https://") {
        let candidate: String = text[index..]
            .chars()
            .take_while(|character| {
                !character.is_whitespace() && !character.is_control() && *character != '\u{1b}'
            })
            .collect();
        let candidate = candidate.trim_end_matches(['.', ',', ';', ')', ']', '>']);
        let allowed = match provider {
            Provider::Codex => candidate == "https://auth.openai.com/codex/device",
            Provider::Claude => candidate.starts_with("https://claude.com/cai/oauth/authorize?"),
        };
        if allowed && candidate.len() <= 4096 {
            return Some(candidate.to_owned());
        }
    }
    None
}

fn extract_codex_user_code(text: &str) -> Option<String> {
    text.split_whitespace()
        .map(|token| {
            token.trim_matches(|character: char| {
                !character.is_ascii_alphanumeric() && character != '-'
            })
        })
        .find(|token| {
            let mut segments = token.split('-');
            let first = segments.next().unwrap_or_default();
            let second = segments.next().unwrap_or_default();
            segments.next().is_none()
                && first.len() == 4
                && second.len() == 5
                && first
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
                && second
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        })
        .map(str::to_owned)
}

fn strip_ansi(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\u{1b}' && characters.peek() == Some(&'[') {
            let _ = characters.next();
            for next in characters.by_ref() {
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
        } else if !character.is_control() || matches!(character, '\n' | '\t') {
            output.push(character);
        }
    }
    output
}

fn set_session_state(state: &Arc<Mutex<String>>, value: &str) {
    if let Ok(mut state) = state.lock() {
        *state = String::from(value);
    }
}

fn write_health_path(
    path: &Path,
    provider: Provider,
    account_id: &str,
    status: &str,
    reason: &str,
    last_verified_at_ms: Option<u64>,
) -> Result<(), &'static str> {
    write_private_json(
        path,
        &HealthRecord {
            schema: String::from(HEALTH_SCHEMA),
            provider: String::from(provider.id()),
            account_id: account_id.to_owned(),
            status: status.to_owned(),
            method: String::from(provider.method()),
            reason: reason.to_owned(),
            observed_at_ms: now_ms(),
            last_verified_at_ms,
        },
    )
}

fn ensure_private_directory(path: &Path) -> Result<(), &'static str> {
    fs::create_dir_all(path).map_err(|_| "agent_auth_directory_unavailable")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| "agent_auth_directory_unavailable")?;
    let metadata = fs::symlink_metadata(path).map_err(|_| "agent_auth_directory_unavailable")?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err("agent_auth_directory_unsafe");
    }
    Ok(())
}

fn read_private_file(path: &Path, limit: u64) -> Result<Vec<u8>, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "agent_auth_file_unavailable")?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.len() > limit
    {
        return Err("agent_auth_file_unsafe");
    }
    fs::read(path).map_err(|_| "agent_auth_file_unavailable")
}

fn write_private_json<T: Serialize>(path: &Path, value: &T) -> Result<(), &'static str> {
    let parent = path.parent().ok_or("agent_auth_path_invalid")?;
    ensure_private_directory(parent)?;
    let temporary = parent.join(format!(".write-{}.tmp", generate_id("auth")?));
    let bytes = serde_json::to_vec(value).map_err(|_| "agent_auth_encode_failed")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| "agent_auth_write_failed")?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "agent_auth_write_failed")?;
    fs::rename(&temporary, path).map_err(|_| "agent_auth_write_failed")?;
    Ok(())
}

fn generate_id(prefix: &str) -> Result<String, &'static str> {
    let mut random = [0_u8; 12];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .map_err(|_| "secure_random_unavailable")?;
    Ok(format!("{prefix}-{}", hex::encode(random)))
}

fn valid_account_id(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("acct-") else {
        return false;
    };
    suffix.len() == 24 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_session_id(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("login-") else {
        return false;
    };
    suffix.len() == 24 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value.chars().count() <= 48
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_output_returns_only_allowlisted_native_authorization_material() {
        let codex = "Open https://auth.openai.com/codex/device and enter ABCD-12345";
        assert_eq!(
            Some(String::from("https://auth.openai.com/codex/device")),
            extract_authorization_url(Provider::Codex, codex)
        );
        assert_eq!(
            Some(String::from("ABCD-12345")),
            extract_codex_user_code(codex)
        );
        assert_eq!(
            None,
            extract_authorization_url(Provider::Codex, "https://attacker.invalid/device")
        );

        let claude = "https://claude.com/cai/oauth/authorize?code=short-lived&state=opaque";
        assert_eq!(
            Some(String::from(claude)),
            extract_authorization_url(Provider::Claude, claude)
        );
        assert_eq!(
            None,
            extract_authorization_url(
                Provider::Claude,
                "https://claude.com.attacker.invalid/cai/oauth/authorize?code=x"
            )
        );
    }

    #[test]
    fn account_registry_is_strict_and_selection_cannot_cross_provider() {
        let mut registry = Registry::empty();
        registry.accounts.push(AccountRecord {
            id: String::from("acct-0123456789abcdef01234567"),
            provider: String::from("codex"),
            label: String::from("Primary Codex"),
            created_at_ms: 1,
            updated_at_ms: 1,
        });
        registry.selected.insert(
            String::from("claude"),
            String::from("acct-0123456789abcdef01234567"),
        );
        assert!(!registry.validate());
        registry.selected.clear();
        registry.selected.insert(
            String::from("codex"),
            String::from("acct-0123456789abcdef01234567"),
        );
        assert!(registry.validate());
    }

    #[test]
    fn labels_and_opaque_ids_are_bounded() {
        assert!(valid_label("Claude Max"));
        assert!(!valid_label(""));
        assert!(!valid_label(" trailing "));
        assert!(!valid_label(&"x".repeat(49)));
        assert!(valid_account_id("acct-0123456789abcdef01234567"));
        assert!(!valid_account_id("../auth.json"));
        assert!(valid_session_id("login-0123456789abcdef01234567"));
    }

    #[test]
    fn empty_manager_creates_only_private_profile_roots() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary.path().join("agent-auth");
        let config = AgentAuthConfig::new(
            root.clone(),
            PathBuf::from("/bin/true"),
            PathBuf::from("/bin/true"),
        )
        .expect("valid fixture config");
        let manager = AgentAuthManager::open(config).expect("manager");
        let view = manager.view().expect("empty view");
        assert!(view.accounts().is_empty());
        assert_eq!(None, view.worker_provider());
        for directory in [root.clone(), root.join("profiles"), root.join("health")] {
            assert_eq!(0o700, fs::metadata(directory).unwrap().mode() & 0o777);
        }
        assert!(!root.join("accounts.json").exists());
    }
}
