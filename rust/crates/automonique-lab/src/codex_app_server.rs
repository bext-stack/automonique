// SPDX-License-Identifier: Elastic-2.0

//! Pinned Codex App Server execution inside an outer lab sandbox.
//!
//! GitHub and deployment credentials are intentionally absent. The process sees
//! only an isolated Codex home, the candidate worktree, read-only build tooling,
//! and ordinary operating-system files. Codex's workspace-write sandbox stays
//! enabled inside that outer boundary, so model-issued commands cannot read the
//! App Server's model-auth home or use the network. The candidate is never
//! mistaken for the authority that later publishes or activates the result.

use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const BWRAP: &str = "/usr/bin/bwrap";
const SANDBOX_CODEX: &str = "/automonique/bin/codex";
const SANDBOX_WORKSPACE: &str = "/workspace";
const SANDBOX_CODEX_HOME: &str = "/codex-home";
const SANDBOX_CARGO_HOME: &str = "/tooling/cargo";
const SANDBOX_RUSTUP_HOME: &str = "/tooling/rustup";
const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_PENDING_NOTIFICATIONS: usize = 4_096;
const MAX_PROMPT_BYTES: usize = 128 * 1024;
const CODEX_WALL_LIMIT: Duration = Duration::from_secs(45 * 60);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexAppServerConfig {
    binary: PathBuf,
    binary_sha256: String,
    worktree: PathBuf,
    codex_home: PathBuf,
    cargo_home: PathBuf,
    rustup_home: PathBuf,
    model: String,
}

impl CodexAppServerConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        binary: impl AsRef<Path>,
        binary_sha256: &str,
        worktree: impl AsRef<Path>,
        codex_home: impl AsRef<Path>,
        cargo_home: impl AsRef<Path>,
        rustup_home: impl AsRef<Path>,
        model: &str,
    ) -> Result<Self, CodexAppServerError> {
        validate_digest(binary_sha256)?;
        validate_label(model, "model", 128)?;
        let binary = canonical_regular_file(binary.as_ref(), "binary")?;
        let worktree = canonical_directory(worktree.as_ref(), "worktree")?;
        let codex_home = canonical_private_directory(codex_home.as_ref(), "codex_home")?;
        let cargo_home = canonical_directory(cargo_home.as_ref(), "cargo_home")?;
        let rustup_home = canonical_directory(rustup_home.as_ref(), "rustup_home")?;
        for tooling in [&cargo_home, &rustup_home] {
            if tooling.starts_with(&worktree) || tooling.starts_with(&codex_home) {
                return Err(CodexAppServerError::UnsafePath("tooling root overlap"));
            }
        }
        if worktree.starts_with(&codex_home) || codex_home.starts_with(&worktree) {
            return Err(CodexAppServerError::UnsafePath(
                "state and worktree overlap",
            ));
        }
        let actual = sha256_file(&binary)?;
        if actual != binary_sha256 {
            return Err(CodexAppServerError::BinaryDigestMismatch);
        }
        Ok(Self {
            binary,
            binary_sha256: binary_sha256.to_owned(),
            worktree,
            codex_home,
            cargo_home,
            rustup_home,
            model: model.to_owned(),
        })
    }

    #[must_use]
    pub fn binary_sha256(&self) -> &str {
        &self.binary_sha256
    }

    #[must_use]
    pub fn worktree(&self) -> &Path {
        &self.worktree
    }

    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    fn bwrap_args(&self) -> Vec<String> {
        let mut args = [
            "--die-with-parent",
            "--new-session",
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-ipc",
            "--clearenv",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/etc",
            "/etc",
            "--dir",
            "/automonique",
            "--dir",
            "/automonique/bin",
            "--dir",
            "/tooling",
            "--ro-bind",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        args.push(path_text(&self.binary));
        args.push(SANDBOX_CODEX.to_owned());
        push_mount(&mut args, "--bind", &self.worktree, SANDBOX_WORKSPACE);
        push_mount(&mut args, "--bind", &self.codex_home, SANDBOX_CODEX_HOME);
        push_mount(&mut args, "--ro-bind", &self.cargo_home, SANDBOX_CARGO_HOME);
        push_mount(
            &mut args,
            "--ro-bind",
            &self.rustup_home,
            SANDBOX_RUSTUP_HOME,
        );
        for library in ["/lib", "/lib64"] {
            if Path::new(library).exists() {
                args.extend([
                    "--ro-bind".to_owned(),
                    library.to_owned(),
                    library.to_owned(),
                ]);
            }
        }
        args.extend([
            "--setenv".to_owned(),
            "HOME".to_owned(),
            SANDBOX_CODEX_HOME.to_owned(),
            "--setenv".to_owned(),
            "CODEX_HOME".to_owned(),
            SANDBOX_CODEX_HOME.to_owned(),
            "--setenv".to_owned(),
            "CARGO_HOME".to_owned(),
            SANDBOX_CARGO_HOME.to_owned(),
            "--setenv".to_owned(),
            "RUSTUP_HOME".to_owned(),
            SANDBOX_RUSTUP_HOME.to_owned(),
            "--setenv".to_owned(),
            "PATH".to_owned(),
            format!("{SANDBOX_CARGO_HOME}/bin:/usr/bin:/bin"),
            "--chdir".to_owned(),
            SANDBOX_WORKSPACE.to_owned(),
            "--".to_owned(),
            SANDBOX_CODEX.to_owned(),
            "app-server".to_owned(),
            "--listen".to_owned(),
            "stdio://".to_owned(),
        ]);
        args
    }
}

fn push_mount(args: &mut Vec<String>, operation: &str, source: &Path, target: &str) {
    args.extend([operation.to_owned(), path_text(source), target.to_owned()]);
}

#[derive(Debug)]
pub enum CodexAppServerError {
    InvalidField(&'static str),
    UnsafePath(&'static str),
    BinaryDigestMismatch,
    Spawn(std::io::Error),
    Io(std::io::Error),
    Protocol(&'static str),
    Server { code: i64, message: String },
    TurnFailed(String),
}

impl fmt::Display for CodexAppServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => {
                write!(formatter, "invalid Codex app-server field: {field}")
            }
            Self::UnsafePath(reason) => write!(formatter, "unsafe Codex app-server path: {reason}"),
            Self::BinaryDigestMismatch => formatter.write_str("Codex binary digest mismatch"),
            Self::Spawn(error) => write!(
                formatter,
                "could not start sandboxed Codex app-server: {error}"
            ),
            Self::Io(error) => write!(formatter, "Codex app-server I/O error: {error}"),
            Self::Protocol(reason) => {
                write!(formatter, "Codex app-server protocol error: {reason}")
            }
            Self::Server { code, message } => write!(
                formatter,
                "Codex app-server refused request ({code}): {message}"
            ),
            Self::TurnFailed(status) => {
                write!(formatter, "Codex implementation turn ended as {status}")
            }
        }
    }
}

impl Error for CodexAppServerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Spawn(error) | Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexTurnResult {
    pub thread_id: String,
    pub turn_id: String,
    pub final_message: String,
}

#[derive(Debug)]
pub struct CodexAppServer {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    next_id: u64,
    model: String,
    pending: Vec<Value>,
    watchdog_stop: Arc<AtomicBool>,
    watchdog: Option<JoinHandle<()>>,
}

impl CodexAppServer {
    pub fn spawn(config: &CodexAppServerConfig) -> Result<Self, CodexAppServerError> {
        // Recheck immediately before exec so replacing the pinned binary after
        // configuration verification cannot silently widen the launch.
        if sha256_file(&config.binary)? != config.binary_sha256 {
            return Err(CodexAppServerError::BinaryDigestMismatch);
        }
        let mut child = Command::new(BWRAP)
            .args(config.bwrap_args())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(CodexAppServerError::Spawn)?;
        let input = child
            .stdin
            .take()
            .ok_or(CodexAppServerError::Protocol("missing stdin"))?;
        let output = child
            .stdout
            .take()
            .ok_or(CodexAppServerError::Protocol("missing stdout"))?;
        let watchdog_stop = Arc::new(AtomicBool::new(false));
        let watchdog = spawn_watchdog(child.id(), Arc::clone(&watchdog_stop));
        let mut server = Self {
            child,
            input,
            output: BufReader::new(output),
            next_id: 1,
            model: config.model.clone(),
            pending: Vec::new(),
            watchdog_stop,
            watchdog: Some(watchdog),
        };
        server.initialize()?;
        Ok(server)
    }

    fn initialize(&mut self) -> Result<(), CodexAppServerError> {
        self.request(
            "initialize",
            json!({
                "clientInfo": {"name": "automonique-lab", "version": env!("CARGO_PKG_VERSION")},
                "capabilities": {"experimentalApi": false}
            }),
        )?;
        self.notify("initialized", Value::Null)
    }

    pub fn start_thread(
        &mut self,
        developer_instructions: &str,
    ) -> Result<String, CodexAppServerError> {
        validate_text(
            developer_instructions,
            "developer_instructions",
            MAX_PROMPT_BYTES,
        )?;
        let response = self.request(
            "thread/start",
            json!({
                "cwd": SANDBOX_WORKSPACE,
                "model": self.model,
                "approvalPolicy": "never",
                "sandbox": "workspace-write",
                "developerInstructions": developer_instructions,
                "ephemeral": false
            }),
        )?;
        response
            .pointer("/thread/id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(CodexAppServerError::Protocol(
                "thread/start omitted thread id",
            ))
    }

    pub fn resume_thread(&mut self, thread_id: &str) -> Result<(), CodexAppServerError> {
        validate_label(thread_id, "thread_id", 256)?;
        self.request(
            "thread/resume",
            json!({
                "threadId": thread_id,
                "cwd": SANDBOX_WORKSPACE,
                "model": self.model,
                "approvalPolicy": "never",
                "sandbox": "workspace-write"
            }),
        )?;
        Ok(())
    }

    pub fn run_turn(
        &mut self,
        thread_id: &str,
        prompt: &str,
    ) -> Result<CodexTurnResult, CodexAppServerError> {
        validate_label(thread_id, "thread_id", 256)?;
        validate_text(prompt, "prompt", MAX_PROMPT_BYTES)?;
        let response = self.request(
            "turn/start",
            json!({
                "threadId": thread_id,
                "input": [{"type": "text", "text": prompt}],
                "cwd": SANDBOX_WORKSPACE,
                "model": self.model,
                "approvalPolicy": "never",
                "sandboxPolicy": {
                    "type": "workspaceWrite",
                    "writableRoots": [SANDBOX_WORKSPACE],
                    "networkAccess": false,
                    "excludeSlashTmp": true,
                    "excludeTmpdirEnvVar": true
                }
            }),
        )?;
        let turn_id = response
            .pointer("/turn/id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(CodexAppServerError::Protocol("turn/start omitted turn id"))?;
        let mut final_message = String::new();
        loop {
            let message = if self.pending.is_empty() {
                self.read_message()?
            } else {
                self.pending.remove(0)
            };
            let method = message.get("method").and_then(Value::as_str).unwrap_or("");
            if method == "item/agentMessage/delta"
                && message.pointer("/params/threadId").and_then(Value::as_str) == Some(thread_id)
                && message.pointer("/params/turnId").and_then(Value::as_str) == Some(&turn_id)
            {
                let delta = message
                    .pointer("/params/delta")
                    .and_then(Value::as_str)
                    .ok_or(CodexAppServerError::Protocol(
                        "agent message delta omitted text",
                    ))?;
                if final_message.len().saturating_add(delta.len()) > MAX_PROMPT_BYTES {
                    return Err(CodexAppServerError::Protocol(
                        "agent message exceeded limit",
                    ));
                }
                final_message.push_str(delta);
            } else if method == "turn/completed"
                && message.pointer("/params/threadId").and_then(Value::as_str) == Some(thread_id)
                && message.pointer("/params/turn/id").and_then(Value::as_str) == Some(&turn_id)
            {
                let status = message
                    .pointer("/params/turn/status")
                    .and_then(Value::as_str)
                    .ok_or(CodexAppServerError::Protocol(
                        "turn completion omitted status",
                    ))?;
                if status != "completed" {
                    return Err(CodexAppServerError::TurnFailed(status.to_owned()));
                }
                return Ok(CodexTurnResult {
                    thread_id: thread_id.to_owned(),
                    turn_id,
                    final_message,
                });
            } else if message.get("id").is_some() && message.get("method").is_some() {
                self.refuse_server_request(&message)?;
            }
        }
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, CodexAppServerError> {
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(CodexAppServerError::Protocol("request id exhausted"))?;
        self.write_message(&json!({"id": id, "method": method, "params": params}))?;
        loop {
            let message = self.read_message()?;
            if message.get("id").and_then(Value::as_u64) == Some(id) {
                if let Some(error) = message.get("error") {
                    let code = error.get("code").and_then(Value::as_i64).unwrap_or(-1);
                    let text = error
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("unspecified refusal");
                    return Err(CodexAppServerError::Server {
                        code,
                        message: text.chars().take(1_024).collect(),
                    });
                }
                return message
                    .get("result")
                    .cloned()
                    .ok_or(CodexAppServerError::Protocol("response omitted result"));
            }
            if message.get("id").is_some() && message.get("method").is_some() {
                self.refuse_server_request(&message)?;
            } else {
                if self.pending.len() >= MAX_PENDING_NOTIFICATIONS {
                    return Err(CodexAppServerError::Protocol(
                        "too many pending notifications",
                    ));
                }
                self.pending.push(message);
            }
        }
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), CodexAppServerError> {
        self.write_message(&json!({"method": method, "params": params}))
    }

    fn refuse_server_request(&mut self, request: &Value) -> Result<(), CodexAppServerError> {
        let id = request
            .get("id")
            .cloned()
            .ok_or(CodexAppServerError::Protocol("server request omitted id"))?;
        self.write_message(&json!({
            "id": id,
            "error": {"code": -32601, "message": "automonique-lab does not delegate approval authority"}
        }))
    }

    fn write_message(&mut self, value: &Value) -> Result<(), CodexAppServerError> {
        let encoded = serde_json::to_vec(value)
            .map_err(|_| CodexAppServerError::Protocol("could not encode request"))?;
        if encoded.len() > MAX_MESSAGE_BYTES {
            return Err(CodexAppServerError::Protocol("request exceeded limit"));
        }
        self.input
            .write_all(&encoded)
            .map_err(CodexAppServerError::Io)?;
        self.input
            .write_all(b"\n")
            .map_err(CodexAppServerError::Io)?;
        self.input.flush().map_err(CodexAppServerError::Io)
    }

    fn read_message(&mut self) -> Result<Value, CodexAppServerError> {
        let mut bytes = Vec::new();
        loop {
            let available = self.output.fill_buf().map_err(CodexAppServerError::Io)?;
            if available.is_empty() {
                return Err(CodexAppServerError::Protocol("app-server closed output"));
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let take = newline.map_or(available.len(), |position| position + 1);
            if bytes.len().saturating_add(take) > MAX_MESSAGE_BYTES {
                return Err(CodexAppServerError::Protocol("response exceeded limit"));
            }
            bytes.extend_from_slice(&available[..take]);
            self.output.consume(take);
            if newline.is_some() {
                break;
            }
        }
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| CodexAppServerError::Protocol("invalid response JSON"))
    }
}

impl Drop for CodexAppServer {
    fn drop(&mut self) {
        self.watchdog_stop.store(true, Ordering::Release);
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(watchdog) = self.watchdog.take() {
            let _ = watchdog.join();
        }
    }
}

fn spawn_watchdog(pid: u32, stop: Arc<AtomicBool>) -> JoinHandle<()> {
    thread::spawn(move || {
        let deadline = Instant::now() + CODEX_WALL_LIMIT;
        while !stop.load(Ordering::Acquire) {
            let now = Instant::now();
            if now >= deadline {
                if let Ok(pid) = i32::try_from(pid) {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                }
                return;
            }
            thread::sleep((deadline - now).min(Duration::from_millis(250)));
        }
    })
}

fn canonical_regular_file(
    path: &Path,
    field: &'static str,
) -> Result<PathBuf, CodexAppServerError> {
    if !path.is_absolute() {
        return Err(CodexAppServerError::UnsafePath(field));
    }
    let canonical = fs::canonicalize(path).map_err(CodexAppServerError::Io)?;
    let metadata = fs::metadata(&canonical).map_err(CodexAppServerError::Io)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_BINARY_BYTES {
        return Err(CodexAppServerError::UnsafePath(field));
    }
    Ok(canonical)
}

fn canonical_directory(path: &Path, field: &'static str) -> Result<PathBuf, CodexAppServerError> {
    if !path.is_absolute() {
        return Err(CodexAppServerError::UnsafePath(field));
    }
    let canonical = fs::canonicalize(path).map_err(CodexAppServerError::Io)?;
    if !fs::metadata(&canonical)
        .map_err(CodexAppServerError::Io)?
        .is_dir()
    {
        return Err(CodexAppServerError::UnsafePath(field));
    }
    Ok(canonical)
}

fn canonical_private_directory(
    path: &Path,
    field: &'static str,
) -> Result<PathBuf, CodexAppServerError> {
    let canonical = canonical_directory(path, field)?;
    let metadata = fs::metadata(&canonical).map_err(CodexAppServerError::Io)?;
    if metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(CodexAppServerError::UnsafePath(field));
    }
    Ok(canonical)
}

fn sha256_file(path: &Path) -> Result<String, CodexAppServerError> {
    let mut file = File::open(path).map_err(CodexAppServerError::Io)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer).map_err(CodexAppServerError::Io)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if total > MAX_BINARY_BYTES {
            return Err(CodexAppServerError::UnsafePath("binary size"));
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn validate_digest(value: &str) -> Result<(), CodexAppServerError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CodexAppServerError::InvalidField("binary_sha256"));
    }
    Ok(())
}

fn validate_label(value: &str, field: &'static str, max: usize) -> Result<(), CodexAppServerError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(CodexAppServerError::InvalidField(field));
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<(), CodexAppServerError> {
    if value.trim().is_empty() || value.len() > max || value.contains('\0') {
        return Err(CodexAppServerError::InvalidField(field));
    }
    Ok(())
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fixture() -> (TempDir, CodexAppServerConfig) {
        let directory = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("permissions");
        let binary = directory.path().join("codex");
        fs::write(&binary, b"pinned fake binary").expect("binary");
        let digest = sha256_file(&binary).expect("digest");
        let worktree = directory.path().join("worktree");
        let home = directory.path().join("codex-home");
        let cargo = directory.path().join("cargo");
        let rustup = directory.path().join("rustup");
        for path in [&worktree, &home, &cargo, &rustup] {
            fs::create_dir(path).expect("directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("permissions");
        }
        let config = CodexAppServerConfig::verify(
            &binary,
            &digest,
            &worktree,
            &home,
            &cargo,
            &rustup,
            "gpt-5.6-codex",
        )
        .expect("configuration");
        (directory, config)
    }

    #[test]
    fn launch_is_an_argument_vector_with_only_explicit_mounts() {
        let (_directory, config) = fixture();
        let args = config.bwrap_args();
        assert!(args.windows(3).any(|parts| parts
            == [
                "--bind",
                config.worktree().to_str().expect("path"),
                SANDBOX_WORKSPACE
            ]));
        assert!(
            args.windows(3)
                .any(|parts| parts == ["--setenv", "CODEX_HOME", SANDBOX_CODEX_HOME])
        );
        assert_eq!(
            &args[args.len() - 4..],
            [SANDBOX_CODEX, "app-server", "--listen", "stdio://"]
        );
        assert!(
            !args
                .iter()
                .any(|arg| arg.contains("GITHUB_TOKEN") || arg.contains("SSH_AUTH_SOCK"))
        );
    }

    #[test]
    fn replacement_binary_and_non_private_state_are_refused() {
        let (directory, config) = fixture();
        fs::write(&config.binary, b"replacement").expect("replace binary");
        assert!(matches!(
            CodexAppServer::spawn(&config),
            Err(CodexAppServerError::BinaryDigestMismatch)
        ));

        let home = directory.path().join("public-home");
        fs::create_dir(&home).expect("home");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o755)).expect("permissions");
        let digest = sha256_file(&config.binary).expect("digest");
        let error = CodexAppServerConfig::verify(
            &config.binary,
            &digest,
            &config.worktree,
            &home,
            &config.cargo_home,
            &config.rustup_home,
            "gpt-5.6-codex",
        )
        .expect_err("public home");
        assert!(matches!(
            error,
            CodexAppServerError::UnsafePath("codex_home")
        ));
    }
}
