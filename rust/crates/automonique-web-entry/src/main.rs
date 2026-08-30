// SPDX-License-Identifier: Elastic-2.0

#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::ExitCode;

/// The same three facts `/api/build` serves, for a caller standing on the host.
///
/// `--json` renders the identical document the HTTP surface returns, byte for
/// byte, so an operator with shell access and a harness with a credential are
/// never comparing two different renderings of one build.
fn build_identity_report(json: bool) -> Vec<u8> {
    let identity = automonique_build_identity::BuildIdentity::current();
    if json {
        let mut document = automonique_web_entry::build_identity_document(&identity);
        document.push(b'\n');
        return document;
    }
    format!(
        "automonique web entry build identity\n  source revision: {}\n  provenance: {}\n  build target: {}\n",
        identity.source_revision().unwrap_or("unknown"),
        identity.provenance().as_str(),
        identity.build_target(),
    )
    .into_bytes()
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("automonique web entry refused: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Before anything is parsed or opened. A deployed binary has to be
    // answerable about which revision it is *without* the configuration,
    // sockets and state directories a serving run needs, because the moment
    // that question matters is usually the moment one of those is in doubt.
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments
        .iter()
        .any(|argument| argument == "--build-identity")
    {
        let json = arguments.iter().any(|argument| argument == "--json");
        std::io::Write::write_all(&mut std::io::stdout(), &build_identity_report(json))?;
        return Ok(());
    }
    let mut bind = IpAddr::from([127, 0, 0, 1]);
    let mut port = 18_082_u16;
    let mut auth_config = None;
    let mut manage_chat_auth_config = None;
    let mut integration_config = None;
    let mut state_dir = None;
    let mut runtime_dir = None;
    let mut agent_auth_dir = None;
    let mut codex_binary = None;
    let mut claude_binary = None;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--bind" => bind = arguments.next().ok_or("--bind requires a value")?.parse()?,
            "--port" => port = arguments.next().ok_or("--port requires a value")?.parse()?,
            "--auth-config" => {
                auth_config = Some(PathBuf::from(
                    arguments.next().ok_or("--auth-config requires a value")?,
                ));
            }
            "--manage-chat-auth-config" => {
                manage_chat_auth_config = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or("--manage-chat-auth-config requires a value")?,
                ));
            }
            "--integration-config" => {
                integration_config = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or("--integration-config requires a value")?,
                ));
            }
            "--state-dir" => {
                state_dir = Some(PathBuf::from(
                    arguments.next().ok_or("--state-dir requires a value")?,
                ));
            }
            "--runtime-dir" => {
                runtime_dir = Some(PathBuf::from(
                    arguments.next().ok_or("--runtime-dir requires a value")?,
                ));
            }
            "--agent-auth-dir" => {
                agent_auth_dir = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or("--agent-auth-dir requires a value")?,
                ));
            }
            "--codex-binary" => {
                codex_binary = Some(PathBuf::from(
                    arguments.next().ok_or("--codex-binary requires a value")?,
                ));
            }
            "--claude-binary" => {
                claude_binary = Some(PathBuf::from(
                    arguments.next().ok_or("--claude-binary requires a value")?,
                ));
            }
            _ => return Err(format!("unknown argument {argument}").into()),
        }
    }
    if !bind.is_loopback() {
        return Err("non-loopback bind".into());
    }
    if port == 0 {
        return Err("port zero".into());
    }
    let auth_config = auth_config.ok_or("--auth-config is required")?;
    let manage_chat_auth_config =
        manage_chat_auth_config.ok_or("--manage-chat-auth-config is required")?;
    let integration_config = integration_config.ok_or("--integration-config is required")?;
    let state_dir = state_dir.ok_or("--state-dir is required")?;
    let runtime_dir = runtime_dir.ok_or("--runtime-dir is required")?;
    let agent_auth_dir = agent_auth_dir.ok_or("--agent-auth-dir is required")?;
    let codex_binary = codex_binary.ok_or("--codex-binary is required")?;
    let claude_binary = claude_binary.ok_or("--claude-binary is required")?;
    if [
        &auth_config,
        &manage_chat_auth_config,
        &integration_config,
        &state_dir,
        &runtime_dir,
        &agent_auth_dir,
        &codex_binary,
        &claude_binary,
    ]
    .iter()
    .any(|path| !path.is_absolute())
    {
        return Err("dashboard paths must be absolute".into());
    }
    let auth = automonique_web_entry::BasicAuth::from_file(&auth_config)?;
    let manage_chat_auth =
        automonique_web_entry::ManageChatAuth::from_file(&manage_chat_auth_config)?;
    let integration_config =
        automonique_web_entry::IntegrationConfig::from_file(&integration_config)?;
    let agent_auth =
        automonique_web_entry::AgentAuthConfig::new(agent_auth_dir, codex_binary, claude_binary)?;
    let integration = automonique_web_entry::WebIntegration::open_with_agent_auth(
        integration_config,
        &state_dir,
        &runtime_dir,
        agent_auth,
    )?;
    let listener = TcpListener::bind(SocketAddr::new(bind, port))?;
    automonique_web_entry::serve(listener, auth, manage_chat_auth, integration)?;
    Ok(())
}
