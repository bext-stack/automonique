// SPDX-License-Identifier: Elastic-2.0

#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::ExitCode;

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
    let mut bind = IpAddr::from([127, 0, 0, 1]);
    let mut port = 18_082_u16;
    let mut auth_config = None;
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
    let integration_config = integration_config.ok_or("--integration-config is required")?;
    let state_dir = state_dir.ok_or("--state-dir is required")?;
    let runtime_dir = runtime_dir.ok_or("--runtime-dir is required")?;
    let agent_auth_dir = agent_auth_dir.ok_or("--agent-auth-dir is required")?;
    let codex_binary = codex_binary.ok_or("--codex-binary is required")?;
    let claude_binary = claude_binary.ok_or("--claude-binary is required")?;
    if [
        &auth_config,
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
    automonique_web_entry::serve(listener, auth, integration)?;
    Ok(())
}
