// SPDX-License-Identifier: Elastic-2.0

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::ExitCode;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroize;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(category) => {
            eprintln!("Manage chat credential generation refused: {category}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), &'static str> {
    let mut arguments = std::env::args_os().skip(1);
    let (Some(config_path), service_id, None) =
        (arguments.next(), arguments.next(), arguments.next())
    else {
        return Err("usage");
    };
    let config_path = PathBuf::from(config_path);
    if !config_path.is_absolute() || config_path.exists() {
        return Err("path");
    }
    let service_id = service_id
        .as_deref()
        .map(|value| value.to_str().ok_or("service_id"))
        .transpose()?;
    if service_id.is_some_and(|value| {
        value.is_empty()
            || value.len() > 64
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
    }) {
        return Err("service_id");
    }

    let mut random = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut random))
        .map_err(|_| "entropy")?;
    let mut token = URL_SAFE_NO_PAD.encode(random);
    let mut config = String::from("schema=automonique.manage-chat-auth/v1\n");
    if let Some(service_id) = service_id {
        config.push_str("id=");
        config.push_str(service_id);
        config.push('\n');
    }
    config.push_str("token=");
    config.push_str(&token);
    config.push_str("\nend=automonique.manage-chat-auth/v1\n");

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(config_path)
        .map_err(|_| "config_file")?;
    file.write_all(config.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| "config_file")?;
    random.zeroize();
    token.zeroize();
    config.zeroize();
    Ok(())
}
