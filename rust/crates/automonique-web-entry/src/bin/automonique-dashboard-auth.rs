// SPDX-License-Identifier: Elastic-2.0

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(category) => {
            eprintln!("dashboard credential generation refused: {category}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), &'static str> {
    let mut arguments = std::env::args_os().skip(1);
    let (Some(config_path), Some(recovery_path), None) =
        (arguments.next(), arguments.next(), arguments.next())
    else {
        return Err("usage");
    };
    let config_path = PathBuf::from(config_path);
    let recovery_path = PathBuf::from(recovery_path);
    if !config_path.is_absolute()
        || !recovery_path.is_absolute()
        || config_path == recovery_path
        || config_path.exists()
        || recovery_path.exists()
    {
        return Err("path");
    }

    let mut random = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut random))
        .map_err(|_| "entropy")?;
    let mut password = URL_SAFE_NO_PAD.encode(random);
    let digest = hex::encode(Sha256::digest(password.as_bytes()));

    let recovery = format!(
        "schema=automonique.dashboard-recovery/v1\nusername=ops\npassword={password}\nend=automonique.dashboard-recovery/v1\n"
    );
    write_new(&recovery_path, recovery.as_bytes()).map_err(|_| "recovery_file")?;
    let config = format!(
        "schema=automonique.dashboard-auth/v1\nusername=ops\ncredential_sha256={digest}\nend=automonique.dashboard-auth/v1\n"
    );
    write_new(&config_path, config.as_bytes()).map_err(|_| "config_file")?;

    random.zeroize();
    password.zeroize();
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
