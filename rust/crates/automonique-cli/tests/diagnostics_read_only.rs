// SPDX-License-Identifier: Elastic-2.0

use automonique_cli::{inspect_admin_socket, inspect_control_plane, inspect_process_control};
use automonique_protocol::CheckStatus;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;

fn private_runtime() -> tempfile::TempDir {
    let runtime = tempfile::tempdir().expect("runtime");
    std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private base");
    let product = runtime.path().join("automonique");
    std::fs::create_dir(&product).expect("product directory");
    std::fs::set_permissions(&product, std::fs::Permissions::from_mode(0o700))
        .expect("private product");
    runtime
}

#[test]
fn private_unix_admin_socket_and_process_control_are_healthy() {
    let runtime = private_runtime();
    let socket = runtime.path().join("automonique/admin.sock");
    let listener = UnixListener::bind(&socket).expect("socket");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
        .expect("private socket");
    let before = std::fs::symlink_metadata(&socket)
        .expect("metadata")
        .permissions()
        .mode();

    assert_eq!(
        inspect_admin_socket(Some(runtime.path().as_os_str())).status(),
        CheckStatus::Healthy
    );
    assert_eq!(inspect_process_control().status(), CheckStatus::Healthy);
    let admin = inspect_admin_socket(Some(runtime.path().as_os_str()));
    let responder = std::thread::spawn(move || {
        let _connection = listener.accept().expect("doctor connects");
    });
    let [database, generation] = inspect_control_plane(Some(runtime.path().as_os_str()), &admin);
    responder.join().expect("responder");
    assert_eq!(database.status(), CheckStatus::Unavailable);
    assert_eq!(generation.status(), CheckStatus::Unavailable);
    assert_eq!(
        std::fs::symlink_metadata(&socket)
            .expect("metadata")
            .permissions()
            .mode(),
        before
    );
}

#[test]
fn missing_wrong_type_and_permissive_socket_are_reported_without_repair() {
    let runtime = private_runtime();
    assert_eq!(
        inspect_admin_socket(Some(runtime.path().as_os_str())).status(),
        CheckStatus::Unavailable
    );

    let socket = runtime.path().join("automonique/admin.sock");
    std::fs::write(&socket, b"not a socket").expect("file");
    assert_eq!(
        inspect_admin_socket(Some(runtime.path().as_os_str())).status(),
        CheckStatus::Finding
    );
    std::fs::remove_file(&socket).expect("remove fixture");

    let _listener = UnixListener::bind(&socket).expect("socket");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))
        .expect("permissive socket");
    assert_eq!(
        inspect_admin_socket(Some(runtime.path().as_os_str())).status(),
        CheckStatus::Finding
    );
    assert_eq!(
        std::fs::symlink_metadata(&socket)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o7777,
        0o666
    );
}

#[test]
fn symlinked_socket_path_is_never_followed() {
    let runtime = private_runtime();
    let target = tempfile::NamedTempFile::new().expect("target");
    let socket = runtime.path().join("automonique/admin.sock");
    std::os::unix::fs::symlink(target.path(), &socket).expect("symlink");
    assert_eq!(
        inspect_admin_socket(Some(runtime.path().as_os_str())).status(),
        CheckStatus::Finding
    );
    assert!(
        std::fs::symlink_metadata(&socket)
            .expect("metadata")
            .file_type()
            .is_symlink()
    );
}
