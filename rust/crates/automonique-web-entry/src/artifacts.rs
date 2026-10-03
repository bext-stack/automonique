// SPDX-License-Identifier: Elastic-2.0
//! Authenticated artifact broker. The Share credential never reaches the browser.
use super::*;
use zeroize::Zeroizing;

fn configuration(state: &Path) -> Result<(String, Zeroizing<String>), &'static str> {
    let path = state.join("share/share.conf");
    let meta = fs::symlink_metadata(&path).map_err(|_| "artifacts_not_configured")?;
    if !meta.is_file()
        || meta.uid() != geteuid().as_raw()
        || meta.mode() & 0o077 != 0
        || meta.len() > 16384
    {
        return Err("artifacts_not_configured");
    }
    let raw = Zeroizing::new(fs::read_to_string(path).map_err(|_| "artifacts_not_configured")?);
    let mut base = None;
    let mut secret = None;
    for line in raw.lines() {
        if let Some(value) = line.strip_prefix("public_base=") {
            base = Some(value.trim_end_matches('/').to_owned());
        }
        if let Some(value) = line.strip_prefix("secret=") {
            secret = Some(Zeroizing::new(value.to_owned()));
        }
    }
    let base = base.ok_or("artifacts_not_configured")?;
    let uri: ureq::http::Uri = base.parse().map_err(|_| "artifacts_not_configured")?;
    if uri.scheme_str() != Some("https")
        || uri.authority().is_none_or(|a| a.as_str().contains('@'))
        || uri.path() != "/"
        || uri.query().is_some()
    {
        return Err("artifacts_not_configured");
    }
    let secret = secret
        .filter(|s| s.len() >= 32 && s.len() <= 4096 && !s.contains(char::is_whitespace))
        .ok_or("artifacts_not_configured")?;
    Ok((base, secret))
}
impl WebIntegration {
    pub(super) fn artifact_action(&self, body: &[u8]) -> Response {
        let request: Value = match serde_json::from_slice(body) {
            Ok(value) => value,
            Err(_) => return json_error("400 Bad Request", "invalid_json"),
        };
        if !matches!(
            request.get("action").and_then(Value::as_str),
            Some("list" | "get" | "begin" | "chunk" | "commit" | "read" | "update" | "delete")
        ) {
            return json_error("400 Bad Request", "invalid_request");
        }
        let (base, secret) = match configuration(&self.state_dir) {
            Ok(config) => config,
            Err(code) => return json_error("503 Service Unavailable", code),
        };
        let result = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(45)))
            .max_redirects(0)
            .http_status_as_error(false)
            .proxy(None)
            .build()
            .new_agent()
            .post(format!("{base}/api/artifacts"))
            .header("content-type", "application/json")
            .header("user-agent", "MoniqueArtifact/1.0")
            .header("x-share-ingest-secret", secret.as_str())
            .send(body);
        let Ok(mut response) = result else {
            return json_error("503 Service Unavailable", "storage_unavailable");
        };
        let status = match response.status().as_u16() {
            200 => "200 OK",
            400 => "400 Bad Request",
            401 | 403 => "403 Forbidden",
            404 => "404 Not Found",
            409 => "409 Conflict",
            413 => "413 Payload Too Large",
            _ => "503 Service Unavailable",
        };
        let Ok(bytes) = response
            .body_mut()
            .with_config()
            .limit(16 * 1024 * 1024)
            .read_to_vec()
        else {
            return json_error("503 Service Unavailable", "storage_unavailable");
        };
        let Ok(mut value) = serde_json::from_slice::<Value>(&bytes) else {
            return json_error("503 Service Unavailable", "storage_unavailable");
        };
        if let Some(object) = value.as_object_mut() {
            object.insert("public_base".to_owned(), Value::String(base));
        }
        json_response(status, &value)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn artifact_configuration_requires_private_https_credentials() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("share")).unwrap();
        let file = root.path().join("share/share.conf");
        fs::write(
            &file,
            format!(
                "public_base=https://share.example.test\nsecret={}\n",
                "a".repeat(48)
            ),
        )
        .unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(configuration(root.path()).is_ok());
        for base in [
            "http://localhost",
            "https://user@share.example.test",
            "https://share.example.test/elsewhere",
            "https://share.example.test?x=1",
        ] {
            fs::write(
                &file,
                format!("public_base={base}\nsecret={}\n", "a".repeat(48)),
            )
            .unwrap();
            assert!(configuration(root.path()).is_err());
        }
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(configuration(root.path()).is_err());
    }
}
