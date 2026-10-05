// SPDX-License-Identifier: Elastic-2.0
//! Signed Share notifications. The job/artifact service remains authoritative.
use super::*;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

fn mac(key: &[u8], value: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|n| n ^ 0x36));
    inner.update(value);
    let mut outer = Sha256::new();
    outer.update(block.map(|n| n ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}
impl WebIntegration {
    pub(super) fn integration_event_authorized(
        &self,
        timestamp: Option<&str>,
        signature: Option<&str>,
        body: &[u8],
    ) -> bool {
        let (Some(timestamp), Some(signature)) = (timestamp, signature) else {
            return false;
        };
        let Ok(seconds) = timestamp.parse::<u64>() else {
            return false;
        };
        if timestamp.len() > 12 || (now_ms() / 1000).abs_diff(seconds) > 300 {
            return false;
        }
        let Some(signature) = signature.strip_prefix("v1=") else {
            return false;
        };
        let Ok(signature) = hex::decode(signature) else {
            return false;
        };
        if signature.len() != 32 {
            return false;
        }
        let Ok(config) = read_private_config(&self.state_dir.join("share/webhooks.json"), 16384)
        else {
            return false;
        };
        let Ok(keys) = serde_json::from_slice::<Vec<String>>(&config) else {
            return false;
        };
        if keys.len() > 32 {
            return false;
        }
        let mut input = timestamp.as_bytes().to_vec();
        input.push(b'.');
        input.extend_from_slice(body);
        keys.iter()
            .filter(|key| key.len() >= 32 && key.len() <= 128)
            .any(|key| bool::from(mac(key.as_bytes(), &input).as_slice().ct_eq(&signature)))
    }
    pub(super) fn integration_event_receive(&self, body: &[u8]) -> Response {
        let Ok(value) = serde_json::from_slice::<Value>(body) else {
            return json_error("400 Bad Request", "invalid_event");
        };
        let Some(id) = value["id"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 100)
        else {
            return json_error("400 Bad Request", "invalid_event");
        };
        let Some(kind) = value["type"]
            .as_str()
            .filter(|s| s.starts_with("job.") || s.starts_with("artifact."))
        else {
            return json_error("400 Bad Request", "invalid_event");
        };
        let store = || -> Result<bool, rusqlite::Error> {
            let db =
                rusqlite::Connection::open(self.state_dir.join("share/integration-events.sqlite"))?;
            db.busy_timeout(Duration::from_secs(5))?;
            db.execute_batch("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, kind TEXT NOT NULL, digest TEXT NOT NULL, received_ms INTEGER NOT NULL);")?;
            let digest = hex::encode(Sha256::digest(body));
            let changed = db.execute(
                "INSERT OR IGNORE INTO events(id,kind,digest,received_ms) VALUES (?1,?2,?3,?4)",
                rusqlite::params![id, kind, digest, now_ms_i64()],
            )?;
            if changed == 0 {
                let old: String =
                    db.query_row("SELECT digest FROM events WHERE id=?1", [id], |row| {
                        row.get(0)
                    })?;
                return Ok(old == digest);
            }
            Ok(true)
        };
        match store() {
            Ok(true) => json_response("200 OK", &serde_json::json!({"received":true,"id":id})),
            Ok(false) => json_error("409 Conflict", "event_identity_conflict"),
            Err(_) => json_error("503 Service Unavailable", "event_storage_unavailable"),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn webhook_signature_matches_rfc4231() {
        assert_eq!(
            hex::encode(mac(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }
}
