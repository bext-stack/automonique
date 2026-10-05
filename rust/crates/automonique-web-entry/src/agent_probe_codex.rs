// SPDX-License-Identifier: Elastic-2.0
use super::*;
use std::io::{BufRead, BufReader};

pub(super) fn run(binary: &Path, profile: &Path, work: &Path) -> Value {
    let mut command = provider_command(Provider::Codex, binary, profile);
    command.current_dir(work).args(["app-server", "--stdio"]);
    for config in [
        "features.shell_tool=false",
        "features.unified_exec=false",
        "features.apps=false",
        "features.browser_use=false",
        "features.multi_agent=false",
        "web_search=\"disabled\"",
        "model_reasoning_effort=\"low\"",
    ] {
        command.args(["-c", config]);
    }
    let Ok(mut child) = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return failed("response_failed");
    };
    let Some(mut stdin) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return failed("response_failed");
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return failed("response_failed");
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    let cwd = work.to_path_buf();
    let spawned=thread::Builder::new().name("codex-response-read".into()).spawn(move||{
        let run=||->Option<Value>{
            fn send(input:&mut ChildStdin,value:Value)->Option<()> {writeln!(input,"{value}").ok()?;input.flush().ok()}
            send(&mut stdin,json!({"id":1,"method":"initialize","params":{"clientInfo":{"name":"monique-check","version":"1.0"},"capabilities":{"experimentalApi":true}}}))?;
            let mut reader=BufReader::new(stdout);let mut line=String::new();let mut model=None;let mut answered=false;
            for _ in 0..1000 {
                line.clear();if reader.by_ref().take(65537).read_line(&mut line).ok()?==0 || line.len()>65536 {return None;}
                let Ok(event)=serde_json::from_str::<Value>(&line) else {continue;};
                if let Some(error)=event.get("error") {return Some(provider_failure(error));}
                match event["id"].as_u64() {
                    Some(1)=>{send(&mut stdin,json!({"method":"initialized"}))?;send(&mut stdin,json!({"id":2,"method":"thread/start","params":{"cwd":cwd,"ephemeral":true,"approvalPolicy":"never","sandbox":"read-only","baseInstructions":"You are a connection test. Reply with MONIQUE_OK without using tools.","developerInstructions":"Do not use tools or access files.","dynamicTools":[],"environments":[]}}))?;},
                    Some(2)=>{let result=&event["result"];model=result["model"].as_str().and_then(safe_model);let id=result["thread"]["id"].as_str()?;send(&mut stdin,json!({"id":3,"method":"turn/start","params":{"threadId":id,"input":[{"type":"text","text":PROMPT,"text_elements":[]}]}}))?;},
                    _=>{}
                }
                if event["method"]=="item/completed" && event["params"]["item"]["type"]=="agentMessage" {answered=event["params"]["item"]["text"].as_str().is_some_and(|s|s.trim()=="MONIQUE_OK");}
                if event["method"]=="turn/completed" {
                    let turn=&event["params"]["turn"];
                    if turn["status"]=="completed" && answered {return Some(json!({"status":"verified","reason":"response_verified","model":model}));}
                    return Some(provider_failure(&turn["error"]));
                }
                // Decline unexpected server requests; this check never approves a tool.
                if event.get("id").is_some() && event.get("method").is_some() {send(&mut stdin,json!({"id":event["id"],"error":{"code":-32601,"message":"Tools are not available for this check"}}))?;}
            }
            None
        };
        let _=sender.send(run());
    });
    let result = if spawned.is_err() {
        failed("response_failed")
    } else {
        match receiver.recv_timeout(TIMEOUT) {
            Ok(Some(value)) => value,
            Ok(None) => failed("response_failed"),
            Err(_) => failed("timed_out"),
        }
    };
    let _ = child.kill();
    let _ = child.wait();
    result
}
fn failed(reason: &str) -> Value {
    json!({"status":"failed","reason":reason})
}
fn provider_failure(error: &Value) -> Value {
    let text = error.to_string().to_lowercase();
    failed(
        if text.contains("quota") || text.contains("rate limit") || text.contains("usage limit") {
            "quota_limited"
        } else if text.contains("401")
            || text.contains("unauthorized")
            || text.contains("authentication")
        {
            "sign_in_required"
        } else {
            "response_failed"
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn native_rpc_requires_a_completed_fixed_response_and_reports_actual_model() {
        let root = tempfile::tempdir().unwrap();
        let binary = root.path().join("native-fixture");
        fs::write(
            &binary,
            r#"#!/usr/bin/python3
import sys,json
read=lambda:json.loads(sys.stdin.readline())
send=lambda v:print(json.dumps(v),flush=True)
assert read()['method']=='initialize'
send({'id':1,'result':{}})
assert read()['method']=='initialized'
request=read();assert request['method']=='thread/start'
assert request['params']['ephemeral'] is True
assert request['params']['approvalPolicy']=='never'
assert request['params']['sandbox']=='read-only'
assert request['params']['environments']==[]
send({'id':2,'result':{'model':'fixture-model','thread':{'id':'fixture-thread'}}})
request=read();assert request['method']=='turn/start'
assert request['params']['threadId']=='fixture-thread'
send({'method':'item/completed','params':{'item':{'type':'agentMessage','text':'MONIQUE_OK'}}})
send({'method':'turn/completed','params':{'turn':{'status':'completed'}}})
"#,
        )
        .unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let result = run(&binary, root.path(), root.path());
        assert_eq!(result["status"], "verified");
        assert_eq!(result["model"], "fixture-model");
    }
    #[test]
    fn provider_errors_only_return_closed_categories() {
        let result = provider_failure(&json!({"message":"401 private access token"}));
        assert_eq!(
            result,
            json!({"status":"failed","reason":"sign_in_required"})
        );
    }
}
