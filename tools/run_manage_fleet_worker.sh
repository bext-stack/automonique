#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0

# Monique's Manage fleet runtime.
#
# The fleet API owns authorization, workspace selection, approval and atomic
# claims. This worker supplies only the execution half: heartbeat, claim,
# explicit argv launch, bounded live logs and a terminal receipt. Prompts are
# delivered on stdin and are never evaluated as shell input.

set -uo pipefail

# Native subscription accounts are the only accepted provider authority for
# this worker. Environment API credentials are deliberately excluded.
unset OPENAI_API_KEY ANTHROPIC_API_KEY CLAUDE_CODE_OAUTH_TOKEN CODEX_API_KEY

state_dir=${AUTOMONIQUE_STATE_DIR:?AUTOMONIQUE_STATE_DIR is required}
max_concurrency=${AUTOMONIQUE_FLEET_CONCURRENCY:-3}
poll_seconds=${AUTOMONIQUE_FLEET_POLL_SECONDS:-2}
heartbeat_seconds=${AUTOMONIQUE_FLEET_HEARTBEAT_SECONDS:-20}

case "$max_concurrency" in
    ''|*[!0-9]*) printf '%s\n' 'invalid AUTOMONIQUE_FLEET_CONCURRENCY' >&2; exit 2 ;;
esac
case "$poll_seconds" in
    ''|*[!0-9]*) printf '%s\n' 'invalid AUTOMONIQUE_FLEET_POLL_SECONDS' >&2; exit 2 ;;
esac
case "$heartbeat_seconds" in
    ''|*[!0-9]*) printf '%s\n' 'invalid AUTOMONIQUE_FLEET_HEARTBEAT_SECONDS' >&2; exit 2 ;;
esac
if (( max_concurrency < 1 || max_concurrency > 8 || poll_seconds < 1 || heartbeat_seconds < 5 )); then
    printf '%s\n' 'fleet worker bounds refused' >&2
    exit 2
fi

fleet_config=$state_dir/support/fleet.conf
provider_config=$state_dir/provider
runtime_dir=$state_dir/manage-fleet-worker
output_dir=$runtime_dir/process-output
aggregate_auth_health_file=$runtime_dir/auth-health.json
agent_auth_dir=${AUTOMONIQUE_AGENT_AUTH_DIR:-}
account_registry=${agent_auth_dir:+$agent_auth_dir/accounts.json}
claude_binary=${AUTOMONIQUE_FLEET_CLAUDE_BINARY:-}

private_value() {
    key=$1
    file=$2
    value=$(sed -n "s/^${key}=//p" "$file")
    if [[ -z "$value" || $(sed -n "s/^${key}=//p" "$file" | wc -l) -ne 1 ]]; then
        printf 'missing or duplicate %s in %s\n' "$key" "$(basename -- "$file")" >&2
        exit 2
    fi
    printf '%s' "$value"
}

fleet_base=$(private_value base "$fleet_config")
fleet_instance=$(private_value instance "$fleet_config")
fleet_token=$(private_value token "$fleet_config")
provider_binary=$(private_value binary "$provider_config")
provider_home=$(private_value home "$provider_config")
provider_engine=$(sed -n 's/^engine=//p' "$provider_config")
if [[ -z "$provider_engine" ]]; then
    provider_engine=codex
elif [[ $(sed -n 's/^engine=//p' "$provider_config" | wc -l) -ne 1 ]]; then
    printf '%s\n' 'missing or duplicate engine in provider configuration' >&2
    exit 2
fi
case "$provider_engine" in
    codex|jcode) ;;
    *) printf '%s\n' 'unsupported provider engine' >&2; exit 2 ;;
esac
codex_worker_home=${AUTOMONIQUE_FLEET_CODEX_HOME:-$provider_home}
platform_url=${fleet_base%/}/api/manage/automonique/platform

if [[ ! -x "$provider_binary" || ! -d "$provider_home" ]]; then
    printf '%s\n' 'configured provider engine is unavailable' >&2
    exit 2
fi
if [[ -n "$agent_auth_dir" && -e "$agent_auth_dir" && ( ! -d "$agent_auth_dir" || ! -x "$claude_binary" ) ]]; then
    printf '%s\n' 'configured native account directory or Claude provider is unavailable' >&2
    exit 2
fi

umask 077
mkdir -p -- "$runtime_dir"
chmod 700 -- "$runtime_dir"
mkdir -p -- "$output_dir"
chmod 700 -- "$output_dir"
mkdir -p -- "$runtime_dir/jcode-runtime"
chmod 700 -- "$runtime_dir/jcode-runtime"

auth_method=unknown
selected_provider=$provider_engine
selected_account=legacy
selected_binary=$provider_binary
selected_home=$provider_home
auth_health_file=$aggregate_auth_health_file
auth_revision_file=$runtime_dir/auth-revision-legacy

load_selected_account() {
    if [[ "$provider_engine" == jcode ]]; then
        selected_provider=jcode
        selected_account=legacy
        selected_binary=$provider_binary
        selected_home=$provider_home
        auth_health_file=$aggregate_auth_health_file
        auth_revision_file=$runtime_dir/auth-revision-jcode
        return 0
    fi
    if [[ -z "$account_registry" || ! -f "$account_registry" ]]; then
        selected_provider=codex
        selected_account=legacy
        selected_binary=$provider_binary
        selected_home=$codex_worker_home
        auth_health_file=$aggregate_auth_health_file
        auth_revision_file=$runtime_dir/auth-revision-legacy
        return 0
    fi
    selection=$(jq -er '
        select(.schema == "automonique.agent-accounts/v1")
        | .worker_provider as $provider
        | select($provider == "codex" or $provider == "claude")
        | .selected[$provider] as $account
        | select($account | type == "string" and test("^acct-[0-9a-f]{24}$"))
        | [.accounts[] | select(.id == $account and .provider == $provider)]
        | select(length == 1)
        | .[0]
        | [.provider, .id, .label]
        | @tsv
    ' "$account_registry" 2>/dev/null) || return 1
    IFS=$'\t' read -r next_provider next_account next_label <<<"$selection"
    [[ "$next_label" != *$'\n'* && "$next_label" != *$'\r'* && -n "$next_label" ]] || return 1
    next_home=$agent_auth_dir/profiles/$next_account
    [[ -d "$next_home" ]] || return 1
    resolved_home=$(realpath -e -- "$next_home") || return 1
    resolved_root=$(realpath -e -- "$agent_auth_dir/profiles") || return 1
    [[ "$resolved_home" == "$resolved_root"/* ]] || return 1
    selected_provider=$next_provider
    selected_account=$next_account
    selected_home=$resolved_home
    if [[ "$selected_provider" == codex ]]; then
        selected_binary=$provider_binary
    else
        selected_binary=$claude_binary
    fi
    auth_health_file=$agent_auth_dir/health/$selected_account.json
    auth_revision_file=$runtime_dir/auth-revision-$selected_account
}

load_selected_account || {
    printf '%s\n' 'native account selection is missing or invalid' >&2
    exit 2
}

credential_revision() {
    if [[ "$selected_provider" == codex || "$selected_provider" == jcode ]]; then
        auth_file=$selected_home/auth.json
    else
        auth_file=$selected_home/.credentials.json
    fi
    if [[ ! -f "$auth_file" ]]; then
        printf '%s' missing
        return
    fi
    stat -c '%y:%s:%i' -- "$auth_file" 2>/dev/null || printf '%s' unreadable
}

probe_local_auth() {
    if [[ "$selected_provider" == codex ]]; then
        auth_method=chatgpt
    elif [[ "$selected_provider" == jcode ]]; then
        auth_method=jcode_native
    else
        auth_method=claude_ai
    fi
    if [[ "$selected_provider" == codex ]]; then
        local_status=$(CODEX_HOME="$selected_home" "$selected_binary" login status 2>&1) || return 1
        case "$local_status" in
            *'Logged in using ChatGPT'*) return 0 ;;
            *'Logged in using an API key'*) return 1 ;;
            *'Logged in using an access token'*) return 1 ;;
        esac
        return 1
    fi
    if [[ "$selected_provider" == jcode ]]; then
        local_status=$(JCODE_HOME="$selected_home" JCODE_RUNTIME_DIR="$runtime_dir/jcode-runtime" \
            "$selected_binary" --quiet --no-update --no-selfdev auth status --json 2>/dev/null) || return 1
        jq -e '.any_available == true' >/dev/null <<<"$local_status"
        return
    fi
    local_status=$(CLAUDE_CONFIG_DIR="$selected_home" "$selected_binary" auth status --json 2>/dev/null) || return 1
    if jq -e '.loggedIn == true and .authMethod == "claude.ai"' >/dev/null <<<"$local_status"; then
        auth_method=claude_ai
        return 0
    fi
    return 1
}

previous_verified_at() {
    if [[ ! -f "$auth_health_file" ]]; then
        printf '%s' null
        return
    fi
    jq -r '.last_verified_at_ms // null | if . == null or (type == "number" and . >= 0) then . else error("invalid") end' \
        "$auth_health_file" 2>/dev/null || printf '%s' null
}

write_auth_health() {
    auth_status=$1
    auth_reason=$2
    last_verified_at=${3:-null}
    now_ms=$(date +%s%3N)
    temporary=$(mktemp "$runtime_dir/.auth-health.XXXXXX") || return 1
    if [[ "$selected_account" != legacy ]]; then
        account_temporary=$(mktemp "$agent_auth_dir/health/.account-health.XXXXXX") || {
            rm -f -- "$temporary"
            return 1
        }
        if ! jq -n \
            --arg provider "$selected_provider" \
            --arg account "$selected_account" \
            --arg status "$auth_status" \
            --arg method "$auth_method" \
            --arg reason "$auth_reason" \
            --argjson observed "$now_ms" \
            --argjson verified "$last_verified_at" \
            '{schema:"automonique.provider-account-health/v1",provider:$provider,account_id:$account,status:$status,method:$method,reason:$reason,observed_at_ms:$observed,last_verified_at_ms:$verified}' \
            >"$account_temporary"
        then
            rm -f -- "$temporary" "$account_temporary"
            return 1
        fi
        chmod 600 -- "$account_temporary"
        mv -f -- "$account_temporary" "$auth_health_file"
    fi
    if ! jq -n \
        --arg provider "$selected_provider" \
        --arg status "$auth_status" \
        --arg method "$auth_method" \
        --arg reason "$auth_reason" \
        --argjson observed "$now_ms" \
        --argjson verified "$last_verified_at" \
        '{schema:"automonique.provider-auth-health/v1",provider:$provider,surface:"manage-fleet-worker",status:$status,method:$method,reason:$reason,observed_at_ms:$observed,last_verified_at_ms:$verified}' \
        >"$temporary"
    then
        rm -f -- "$temporary"
        return 1
    fi
    chmod 600 -- "$temporary"
    mv -f -- "$temporary" "$aggregate_auth_health_file"
}

write_auth_revision() {
    revision=$1
    temporary=$(mktemp "$runtime_dir/.auth-revision.XXXXXX") || return 1
    printf '%s\n' "$revision" >"$temporary"
    chmod 600 -- "$temporary"
    mv -f -- "$temporary" "$auth_revision_file"
}

auth_health_status() {
    jq -er '.status | select(. == "authenticated" or . == "configured_unverified" or . == "authenticating" or . == "expired" or . == "signed_out" or . == "unavailable")' \
        "$auth_health_file" 2>/dev/null || printf '%s' unavailable
}

refresh_auth_after_credential_change() {
    current_revision=$(credential_revision)
    previous_revision=$(sed -n '1p' "$auth_revision_file" 2>/dev/null || true)
    [[ "$current_revision" == "$previous_revision" ]] && return
    if probe_local_auth; then
        write_auth_health configured_unverified credentials_changed "$(previous_verified_at)" || true
    else
        write_auth_health signed_out local_session_missing "$(previous_verified_at)" || true
    fi
    write_auth_revision "$current_revision" || true
}

auth_failure_reason() {
    output=$1
    error_output=$2
    if jq -ers '
        any(.[];
            (.type == "error" or .type == "turn.failed")
            and ((.message // .error.message // "") | ascii_downcase
                | test("access token could not be refreshed|refresh token.*(revoked|invalid)|token.*invalidated|session has ended|not logged in|login expired|please run /login|authentication[_ ]error")))
    ' "$output" >/dev/null 2>&1 \
        || grep -Eqi '((codex_models_manager|codex_login|responses_websocket).*(401 Unauthorized|token_invalidated|refresh_token_invalidated)|login expired|please run /login|oauth token.*expired|authentication[_ ]error)' "$error_output"
    then
        if grep -Eqi 'not logged in' "$output" "$error_output"; then
            printf '%s' local_session_missing
        else
            printf '%s' refresh_token_rejected
        fi
        return 0
    fi
    return 1
}

latest_job_auth_failure_reason() {
    latest_output=
    for candidate in "$runtime_dir"/*.jsonl; do
        [[ -f "$candidate" ]] || continue
        if [[ -z "$latest_output" || "$candidate" -nt "$latest_output" ]]; then
            latest_output=$candidate
        fi
    done
    [[ -n "$latest_output" ]] || return 1
    latest_error=${latest_output%.jsonl}.stderr
    [[ -f "$latest_error" ]] || return 1
    auth_failure_reason "$latest_output" "$latest_error"
}

initialize_auth_health() {
    current_revision=$(credential_revision)
    previous_revision=$(sed -n '1p' "$auth_revision_file" 2>/dev/null || true)
    previous_status=$(auth_health_status)
    historical_failure=$(latest_job_auth_failure_reason || true)
    if ! probe_local_auth; then
        write_auth_health signed_out local_session_missing "$(previous_verified_at)" || true
    elif [[ "$selected_account" != legacy && "$previous_status" == authenticated ]]; then
        :
    elif [[ "$current_revision" == "$previous_revision" ]] \
        && [[ "$previous_status" == authenticated || "$previous_status" == expired ]]
    then
        :
    elif [[ -z "$previous_revision" && -n "$historical_failure" ]]; then
        if [[ "$historical_failure" == local_session_missing ]]; then
            write_auth_health signed_out "$historical_failure" "$(previous_verified_at)" || true
        else
            write_auth_health expired "$historical_failure" "$(previous_verified_at)" || true
        fi
    elif [[ -n "$previous_revision" && "$current_revision" != "$previous_revision" ]]; then
        write_auth_health configured_unverified credentials_changed "$(previous_verified_at)" || true
    else
        write_auth_health configured_unverified local_session_present "$(previous_verified_at)" || true
    fi
    write_auth_revision "$current_revision" || true
}

initialize_auth_health
selection_key=$selected_provider:$selected_account

platform_runtime() {
    runtime=$1
    body=$(jq -cn \
        --arg node "$fleet_instance" \
        --argjson runtime "$runtime" \
        '{node_id:$node,revision:0,capabilities:["execute_jobs","report_jobs","stream_job_logs"],receipts:[],runtime:$runtime}') || return 1
    curl --silent --show-error --max-time 15 \
        --request PUT "$platform_url" \
        --header "Authorization: Bearer $fleet_token" \
        --header 'Content-Type: application/json' \
        --header 'Accept: application/json' \
        --data-binary "$body" \
        | jq -ec 'if .ok == true and (.runtime | type) == "object" then .runtime else error(.error // "platform runtime request refused") end'
}

fleet_snapshot() {
    body=$(jq -cn --arg id "$fleet_instance" '{action:"snapshot",id:$id}')
    platform_runtime "$body"
}

register_runtime() {
    runtime_workdir=${AUTOMONIQUE_FLEET_WORKDIR:-$PWD}
    runtime_workdir=$(realpath -e -- "$runtime_workdir") || return 1
    body=$(jq -cn \
        --arg id "$fleet_instance" \
        --arg workdir "$runtime_workdir" \
        --arg provider "$selected_provider" \
        '{action:"register",id:$id,workdir:$workdir,provider:$provider}')
    response=$(platform_runtime "$body") || return 1
    jq -e '.ok == true and .instance.id != null' >/dev/null <<<"$response"
}

publish_process_snapshot() {
    snapshot=$1
    observed_at=$(date +%s%3N)
    issue_links='{}'
    output_map='{}'
    ticket_jobs=$state_dir/slack-ticket-jobs.v1.json
    if [[ -f "$ticket_jobs" && ! -L "$ticket_jobs" ]]; then
        issue_links=$(jq -cer '
            [ .[]
              | select((.job_id | type) == "string" and (.issue_url | type) == "string")
              | select(.job_id | test("^[A-Za-z0-9._-]{8,120}$"))
              | select(.issue_url | test("^https://github\\.com/[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}/issues/[1-9][0-9]{0,19}$"))
              | {key:.job_id, value:.issue_url} ]
            | from_entries
        ' "$ticket_jobs" 2>/dev/null) || issue_links='{}'
    fi
    output_files=("$output_dir"/*.json)
    if [[ -e "${output_files[0]}" ]]; then
        output_map=$(jq -sc '
            [ .[]
              | select(.schema == "automonique.manage-process-output/v1")
              | select(.job_id | type == "string" and test("^[A-Za-z0-9._-]{8,120}$"))
              | select(.lines | type == "array" and length <= 12)
              | {key:.job_id, value:.lines} ]
            | from_entries
        ' "${output_files[@]}" 2>/dev/null) || output_map='{}'
    fi
    temporary=$(mktemp "$runtime_dir/.processes.XXXXXX") || return 1
    if ! jq -e \
        --arg instance "$fleet_instance" \
        --arg provider "$selected_provider" \
        --arg auth "$(auth_health_status)" \
        --arg fleet_base "${fleet_base%/}" \
        --argjson issue_links "$issue_links" \
        --argjson output_map "$output_map" \
        --argjson concurrency "$max_concurrency" \
        --argjson observed "$observed_at" '
        def safe_text($limit):
            if type == "string" then
                (gsub("[\u0000-\u001f\u007f]"; " ") | .[0:$limit]) as $value
                | if ($value | length) > 0 then $value else null end
            else null end;
        def safe_state:
            if type == "string" and length > 0 and length <= 64
                and test("^[A-Za-z0-9._-]+$") then ascii_downcase
            else "unknown" end;
        def safe_id:
            if type == "string" and length > 0 and length <= 160
                and test("^[A-Za-z0-9._:#/-]+$") then .
            else null end;
        def output_text:
            if type == "string" then
                (gsub("\u0000"; "�") | .[0:1000]) as $value
                | if ($value | length) > 0 then $value else null end
            else null end;
        select(.ok == true and (.instances | type == "array") and (.jobs | type == "array"))
        | ([.instances[] | select(.id == $instance)] | first) as $worker
        | {
            schema: "automonique.manage-processes/v1",
            health: (if $worker == null then "degraded" else "ready" end),
            observed_at_ms: $observed,
            stats: {
                total: ([.jobs[]] | length),
                queued: ([.jobs[] | select(.status == "pending")] | length),
                running: ([.jobs[] | select(.status == "running")] | length),
                completed: ([.jobs[] | select(.status == "done")] | length),
                failed: ([.jobs[] | select(.status == "failed")] | length)
            },
            worker: (if $worker == null then null else {
                name: ($worker.name | safe_text(120)),
                status: ($worker.status | safe_state),
                status_detail: ($worker.status_detail | safe_text(240)),
                provider: $provider,
                agent: (($worker.runtime_harness.agent // $worker.agent) | safe_state),
                model: (($worker.runtime_harness.model // $worker.model) | safe_text(120)),
                runtime: ($worker.runtime | safe_state),
                binary: ($worker.runtime_harness.binary | safe_text(120)),
                cli_version: (($worker.runtime_harness.cli_version // $worker.agent_version) | safe_text(80)),
                permission_mode: ($worker.runtime_harness.permission_mode | safe_state),
                auth_status: $auth,
                active_jobs: ([.jobs[] | select(.instance_id == $instance and .status == "running")] | length),
                concurrency: $concurrency,
                last_seen_at: ($worker.last_seen_at | safe_text(64))
            } end),
            jobs: ([.jobs[] | {
                id: (.id | safe_id),
                status: (.status | safe_state),
                source: (.source | safe_state),
                issue_id: (.issue_id | safe_id),
                issue_url: $issue_links[.id],
                manage_url: (if (.issue_id | type) == "string"
                    and (.issue_id | test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))
                    then ($fleet_base + "/manage/ai-operations/issues?issue=" + .issue_id)
                    else null end),
                site_id: (.site_id | safe_id),
                session_id: (.session_id | safe_id),
                parent_id: (.parent_id | safe_id),
                kind: (if (.kind | type) == "string" and (.kind | length) > 0 and (.kind | length) <= 64
                    and (.kind | test("^[A-Za-z0-9._-]+$")) then (.kind | ascii_downcase) else null end),
                provider: (.claimed_agent | safe_state),
                runtime: (.claimed_runtime | safe_state),
                assigned_to_worker: (.instance_id == $instance),
                approved: ((.approved_by | type) == "string" and (.approved_by | length) > 0),
                decision_count: (if (.decisions | type) == "array" then (.decisions | length) else 0 end),
                created_at: (.created_at | safe_text(64)),
                updated_at: (.updated_at | safe_text(64)),
                output: (($output_map[.id] // []) as $live
                    | (.result | output_text) as $final
                    | if ($live | length) > 0 then $live[-12:]
                      elif $final != null then [{
                        at_ms: $observed,
                        kind: "final",
                        text: $final,
                        truncated: ((.result | length) > 1000)
                      }]
                      else [] end)
            } | select(.id != null)]
                | sort_by(.updated_at // "") | reverse | .[:100]
                | to_entries
                | map(if .key < 10 then .value else (.value | .output = []) end))
        }
    ' <<<"$snapshot" >"$temporary"
    then
        rm -f -- "$temporary"
        return 1
    fi
    chmod 600 -- "$temporary"
    mv -f -- "$temporary" "$runtime_dir/processes.json"
}

refresh_process_snapshot() {
    snapshot=$(fleet_snapshot) || return 1
    publish_process_snapshot "$snapshot"
}

load_instance_root() {
    snapshot=$(fleet_snapshot) || return 1
    jq -er --arg id "$fleet_instance" \
        '[.instances[]? | select(.id == $id) | .workdir] | first | select(type == "string" and startswith("/"))' \
        <<<"$snapshot"
}

register_runtime || {
    printf '%s\n' 'Manage refused the platform runtime registration' >&2
    exit 1
}

instance_root=$(load_instance_root) || {
    printf '%s\n' 'configured Manage instance or workspace is unavailable' >&2
    exit 2
}
instance_root=$(realpath -e -- "$instance_root") || {
    printf '%s\n' 'configured Manage workspace does not exist' >&2
    exit 2
}

active_jobs() {
    jobs -pr | wc -l
}

refresh_process_snapshot || true

heartbeat() {
    status=$1
    active=$2
    auth_status=$(auth_health_status)
    detail="Monique ${selected_provider} worker: ${active}/${max_concurrency} active; auth ${auth_status}"
    body=$(jq -cn \
        --arg id "$fleet_instance" \
        --arg status "$status" \
        --arg detail "$detail" \
        --arg provider "$selected_provider" \
        --arg binary "$(basename -- "$selected_binary")" \
        --arg auth "$auth_status" \
        '{action:"heartbeat",id:$id,status:$status,detail:$detail,version:"automonique-manage-worker/v1",harness:{agent:$provider,binary:$binary,available:true,auth_status:$auth,permission_mode:"confirmed-ticket"}}')
    response=$(platform_runtime "$body") || return 1
    jq -e '.ok == true' >/dev/null <<<"$response"
}

claim_one() {
    body=$(jq -cn --arg id "$fleet_instance" '{action:"claim",id:$id}')
    response=$(platform_runtime "$body") || return 1
    jq -ec 'if .ok == true then (.job // null) else error("claim refused") end' <<<"$response"
}

report_job() {
    job_id=$1
    status=$2
    result=$3
    session_id=${4:-}
    body=$(jq -cn \
        --arg job "$job_id" \
        --arg status "$status" \
        --arg result "${result:0:2000}" \
        --arg session "$session_id" \
        '{action:"job",jobId:$job,status:$status,result:$result} + (if $session == "" then {} else {session_id:$session} end)')
    response=$(platform_runtime "$body") || return 1
    jq -e '.ok == true' >/dev/null <<<"$response"
}

record_job_output() {
    job_id=$1
    kind=$2
    text=$3
    at_ms=$4
    target=$output_dir/$job_id.json
    temporary=$(mktemp "$output_dir/.output.XXXXXX") || return 1
    if [[ -f "$target" && ! -L "$target" ]]; then
        jq -e \
            --arg job "$job_id" \
            --arg kind "${kind:0:40}" \
            --arg text "$text" \
            --argjson at "$at_ms" '
            select(.schema == "automonique.manage-process-output/v1" and .job_id == $job and (.lines | type == "array"))
            | .observed_at_ms = $at
            | .lines = ((.lines + [{
                at_ms: $at,
                kind: ($kind | if test("^[A-Za-z0-9._-]{1,40}$") then ascii_downcase else "output" end),
                text: ($text | gsub("\u0000"; "�") | .[0:1000]),
                truncated: (($text | length) > 1000)
            }])[-12:])
        ' "$target" >"$temporary" || {
            rm -f -- "$temporary"
            return 1
        }
    else
        jq -n \
            --arg job "$job_id" \
            --arg kind "${kind:0:40}" \
            --arg text "$text" \
            --argjson at "$at_ms" '{
            schema: "automonique.manage-process-output/v1",
            job_id: $job,
            observed_at_ms: $at,
            lines: [{
                at_ms: $at,
                kind: ($kind | if test("^[A-Za-z0-9._-]{1,40}$") then ascii_downcase else "output" end),
                text: ($text | gsub("\u0000"; "�") | .[0:1000]),
                truncated: (($text | length) > 1000)
            }]
        }' >"$temporary" || {
            rm -f -- "$temporary"
            return 1
        }
    fi
    chmod 600 -- "$temporary"
    mv -f -- "$temporary" "$target"
    refresh_process_snapshot || true
}

post_job_log() {
    job_id=$1
    kind=$2
    text=$3
    [[ -n "$text" ]] || return 0
    now_ms=$(date +%s%3N)
    if [[ "$kind" != provider_stderr ]]; then
        record_job_output "$job_id" "$kind" "$text" "$now_ms" || true
    fi
    body=$(jq -cn \
        --arg job "$job_id" \
        --arg kind "${kind:0:40}" \
        --arg text "${text:0:1000}" \
        --argjson at "$now_ms" \
        '{action:"joblog",jobId:$job,lines:[{at:$at,kind:$kind,text:$text}]}')
    response=$(platform_runtime "$body") || return 0
    jq -e '.ok == true' >/dev/null <<<"$response" || true
}

# Extract the one receipt that proves the provider reached Automonique's
# GitHub handoff contract. A successful provider process is not, by itself,
# proof that ticket delivery finished: the final message must identify the
# completion-summary comment recorded on the canonical issue.
completion_comment_permalink() {
    final_text=$1
    expected_issue=${2:-}
    printf '%s' "$final_text" | jq -Rsr --arg issue "$expected_issue" '
        [ .
          | scan("https://github[.]com/[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}/issues/[1-9][0-9]{0,19}#issuecomment-[1-9][0-9]{0,19}")
        ]
        | map(select($issue == "" or startswith($issue + "#issuecomment-")))
        | first // empty
    '
}

workspace_for() {
    requested=$1
    if [[ -z "$requested" ]]; then
        printf '%s' "$instance_root"
        return 0
    fi
    [[ "$requested" == /* ]] || return 1
    resolved=$(realpath -e -- "$requested") || return 1
    case "$resolved" in
        "$instance_root"|"$instance_root"/*|/var/lib/bext-sites/*) printf '%s' "$resolved" ;;
        *) return 1 ;;
    esac
}

log_provider_line() {
    job_id=$1
    line=$2
    kind=$(jq -r '.type // "output"' <<<"$line" 2>/dev/null) || kind=output
    if [[ "$selected_provider" == codex ]]; then
        text=$(jq -r '
            if .type == "item.completed" and .item.type == "agent_message" then .item.text
            elif .type == "item.started" then ("started " + (.item.type // "item"))
            elif .type == "error" then (.message // "provider error")
            else empty end
        ' <<<"$line" 2>/dev/null) || text=
    elif [[ "$selected_provider" == jcode ]]; then
        text=$(jq -r '
            if .type == "done" then (.text // empty)
            elif .type == "tool_start" then ("started tool " + (.name // "unknown"))
            elif .type == "tool_done" then
                ((if .error == null then "completed tool " else "failed tool " end) + (.name // "unknown"))
            elif .type == "error" then (.message // "provider error")
            else empty end
        ' <<<"$line" 2>/dev/null) || text=
    else
        text=$(jq -r '
            if .type == "assistant" then
                [.message.content[]? | select(.type == "text") | .text] | join("\n")
            elif .type == "result" then (.result // empty)
            elif .type == "error" then (.error.message // .message // "provider error")
            else empty end
        ' <<<"$line" 2>/dev/null) || text=
    fi
    post_job_log "$job_id" "$kind" "$text"
}

# Ask the daemon binary that ships beside this worker for the local context
# brief of one job. Output is capped and the call is bounded in time so a slow
# store can only delay a launch by seconds, never block it.
local_work_brief() {
    brief_job=$1
    brief_issue=$2
    brief_binary=$(dirname -- "${BASH_SOURCE[0]}")/automonique
    [[ -x "$brief_binary" ]] || brief_binary=$state_dir/improvement-code/current/bin/automonique
    [[ -x "$brief_binary" ]] || return 1
    timeout 20s "$brief_binary" work-brief \
        --state-dir "$state_dir" \
        --job-id "$brief_job" \
        --issue-url "$brief_issue" 2>/dev/null | head -c 24576
}

# Read the body of the completion comment a permalink names. The permalink
# has already passed the strict regex in completion_comment_permalink, so its
# owner, repository and comment id are safe to place in an API path. Prints
# nothing when GitHub cannot be read; the caller decides what that means.
completion_comment_body() {
    permalink=$1
    comment_id=${permalink##*#issuecomment-}
    path=${permalink#https://github.com/}
    owner=${path%%/*}
    path=${path#*/}
    repo=${path%%/*}
    [[ "$owner" =~ ^[A-Za-z0-9_.-]{1,100}$ && "$repo" =~ ^[A-Za-z0-9_.-]{1,100}$ && "$comment_id" =~ ^[1-9][0-9]{0,19}$ ]] || return 1
    timeout 20s gh api "repos/$owner/$repo/issues/comments/$comment_id" --jq '.body' 2>/dev/null | head -c 65536
}

# Whether a completion report follows the per-request shape the work method
# prescribes: at least one "Demande 1" section. A report without it is the
# kind the clients answered with "non, ce n'est pas fait".
completion_report_is_structured() {
    grep -q 'Demande 1' <<<"$1"
}

run_job() {
    job=$1
    job_id=$(jq -er '.id | select(type == "string" and test("^[A-Za-z0-9._-]{8,120}$"))' <<<"$job") || return
    expected_issue_url=
    ticket_jobs=$state_dir/slack-ticket-jobs.v1.json
    if [[ -f "$ticket_jobs" && ! -L "$ticket_jobs" ]]; then
        expected_issue_url=$(jq -er --arg job "$job_id" '
            [ .[]
              | select(.job_id == $job)
              | .issue_url
              | select(type == "string")
              | select(test("^https://github[.]com/[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}/issues/[1-9][0-9]{0,19}$"))
            ]
            | first // empty
        ' "$ticket_jobs" 2>/dev/null) || expected_issue_url=
    fi
    prompt=$(jq -er '.prompt | select(type == "string" and length > 0 and length <= 8000)' <<<"$job") || {
        report_job "$job_id" failed 'Manage returned an invalid job prompt.' || true
        return
    }
    completion_receipt=$'Monique completion receipt contract:\nAfter implementing and verifying the ticket, update the GitHub issue as authorized. Your final response must include the exact permalink of the completion-summary comment, in the form https://github.com/<owner>/<repo>/issues/<number>#issuecomment-<number>. Do not report completion without that permalink.'
    # Local context this host holds about the owner, the site and the Slack
    # thread that asked: owner preferences, matching memories, the entity
    # catalog, approved skills. Rendered by the daemon binary beside this
    # worker; the prompt head is the ranking hint and travels on stdin so no
    # console- or model-produced text becomes a command argument. Best effort:
    # a job never fails for lack of a brief.
    local_brief=$(printf '%s' "${prompt:0:2000}" | local_work_brief "$job_id" "${expected_issue_url:-none}") || local_brief=
    if [[ -n "$local_brief" ]]; then
        provider_prompt=$(printf '%s\n\n%s\n\n%s\n' "$prompt" "$local_brief" "$completion_receipt")
    else
        provider_prompt=$(printf '%s\n\n%s\n' "$prompt" "$completion_receipt")
    fi
    requested_cwd=$(jq -r '.cwd // ""' <<<"$job")
    cwd=$(workspace_for "$requested_cwd") || {
        report_job "$job_id" failed 'Manage returned a workspace outside the configured execution roots.' || true
        return
    }
    output=$runtime_dir/$job_id.jsonl
    error_output=$runtime_dir/$job_id.stderr
    : >"$output"
    : >"$error_output"
    chmod 600 -- "$output"
    chmod 600 -- "$error_output"

    report_job "$job_id" running "${selected_provider} started by Monique." || return
    post_job_log "$job_id" lifecycle "${selected_provider} started by Monique."

    set +e
    if [[ "$selected_provider" == codex ]]; then
        printf '%s\n' "$provider_prompt" \
            | CODEX_HOME="$selected_home" "$selected_binary" exec \
                --json \
                --dangerously-bypass-approvals-and-sandbox \
                --skip-git-repo-check \
                -C "$cwd" \
                - 2> >(while IFS= read -r line; do
                    printf '%s\n' "$line" >>"$error_output"
                    post_job_log "$job_id" provider_stderr "$line"
                done) \
            | tee "$output" \
            | while IFS= read -r line; do
                log_provider_line "$job_id" "$line"
            done
        provider_status=${PIPESTATUS[1]:-1}
    elif [[ "$selected_provider" == jcode ]]; then
        cd -- "$cwd" || {
            set -u
            report_job "$job_id" failed 'JCode could not enter the selected workspace.' || true
            return
        }
        printf '%s\n' "$provider_prompt" \
            | JCODE_HOME="$selected_home" \
                JCODE_RUNTIME_DIR="$runtime_dir/jcode-runtime" \
                JCODE_SERVER_EXECUTABLE="$selected_binary" \
                "$selected_binary" --quiet --no-update --no-selfdev run --ndjson - \
                2> >(while IFS= read -r line; do
                    printf '%s\n' "$line" >>"$error_output"
                    post_job_log "$job_id" provider_stderr "$line"
                done) \
            | tee "$output" \
            | while IFS= read -r line; do
                log_provider_line "$job_id" "$line"
            done
        provider_status=${PIPESTATUS[1]:-1}
    else
        cd -- "$cwd" || {
            set -u
            report_job "$job_id" failed 'Claude could not enter the selected workspace.' || true
            return
        }
        printf '%s\n' "$provider_prompt" \
            | CLAUDE_CONFIG_DIR="$selected_home" "$selected_binary" \
                --print \
                --output-format stream-json \
                --verbose \
                --dangerously-skip-permissions \
                2> >(while IFS= read -r line; do
                    printf '%s\n' "$line" >>"$error_output"
                    post_job_log "$job_id" provider_stderr "$line"
                done) \
            | tee "$output" \
            | while IFS= read -r line; do
                log_provider_line "$job_id" "$line"
            done
        provider_status=${PIPESTATUS[1]:-1}
    fi
    set -u

    if [[ "$selected_provider" == codex ]]; then
        session_id=$(jq -rs '[.[] | select(.type == "thread.started") | .thread_id] | first // ""' "$output" 2>/dev/null) || session_id=
        result=$(jq -rs '[.[] | select(.type == "item.completed" and .item.type == "agent_message") | .item.text] | last // ""' "$output" 2>/dev/null) || result=
    elif [[ "$selected_provider" == jcode ]]; then
        session_id=$(jq -rs '[.[] | select(.type == "done") | .session_id] | last // ""' "$output" 2>/dev/null) || session_id=
        result=$(jq -rs '[.[] | select(.type == "done") | .text] | last // ""' "$output" 2>/dev/null) || result=
    else
        session_id=$(jq -rs '[.[] | select(.type == "result") | .session_id] | last // ""' "$output" 2>/dev/null) || session_id=
        result=$(jq -rs '[.[] | select(.type == "result") | .result] | last // ""' "$output" 2>/dev/null) || result=
    fi
    if (( provider_status == 0 )); then
        probe_local_auth || true
        write_auth_health authenticated execution_succeeded "$(date +%s%3N)" || true
        completion_permalink=$(completion_comment_permalink "$result" "$expected_issue_url") || completion_permalink=
        if [[ -n "$completion_permalink" ]]; then
            completion_body=$(completion_comment_body "$completion_permalink") || completion_body=
            if [[ -z "$completion_body" ]]; then
                report_job "$job_id" "done" "$result" "$session_id" || true
                post_job_log "$job_id" lifecycle "${selected_provider} completed with a GitHub receipt; the report shape could not be read back."
            elif completion_report_is_structured "$completion_body"; then
                report_job "$job_id" "done" "$result" "$session_id" || true
                post_job_log "$job_id" lifecycle "${selected_provider} completed with a verified, per-request GitHub report."
            else
                result="Completion receipt rejected: the completion comment ${completion_permalink} does not follow the per-request report format (no 'Demande 1' section with Vérification and Preuve). Delivery remains unverified. Last provider message: ${result:-none}"
                report_job "$job_id" "failed" "$result" "$session_id" || true
                post_job_log "$job_id" lifecycle "${selected_provider} completion report was rejected for its shape."
            fi
        else
            result="Completion receipt rejected: ${selected_provider} exited successfully but did not return the required GitHub completion-comment permalink. Delivery remains unverified. Last provider message: ${result:-none}"
            report_job "$job_id" "failed" "$result" "$session_id" || true
            post_job_log "$job_id" lifecycle "${selected_provider} completion receipt was rejected."
        fi
    else
        [[ -n "$result" ]] || result="${selected_provider} exited with status $provider_status."
        report_job "$job_id" "failed" "$result" "$session_id" || true
        post_job_log "$job_id" lifecycle "${selected_provider} failed."
        if reason=$(auth_failure_reason "$output" "$error_output"); then
            probe_local_auth || true
            if [[ "$reason" == local_session_missing ]]; then
                write_auth_health signed_out "$reason" "$(previous_verified_at)" || true
            else
                write_auth_health expired "$reason" "$(previous_verified_at)" || true
            fi
        fi
    fi
    refresh_process_snapshot || true
}

stopping=0
stop_worker() {
    stopping=1
}
trap stop_worker INT TERM

last_heartbeat=0
heartbeat online 0 || {
    printf '%s\n' 'Manage refused the initial Monique heartbeat' >&2
    exit 1
}

while (( stopping == 0 )); do
    previous_selection=$selection_key
    if load_selected_account; then
        selection_key=$selected_provider:$selected_account
        if [[ "$selection_key" != "$previous_selection" ]]; then
            initialize_auth_health
            last_heartbeat=0
        else
            refresh_auth_after_credential_change
        fi
    else
        auth_method=unknown
        auth_health_file=$aggregate_auth_health_file
        write_auth_health unavailable provider_unavailable "$(previous_verified_at)" || true
        selection_key=invalid
    fi
    active=$(active_jobs)
    now=$(date +%s)
    if (( now - last_heartbeat >= heartbeat_seconds )); then
        if (( active > 0 )); then status=busy; else status=online; fi
        heartbeat "$status" "$active" || true
        refresh_process_snapshot || true
        last_heartbeat=$now
    fi

    before_claim=$active
    while (( active < max_concurrency && stopping == 0 )) \
        && [[ "$(auth_health_status)" != expired ]] \
        && [[ "$(auth_health_status)" != signed_out ]] \
        && [[ "$(auth_health_status)" != authenticating ]] \
        && [[ "$(auth_health_status)" != unavailable ]]
    do
        job=$(claim_one) || break
        [[ "$job" != null ]] || break
        run_job "$job" &
        active=$((active + 1))
    done
    if (( active != before_claim )); then
        refresh_process_snapshot || true
    fi
    sleep "$poll_seconds" &
    wait $! || true
done

active=$(active_jobs)
heartbeat offline "$active" || true
refresh_process_snapshot || true
wait || true
