#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0

# Monique's Manage fleet runtime.
#
# The fleet API owns authorization, workspace selection, approval and atomic
# claims. This worker supplies only the execution half: heartbeat, claim,
# explicit argv launch, bounded live logs and a terminal receipt. Prompts are
# delivered on stdin and are never evaluated as shell input.

set -uo pipefail

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
fleet_url=${fleet_base%/}/api/manage/shelldeck/fleet

if [[ ! -x "$provider_binary" || ! -d "$provider_home" ]]; then
    printf '%s\n' 'configured Codex provider is unavailable' >&2
    exit 2
fi

umask 077
mkdir -p -- "$runtime_dir"
chmod 700 -- "$runtime_dir"

fleet_post() {
    body=$1
    curl --silent --show-error --max-time 15 \
        --request POST "$fleet_url" \
        --header "Authorization: Bearer $fleet_token" \
        --header 'Content-Type: application/json' \
        --header 'Accept: application/json' \
        --data-binary "$body"
}

fleet_snapshot() {
    curl --silent --show-error --max-time 15 \
        --request GET "$fleet_url" \
        --header "Authorization: Bearer $fleet_token" \
        --header 'Accept: application/json'
}

load_instance_root() {
    snapshot=$(fleet_snapshot) || return 1
    jq -er --arg id "$fleet_instance" \
        '[.instances[]? | select(.id == $id) | .workdir] | first | select(type == "string" and startswith("/"))' \
        <<<"$snapshot"
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

heartbeat() {
    status=$1
    active=$2
    detail="Monique Codex worker: ${active}/${max_concurrency} active"
    body=$(jq -cn \
        --arg id "$fleet_instance" \
        --arg status "$status" \
        --arg detail "$detail" \
        --arg binary "$(basename -- "$provider_binary")" \
        '{action:"heartbeat",id:$id,status:$status,detail:$detail,version:"automonique-manage-worker/v1",harness:{agent:"codex",binary:$binary,available:true,auth_status:"configured",permission_mode:"confirmed-ticket"}}')
    response=$(fleet_post "$body") || return 1
    jq -e '.ok == true' >/dev/null <<<"$response"
}

claim_one() {
    body=$(jq -cn --arg id "$fleet_instance" '{action:"claim",id:$id}')
    response=$(fleet_post "$body") || return 1
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
    response=$(fleet_post "$body") || return 1
    jq -e '.ok == true' >/dev/null <<<"$response"
}

post_job_log() {
    job_id=$1
    kind=$2
    text=$3
    [[ -n "$text" ]] || return 0
    now_ms=$(date +%s%3N)
    body=$(jq -cn \
        --arg job "$job_id" \
        --arg kind "${kind:0:40}" \
        --arg text "${text:0:1000}" \
        --argjson at "$now_ms" \
        '{action:"joblog",jobId:$job,lines:[{at:$at,kind:$kind,text:$text}]}')
    response=$(fleet_post "$body") || return 0
    jq -e '.ok == true' >/dev/null <<<"$response" || true
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

log_codex_line() {
    job_id=$1
    line=$2
    kind=$(jq -r '.type // "output"' <<<"$line" 2>/dev/null) || kind=output
    text=$(jq -r '
        if .type == "item.completed" and .item.type == "agent_message" then .item.text
        elif .type == "item.started" then ("started " + (.item.type // "item"))
        elif .type == "error" then (.message // "provider error")
        else empty end
    ' <<<"$line" 2>/dev/null) || text=
    post_job_log "$job_id" "$kind" "$text"
}

run_job() {
    job=$1
    job_id=$(jq -er '.id | select(type == "string" and test("^[A-Za-z0-9._-]{8,120}$"))' <<<"$job") || return
    prompt=$(jq -er '.prompt | select(type == "string" and length > 0 and length <= 8000)' <<<"$job") || {
        report_job "$job_id" failed 'Manage returned an invalid job prompt.' || true
        return
    }
    requested_cwd=$(jq -r '.cwd // ""' <<<"$job")
    cwd=$(workspace_for "$requested_cwd") || {
        report_job "$job_id" failed 'Manage returned a workspace outside the configured execution roots.' || true
        return
    }
    output=$runtime_dir/$job_id.jsonl
    : >"$output"
    chmod 600 -- "$output"

    report_job "$job_id" running 'Codex started by Monique.' || return
    post_job_log "$job_id" lifecycle 'Codex started by Monique.'

    set +e
    printf '%s\n' "$prompt" \
        | CODEX_HOME="$provider_home" "$provider_binary" exec \
            --json \
            --dangerously-bypass-approvals-and-sandbox \
            --skip-git-repo-check \
            -C "$cwd" \
            - 2>&1 \
        | tee "$output" \
        | while IFS= read -r line; do
            log_codex_line "$job_id" "$line"
        done
    statuses=("${PIPESTATUS[@]}")
    set -u
    provider_status=${statuses[1]:-1}

    session_id=$(jq -rs '[.[] | select(.type == "thread.started") | .thread_id] | first // ""' "$output" 2>/dev/null) || session_id=
    result=$(jq -rs '[.[] | select(.type == "item.completed" and .item.type == "agent_message") | .item.text] | last // ""' "$output" 2>/dev/null) || result=
    if (( provider_status == 0 )); then
        [[ -n "$result" ]] || result='Codex completed without a final text receipt.'
        report_job "$job_id" "done" "$result" "$session_id" || true
        post_job_log "$job_id" lifecycle 'Codex completed.'
    else
        [[ -n "$result" ]] || result="Codex exited with status $provider_status."
        report_job "$job_id" "failed" "$result" "$session_id" || true
        post_job_log "$job_id" lifecycle 'Codex failed.'
    fi
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
    active=$(active_jobs)
    now=$(date +%s)
    if (( now - last_heartbeat >= heartbeat_seconds )); then
        if (( active > 0 )); then status=busy; else status=online; fi
        heartbeat "$status" "$active" || true
        last_heartbeat=$now
    fi

    while (( active < max_concurrency && stopping == 0 )); do
        job=$(claim_one) || break
        [[ "$job" != null ]] || break
        run_job "$job" &
        active=$((active + 1))
    done
    sleep "$poll_seconds" &
    wait $! || true
done

active=$(active_jobs)
heartbeat offline "$active" || true
wait || true
