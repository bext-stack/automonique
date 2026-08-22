#!/bin/sh
# SPDX-License-Identifier: Elastic-2.0

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
verify_state=$(mktemp -d)
trap 'rm -rf -- "$verify_state"' EXIT HUP INT TERM

release_bin="$verify_state/automonique/improvement-code/current/bin"
web_entry_bin="$verify_state/automonique/web-entry/current/bin"
tunnel_bin="$verify_state/bin"
mkdir -p "$release_bin"
mkdir -p "$web_entry_bin"
mkdir -p "$tunnel_bin"
cp /bin/true "$release_bin/automonique"
cp /bin/true "$release_bin/automonique-manage-worker"
cp /bin/true "$web_entry_bin/automonique-web-entry"
cp /bin/true "$tunnel_bin/cloudflared"

# `systemd-analyze verify` resolves absolute executables on the machine running
# the check. The tunnel binary is deployment-owned and intentionally absent on
# a clean CI runner, so verify an otherwise byte-equivalent temporary unit with
# a local executable while pinning the packaged path separately. This keeps a
# missing production binary a deployment failure without making static unit
# syntax depend on CI's installed packages.
tunnel_unit="$repo_root/packaging/systemd/automonique-web-tunnel.service"
verified_tunnel="$verify_state/automonique-web-tunnel.service"
expected_tunnel_exec='ExecStart=/usr/local/bin/cloudflared tunnel --config %h/.cloudflared/config-monique-web.yml --no-autoupdate run'
grep -Fqx "$expected_tunnel_exec" "$tunnel_unit"
sed "s|^ExecStart=/usr/local/bin/cloudflared |ExecStart=$tunnel_bin/cloudflared |" \
    "$tunnel_unit" >"$verified_tunnel"
grep -Fq "ExecStart=$tunnel_bin/cloudflared tunnel " "$verified_tunnel"

XDG_STATE_HOME="$verify_state" systemd-analyze --user verify \
    "$repo_root/packaging/systemd/automonique.service" \
    "$repo_root/packaging/systemd/automonique-manage-worker.service" \
    "$repo_root/packaging/systemd/automonique-web-entry.service" \
    "$verified_tunnel" \
    "$repo_root/packaging/systemd/automonique-recovery.service" \
    "$repo_root/packaging/systemd/automonique-backup.service" \
    "$repo_root/packaging/systemd/automonique-backup.timer"
