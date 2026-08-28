#!/bin/sh
# SPDX-License-Identifier: Elastic-2.0

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
verify_state=$(mktemp -d)
trap 'rm -rf -- "$verify_state"' EXIT HUP INT TERM

daemon_bin="$verify_state/automonique/bin"
worker_bin="$verify_state/automonique/improvement-code/current/bin"
web_entry_bin="$verify_state/automonique/web-entry/bin"
ag_ui_bin="$verify_state/automonique/ag-ui-adapter"
tunnel_bin="$verify_state/bin"
unit_dir="$verify_state/systemd"
mkdir -p "$daemon_bin"
mkdir -p "$worker_bin"
mkdir -p "$web_entry_bin"
mkdir -p "$ag_ui_bin/src"
mkdir -p "$tunnel_bin"
mkdir -p "$unit_dir"
cp /bin/true "$daemon_bin/automonique"
cp /bin/true "$daemon_bin/automonique-launch-enter"
cp /bin/true "$worker_bin/automonique-manage-worker"
cp /bin/true "$web_entry_bin/automonique-web-entry"
cp /bin/true "$ag_ui_bin/src/main.ts"
cp /bin/true "$tunnel_bin/cloudflared"

# `systemd-analyze verify` resolves absolute executables on the machine running
# the check. The tunnel binary is deployment-owned and intentionally absent on
# a clean CI runner, so verify an otherwise byte-equivalent temporary unit with
# a local executable while pinning the packaged path separately. This keeps a
# missing production binary a deployment failure without making static unit
# syntax depend on CI's installed packages.
tunnel_unit="$repo_root/packaging/systemd/automonique-web-tunnel.service"
verified_tunnel="$unit_dir/automonique-web-tunnel.service"
ag_ui_unit="$repo_root/packaging/systemd/automonique-ag-ui-adapter.service"
verified_ag_ui="$unit_dir/automonique-ag-ui-adapter.service"
expected_tunnel_exec='ExecStart=/usr/local/bin/cloudflared tunnel --config %h/.cloudflared/config-monique-web.yml --no-autoupdate run'
grep -Fqx "$expected_tunnel_exec" "$tunnel_unit"
sed "s|^ExecStart=/usr/local/bin/cloudflared |ExecStart=$tunnel_bin/cloudflared |" \
    "$tunnel_unit" >"$verified_tunnel"
grep -Fq "ExecStart=$tunnel_bin/cloudflared tunnel " "$verified_tunnel"
expected_ag_ui_exec='ExecStart=%h/.bun/bin/bun %S/automonique/ag-ui-adapter/src/main.ts'
grep -Fqx "$expected_ag_ui_exec" "$ag_ui_unit"
sed "s|^ExecStart=%h/.bun/bin/bun |ExecStart=/bin/true |" "$ag_ui_unit" >"$verified_ag_ui"

# Keep every unit in one isolated load path. When units with dependencies are
# verified from the source directory, systemd may reload the packaged tunnel
# by unit name and bypass the temporary executable substitution.
for unit in \
    automonique.socket \
    automonique-tempfs-owner.service \
    automonique.service \
    automonique-manage-worker.service \
    automonique-web-entry.service \
    automonique-recovery.service \
    automonique-backup.service \
    automonique-backup.timer
do
    cp "$repo_root/packaging/systemd/$unit" "$unit_dir/$unit"
done

XDG_STATE_HOME="$verify_state" systemd-analyze --user verify \
    "$unit_dir/automonique.socket" \
    "$unit_dir/automonique-tempfs-owner.service" \
    "$unit_dir/automonique.service" \
    "$unit_dir/automonique-manage-worker.service" \
    "$unit_dir/automonique-web-entry.service" \
    "$verified_ag_ui" \
    "$verified_tunnel" \
    "$unit_dir/automonique-recovery.service" \
    "$unit_dir/automonique-backup.service" \
    "$unit_dir/automonique-backup.timer"
