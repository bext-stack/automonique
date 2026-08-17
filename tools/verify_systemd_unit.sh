#!/bin/sh
# SPDX-License-Identifier: Elastic-2.0

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
verify_state=$(mktemp -d)
trap 'rm -rf -- "$verify_state"' EXIT HUP INT TERM

release_bin="$verify_state/automonique/improvement-code/current/bin"
mkdir -p "$release_bin"
cp /bin/true "$release_bin/automonique"
cp /bin/true "$release_bin/automonique-manage-worker"

XDG_STATE_HOME="$verify_state" systemd-analyze --user verify \
    "$repo_root/packaging/systemd/automonique.service" \
    "$repo_root/packaging/systemd/automonique-manage-worker.service" \
    "$repo_root/packaging/systemd/automonique-recovery.service" \
    "$repo_root/packaging/systemd/automonique-backup.service" \
    "$repo_root/packaging/systemd/automonique-backup.timer"
