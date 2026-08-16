#!/bin/sh
# SPDX-License-Identifier: Elastic-2.0

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
verify_state=$(mktemp -d)
trap 'rm -rf -- "$verify_state"' EXIT HUP INT TERM

release_bin="$verify_state/automonique/improvement-code/current/bin"
mkdir -p "$release_bin"
cp /bin/true "$release_bin/automonique"

XDG_STATE_HOME="$verify_state" \
    systemd-analyze --user verify "$repo_root/packaging/systemd/automonique.service"
