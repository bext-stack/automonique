#!/bin/sh
# SPDX-License-Identifier: Elastic-2.0

# Build the no-tools chat adapter as a static PIE. Provider execution grants
# exactly one pinned executable and intentionally does not grant a dynamic
# loader or shared-library tree, so a normal dynamically linked development
# binary is ineligible for the contained lane.

set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_directory/.." && pwd)
cd "$repository_root/rust"

CARGO_TARGET_DIR=target/chat-provider-static \
    cargo rustc --release -p automonique-chat-provider \
    --bin automonique-chat-provider -- -C target-feature=+crt-static

file target/chat-provider-static/release/automonique-chat-provider
