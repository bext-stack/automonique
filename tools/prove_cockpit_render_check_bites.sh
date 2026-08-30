#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0
#
# Prove that the cockpit render check can fail.
#
# `tests/browser/live-cockpit-attention.spec.js` is the automated half of
# LIVE-GUI-2: it signs into the deployed cockpit and asserts the rendered
# attention item against the projection that deployment itself answered with. A
# check like that is worth nothing if it cannot fail, and it runs where nobody
# can see it, so its bite is established here instead — offline, against the
# real cockpit assets and the committed render-proof document, with a named
# mutation applied to the real render path.
#
# Every mutation must fail and the unmutated run must pass. Needs no credential,
# no network and no deployment.

set -euo pipefail

crate="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/rust/crates/automonique-web-entry"
cd "$crate"

runner="$(command -v bunx || command -v npx || true)"
if [ -z "$runner" ]; then
  echo "neither bunx nor npx is on PATH; the browser check cannot be run" >&2
  exit 2
fi

export AUTOMONIQUE_LIVE_COCKPIT_PROOF_DOCUMENT="$crate/fixtures/cockpit-render-proof-v1.json"

# `none` must pass; a check that fails on everything proves nothing either.
declare -a must_fail=(generation review_inference review_decision dropped_item)
status=0

run_mutation() {
  local mutation="$1" expected="$2" outcome
  export AUTOMONIQUE_LIVE_COCKPIT_PROOF_MUTATION="$mutation"
  export AUTOMONIQUE_LIVE_COCKPIT_EVIDENCE_DIR="$crate/test-results/proof-$mutation"
  if "$runner" playwright test --project=live-cockpit --reporter=line >"/tmp/cockpit-proof-$mutation.log" 2>&1; then
    outcome=passed
  else
    outcome=failed
  fi
  if [ "$outcome" = "$expected" ]; then
    printf 'ok    %-18s %s (expected)\n' "$mutation" "$outcome"
  else
    printf 'BITE  %-18s %s, expected %s\n' "$mutation" "$outcome" "$expected"
    sed -n '1,40p' "/tmp/cockpit-proof-$mutation.log" >&2
    status=1
  fi
}

run_mutation none passed
for mutation in "${must_fail[@]}"; do
  run_mutation "$mutation" failed
done

if [ "$status" -ne 0 ]; then
  echo "the cockpit render check did not behave as a check; do not trust a green live run" >&2
fi
exit "$status"
