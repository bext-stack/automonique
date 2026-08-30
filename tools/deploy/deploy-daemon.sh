#!/usr/bin/env bash
# Deploy an automonique daemon through its own release machinery, without a restart.
#
#   automonique-deploy-daemon.sh --state-dir DIR --unit UNIT --worktree DIR
#                                [--release-tool PATH] [--force] [--no-align-bin]
#
# The daemon activates releases under <state-dir>/improvement-code/, and
# `automonique reload` performs a GENERATION HANDOFF: the new code takes over
# without a supervised restart, so accepted work is not interrupted.
#
# Two traps this exists to stop repeating:
#
#   * `reload` does NOT update <state-dir>/bin/. The live process runs from the
#     release directory, but ExecStart points at bin/, so a COLD START would
#     silently revert to the previous binary. This aligns bin/ afterwards.
#   * <state-dir>/bin must stay a real directory, NOT a symlink to current/bin:
#     the handoff machinery writes its own copies there (automonique.pre-NNN).
set -euo pipefail

state=; unit=; worktree=; tool=; force=0; align=1
while [ $# -gt 0 ]; do
  case "$1" in
    --state-dir) state="$2"; shift 2 ;;
    --unit) unit="$2"; shift 2 ;;
    --worktree) worktree="$2"; shift 2 ;;
    --release-tool) tool="$2"; shift 2 ;;
    --force) force=1; shift ;;
    --no-align-bin) align=0; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
for required in state unit worktree; do
  [ -n "${!required}" ] || { echo "refused: --${required//_/-} is required" >&2; exit 2; }
done
# Default to the release tool built beside this checkout, so the script works
# from a clone without the operator restating where the workspace lives.
if [ -z "$tool" ]; then
  here=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
  tool="$here/../../rust/target/release/automonique-release"
fi
[ -x "$tool" ] || { echo "refused: no release tool at $tool" >&2; exit 1; }
[ -d "$state" ] || { echo "refused: no state directory at $state" >&2; exit 1; }
[ -d "$worktree/.git" ] || [ -f "$worktree/.git" ] || { echo "refused: $worktree is not a git worktree" >&2; exit 1; }

# The builder refuses a worktree whose HEAD does not match what it is told, so
# a dirty tree would silently release something nobody named.
if [ -n "$(git -C "$worktree" status --porcelain)" ]; then
  echo "refused: $worktree has uncommitted changes; a release must name a committed revision" >&2
  exit 1
fi
src=$(git -C "$worktree" rev-parse HEAD)
echo "source   $src"

# The daemon reads its admin socket under the unit's own XDG_RUNTIME_DIR, so a
# non-production daemon is only reachable when that is honoured.
runtime=$(systemctl --user show "$unit" -p Environment --value | tr ' ' '\n' | sed -n 's/^XDG_RUNTIME_DIR=//p' | head -1)
runtime="${runtime:-${XDG_RUNTIME_DIR:-/run/user/$(id -u)}}"
cli="$state/bin/automonique"
[ -x "$cli" ] || { echo "refused: no daemon CLI at $cli" >&2; exit 1; }
run_cli() { XDG_RUNTIME_DIR="$runtime" "$cli" "$@"; }

before=$(run_cli status 2>/dev/null | sed -n 's/^generation: //p' | head -1 || true)
[ -n "$before" ] || { echo "refused: the daemon at $state did not answer on $runtime" >&2; exit 1; }
echo "unit     $unit  (generation $before, runtime $runtime)"

# Changed paths only classify the release kind, but naming the real difference
# from what is deployed keeps the manifest honest about what it carries.
deployed_src=""
if [ -e "$state/improvement-code/current/manifest.json" ]; then
  deployed_src=$(sed -n 's/.*"source_sha":"\([0-9a-f]\{40\}\)".*/\1/p' "$state/improvement-code/current/manifest.json" | head -1)
fi
# Decide whether there is anything to do BEFORE building. The plan digest is
# operator-chosen, so an unchanged source still yields a fresh manifest and a
# fresh digest: comparing digests after the build would rebuild and hand off
# every run for no change. The deployed source revision is the honest predicate.
if [ "$deployed_src" = "$src" ] && [ "$force" = 0 ]; then
  stale=0
  if [ "$align" = 1 ]; then
    for b in automonique automonique-launch-enter; do
      installed="$state/improvement-code/current/bin/$b"
      [ -f "$installed" ] || continue
      [ -f "$state/bin/$b" ] || { stale=1; break; }
      a=$(sha256sum "$installed" | cut -d' ' -f1)
      c=$(sha256sum "$state/bin/$b" | cut -d' ' -f1)
      [ "$a" = "$c" ] || { stale=1; break; }
    done
  fi
  if [ "$stale" = 0 ]; then
    echo "handoff  skipped: generation $before already serves $src, and bin/ matches it"
    echo "         (pass --force to build and hand off anyway)"
    echo "deployed."
    exit 0
  fi
  echo "note     current already serves $src, but bin/ has drifted from it; continuing"
fi

if [ -n "$deployed_src" ] && git -C "$worktree" cat-file -e "$deployed_src^{commit}" 2>/dev/null; then
  mapfile -t changed < <(git -C "$worktree" diff --name-only "$deployed_src..$src")
else
  mapfile -t changed < <(git -C "$worktree" ls-tree -r --name-only HEAD | head -1)
fi
# The builder requires at least one changed path; it only classifies the
# release kind. When the diff is empty (a forced rebuild of the same source)
# name a real code path rather than an arbitrary first file, so the manifest
# still classifies as a code release.
if [ "${#changed[@]}" -eq 0 ]; then
  changed=(rust/crates/automonique-daemon/src/lib.rs)
  echo "changed  none since ${deployed_src:0:7}; forced rebuild of the same source"
else
  echo "changed  ${#changed[@]} path(s) since ${deployed_src:0:7}${deployed_src:+ (deployed)}"
fi

plan="sha256:$(printf 'operator-deploy:%s' "$src" | sha256sum | cut -d' ' -f1)"
args=(); for p in "${changed[@]}"; do args+=(--changed-path "$p"); done

out=$("$tool" build --state-dir "$state" --worktree "$worktree" --plan-digest "$plan" "${args[@]}")
digest=$(printf '%s' "$out" | sed -n 's/^manifest_digest=//p' | head -1)
reldir=$(printf '%s' "$out" | sed -n 's/^release_directory=//p' | head -1)
[ -n "$digest" ] && [ -d "$reldir" ] || { echo "refused: the builder named no release" >&2; echo "$out" >&2; exit 1; }
echo "release  $digest"

# The binary can name its own revision since #217. Refuse to activate one that
# disagrees with the tree we just built from, or that cannot be attributed.
identity=$("$reldir/bin/automonique" build-identity --json 2>/dev/null || true)
if [ -n "$identity" ]; then
  rev=$(printf '%s' "$identity" | sed -n 's/.*"source_revision":"\([^"]*\)".*/\1/p')
  prov=$(printf '%s' "$identity" | sed -n 's/.*"provenance":"\([^"]*\)".*/\1/p')
  echo "identity $prov $rev"
  [ "$rev" = "$src" ] || { echo "refused: the built binary says $rev, not $src" >&2; exit 1; }
  case "$prov" in declared|committed) ;; *)
    echo "refused: provenance '$prov' is not attributable" >&2; exit 1 ;;
  esac
else
  echo "identity this build cannot name its own revision (predates #217)"
fi

current=""
[ -L "$state/improvement-code/current" ] && current=$(basename "$(readlink "$state/improvement-code/current")")
if [ "$current" = "${digest#sha256:}" ] && [ "$force" = 0 ]; then
  echo "handoff  skipped: current already is this release (pass --force to hand off anyway)"
else
  run_cli reload "$digest" --wait
  after=$(run_cli status 2>/dev/null | sed -n 's/^generation: //p' | head -1)
  echo "handoff  generation $before -> $after"
  [ "$after" != "$before" ] || { echo "refused: the generation did not advance" >&2; exit 1; }
fi

if [ "$align" = 1 ]; then
  [ -L "$state/bin" ] && { echo "refused: $state/bin is a symlink; the handoff machinery needs a real directory" >&2; exit 1; }
  stamp=$(date -u +%Y%m%d-%H%M%S)
  mkdir -p "$state/bin.premigration-$stamp"
  cp -a "$state/bin/." "$state/bin.premigration-$stamp/" 2>/dev/null || true
  for b in automonique automonique-launch-enter automonique-chat-provider automonique-manage-worker; do
    [ -f "$state/improvement-code/current/bin/$b" ] || continue
    install -m 0700 "$state/improvement-code/current/bin/$b" "$state/bin/$b.incoming"
    mv -f "$state/bin/$b.incoming" "$state/bin/$b"
  done
  echo "bin/     aligned with current (previous kept as bin.premigration-$stamp)"
  python3 - "$state" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
manifest = json.load(open(root / "improvement-code/current/manifest.json"))
pairs = [("binary_path", "binary_sha256"), ("launch_helper_binary_path", "launch_helper_binary_sha256"),
         ("chat_provider_binary_path", "chat_provider_binary_sha256"), ("manage_worker_path", "manage_worker_sha256")]
bad = False
for path_key, digest_key in pairs:
    rel = manifest.get(path_key)
    if not rel:
        continue
    installed = root / rel
    if not installed.exists():
        continue
    got = hashlib.sha256(installed.read_bytes()).hexdigest()
    ok = got == manifest[digest_key]
    bad |= not ok
    print(f"         {rel:<34} {'match' if ok else 'MISMATCH'}")
sys.exit(1 if bad else 0)
PY
fi

echo "doctor"
run_cli doctor 2>/dev/null | grep -E "^- release\." | sed 's/^/         /' || true
echo "deployed."
