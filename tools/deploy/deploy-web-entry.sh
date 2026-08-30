#!/usr/bin/env bash
# Deploy an automonique web entry so the running binary can name its revision.
#
#   automonique-deploy-web-entry.sh --root DIR --service UNIT --binary FILE \
#                                   --source-sha SHA [--probe URL] [--no-restart]
#
# Why this exists: both deployed roots were installed by copying a binary
# straight into <root>/bin/, which is a REAL directory. `current` and
# `manifest.json` therefore described a build that was not the one serving
# traffic, and no manifest anywhere named the running bytes (issue #217).
#
# This script promotes through releases/ and then replaces <root>/bin with a
# symlink to current/bin, so that after the first run the pointer IS the
# deployment and the drift cannot silently reappear.
set -euo pipefail

root=; service=; binary=; source_sha=; probe=; restart=1; allow_unattributable=0
while [ $# -gt 0 ]; do
  case "$1" in
    --root) root="$2"; shift 2 ;;
    --service) service="$2"; shift 2 ;;
    --binary) binary="$2"; shift 2 ;;
    --source-sha) source_sha="$2"; shift 2 ;;
    --probe) probe="$2"; shift 2 ;;
    --no-restart) restart=0; shift ;;
    --allow-unattributable) allow_unattributable=1; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
for required in root service binary source_sha; do
  [ -n "${!required}" ] || { echo "refused: --${required//_/-} is required" >&2; exit 2; }
done
[ -f "$binary" ] || { echo "refused: no binary at $binary" >&2; exit 1; }
[ -d "$root" ]   || { echo "refused: no release root at $root" >&2; exit 1; }

binary_sha=$(sha256sum "$binary" | cut -d' ' -f1)

# Ask the binary what revision it was built from, and refuse to write a manifest
# that contradicts it. Before builds could name themselves (#217) a manifest was
# an unverifiable assertion about bytes beside it; now it is checkable, so check
# it. A binary too old to answer is tolerated, and says so.
identity=$("$binary" --build-identity --json 2>/dev/null) || identity=
if [ -n "$identity" ]; then
  declared_revision=$(printf '%s' "$identity" | sed -n 's/.*"source_revision":"\([^"]*\)".*/\1/p')
  provenance=$(printf '%s' "$identity" | sed -n 's/.*"provenance":"\([^"]*\)".*/\1/p')
  echo "identity ${provenance:-unreadable} ${declared_revision:-<none>}"
  if [ -n "$declared_revision" ] && [ "$declared_revision" != "$source_sha" ]; then
    echo "refused: the binary says it was built from $declared_revision, not $source_sha" >&2
    exit 1
  fi
  case "$provenance" in
    declared|committed) ;;
    *)
      if [ "$allow_unattributable" = 1 ]; then
        echo "warning: provenance is '${provenance:-unknown}'; deploying anyway on request"
      else
        echo "refused: provenance is '${provenance:-unknown}', so this build cannot be attributed." >&2
        echo "         Rebuild with AUTOMONIQUE_SOURCE_REVISION set from a clean tree," >&2
        echo "         or pass --allow-unattributable if you accept an unattributable deployment." >&2
        exit 1
      fi ;;
  esac
else
  echo "identity this binary cannot name its own revision (predates #217)"
fi
release="$root/releases/${source_sha:0:7}-${binary_sha:0:7}"
echo "source   ${source_sha}"
echo "binary   ${binary_sha}"
echo "release  ${release}"

if [ -e "$release" ]; then
  echo "note: release directory already exists; verifying rather than rewriting"
else
  mkdir -p "$release/bin"
  install -m 0755 "$binary" "$release/bin/automonique-web-entry"
  printf '{"schema":"automonique.web-entry-release/v1","source_sha":"%s","binary_sha256":"%s","built":"%s"}\n' \
    "$source_sha" "$binary_sha" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$release/manifest.json"
  # 0600, matching what release_builder writes: the shared manifest reader
  # refuses a permissive mode and would stop at release.permissive-mode
  # before it could reach the digest cross-check that makes it useful.
  chmod 0600 "$release/manifest.json"
fi

# Never promote bytes we did not just verify on disk.
placed=$(sha256sum "$release/bin/automonique-web-entry" | cut -d' ' -f1)
[ "$placed" = "$binary_sha" ] || { echo "refused: placed binary hashes ${placed}, expected ${binary_sha}" >&2; exit 1; }

# Keep whatever is serving now, so a rollback is one move rather than a rebuild.
stamp=$(date -u +%Y%m%d-%H%M%S)
if [ -e "$root/bin/automonique-web-entry" ] && [ ! -L "$root/bin" ]; then
  cp -a "$root/bin" "$root/bin.realdir.$stamp"
  echo "kept the pre-existing real bin/ as bin.realdir.$stamp"
fi
[ -L "$root/current" ] && ln -sfn "$(readlink -f "$root/current")" "$root/previous"

ln -sfn "$release" "$root/current.new" && mv -Tf "$root/current.new" "$root/current"

# The structural fix: bin follows current, instead of being a separate copy.
if [ ! -L "$root/bin" ]; then
  # ${root:?} so an empty root can never make this `rm -rf /bin`. The argument
  # check above already refuses an empty root; this survives that check moving.
  rm -rf "${root:?}/bin"
  ln -sfn current/bin "$root/bin"
  echo "bin/ is now a symlink to current/bin"
fi

running=$(sha256sum "$root/bin/automonique-web-entry" | cut -d' ' -f1)
[ "$running" = "$binary_sha" ] || { echo "refused: bin/ resolves to ${running}" >&2; exit 1; }

if [ "$restart" = 1 ]; then
  systemctl --user restart "$service"
  for _ in $(seq 20); do
    [ "$(systemctl --user is-active "$service")" = active ] && break
    sleep 1
  done
  state=$(systemctl --user is-active "$service")
  echo "service  $service is $state"
  [ "$state" = active ] || { echo "refused: service did not come back active" >&2; exit 1; }
  # The entry answers only behind its canonical host and a TLS-terminated hop,
  # so a bare loopback GET reports nothing about health. Read the host the
  # deployment itself declares, and treat an auth challenge as proof the
  # application is answering: 000 or 5xx is not.
  if [ -z "$probe" ]; then
    # The unit's own ExecStart is the authority for both: the integration config
    # is not always inside the release root, and the port is only declared there.
    exec_start=$(systemctl --user show -p ExecStart --value "$service")
    port=$(printf '%s' "$exec_start" | grep -o -- '--port [0-9]*' | awk '{print $2}')
    conf=$(printf '%s' "$exec_start" | grep -o -- '--integration-config [^ ]*' | awk '{print $2}')
    host=
    [ -n "$conf" ] && [ -r "$conf" ] && host=$(sed -n 's/^canonical_host=//p' "$conf" | head -1)
    if [ -n "$host" ] && [ -n "$port" ]; then
      # Type=simple reports active as soon as the process forks, which is before
      # it binds. Poll until it answers rather than reading the race as a fault.
      code=000
      for _ in $(seq 30); do
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
          -H "Host: $host" -H 'X-Forwarded-Proto: https' "http://127.0.0.1:$port/") || code=000
        case "$code" in 401|200|302) break ;; esac
        sleep 1
      done
      echo "probe    loopback:$port as $host -> $code"
      case "$code" in
        401|200|302) ;;
        *) echo "refused: the deployment did not answer (got $code); roll back with the kept bin.realdir.* or previous" >&2; exit 1 ;;
      esac
    else
      echo "probe    skipped: the unit declares no canonical host and port"
    fi
  else
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$probe" || echo 000)
    echo "probe    $probe -> $code"
  fi
fi
echo "deployed."
