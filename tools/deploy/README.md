# Deploy procedures

Two scripts that install a build so the running bytes can be attributed to the
revision they were made from. Both are idempotent and fail closed.

They exist because both deployed surfaces had drifted out of the release
machinery that was supposed to govern them (#217, #227), in two different ways,
and the fix in each case is a property of the *procedure*, not of the artifact.

## Web entry

```
tools/deploy/deploy-web-entry.sh --root DIR --service UNIT \
  --binary FILE --source-sha SHA
```

Promotes through `releases/`, writes the manifest, moves `current`, then
**replaces `<root>/bin` with a symlink to `current/bin`**.

> `<root>/bin` was a real directory. Promoting a release therefore changed
> nothing about what served traffic, and a binary copied into `bin/` updated no
> manifest. `current`, `previous` and all 47 release manifests were decorative.
> After the first run the pointer *is* the deployment.

It asks the binary what revision it was built from (`--build-identity`) and
refuses to write a manifest the binary contradicts, or to deploy a build whose
provenance is `modified` or `unknown` unless `--allow-unattributable` is given.

⚠️ The manifest is written **0600**. The shared manifest reader refuses a
permissive mode and stops at `release.permissive-mode` before it reaches the
digest cross-check that makes it useful.

## Daemon

```
tools/deploy/deploy-daemon.sh --state-dir DIR --unit UNIT --worktree DIR
```

Builds through `automonique-release build`, then hands off with
`automonique reload`, which is a **generation handoff and not a restart**:
accepted work is not interrupted.

Two traps it exists to stop repeating:

- ⚠️ **`reload` does not update `<state-dir>/bin/`.** The live process runs from
  `improvement-code/releases/<digest>/bin/`, but `ExecStart` points at `bin/`,
  so a **cold start would silently revert** to the previous binary. The script
  aligns `bin/` afterwards and verifies each file against the manifest.
- ⚠️ **`<state-dir>/bin` must stay a real directory**, unlike the web entry: the
  handoff machinery writes its own copies there (`automonique.pre-NNN`,
  `automonique.previous`). The script refuses if it finds a symlink.

The daemon's release root is `<state-dir>/improvement-code/`, **not** the state
root. Looking at the state root is what led #227 to be filed claiming no release
machinery existed when it did.

It skips entirely when the deployed `source_sha` already matches and `bin/`
agrees, so re-running is cheap and does not burn a generation. `--force`
overrides.

## Supervised activation

`automonique-release activate` restarts the unit instead of handing off. It
refuses unless the unit proves an unbounded orderly stop:

```
systemctl --user show <unit> --property=TimeoutStopUSec --value   # must be exactly `infinity`
```

At the default the daemon's orderly SIGTERM path is cut short and accepted work
is killed at the deadline rather than joined. Set it with a drop-in:

```ini
# ~/.config/systemd/user/<unit>.service.d/10-unbounded-orderly-stop.conf
[Service]
TimeoutStopSec=infinity
```

Trade-off: a wedged daemon is no longer force-killed on stop. Recovery is
`systemctl --user kill -s SIGKILL <unit>`.

## Verifying a deployment

```
automonique doctor            # release.build-identity and release.manifest-structure
automonique generations       # handoff history
<binary> --build-identity --json
```

`GET /api/build` serves the same document from the web entry, behind the
operator gate. It is deliberately not exempt alongside `/healthz`: a revision is
not a secret, but an anonymous caller has no business collecting a precise
statement of what is deployed.
