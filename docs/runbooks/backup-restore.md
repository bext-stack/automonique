<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Backup and restore

The user timer creates an online recovery set every five minutes. Check it with:

```sh
systemctl --user status automonique-backup.timer
automonique backup verify "$XDG_STATE_HOME/automonique/backups/recovery-..."
```

Create an immediate set with `automonique backup create <backup-root>`. The
manifest hashes every member and records SQLite integrity results. Databases are
snapshotted before blob and non-secret configuration paths are derived from the
snapshot.

Restore only while the normal service is stopped, into an empty state directory.
Run the restore from a verified binary kept outside the target directory: the
normal installed binary lives inside product state and is installed only after
the data restore succeeds.

```sh
systemctl --user stop automonique.service
/path/to/verified/automonique restore --from <recovery-set> --into "$XDG_STATE_HOME/automonique"
# Install the verified release and activate its current link.
systemctl --user start automonique-recovery.service
automonique status --json
```

The recovery service reads no Slack, Telegram, or support configuration and
refuses new intake and provider starts. Verify database and artifact state,
transport offsets, outstanding outbox effects, and credential audiences before
stopping recovery mode and starting `automonique.service`.

Plaintext credential files are deliberately not copied. Recover credentials
through their separately escrowed key or external secret provider; never add
them to a recovery manifest to make a drill pass. Restore refuses a non-empty
target, so preserve or move an existing state directory before running it.

CI runs the same drill on a fresh runner and fails if the fresh set is older
than five minutes or verified restore exceeds thirty minutes. A local fixture
run reports those timings but cannot claim the host-level objectives:

```sh
automonique restore drill --scope local-fixture --from <recovery-set> --into <empty-target>
```
