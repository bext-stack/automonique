<!-- SPDX-License-Identifier: Elastic-2.0 -->

# systemd user service

Install the units in this directory under `~/.config/systemd/user/`, then run:

```sh
systemctl --user daemon-reload
systemctl --user enable --now automonique.service
systemctl --user enable --now automonique-backup.timer
systemctl --user status automonique.service
```

The unit starts the current verified release from the product state directory,
creates private XDG runtime/state directories, delegates its cgroup subtree,
and waits for the daemon's real readiness notification. Upgrade switches the
`improvement-code/current` release link; restarting the unit activates it.
The timer writes an online recovery set every five minutes.
`automonique-recovery.service` is started manually after a restore; it disables
external transports and refuses provider starts.

Before replacing an installed unit, verify the checked-in file with
`tools/verify_systemd_unit.sh`. To roll back,
restore the previous `current` link through the release activation procedure
and restart the unit.
