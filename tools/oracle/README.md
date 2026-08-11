<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Parity-oracle boundary

`BOOT-004`, closing condition for [`GATE-ORACLE`](../../plan/gates.md#gate-oracle).

[`PROVENANCE.md`](../../PROVENANCE.md) permits a parity oracle to run privately
against the prior implementation provided it "must expose only bounded behavior
results and must not emit source, private data, credentials, proprietary
identifiers, or implementation text." This directory is that enforcement.

## The two sides and their owners

| | Custody side | Clean side |
|---|---|---|
| Holds | the prior implementation's source, its data, its credentials | the specification, this repository, implementing agents |
| Runs | `runner.py` and one custody plugin, on the custody host | `channel.py`, `release.py`, `scan.py` |
| Owner | the **repository owner**, as custodian of the private archive | the **primary session** and the implementer role it dispatches |
| Trust | none. Assumed hostile | receives `Verdict` values and nothing else |

No agent role holds the custody side. `PROVENANCE.md` keeps the prior
repositories as private read-only archives, and nothing in this repository —
including this directory — is authorized to read them. The custody side exists
here only as the far end of a pipe.

**The trust transition is one function: `release.parse`.** Everything upstream
of it is untrusted, including `runner.py`, which this repository ships and which
still runs in the contaminated process. Nothing downstream of it has ever held a
byte the custody side produced.

Changing `release.py`, `scan.py`, `vocabulary.py` or `fields.json` changes a
security boundary. [`GOVERNANCE.md`](../../GOVERNANCE.md) § Protected policy
changes reserves that class of change to an external exact-revision decision; a
candidate cannot widen this vocabulary and use the widened one to certify
itself.

## The mechanism

The obvious design filters the oracle's output. That design fails the way
[`plan/contracts/BOOT-004.md`](../../plan/contracts/BOOT-004.md) predicts: it
protects the paths somebody enumerated, and a traceback, a diff quote or a debug
print arrives on a path nobody enumerated.

This design removes the paths instead.

**The wire carries selectors, not content.** A record names an outcome, a field,
a relation and a magnitude. Every one of those names is looked up in a table on
the clean side, and the *table's own string object* is what goes into the
verdict. A record that selects nothing valid produces a `Refusal`, itself a
member of a closed set, carrying no offending bytes, no length, and no exception
message. There is no free-text field anywhere in the shape, so there is no slot
a source line, a path, a credential or an identifier could occupy.
[`vocabulary.md`](vocabulary.md) is the generated list of every value that can
ever cross.

**The custody process has three descriptors and two of them go nowhere.**
`channel.py` starts it with `stdin`, `stdout` and `stderr` on the null device
and `pass_fds` naming the release pipe alone, so it inherits no other descriptor
of this process — no terminal, no log file, no socket. A `print`, a warning, an
uncaught traceback or an interpreter crash message is discarded by the operating
system before any code of ours could log it. `runner.py` also `dup2`s the null
device over descriptors 1 and 2 before it imports the plugin, which is defence
in depth rather than the control.

**Nothing raises.** `release.parse` returns a `Verdict` for every input,
including malformed, hostile and absent ones. An exception would carry a message
and a traceback, which is precisely the payload that must not cross. The
trust-transition modules are audited by
[`test_boundary.py`](test_boundary.py) for three properties: no `logging`
import, no `print`, and no `except ... as name` — an unbound handler cannot
interpolate what it caught.

**No debug mode.** There is no verbosity switch, no raw-output flag and no
environment variable that changes what is released. `test_boundary.py` runs the
full attack set with six debug-shaped variables set and asserts the verdicts are
identical.

**Fail closed.** A custody process that exits non-zero, is killed, or is still
running at the deadline releases `refused`/`timeout`, whatever it managed to
write first.

**The environment is an allow list of names.** The clean side's environment is
not forwarded. A name that looks like a credential
(`SECRET`, `TOKEN`, `PASSWORD`, `CREDENTIAL`, `PRIVATE`, `SESSION`, `COOKIE`)
cannot be added to the list at all: `Custody` refuses to construct. Custody
credentials are the custody host's to supply, by its own means, to its own
plugin.

## Running it

```sh
python3 -m unittest discover -s tools/oracle -p 'test_*.py'   # the attack suite
python3 tools/oracle/check_boundary.py                        # drift, write nothing
python3 tools/oracle/check_boundary.py --write                # regenerate vocabulary.md
```

`check_boundary.py` is standalone and importable, with its own `main()`
returning an exit code. Wiring it into `plan/check.py` is a follow-up for the
integrator; it is not wired there yet, because several work items share that
file.

## What this does not contain

The boundary owns the release channel. It does not sandbox the custody process,
and two channels around it are measured rather than assumed:

| Residual | Measured by | Control |
|---|---|---|
| The custody process can write files. | `FilesystemChannelTests` — the attack succeeds. | Deployment: the custody process runs as an account with no writable path any agent can read, and no network path to one. This is a requirement on the custody host, not a property of this code. |
| Wall-clock time is observable by the caller. | `TimingChannelTests` — the attack succeeds with `hold_release=False` and fails with it on. | `ChannelConfig.hold_release` defaults to on: the channel returns at the deadline whatever happened, at a cost of one deadline per comparison. |
| A hostile custody process can still choose *which* verdict it sends. | `check_boundary.py` prints the bound. | Capacity is finite and stated: about 38.7 bits per comparison under `field_relations`, about 4.95 under `outcome_only`. Shrink the registry or use `outcome_only` for a run that only asks "did it match". |

Stating a residual channel's capacity is the point. "The output is sanitized" is
not a measurement; "a fully hostile custody process can signal at most 38.7 bits
per comparison, and here is the arithmetic" is.

A note on freshness, found while attacking this: importing the custody plugin
through the ordinary machinery served a **stale compiled copy** whose source had
already changed, because bytecode validity is (source mtime in whole seconds,
source size). An oracle answering from last week's compiled legacy code is wrong
in the one way a parity oracle must never be wrong, and silently. `runner.py`
compiles the entry point from source bytes and the channel runs the interpreter
with `-B`. The guarantee covers the entry point; whatever the plugin imports in
turn uses the ordinary machinery.

## Out of scope

Capturing any fixture. That is `R0-02` and `R0-07`, and this boundary is one of
several conditions they wait on — see
[`plan/gates.md`](../../plan/gates.md#gate-oracle) for what else they need.
Comparison fidelity is a separate objective from containment: this directory
decides what may be said about a comparison, never whether the comparison was
right.
