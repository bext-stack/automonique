# Historical capability labels

These names survive because archived plans, evidence, and a few diagnostic
tools refer to them. They are not development gates and do not decide whether
work may start, land, or be pushed.

### GATE-BASELINE

**State: historical/closed.** The old executable plan could reproduce and
check its graph.

### GATE-IDENTITY

**State: advisory/open.** Dedicated credentials, commit signing, and protected
branch separation are not configured. This limits claims about identity
separation, not repository work.

### GATE-SCRUB

**State: open.** Public development scanning is active, but the private
identifier rule bundle and an independent publication check are not available
in this repository. Do not claim a publication-grade private-data scrub from
the public scanner alone.

The predecessor identifier is allowed only in the sanctioned reference and
compatibility locations enforced by `plan/check.py --identifiers`. Private,
customer, third-party, credential, host, and personal values remain forbidden
from committed files.

### GATE-ORACLE

**State: open.** The clean-side oracle boundary exists but has not received the
external acceptance recorded by the old plan. This label applies only to
archive-differential work and private-archive fixture capture; it does not
apply to comparison of Automonique's own live traffic.

### GATE-HARNESS

**State: historical/open.** This froze expansion of the former self-hosting
harness. That harness is optional and this label has no effect on product work.

### GATE-LICENCE

**State: advisory/open.** Distribution readiness is evaluated when an artifact
is actually prepared for distribution. Follow `LICENSE-POLICY.md`; ordinary
development does not require an SBOM or release evidence bundle.
