# Contributing

Automonique is not yet accepting external code contributions.
Issues, behavioral reports, and design proposals may be accepted once public
intake and privacy terms are established.

Before external code contributions open, the project must publish a contributor
agreement that gives Favre Benjamin sufficient rights to distribute
contributions under the repository licence boundary and under separate
commercial terms. A DCO sign-off alone is not the planned relicensing basis.

Commits use the truthful identity of their author and carry no assistant
attribution or co-author trailer. Codex-authored commits use
`Automonique Candidate <candidate@automonique.invalid>`; human-authored commits
use the human's configured identity. The identity register and checker are an
audit tool, and the `identity` workflow runs them on every push and pull
request — it refuses a commit whose author or committer the register does not
list, and a commit carrying an attribution trailer.
Dedicated workload identities may still be configured for unattended release
or deployment automation.

No contribution may include credentials, personal or customer data, private
provider transcripts, real infrastructure identifiers, absolute home paths, or
material without a verified right to use and distribute it.

## Change checklist

- A pull request that adds or enables an external surface — a network call, a
  connector, a command that reaches a third-party API, or a configuration file
  that turns one of those on — updates the "Repository status" section of
  [`README.md`](README.md) in the same pull request, and moves its
  reconciliation stamp to the reviewed commit. A reader making a risk decision
  from that section must not be reading a description of an older system.
