# Development guidelines

Work directly from the requested outcome, the current code, and the relevant
product requirements. Inspect before editing, preserve unrelated changes, and
run checks appropriate to the change. Ordinary commits and non-force pushes
are allowed when requested.

Keep progress updates and handoffs concise: state the outcome, material risks,
and checks that actually ran. Do not generate evidence packets, approval
records, role reports, or workflow narration for ordinary development.

No claim, packet, lease, ready ID, contract, evidence record, gate, review
stage, or plan update is required to start or finish repository work.

## Guardrails

- This is a clean-room repository. Do not access prior implementation source,
  tests, build files, configuration, or Git history. Allowed inputs are this
  repository, owner-authorized structural references, provenance-bound
  black-box fixtures, and compatible public standards and dependencies. Ask if
  an input may cross that boundary.
- Never commit secrets, private or customer data, logs, sessions, real
  infrastructure identifiers, personal email addresses, or absolute home
  paths.
- Do not deploy, publish, change production, enable a live provider or
  transport, rotate credentials, or administer the repository without the
  owner's explicit authority for that operation.
- Preserve useful tests. Regenerate generated files from their source, and do
  not weaken or suppress checks just to make a change pass.
- Do not build a shell command from model-produced data; use typed APIs or
  explicit argument vectors.
- Do not discard work, rewrite history, force-push, delete refs, or change
  remotes without explicit authority. Stop on conflicts or a non-fast-forward
  push rather than forcing through them.

## Licensing and commits

Product code is `Elastic-2.0`; `sdk/` is the only `Apache-2.0` root. Moving code
across that boundary needs owner review before distribution. Distribution work
also follows `LICENSE-POLICY.md`.

Codex commits use `Automonique Candidate <candidate@automonique.invalid>`.
Human commits use the human author's configured identity. Do not add assistant
attribution or co-author trailers.
