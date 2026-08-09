# Models, media and execution backends

**Status:** accepted expansion architecture

## Model and provider catalog

Automonique maintains a normalized catalog for built-in Jcode, Claude, Codex and opencode plus direct/custom model providers. Provider plugins declare models, modalities, context/output limits, reasoning controls, tool/structured-output support, regions/data policy, pricing and auth methods.

Users may select models per profile, session, automation, delegated node and auxiliary task. Model aliases are versioned profile data. A mid-session switch is a new turn revision with visible cache/context consequences and cannot cross a sovereignty or provider-account boundary silently.

## Routing, fallback and credential pools

Routing policy can constrain/order providers by explicit list, region, data collection, required parameters, cost, latency, throughput, health and tenant contract. A route decision is durable and explainable.

Credential pools contain separately identified provider accounts/keys with owner, billing tenant, quota and data boundary. Rotation on rate limits/failure is allowed only inside a reviewed pool; it never crosses organizations or paid subscriptions implicitly. Usage and exhaustion are visible without secret values.

Fallback chains exist independently for primary turns and auxiliary titling, compression, memory review, image/vision, transcription/TTS and evaluation. A fallback must preserve requested tools, sandbox, residency and approval semantics. Session-bound providers do not migrate mid-session merely because another model is healthy.

## Mixture of agents and auxiliary models

Optional MoA presets call bounded reference models and one acting aggregator. Reference outputs are labelled untrusted advice, receive a minimized/redacted context, have no tools and cannot approve actions. Presets define fanout/cadence, reasoning budgets, privacy mode and failure tolerance. All calls count against tenant budgets and data-boundary disclosures.

Auxiliary tasks are first-class usage records with independent model policy and fallbacks. The UI warns when an auxiliary model sends data to a different provider/region.

## Media capabilities

Adapter families cover:

- vision and image/clipboard/file inputs;
- speech-to-text for voice messages and live input;
- text-to-speech with streaming and platform voice-message delivery;
- wake-word detection performed locally when possible;
- image generation/editing;
- video generation;
- OCR/document extraction and media conversion.

Backends may be local, organization-hosted or cloud. Each declares supported formats, content limits, model/version, cost, retention/data policy, credential and egress. Generated/derived media enters the artifact service with provenance. Messaging platforms receive format/size-specific derivatives while the original remains protected.

Voice mode never treats spoken confirmation as privileged approval unless strong platform identity and the exact action-review protocol explicitly permit it. Wake word only starts input capture; it grants no authority.

## Web, browser and computer use

Web search/extraction has pluggable providers and citation/provenance records. Browser automation supports local CDP/Playwright and reviewed remote providers. Sessions are isolated per tenant/run, downloads become quarantined artifacts and credentials are capability-injected rather than typed by the model when possible.

Computer use is a separate high-risk capability using accessibility trees, screenshots and an isolated driver. Every target display/session is explicit; capture/input events are audited; stale element references fail; native OS access is never inferred from browser permission. It requires an eligible sandbox or disposable remote desktop.

## LSP and development intelligence

A shared LSP manager may start language servers inside the attempt workspace and tool sandbox. Diagnostics, definitions and safe code actions become bounded tool results. The provider may also use its native LSP, but Automonique records which implementation produced evidence and avoids duplicate conflicting edits.

## Execution-provider SPI

The execution host protocol supports these independently graduated backends:

- local direct-process execution with cgroup support and optional systemd adapter;
- rootless OCI containers;
- SSH workers with attested host identity;
- Singularity/Apptainer for HPC and optional Slurm submission;
- disposable microVMs;
- Kubernetes Jobs where an operator already has a cluster policy;
- Modal, Daytona and Vercel Sandbox adapters;
- organization-defined remote executors through the TypeScript/Rust SPI.

Every backend implements workspace/artifact transfer, immutable spec, sandbox attestation, credentials, event cursor, approval pause, cancellation, cleanup and cost/resource accounting. Persistent remote environments have identity, snapshot and hibernation state; scale-to-zero/wake is distinct from a running process. No backend graduates merely because it can execute a shell command.

## Batch, evaluation and trajectories

Automonique can run a dataset of prompts/tasks with bounded concurrency, per-record model/tools/profile/workspace/image, resumable checkpoints and structured outputs. The trajectory format records public model/tool messages, normalized events, schema digests, artifacts, costs and outcomes while excluding hidden reasoning and secrets by default.

Provide deterministic merge/resume, quality filters, tool success statistics, evaluation assertions, redaction and export licenses. Trajectory compression is a derived dataset with source hashes and compressor provenance. Training-data export requires explicit consent/retention policy and synthetic/public fixtures by default; production customer sessions are never silently collected.

## Tool gateway and subscription proxy

An optional sovereign tool gateway fronts approved search, browser, image, video, TTS and other services behind Automonique identity, quotas and receipts. A local subscription/OAuth proxy is restricted as described in [Public agent protocols](public-agent-protocols.md); it cannot misrepresent provider entitlements or leak reusable upstream credentials.

## Exit gate

Routing and credential rotation never cross policy boundaries; media artifacts retain provenance and platform-safe delivery; browser/computer sessions are contained; remote executors pass the same lifecycle contract; and batch/trajectory exports are reproducible, consented and scrubbed.
