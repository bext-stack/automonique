# Client experience and surfaces

**Status:** accepted product architecture

## Shared interaction contract

CLI, TUI, dashboard, desktop, IDE and messaging clients share command IDs, context references, input queues, session state, revisions and action receipts. Presentation shortcuts never become new authority.

Common features include multiline composition, history/search, slash-command and context-reference autocomplete, model/profile/tool/skill selection, queued-input editing, retry/undo/stop/compress, attachment preview, streaming tool/output views, unread markers, native notifications and explicit offline/stale state.

## Rust CLI and TUI

The Ratatui client keeps the planned N-pane agent cockpit and adds:

- classic REPL/one-shot/quiet/structured-output modes;
- session browse/search/rename/archive/export/prune/statistics;
- command/context completion and generated shell completions;
- context usage breakdown and compression lineage;
- input queue editor, retry/undo/checkpoint controls;
- skills, memory, goals, automations, tools/MCP, profiles and connector management;
- dockable, sandboxed TUI widgets using a constrained declarative/WASI extension API;
- themes/skins with accessibility and light/dark/monochrome validation;
- voice input/output when the local media capability is enabled.

The TUI never loads arbitrary JavaScript in process. Widgets receive read-only subscribed projections and explicitly authorized actions through the SDK.

## Web dashboard

The SDK-only dashboard gains embedded chat, command center/Kanban, session search, skill catalog/learning review, memory graph, automation editor, webhook tester, MCP/tool manager, model/account routing, profiles, connectors, artifacts, sandbox evidence, goals, trajectory/evaluation views and extension management.

Remote authentication supports OIDC/Entra-compatible providers and scoped service credentials. A local/trusted-network basic mode may exist only with explicit warning. Public exposure requires TLS, CSRF/origin controls, rate limits and audited sessions.

## Native desktop

The native desktop client is ShellDeck (`github.com/benfavre/shelldeck`), an owner-controlled Rust/GPUI application maintained in its own MIT repository. It consumes the typed admin/SDK protocols through the same shared Rust client crate as the TUI, embeds no daemon policy, and must pass the same semantic conformance suite as every other surface before presenting itself as the Automonique desktop. The core production daemon remains Linux-first. Linux and macOS are the primary desktop targets; until a Windows build passes conformance, Windows users are served by the dashboard/PWA as a clearly weaker named profile, never an equivalent desktop claim.

Desktop capabilities include:

- streaming multi-tab/multi-window chat and cross-profile sessions;
- drag/drop/paste attachments, vision and artifact preview rail;
- file browser and named multi-folder projects;
- Git status/diffs by uncommitted/branch/last turn, stage/unstage, checkpoint restore, commit/push and PR proposal workflows;
- N-pane agents, persistent authorized shell terminals and add-selection-to-context;
- command palette, rebindable shortcuts, localization and accessibility;
- native notifications, quick entry, optional wake word and voice;
- provider/account, tools, skills, memory, goals, cron, connectors and profile setup;
- remote Automonique selection over OIDC/VPN with per-backend identity.

Desktop plugins follow the same constrained declarative/WASI widget model as the TUI: signed extensions may add namespaced routes, panes, status items, commands, keybinds, themes and read models. Backend functionality remains a separate sandboxed extension. Plugin storage, translations and events are namespaced; arbitrary UI-process, network or native access is not granted by default.

## Themes, widgets and mascot

One design-token/skin format themes CLI, TUI, web and desktop where representable. Imports from VS Code themes are sanitized and converted to Automonique tokens. Brand defaults remain accessible and deterministic.

Optional mascot/pet packs are presentation-only signed assets/animations with no tools, secrets or authority. Monique is the first-party mascot; third-party packs cannot impersonate approval/security state.

## Mobile and terminal portability

Provide responsive/PWA access first. Android Termux supports CLI/TUI and approved local providers where dependencies pass a platform matrix. Native iOS/Android clients are later SDK consumers, not embedded privileged agents. Windows/macOS local execution is an expansion adapter; unsupported sandbox controls produce a clearly weaker named profile or refusal, never a Linux-equivalent claim.

## Onboarding, update and migration

Ship setup wizards for product/profile, provider accounts, tools, sandbox capabilities, channels and remote access; `doctor` and separately authorized `doctor --fix`; signed update/rollback; component status/logs; uninstall modes that distinguish binaries from user data; and import preview/apply for legacy, OpenClaw and supported agent formats.

Imports cover persona, memories, skills, project rules, command policies, channel settings, provider descriptors and media assets. Secrets import only through allowlisted providers and never appear in reports. Every migration is dry-run capable and reversible before cutover.

## Exit gate

Every surface passes the same semantic conformance suite; queue/retry/checkpoint state survives reconnect; accessibility/terminal restoration work; remote clients cannot exceed server policy; desktop/UI extensions are isolated; and installers/updaters are signed, resumable and never overwrite user state silently.
