// SPDX-License-Identifier: Elastic-2.0

import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const asset = (name) => readFile(`${root}assets/${name}`, "utf8");
const renderCorpus = JSON.parse(await readFile(
  `${root}../automonique-protocol/fixtures/platform-v2-render-conformance-v1.json`,
  "utf8",
));
const freshCockpitReview = structuredClone(renderCorpus.cases.find(({ id }) => id === "needs_you").input);
freshCockpitReview.checks[0].freshness.state = "fresh";

const cockpit = {
  schema: "automonique.dashboard.cockpit/v2",
  mode: "v2",
  degradation: null,
  retained_v1: {
    health: "operational",
    inventory: { state: "available" },
    sessions_cursor: { authority: "automonique", topic: "sessions", sequence: "4" },
    sessions: [
      {
        session: {
          resource: { authority: "automonique", kind: "session", id: "session-1" },
          summary: "Retained cockpit work",
          freshness: "fresh",
          revision: "4",
        },
        attachable: true,
        controllable: false,
        run: null,
      },
      {
        session: {
          resource: { authority: "automonique", kind: "session", id: "session-2" },
          summary: "Blocked workspace conversation",
          freshness: "fresh",
          revision: "8",
        },
        attachable: true,
        controllable: false,
        run: null,
      },
    ],
  },
  projects: [{ id: "project-1", label: "Automonique", revision: "1", lifecycle: "active" }],
  hosts: [{ id: "host-1", label: "Local host", revision: "1", lifecycle: "active", project_id: "project-1", kind: "local" }],
  workspaces: [
    { id: "workspace-1", label: "Cockpit", revision: "9007199254740995", lifecycle: "active", project_id: "project-1", host_id: "host-1", attempts: [{ id: "attempt-1", label: "Attempt 1", revision: "2", lifecycle: "running", sessions: [{ id: "runtime-session-1", label: "Session 1", revision: "3", lifecycle: "active", platform_session_id: "session-1", panes: [] }] }], attention: "needs_you" },
    { id: "workspace-2", label: "Blocked workspace", revision: "7", lifecycle: "active", project_id: "project-1", host_id: "host-1", attempts: [{ id: "attempt-2", label: "Attempt 2", revision: "2", lifecycle: "running", sessions: [{ id: "runtime-session-2", label: "Session 2", revision: "3", lifecycle: "active", platform_session_id: "session-2", panes: [] }] }], attention: "blocked" },
  ],
  selected: { workspace: "workspace-1" },
  lineage: { state: "available", document: { workspace: "workspace-1", external_work_items: [], orchestration: [] } },
  review: { state: "available", document: freshCockpitReview },
  attention: { state: "available", known_workspaces: "2", total_workspaces: "2" },
  inbox: {
    state: "complete", total: "1", omitted: "0", sources: { review: { state: "available" } },
    items: [{
      id: "attention-comment",
      state: "needs_you",
      reason: "comment_reply",
      origin_kind: "comment",
      source_revision: "9007199254741002",
      unread: "1",
      link: {
        workspace: "workspace-1",
        file: "file-text",
        hunk: "hunk-text",
        side: "new",
        line: "9007199254740995",
      },
    }],
  },
  activities: {
    state: "complete", total: "2", omitted: "0",
    sources: { lineage: { state: "available" }, review: { state: "available" } },
    items: [
      {
        id: "activity-review",
        at: "1800000000001",
        kind: "review",
        label: "Review pending",
        source: "review",
        freshness: "fresh",
        source_revision: "9007199254741003",
        link: { workspace: "workspace-1" },
      },
      {
        id: "activity-agent",
        at: "1800000000000",
        kind: "task",
        label: "Task working",
        source: "orchestration",
        freshness: "fresh",
        source_revision: "9007199254741002",
        link: { workspace: "workspace-1", session: "runtime-session-1" },
      },
    ],
  },
  actions: {
    lifecycle: { available: false, category: "platform_v2_lifecycle_adapter_pending" },
    review: { available: false, category: "platform_v2_review_adapter_pending" },
  },
};

test.beforeEach(async ({ page }) => {
  const [html, css, dashboard, core] = await Promise.all([
    asset("dashboard.html"), asset("dashboard.css"), asset("dashboard.js"), asset("platform-cockpit-core.js"),
  ]);
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/") return route.fulfill({ contentType: "text/html", body: html });
    if (url.pathname === "/assets/dashboard.css") return route.fulfill({ contentType: "text/css", body: css });
    if (url.pathname === "/assets/dashboard.js") return route.fulfill({ contentType: "text/javascript", body: dashboard });
    if (url.pathname === "/assets/platform-cockpit-core.js") return route.fulfill({ contentType: "text/javascript", body: core });
    if (url.pathname === "/assets/qrcode.js") return route.fulfill({ contentType: "text/javascript", body: "" });
    if (url.pathname === "/api/platform/cockpit") return route.fulfill({ contentType: "application/json", body: JSON.stringify(cockpit) });
    if (url.pathname === "/api/platform/session") {
      const request = route.request().postDataJSON();
      if (request.action === "open") {
        if (request.session_id === "session-2") await new Promise((resolve) => setTimeout(resolve, 250));
        const session = cockpit.retained_v1.sessions.find((item) => item.session.resource.id === request.session_id);
        return route.fulfill({
          contentType: "application/json",
          body: JSON.stringify({
            state: "open",
            session,
            history: { state: "page", terminal_cursor: "0", events: [], has_more: false },
            command: { state: "unavailable" },
            control: { state: "not_claimed", available: false },
          }),
        });
      }
      return route.fulfill({ contentType: "application/json", body: JSON.stringify({ state: "detached" }) });
    }
    return route.fulfill({ contentType: "application/json", body: "{}" });
  });
  await page.goto("https://cockpit.test/#sessions");
  await expect(page.getByRole("heading", { name: "Cockpit", exact: true })).toBeVisible();
});

test("workspace projection is accessible and lifecycle controls fail closed", async ({ page }) => {
  await expect(page.getByRole("listbox", { name: "Hosted workspaces" })).toBeVisible();
  await expect(page.getByRole("option", { name: /Cockpit/ })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("tablist", { name: "Selected workspace surfaces" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Create unavailable" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Resume unavailable" })).toBeDisabled();
  await expect(page.getByText(/platform_v2_lifecycle_adapter_pending/)).toBeVisible();
  await page.getByRole("tab", { name: "Files & review" }).focus();
  await page.keyboard.press("ArrowRight");
  await expect(page.getByRole("tab", { name: "Activity" })).toBeFocused();
});

test("shared corpus renders exact review semantics and lossless source revisions", async ({ page }) => {
  const previous = cockpit.review.document;
  cockpit.review.document = structuredClone(renderCorpus.cases.find(({ id }) => id === "needs_you").input);
  try {
    await page.reload();
    await expect(page.locator("#cockpit-files-state")).toContainText(
      "text · sanitized · source revision 9007199254741011",
    );
    await expect(page.locator("#cockpit-files-state")).toHaveAttribute("data-semantic-key", "preview.text.sanitized");
    await expect(page.locator("#cockpit-review-state")).toContainText(
      "needs you · review requested · pending · fresh · source revision 9007199254741003",
    );
    await expect(page.locator("#cockpit-review-state")).toContainText(
      "open · blocked · fresh · source revision 9007199254741005",
    );
    await expect(page.locator("#cockpit-checks-state")).toContainText(
      "failed · required · stale · source revision 9007199254741004",
    );
    await expect(page.locator("#cockpit-delivery-state")).toHaveText(
      "pending · fresh · source revision 9007199254741006",
    );
  } finally {
    cockpit.review.document = previous;
  }
});

test("installed local adapter is visible without enabling task or session actions", async ({ page }) => {
  const previous = cockpit.actions.lifecycle;
  cockpit.actions.lifecycle = {
    available: true,
    operations: {
      create_host_setup: { available: true, scope: "local", preview_operation: "prepare_mutation", receipt_operation: "get_mutation_receipt" },
      create_checkout: { available: true, scope: "local", preview_operation: "prepare_mutation", receipt_operation: "get_mutation_receipt" },
      create_attempt_workspace: { available: false, category: "platform_v2_lifecycle_adapter_pending" },
      resume_attempt_workspace: { available: false, category: "platform_v2_lifecycle_adapter_pending" },
      resume_session: { available: false, category: "platform_v2_lifecycle_adapter_pending" },
    },
  };
  try {
    await page.reload();
    await expect(page.locator("#cockpit-action-reason")).toHaveAttribute("data-local-lifecycle", "available");
    await expect(page.locator("#cockpit-action-reason")).toContainText("Local host setup and checkout support typed preview and receipt operations");
    await expect(page.getByRole("button", { name: "Create unavailable" })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Resume unavailable" })).toBeDisabled();
  } finally {
    cockpit.actions.lifecycle = previous;
  }
});

test("missing local selectors render their exact action-specific categories", async ({ page }) => {
  const previous = cockpit.actions.lifecycle;
  cockpit.actions.lifecycle = {
    available: false,
    operations: {
      create_host_setup: { available: false, category: "platform_v2_local_host_selector_unavailable" },
      create_checkout: { available: false, category: "platform_v2_local_checkout_selector_unavailable" },
      create_attempt_workspace: { available: false, category: "platform_v2_lifecycle_adapter_pending" },
      resume_attempt_workspace: { available: false, category: "platform_v2_lifecycle_adapter_pending" },
      resume_session: { available: false, category: "platform_v2_lifecycle_adapter_pending" },
    },
  };
  try {
    await page.reload();
    const reason = page.locator("#cockpit-action-reason");
    await expect(reason).toHaveAttribute("data-local-lifecycle", "unavailable");
    await expect(reason).toContainText("Local host setup unavailable (platform_v2_local_host_selector_unavailable)");
    await expect(reason).toContainText("Local checkout unavailable (platform_v2_local_checkout_selector_unavailable)");
    await expect(reason).not.toContainText("adapter is not installed");
  } finally {
    cockpit.actions.lifecycle = previous;
  }
});

test("partial local lifecycle renders the exact fenced registry category", async ({ page }) => {
  const previous = cockpit.actions.lifecycle;
  cockpit.actions.lifecycle = {
    available: true,
    operations: {
      create_host_setup: { available: true, scope: "local", preview_operation: "prepare_mutation", receipt_operation: "get_mutation_receipt" },
      create_checkout: { available: false, category: "platform_v2_lifecycle_registry_changed" },
      create_attempt_workspace: { available: false, category: "platform_v2_lifecycle_adapter_pending" },
      resume_attempt_workspace: { available: false, category: "platform_v2_lifecycle_adapter_pending" },
      resume_session: { available: false, category: "platform_v2_lifecycle_adapter_pending" },
    },
  };
  try {
    await page.reload();
    const reason = page.locator("#cockpit-action-reason");
    await expect(reason).toHaveAttribute("data-local-lifecycle", "partial");
    await expect(reason).toContainText("Local host setup supports typed preview and receipt operations");
    await expect(reason).toContainText("Local checkout unavailable (platform_v2_lifecycle_registry_changed)");
    await expect(reason).not.toContainText("platform_v2_lifecycle_adapter_pending");
  } finally {
    cockpit.actions.lifecycle = previous;
  }
});

test("workspace-first layout does not overflow the active viewport", async ({ page }) => {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
  expect(overflow).toBe(false);
  await expect(page.locator("#cockpit-workspace-navigation")).toBeVisible();
  await expect(page.locator("#cockpit-workspace-summary")).toBeVisible();
  await expect(page.locator("#cockpit-workspace-inspector")).toBeVisible();
});

test("attention inbox and chronological activity are accessible at desktop and mobile widths", async ({ page }) => {
  await page.getByRole("tab", { name: "Activity" }).click();
  const inbox = page.getByRole("list", { name: "Structured workspace attention inbox" });
  const activity = page.getByRole("list", { name: "Chronological workspace activity" });
  await expect(inbox).toBeVisible();
  await expect(activity).toBeVisible();
  await expect(inbox.getByText("Needs You · comment reply")).toBeVisible();
  const reviewLink = inbox.getByRole("link", { name: /Open exact review context for comment reply/ });
  await expect(reviewLink).toHaveAttribute(
    "href",
    "#sessions?workspace=workspace-1&file=file-text&hunk=hunk-text&side=new&line=9007199254740995",
  );
  await expect(activity.locator("li").first()).toContainText("Review pending");
  await expect(activity.locator("li").nth(1)).toContainText("Task working");
  await expect(activity.getByRole("link", { name: /Open exact context for Task working/ })).toHaveAttribute(
    "href",
    "#sessions?workspace=workspace-1&session=runtime-session-1",
  );
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
  expect(overflow).toBe(false);
});

test("partial and truncated collection coverage is never rendered as known empty", async ({ page }) => {
  await page.getByRole("tab", { name: "Activity" }).click();
  await page.evaluate((view) => globalThis.renderPlatform(view), {
    ...cockpit,
    inbox: {
      state: "unavailable", items: [], total: "0", omitted: "0",
      sources: { review: { state: "refused", category: "review_authority_refused" } },
    },
    activities: {
      state: "partial",
      items: [cockpit.activities.items[0]],
      total: "4",
      omitted: "3",
      sources: {
        lineage: { state: "available" },
        review: { state: "refused", category: "review_authority_refused" },
      },
    },
  });
  await expect(page.locator("#cockpit-inbox-list")).toContainText("Structured projection unavailable");
  await expect(page.locator("#cockpit-inbox-list")).toContainText("review_authority_refused");
  await expect(page.locator("#cockpit-inbox-list")).not.toContainText("has no authoritative attention events");
  await expect(page.locator("#cockpit-activity-list")).toContainText("Structured projection is partial");
  await expect(page.locator("#cockpit-activity-list")).toContainText("3 of 4 newest-ordered records omitted");
  await expect(page.locator("#cockpit-activity-list")).toContainText("review_authority_refused");
});

test("attention filtering preserves structured workspaces and retained sessions", async ({ page }) => {
  await expect(page.locator("#cockpit-needs-you-count")).toHaveText("1");
  await expect(page.locator("#cockpit-blocked-count")).toHaveText("1");
  await expect(page.locator(".platform-session-option").filter({ hasText: "Retained cockpit work" })).toBeVisible();

  await page.locator('[data-cockpit-attention="needs_you"]').click();
  await expect(page.getByRole("option", { name: /Cockpit/ })).toBeVisible();
  await expect(page.getByRole("option", { name: /Blocked workspace/ })).toHaveCount(0);
  await expect(page.locator(".platform-session-option").filter({ hasText: "Retained cockpit work" })).toBeVisible();
  await expect(page.locator("#cockpit-capability-state")).toHaveAttribute("data-mode", "v2");

  await page.locator('[data-cockpit-attention="blocked"]').click();
  await expect(page.getByRole("option", { name: /Blocked workspace/ })).toBeVisible();
  await expect(page.getByRole("option", { name: /Cockpit/ })).toHaveCount(0);
  await expect(page.locator(".platform-session-option").filter({ hasText: "Retained cockpit work" })).toBeVisible();
});

test("retained session selection and detach never discard the cockpit snapshot", async ({ page }) => {
  await page.locator(".platform-session-option").filter({ hasText: "Retained cockpit work" }).click();
  await expect(page.locator(".platform-session-option").filter({ hasText: "Retained cockpit work" })).toBeVisible();
  await expect(page.getByRole("option", { name: /Cockpit/ })).toBeVisible();
  await expect(page.locator("#cockpit-capability-state")).toHaveAttribute("data-mode", "v2");

  await page.locator("#platform-session-detach").click();
  await expect(page.locator(".platform-session-option").filter({ hasText: "Retained cockpit work" })).toBeVisible();
  await expect(page.getByRole("option", { name: /Cockpit/ })).toBeVisible();
  await expect(page.locator("#cockpit-capability-state")).toHaveAttribute("data-mode", "v2");
});

test("partial lineage and review refusals disable attention filtering without inference", async ({ page }) => {
  const partial = {
    ...cockpit,
    lineage: { state: "refused", category: "lineage_authority_refused", explanation: "Fixture refusal" },
    review: { state: "refused", category: "review_authority_refused", explanation: "Fixture refusal" },
    attention: { state: "partial", category: "platform_v2_attention_partial", known_workspaces: "1", total_workspaces: "2" },
  };
  await page.evaluate((view) => globalThis.renderPlatform(view), partial);
  await expect(page.locator("#cockpit-capability-state")).toHaveAttribute("data-mode", "partial");
  await expect(page.locator("#cockpit-capability-state")).toContainText("lineage_authority_refused");
  await expect(page.locator("#cockpit-capability-state")).toContainText("review_authority_refused");
  await expect(page.locator('[data-cockpit-attention="needs_you"]')).toBeDisabled();
  await expect(page.locator('[data-cockpit-attention="blocked"]')).toBeDisabled();
  await expect(page.locator("#cockpit-needs-you-count")).toHaveText("—");
  await expect(page.getByRole("option", { name: /Cockpit/ })).toBeVisible();
  await expect(page.getByRole("option", { name: /Blocked workspace/ })).toBeVisible();
  await expect(page.locator(".platform-session-option").filter({ hasText: "Retained cockpit work" })).toBeVisible();
});

test("cross-workspace retained session selection updates URL and cockpit before attach settles", async ({ page }) => {
  await page.goto("https://cockpit.test/#sessions?workspace=workspace-1&session=session-1&file=file-1&hunk=hunk-1&side=new&line=1");
  await expect(page.getByRole("heading", { name: "Cockpit", exact: true })).toBeVisible();

  await page.locator(".platform-session-option").filter({ hasText: "Blocked workspace conversation" }).click();
  await expect(page.locator("#platform-session-status")).toHaveText("Attaching as observer…");
  await expect(page).toHaveURL("https://cockpit.test/#sessions?workspace=workspace-2&session=session-2");
  await expect(page.getByRole("option", { name: /Blocked workspace/ })).toHaveAttribute("aria-selected", "true");
  await expect(page.locator("#cockpit-workspace-title")).toHaveText("Blocked workspace");
  await expect(page.locator("#cockpit-inspector-workspace")).toHaveText("workspace-2");
  await expect(page.locator("#cockpit-inspector-session")).toHaveText("session-2");
  await expect(page.locator("#cockpit-inspector-anchor")).toHaveText("—");
  await expect(page.locator("#cockpit-conversation")).toBeVisible();

  await expect(page.locator("#platform-session-coordinate")).toContainText("session-2");
});

test("create confirmation shows exact selectors before any mutation can be sent", async ({ page }) => {
  const previous = cockpit.actions.lifecycle;
  cockpit.actions.lifecycle = {
    available: true,
    operations: {
      create_attempt_workspace: {
        available: true,
        submit_operation: "submit_workspace_intent",
        receipt_operation: "get_workspace_intent",
        project_id: "project-1",
        workspace_id: "workspace-1",
        exact_revision: "9007199254740995",
        task_id: "task-1",
        external_work: { provider: "github", authority: "github.com", scope: "bext-stack/automonique", key: "170" },
      },
      resume_attempt_workspace: { available: false, category: "platform_v2_lifecycle_adapter_pending" },
    },
  };
  const requests = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname !== "/api/platform/cockpit") return;
    requests.push(request.postDataJSON());
  });
  try {
    await page.reload();
    await page.locator("#cockpit-create-preview").click();
    await expect(page.locator("#cockpit-action-preview")).toBeHidden();
    await page.locator("#cockpit-base-selector").fill("base-main");
    await page.locator("#cockpit-branch-selector").fill("branch-task-170");
    await page.locator("#cockpit-create-preview").click();
    await expect(page.locator("#cockpit-action-preview")).toContainText("Bound task task-1");
    await expect(page.locator("#cockpit-action-preview")).toContainText(
      "Exact base base-main · exact branch branch-task-170",
    );
    await expect(page.locator("#cockpit-action-preview")).toContainText(
      "External work github · github.com · bext-stack/automonique · 170",
    );
    expect(requests.map(({ action }) => action)).not.toContain("submit_workspace_create");

    await page.locator("#cockpit-base-selector").fill("unreviewed-base");
    await page.locator("#cockpit-branch-selector").fill("unreviewed-branch");
    cockpit.actions.lifecycle.operations.create_attempt_workspace = {
      ...cockpit.actions.lifecycle.operations.create_attempt_workspace,
      available: false,
      category: "platform_v2_lineage_stale",
    };
    await page.evaluate((view) => globalThis.renderPlatform(view), cockpit);
    await page.getByRole("button", { name: "Confirm create" }).click();
    expect(requests.map(({ action }) => action)).not.toContain("submit_workspace_create");
    expect(await page.evaluate(() => localStorage.getItem("automonique-cockpit-control-v1"))).toBeNull();

    cockpit.actions.lifecycle.operations.create_attempt_workspace = {
      ...cockpit.actions.lifecycle.operations.create_attempt_workspace,
      available: true,
      category: null,
      project_id: "project-drifted",
      workspace_id: "workspace-drifted",
      exact_revision: "9007199254740996",
      task_id: "task-drifted",
      external_work: { provider: "gitlab", authority: "gitlab.example", scope: "other/repository", key: "999" },
    };
    await page.evaluate((view) => globalThis.renderPlatform(view), cockpit);
    const submitted = page.waitForRequest((request) =>
      new URL(request.url()).pathname === "/api/platform/cockpit"
        && request.postDataJSON()?.action === "submit_workspace_create",
    );
    await page.getByRole("button", { name: "Confirm create" }).click();
    await submitted;
    expect(requests.find(({ action }) => action === "submit_workspace_create")).toMatchObject({
      project_id: "project-1",
      workspace_id: "workspace-1",
      expected_revision: "9007199254740995",
      task_id: "task-1",
      external_work: { provider: "github", authority: "github.com", scope: "bext-stack/automonique", key: "170" },
      base_selector: "base-main",
      branch_selector: "branch-task-170",
    });
  } finally {
    cockpit.actions.lifecycle = previous;
  }
});

test("an ambiguous durable handle reloads through lookup only and never replays submit", async ({ page }) => {
  const actions = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname !== "/api/platform/cockpit") return;
    try {
      actions.push(request.postDataJSON()?.action);
    } catch (_error) {
      // Only JSON cockpit requests are relevant to this assertion.
    }
  });
  await page.evaluate(() => localStorage.setItem("automonique-cockpit-control-v1", JSON.stringify({
    version: 1,
    family: "workspace_intent",
    action: "resume",
    project_id: "project-1",
    workspace_id: "workspace-1",
    receipt_id: "intent-ambiguous-reload",
  })));
  await page.reload();
  await expect(page.locator("#cockpit-action-receipt")).toContainText(/ambiguous/i);
  expect(actions).toContain("get_workspace_intent");
  expect(actions).not.toContain("submit_workspace_create");
  expect(actions).not.toContain("submit_workspace_resume");
});
