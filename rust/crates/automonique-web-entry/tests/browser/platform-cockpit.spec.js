// SPDX-License-Identifier: Elastic-2.0

import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const asset = (name) => readFile(`${root}assets/${name}`, "utf8");

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
    { id: "workspace-1", label: "Cockpit", revision: "9007199254740995", lifecycle: "active", project_id: "project-1", host_id: "host-1", session_id: "session-1", attention: "needs_you" },
    { id: "workspace-2", label: "Blocked workspace", revision: "7", lifecycle: "active", project_id: "project-1", host_id: "host-1", session_id: "session-2", attention: "blocked" },
  ],
  selected: { workspace: "workspace-1" },
  lineage: { state: "available", document: { workspace: "workspace-1", external_work_items: [], orchestration: [] } },
  review: { state: "available", document: { files: [], checks: [], review: { freshness: { state: "fresh" } }, delivery: { freshness: { state: "fresh" } } } },
  attention: { state: "available", known_workspaces: "2", total_workspaces: "2" },
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

test("workspace-first layout does not overflow the active viewport", async ({ page }) => {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
  expect(overflow).toBe(false);
  await expect(page.locator("#cockpit-workspace-navigation")).toBeVisible();
  await expect(page.locator("#cockpit-workspace-summary")).toBeVisible();
  await expect(page.locator("#cockpit-workspace-inspector")).toBeVisible();
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
  await page.goto("https://cockpit.test/#sessions?workspace=workspace-1&session=session-1&file=file-1&hunk=hunk-1&side=head&line=1");
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
