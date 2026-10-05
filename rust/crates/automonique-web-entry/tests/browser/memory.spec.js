// SPDX-License-Identifier: Elastic-2.0
import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";

const asset = (name) => readFile(new URL(`../../assets/${name}`, import.meta.url), "utf8");
const now = Date.now();
const record = (id, status, extra = {}) => ({
  reference: `M-${id}`, content: `Memory ${id} content`, kind: "procedure", status,
  confidence: 900, sensitivity: "internal", visibility: "private", provenance: "dashboard",
  review_at_ms: null, expires_at_ms: null, superseded_by: null,
  updated_at_ms: now - id * 1000, revision: 1, editable: ["active", "candidate"].includes(status), ...extra,
});

let entries;
let actions;
test.beforeEach(async ({ page }) => {
  entries = [record(1, "active", { review_at_ms: now - 1000 }), record(2, "candidate"), record(3, "deleted"), record(4, "active", { editable: false, visibility: "team" })];
  actions = [];
  const files = Object.fromEntries(await Promise.all(["dashboard.html", "dashboard.css", "dashboard.js", "platform-cockpit-core.js"].map(async (name) => [name, await asset(name)])));
  await page.route("**/*", async (route) => {
    const { pathname } = new URL(route.request().url());
    if (pathname === "/") return route.fulfill({ contentType: "text/html", body: files["dashboard.html"] });
    if (pathname.startsWith("/assets/")) return route.fulfill({ contentType: pathname.endsWith(".css") ? "text/css" : "text/javascript", body: files[pathname.split("/").pop()] || "" });
    if (pathname === "/api/memory" || pathname === "/api/memory/search") {
      const query = pathname.endsWith("/search") ? route.request().postDataJSON().query.toLowerCase() : "";
      return route.fulfill({ json: { entries: entries.filter((entry) => `${entry.content} ${entry.reference}`.toLowerCase().includes(query)), counts: { active: 2, candidates: 1, deleted: 1, superseded: 0, messages: 0 } } });
    }
    if (pathname === "/api/memory/action") {
      const action = route.request().postDataJSON();
      actions.push(action);
      let entry = entries.find((entry) => entry.reference === action.reference);
      if (["create", "edit"].includes(action.action)) {
        if (entry) { entry.status = "superseded"; entry.editable = false; }
        entry = record(5, "active", action);
        entry.reference = "M-5";
        entries.unshift(entry);
      } else {
        entry.status = action.action === "approve" ? "active" : "deleted";
        entry.editable = entry.status === "active";
        entry.revision += 1;
      }
      return route.fulfill({ json: entry });
    }
    return route.fulfill({ json: {} });
  });
  await page.goto("https://memory.test/#memory");
  await expect(page.locator("#memory-result-label")).toHaveText("4 memories");
});

test("filters all statuses, review dates, and resets search", async ({ page }) => {
  await page.locator("#memory-status").selectOption("candidate");
  await expect(page.locator("#memory-list [data-memory-reference]")).toHaveCount(1);
  await page.locator("#memory-reset").click();
  await page.locator("#memory-review").selectOption("due");
  await expect(page.locator("#memory-list [data-memory-reference]")).toHaveCount(1);
  await page.locator("#memory-reset").click();
  await page.locator("#memory-query").fill("M-3");
  await page.locator("#memory-search").getByRole("button", { name: "Search", exact: true }).click();
  await expect(page.locator("#memory-result-label")).toContainText("1 memory");
  await page.locator("#memory-reset").click();
  await expect(page.locator("#memory-result-label")).toHaveText("4 memories");
  await expect(page.locator("#memory-query")).toHaveValue("");
});

test("creates a private memory and edits it with the exact revision", async ({ page }) => {
  await page.locator("#memory-create").click();
  await expect(page.locator("#memory-editor")).toBeVisible();
  await expect(page.locator("#memory-edit-visibility")).toHaveValue("private");
  await page.locator("#memory-edit-content").fill("Prefer clear summaries");
  await page.locator("#memory-save").click();
  await expect(page.locator("#memory-editor")).not.toBeVisible();
  await expect(page.locator("#memory-inspector")).toContainText("Prefer clear summaries");
  expect(actions[0]).toMatchObject({ action: "create", visibility: "private", sensitivity: "personal", confidence: 1000 });
  await page.getByRole("button", { name: "Edit memory", exact: true }).click();
  await page.locator("#memory-edit-content").fill("Prefer short summaries");
  await page.locator("#memory-save").click();
  await expect(page.locator("#memory-editor")).not.toBeVisible();
  expect(actions[1]).toMatchObject({ action: "edit", reference: "M-5", revision: 1 });
});

test("approves proposals and requires confirmation before forgetting", async ({ page }) => {
  await page.locator('#memory-list [data-memory-reference="M-2"]').click();
  await page.getByRole("button", { name: "Approve", exact: true }).click();
  expect(actions).toHaveLength(0);
  await page.locator("#memory-confirm-submit").click();
  await expect(page.locator("#memory-confirm")).not.toBeVisible();
  expect(actions[0]).toMatchObject({ action: "approve", reference: "M-2", revision: 1 });
  await page.getByRole("button", { name: "Forget", exact: true }).click();
  await page.locator("#memory-confirm").getByRole("button", { name: "Cancel" }).click();
  expect(actions).toHaveLength(1);
  await page.getByRole("button", { name: "Forget", exact: true }).click();
  await page.locator("#memory-confirm-submit").click();
  await expect(page.locator("#memory-confirm")).not.toBeVisible();
  expect(actions[1]).toMatchObject({ action: "forget", reference: "M-2", revision: 2 });
  await expect(page.getByRole("button", { name: "Edit memory", exact: true })).toHaveCount(0);
});

test("retains the draft on conflict and keeps shared records read-only", async ({ page }) => {
  await page.locator('#memory-list [data-memory-reference="M-4"]').click();
  await expect(page.getByRole("button", { name: "Edit memory", exact: true })).toHaveCount(0);
  await page.locator('[data-drawer-close="memory-drawer"]').click();
  await page.locator('#memory-list [data-memory-reference="M-1"]').click();
  await page.getByRole("button", { name: "Edit memory", exact: true }).click();
  await page.locator("#memory-edit-content").fill("My unsaved correction");
  await page.route("**/api/memory/action", (route) => route.fulfill({ status: 409, json: { error: "memory_revision_stale" } }));
  await page.locator("#memory-save").click();
  await expect(page.locator("#memory-editor-error")).toContainText("changed elsewhere");
  await expect(page.locator("#memory-edit-content")).toHaveValue("My unsaved correction");
  await expect(page.locator("#memory-save")).toBeEnabled();
  await page.keyboard.press("Escape");
  await expect(page.locator("#memory-editor")).not.toBeVisible();
});

test("exports only filtered results and clears stale data after failed refresh", async ({ page }) => {
  await page.locator("#memory-status").selectOption("candidate");
  const downloadEvent = page.waitForEvent("download");
  await page.locator("#memory-export").click();
  const download = await downloadEvent;
  const exported = JSON.parse(await readFile(await download.path(), "utf8"));
  expect(exported.entries.map((entry) => entry.reference)).toEqual(["M-2"]);
  expect(exported.filters.status).toBe("candidate");
  await page.route("**/api/memory", (route) => route.fulfill({ status: 503, json: { error: "memory_unavailable" } }));
  await page.locator("#memory-refresh").click();
  await expect(page.locator("#memory-result-label")).toContainText("Memory unavailable");
  await expect(page.locator("#memory-export")).toBeDisabled();
  await expect(page.locator("#memory-list [data-memory-reference]")).toHaveCount(0);
});

test("renders untrusted content as text and keeps the editor within the viewport", async ({ page }) => {
  entries[0].content = '<img src=x onerror="window.memoryInjected=true">';
  await page.locator("#memory-refresh").click();
  await page.locator('#memory-list [data-memory-reference="M-1"]').click();
  await expect(page.locator("#memory-inspector img")).toHaveCount(0);
  expect(await page.evaluate(() => window.memoryInjected)).toBeUndefined();
  await page.getByRole("button", { name: "Edit memory", exact: true }).click();
  const box = await page.locator("#memory-editor").boundingBox();
  expect(box.x).toBeGreaterThanOrEqual(0);
  expect(box.x + box.width).toBeLessThanOrEqual(page.viewportSize().width);
  expect((await page.locator("#memory-edit-kind").boundingBox()).height).toBeGreaterThanOrEqual(40);
});

test("translates the memory editor into French", async ({ page }) => {
  await page.evaluate(() => localStorage.setItem("monique-language", "fr"));
  await page.reload();
  await expect(page.locator("#memory-create")).toHaveText("Ajouter un souvenir");
  await page.locator("#memory-create").click();
  await expect(page.locator("#memory-editor-title")).toHaveText("Ajouter un souvenir");
  await expect(page.locator("#memory-save")).toHaveText("Enregistrer le souvenir");
  await expect(page.locator("#memory-edit-content")).toHaveAttribute("placeholder", "Que doit retenir Monique ?");
  await page.keyboard.press("Escape");
  await page.locator('#memory-list [data-memory-reference="M-1"]').click();
  await page.getByRole("button", { name: "Modifier le souvenir", exact: true }).click();
  await expect(page.locator("#memory-editor-title")).toHaveText("Modifier M-1");
});
