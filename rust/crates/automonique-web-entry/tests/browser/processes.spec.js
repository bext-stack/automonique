// SPDX-License-Identifier: Elastic-2.0
import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";

async function openProcesses(page, snapshot) {
  const files = Object.fromEntries(await Promise.all(["dashboard.html", "dashboard.css", "dashboard.js", "platform-cockpit-core.js"].map(async (name) => [name, await readFile(new URL(`../../assets/${name}`, import.meta.url), "utf8")])));
  await page.route("**/*", async (route) => {
    const { pathname } = new URL(route.request().url());
    if (pathname === "/") return route.fulfill({ contentType: "text/html", body: files["dashboard.html"] });
    if (pathname.startsWith("/assets/")) return route.fulfill({ contentType: pathname.endsWith(".css") ? "text/css" : "text/javascript", body: files[pathname.split("/").pop()] || "" });
    return route.fulfill({ json: pathname === "/api/processes" ? snapshot : {} });
  });
  await page.goto("https://processes.test/#operations");
  await page.locator('[data-process-id="fixture-job-0001"]').click();
}

function fixture(age = 0) {
  return { health: "ready", observed_at_ms: Date.now() - age,
    stats: { total: 1, running: 1, queued: 0, completed: 0, failed: 0 }, worker: null,
    jobs: [{ id: "fixture-job-0001", status: "running", provider: "jcode", runtime: "native",
      issue_url: "https://github.com/example/site/issues/1", assigned_to_worker: true, approved: true,
      created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T01:00:00Z", decision_count: 1,
      output: [{ at_ms: 1767229200000, kind: "tool_input", text: "Preparing the final report", truncated: false }] }] };
}

test("old snapshots never claim that an agent is currently running", async ({ page }) => {
  await openProcesses(page, fixture(2 * 60 * 60 * 1000));
  await expect(page.locator("#ops-drawer-kicker")).toHaveText("Agent run · Status unconfirmed");
  await expect(page.locator("#ops-drawer-body")).toContainText("Out-of-date snapshot");
  await expect(page.locator("#ops-drawer-body")).not.toContainText("An agent is working on this right now.");
  await expect(page.locator("#ops-drawer-body")).toContainText("Saved output · 1 events");
  await expect(page.locator("#process-running")).toHaveText("-");
  await expect(page.locator("#process-filter-active")).toHaveText("0");
});

test("a fresh completion updates an already open drawer and preserves the receipt", async ({ page }) => {
  const snapshot = fixture();
  await openProcesses(page, snapshot);
  await expect(page.locator("#ops-drawer-kicker")).toHaveText("Agent run · Running");
  snapshot.jobs[0].status = "done";
  snapshot.jobs[0].output.push({ at_ms: Date.now(), kind: "final", text: "Completed; see the GitHub report.", truncated: false });
  snapshot.stats.running = 0;
  snapshot.stats.completed = 1;
  // The drawer covers the toolbar on phones; refresh through the normal poller.
  await page.evaluate(() => loadProcesses());
  await expect(page.locator("#ops-drawer-kicker")).toHaveText("Agent run · Finished");
  await expect(page.locator("#ops-drawer-body")).toContainText("Saved output · 2 events");
  await expect(page.locator("#ops-drawer-body")).toContainText("Completed; see the GitHub report.");
  await expect(page.locator("#process-running")).toHaveText("0");
});

test("a failed refresh closes the old running drawer", async ({ page }) => {
  await openProcesses(page, fixture());
  await page.route("**/api/processes", (route) => route.fulfill({ status: 503, json: {} }));
  await page.evaluate(() => loadProcesses());
  await expect(page.locator("#ops-drawer")).not.toHaveClass(/is-open/);
  await expect(page.locator("#process-list [data-process-id]")).toHaveCount(0);
});

test("an older request cannot replace a newer completion", async ({ page }) => {
  const snapshot = fixture();
  await openProcesses(page, snapshot);
  let calls = 0;
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  await page.route("**/api/processes", async (route) => {
    if (++calls === 1) {
      await pending;
      return route.fulfill({ json: fixture() });
    }
    const completed = fixture();
    completed.jobs[0].status = "done";
    return route.fulfill({ json: completed });
  });
  await page.evaluate(() => { window.firstProcessRefresh = loadProcesses(); });
  await expect.poll(() => calls).toBe(1);
  await page.evaluate(() => loadProcesses());
  release();
  await page.evaluate(() => window.firstProcessRefresh);
  await expect(page.locator("#ops-drawer-kicker")).toHaveText("Agent run · Finished");
});
