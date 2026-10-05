// SPDX-License-Identifier: Elastic-2.0
import { test, expect } from "@playwright/test";
import { readFile } from "node:fs/promises";

let actions, reply, failure, hold;
test.beforeEach(async ({ page }) => {
  actions = []; failure = false; hold = null;
  reply = { ok: true, reason: "bot_authenticated", checked_at_ms: 1791025200000, duration_ms: 42 };
  const files = Object.fromEntries(await Promise.all(["dashboard.html", "dashboard.css", "dashboard.js", "platform-cockpit-core.js"].map(async (name) => [name, await readFile(new URL(`../../assets/${name}`, import.meta.url), "utf8")])));
  await page.route("**/*", async (route) => {
    const { pathname } = new URL(route.request().url());
    if (pathname === "/") return route.fulfill({ contentType: "text/html", body: files["dashboard.html"] });
    if (pathname.startsWith("/assets/")) return route.fulfill({ contentType: pathname.endsWith(".css") ? "text/css" : "text/javascript", body: files[pathname.split("/").pop()] || "" });
    if (pathname === "/api/configuration") return route.fulfill({ json: { agent_authentication: { status: "authenticated" }, manage: {}, providers: {}, connectors: { slack: true, telegram: true, github: true, support: true, mcp: false }, memory: {}, governance: {}, extensions: {} } });
    if (pathname === "/api/connections/test") {
      expect(route.request().method()).toBe("POST");
      const action = route.request().postDataJSON(); actions.push(action);
      if (hold) await hold;
      if (failure) return route.fulfill({ status: 409, json: { error: "connection_test_busy" } });
      return route.fulfill({ json: { connector: action.connector, ...reply } });
    }
    return route.fulfill({ json: {} });
  });
  await page.goto("https://connections.test/#configuration");
  await expect(page.locator("[data-connection-test]")).toHaveCount(5);
});

test("tests only the selected connection and shows its checked time", async ({ page }) => {
  expect(actions).toEqual([]);
  for (const key of ["slack", "telegram", "github", "support", "mcp"]) {
    const row = page.locator(`[data-connection="${key}"]`);
    await row.getByRole("button").click();
    await expect(row.locator('[role="status"]')).toContainText("Bot authentication verified.");
    await expect(row.locator("time")).toHaveAttribute("datetime", "2026-10-03T11:00:00.000Z");
    await expect(row.getByRole("button")).toHaveText("Test again");
  }
  expect(actions).toEqual(["slack", "telegram", "github", "support", "mcp"].map((connector) => ({ connector })));
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test("prevents duplicate checks while a provider is slow", async ({ page }) => {
  let release;
  hold = new Promise((resolve) => { release = resolve; });
  const button = page.locator('[data-connection-test="slack"]');
  await button.click();
  await expect(button).toHaveText("Testing…");
  await expect(button).toHaveAttribute("aria-busy", "true");
  for (const other of await page.locator("[data-connection-test]").all()) await expect(other).toBeDisabled();
  await button.dispatchEvent("click");
  expect(actions).toHaveLength(1);
  release();
  await expect(button).toBeEnabled();
  await expect(button).not.toHaveAttribute("aria-busy");
});

test("reports partial MCP failures and recovers on retry", async ({ page }) => {
  reply = { ...reply, ok: false, reason: "discovery_failed", servers_passed: 1, servers_total: 2 };
  const row = page.locator('[data-connection="mcp"]');
  await row.getByRole("button").click();
  await expect(row.locator('[role="status"]')).toHaveAttribute("data-state", "error");
  await expect(row).toContainText("1/2 servers verified");
  reply = { ...reply, ok: true, reason: "tools_discovered", servers_passed: 2 };
  await row.getByRole("button").click();
  await expect(row.locator('[role="status"]')).toHaveAttribute("data-state", "success");
  await expect(row).toContainText("2/2 servers verified");
});

test("clears stale success when a new check cannot finish", async ({ page }) => {
  const row = page.locator('[data-connection="github"]');
  await row.getByRole("button").click();
  await expect(row.locator("time")).toBeVisible();
  failure = true;
  await row.getByRole("button").click();
  await expect(row.locator('[role="status"]')).toContainText("Another connection test is running.");
  await expect(row.locator("time")).toHaveCount(0);
  await expect(row.getByRole("button")).toBeEnabled();
});

test("renders French controls and safe unknown errors", async ({ page }) => {
  await page.evaluate(() => localStorage.setItem("monique-language", "fr"));
  await page.reload();
  reply = { ...reply, ok: false, reason: '<img src=x onerror="alert(1)">', checked_at_ms: 0 };
  const row = page.locator('[data-connection="slack"]');
  await row.getByRole("button", { name: "Tester Slack" }).click();
  await expect(row.locator('[role="status"]')).toHaveText("Le test n’a pas pu aboutir. Réessayez.");
  await expect(row.getByRole("button")).toHaveText("Retester");
  await expect(row.locator("img")).toHaveCount(0);
  await expect(row).not.toContainText("onerror");
});
