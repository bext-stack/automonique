// SPDX-License-Identifier: Elastic-2.0
import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
const now = Date.now();
const account = (id, provider, extra = {}) => ({ id, provider, provider_name: provider === "codex" ? "Codex CLI" : "Claude Code", label: `${provider} personal`, status: "authenticated", worker_selected: id === "one", last_verified_at_ms: now, usage: { status: "available", checked_at_ms: now, windows: [{ name: provider, used_percent: 0, duration_minutes: 300, resets_at_ms: now + 3600000 }, { name: provider, used_percent: 87, duration_minutes: 10080, resets_at_ms: now + 86400000 }] }, ...extra });
let view, actions, reads, fail;
test.beforeEach(async ({ page }) => {
  actions = []; reads = 0; fail = false;
  view = { max_accounts: 64, providers: [{ id: "codex", available: true }, { id: "claude", available: true }], accounts: [account("one", "codex"), account("two", "claude", { status: "signed_out", usage: { status: "unavailable", reason: "sign_in_required", windows: [] } })], login_sessions: [] };
  const files = Object.fromEntries(await Promise.all(["dashboard.html", "dashboard.css", "dashboard.js", "platform-cockpit-core.js"].map(async (name) => [name, await readFile(new URL(`../../assets/${name}`, import.meta.url), "utf8")])));
  await page.route("**/*", async (route) => {
    const { pathname } = new URL(route.request().url());
    if (pathname === "/") return route.fulfill({ contentType: "text/html", body: files["dashboard.html"] });
    if (pathname.startsWith("/assets/")) return route.fulfill({ contentType: pathname.endsWith(".css") ? "text/css" : "text/javascript", body: files[pathname.split("/").pop()] || "" });
    if (pathname === "/api/configuration") return route.fulfill({ json: { agent_authentication: { status: "authenticated" }, manage: {}, providers: {}, connectors: {}, memory: {}, governance: {}, extensions: {} } });
    if (pathname === "/api/agent-accounts/action") {
      const action = route.request().postDataJSON(); actions.push(action);
      if (action.action === "rename") view.accounts.find((a) => a.id === action.account_id).label = action.label;
      if (action.action === "remove") view.accounts = view.accounts.filter((a) => a.id !== action.account_id);
      return route.fulfill({ json: view });
    }
    if (pathname === "/api/agent-accounts") { reads++; return fail ? route.fulfill({ status: 503, json: { error: "unavailable" } }) : route.fulfill({ json: view }); }
    return route.fulfill({ json: {} });
  });
  await page.goto("https://accounts.test/#configuration");
  await expect(page.locator(".agent-account-card")).toHaveCount(2);
});
test("shows zero, quota warnings and signed-out states without horizontal overflow", async ({ page }) => {
  const card = page.locator('[data-account-id="one"]');
  await expect(card.locator("progress").first()).toHaveAttribute("value", "0");
  await expect(card.locator('[data-level="warning"]')).toContainText("87% used");
  await expect(card).toContainText("Resets");
  await expect(page.locator('[data-account-id="two"] progress')).toHaveCount(0);
  await expect(page.locator('[data-account-id="two"]')).toContainText("Sign in to view subscription usage.");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
test("filters provider and name and gives an explicit empty result", async ({ page }) => {
  await page.locator("#agent-account-filter").selectOption("claude");
  await expect(page.locator(".agent-account-card:visible")).toHaveCount(1);
  await page.locator("#agent-account-search").fill("missing");
  await expect(page.locator("#agent-account-no-matches")).toBeVisible();
  await page.locator("#agent-account-search").fill("");
  await page.locator("#agent-account-filter").selectOption("connected");
  await expect(page.locator('[data-account-id="one"]')).toBeVisible();
  await expect(page.locator('[data-account-id="two"]')).toBeHidden();
});
test("renames safely and protects worker removal", async ({ page }) => {
  const card = page.locator('[data-account-id="one"]');
  await card.locator("summary").click();
  await expect(card.getByRole("button", { name: "Remove", exact: true })).toBeDisabled();
  await card.getByRole("button", { name: "Rename", exact: true }).click();
  await page.getByRole("dialog").getByRole("textbox").fill("<img src=x onerror=alert(1)>");
  await page.getByRole("dialog").getByRole("button", { name: "Save", exact: true }).click();
  await expect(card).toContainText("<img src=x onerror=alert(1)>");
  await expect(card.locator("img")).toHaveCount(0);
  expect(actions).toEqual([{ action: "rename", account_id: "one", label: "<img src=x onerror=alert(1)>" }]);
});
test("confirms removal and can cancel sign-in", async ({ page }) => {
  await page.locator('[data-add-agent-provider="codex"]').click();
  await page.getByRole("dialog").getByRole("button", { name: "Cancel", exact: true }).click();
  expect(actions).toHaveLength(0);
  const card = page.locator('[data-account-id="two"]');
  await card.locator("summary").click();
  await card.getByRole("button", { name: "Remove", exact: true }).click();
  expect(actions).toHaveLength(0);
  await page.getByRole("dialog").getByRole("button", { name: "Remove", exact: true }).click();
  await expect(card).toHaveCount(0);
  expect(actions[0]).toEqual({ action: "remove", account_id: "two", confirm: true });
});
test("preserves authorization codes and focus during polling", async ({ page }) => {
  view.login_sessions = [{ id: "login", provider: "claude", status: "awaiting_user", accepts_authorization_code: true }];
  await page.locator("#agent-accounts-refresh").click();
  const input = page.locator(".agent-authorization-input");
  await input.fill("private-authorization-code");
  const before = reads;
  await expect.poll(() => reads).toBeGreaterThan(before);
  await expect(input).toHaveValue("private-authorization-code");
  await expect(input).toBeFocused();
});
test("marks stale readings and reauthentication and preserves cards on failed refresh", async ({ page }) => {
  view.accounts[0].usage.status = "unavailable"; view.accounts[0].usage.reason = "sign_in_required";
  await page.locator("#agent-accounts-refresh").click();
  const card = page.locator('[data-account-id="one"]');
  await expect(card).toContainText("Previous reading");
  await expect(card).toContainText("Sign-in required");
  await expect(card.getByRole("button", { name: "Sign in", exact: true })).toBeEnabled();
  await expect(card.locator('[data-level="warning"]')).toHaveCount(0);
  fail = true;
  await page.locator("#agent-accounts-refresh").click();
  await expect(card).toBeVisible();
  await expect(page.locator("#agent-accounts-refresh")).toBeEnabled();
});
test("supports French management and mobile dialogs", async ({ page }) => {
  await page.locator("#configuration-language").selectOption("fr");
  await expect(page.locator("#agent-accounts-manager")).toContainText("Utilisation de l’abonnement");
  await page.locator('[data-add-agent-provider="claude"]').click();
  await expect(page.getByRole("dialog")).toContainText("Connecter un abonnement");
  expect(await page.getByRole("dialog").evaluate((node) => node.getBoundingClientRect().right <= innerWidth)).toBe(true);
});

test("clears completed sign-in panels and their authorization material", async ({ page }) => {
  view.login_sessions = [{ id: "login", provider: "codex", status: "awaiting_user", authorization_url: "https://auth.openai.com/codex/device", user_code: "TEST-CODE" }];
  await page.locator("#agent-accounts-refresh").click();
  await expect(page.locator(".agent-login-code")).toHaveText("TEST-CODE");
  view.login_sessions[0].status = "authenticated";
  await page.locator("#agent-accounts-refresh").click();
  await expect(page.locator(".agent-login-card")).toHaveCount(0);
  await expect(page.locator(".agent-login-code, .agent-login-link")).toHaveCount(0);
  await expect(page.locator(".agent-account-card")).toHaveCount(2);
});

test("failed sign-in can be dismissed without showing expired login controls", async ({ page }) => {
  view.login_sessions = [{ id: "failed-login", provider: "claude", status: "failed", authorization_url: "https://claude.ai/oauth/authorize", user_code: "EXPIRED-CODE", accepts_authorization_code: true }];
  await page.locator("#agent-accounts-refresh").click();
  await expect(page.locator(".agent-login-card")).toHaveCount(1);
  await expect(page.locator(".agent-login-code, .agent-login-link, .agent-authorization-input")).toHaveCount(0);
  await page.locator(".agent-login-card").getByRole("button", { name: "Dismiss", exact: true }).click();
  await page.locator("#agent-accounts-refresh").click();
  await expect(page.locator(".agent-login-card")).toHaveCount(0);
  expect(actions).toHaveLength(0);
});
