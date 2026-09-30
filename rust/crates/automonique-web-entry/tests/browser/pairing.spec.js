// SPDX-License-Identifier: Elastic-2.0
import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
const assets = new URL("../../assets/", import.meta.url);
let requests;
let offerText;
test.beforeEach(async ({ page }) => {
  requests = [];
  offerText = JSON.stringify({ exchange_endpoint: "https://pairing.test/api/mobile/pairings/exchange", expires_at_ms: Date.now() + 300000, origin: "https://pairing.test", pairing_id: "fixture-pairing", pairing_token: "fixture-single-use-token", schema: "automonique.mobile-auth/v1", server_identity: "fixture-server" });
  await page.addInitScript(() => { Object.defineProperty(navigator, "clipboard", { value: { writeText: async (text) => { window.copiedPairingText = text; } }, configurable: true }); });
  await page.route("**/*", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/") return route.fulfill({ contentType: "text/html", body: await readFile(new URL("dashboard.html", assets), "utf8") });
    if (path.startsWith("/assets/")) {
      const file = path.slice(8);
      if (["dashboard.css", "dashboard.js", "platform-cockpit-core.js", "qrcode.js"].includes(file)) return route.fulfill({ contentType: file.endsWith(".css") ? "text/css" : "text/javascript", body: await readFile(new URL(file === "qrcode.js" ? "../../../../third_party/qrcode/qrcode-core.js" : file, assets), "utf8") });
    }
    if (path === "/api/mobile/pairing-sessions") return route.fulfill({ json: { sessions: [] } });
    if (path === "/api/mobile/pairings") { requests.push(route.request().postDataJSON()); return route.fulfill({ status: 201, contentType: "application/vnd.automonique.mobile-auth.v1+json", body: offerText }); }
    return route.fulfill({ json: {} });
  });
  await page.goto("https://pairing.test/#sessions");
});
async function open(page) { await page.locator("#pairing-open").click(); await expect(page.getByRole("dialog")).toBeVisible(); }
test("pairing is obvious from Sessions, with no preselected grants and no horizontal overflow", async ({ page }) => {
  await expect(page.getByRole("button", { name: "Connect phone", exact: true })).toBeVisible();
  await open(page);
  await expect(page.getByRole("heading", { name: "Take Monique with you" })).toBeVisible();
  await expect(page.locator("#pairing-create")).toBeDisabled();
  expect(await page.locator(".pairing-options input:checked").count()).toBe(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(await page.locator("#pairing-panel").evaluate((node) => node.scrollWidth <= node.clientWidth)).toBe(true);
  await page.screenshot({ path: test.info().outputPath("pairing-choose-access.png") });
  await page.locator("#pairing-close").click();
  await expect(page.locator("#pairing-open")).toBeFocused();
});
test("Slack pairing needs no sessions, grants only the chosen access and copies exact offer bytes", async ({ page }) => {
  await open(page);
  await page.locator("#pairing-manage-work").check();
  await page.locator("#pairing-method-scan").click();
  await page.locator("#pairing-create").click();
  await expect(page.locator("#pairing-code svg")).toBeVisible();
  expect(requests).toEqual([{ actions: ["attach", "manage_work"], session_scope: [], limits: { max_follow_up_bytes: 65536, max_page_events: 100 } }]);
  await page.locator("#pairing-copy").click();
  expect(await page.evaluate(() => window.copiedPairingText)).toBe(offerText);
  expect(await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))).not.toContain("fixture-single-use-token");
  await page.screenshot({ path: test.info().outputPath("pairing-qr.png") });
  await page.locator("#pairing-close").click();
  await expect(page.locator("#pairing-code")).toBeEmpty();
  await expect(page.locator("#pairing-invite-text")).toHaveValue("");
});
test("new tasks and selected existing sessions have explicit scopes", async ({ page }) => {
  await page.route("**/api/mobile/pairing-sessions", (route) => route.fulfill({ json: { sessions: ["one", "two"].map((id) => ({ session: { resource: { id }, summary: `Session ${id}` } })) } }));
  await open(page);
  await page.locator("#pairing-existing").check();
  await expect(page.locator("#pairing-sessions input")).toHaveCount(2);
  await expect(page.locator("#pairing-create")).toBeDisabled();
  await page.getByRole("checkbox", { name: "Session two" }).check();
  await page.locator("#pairing-start-task").check();
  await page.locator("#pairing-create").click();
  await expect(page.locator("#pairing-result")).toBeVisible();
  expect(requests[0].session_scope).toEqual(["two"]);
  expect(requests[0].actions).toEqual(["attach", "follow_up", "decide_approval", "stop_run", "start_task"]);
  await page.locator("#pairing-manage-work").check();
  await expect(page.locator("#pairing-result")).toBeHidden();
});
test("unavailable sessions do not block independent Slack access", async ({ page }) => {
  await page.route("**/api/mobile/pairing-sessions", (route) => route.fulfill({ status: 503, json: { error: "unavailable" } }));
  await open(page);
  await page.locator("#pairing-existing").check();
  await expect(page.locator("#pairing-sessions-status")).toContainText("could not load");
  await page.locator("#pairing-manage-work").check();
  await expect(page.locator("#pairing-create")).toBeDisabled();
  await page.locator("#pairing-existing").uncheck();
  await expect(page.locator("#pairing-create")).toBeEnabled();
});
test("same-phone copy has a manual fallback and clears on expiry", async ({ page }) => {
  await page.clock.install();
  await page.evaluate(() => { navigator.clipboard.writeText = async () => { throw new Error("clipboard denied"); }; });
  await open(page);
  await page.locator("#pairing-manage-work").check();
  await page.locator("#pairing-method-copy").click();
  await page.locator("#pairing-create").click();
  await expect(page.locator("#pairing-copy-help")).toBeVisible();
  await expect(page.locator("#pairing-scan-help")).toBeHidden();
  await page.locator("#pairing-copy").click();
  await expect(page.locator("#pairing-invite-text")).toHaveValue(offerText);
  await page.clock.fastForward(301000);
  await expect(page.locator("#pairing-ready")).toHaveText("Invitation expired");
  await expect(page.locator("#pairing-code")).toBeEmpty();
  await expect(page.locator("#pairing-copy")).toBeHidden();
  await expect(page.locator("#pairing-invite-text")).toHaveValue("");
  await expect(page.locator("#pairing-create")).toBeEnabled();
});
test("closing a pending creation cannot resurrect a secret in a later dialog", async ({ page }) => {
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  let sent = false;
  await page.route("**/api/mobile/pairings", async (route) => { sent = true; await pending; await route.fulfill({ status: 201, body: offerText }); });
  await open(page);
  await page.locator("#pairing-manage-work").check();
  await page.locator("#pairing-create").click();
  await expect.poll(() => sent).toBe(true);
  await expect(page.locator("#pairing-create")).toBeDisabled();
  await page.locator("#pairing-close").click();
  await open(page);
  release();
  await page.waitForResponse("**/api/mobile/pairings");
  await expect(page.locator("#pairing-result")).toBeHidden();
  await expect(page.locator("#pairing-code")).toBeEmpty();
});
test("French pairing and keyboard focus stay usable", async ({ page }) => {
  await page.locator("#language-cycle").click();
  await expect(page.locator("#pairing-open")).toHaveText("Connecter un téléphone");
  await open(page);
  await expect(page.locator("#pairing-title")).toHaveText("Emportez Monique avec vous");
  await expect(page.locator("#pairing-access-title")).toHaveText("Choisissez les accès de votre téléphone");
  await page.locator("#pairing-close").focus();
  await page.keyboard.press("Shift+Tab");
  expect(await page.evaluate(() => document.activeElement.closest("#pairing-panel") !== null)).toBe(true);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toBeHidden();
  await expect(page.locator("#pairing-open")).toBeFocused();
});
test("QR failure falls back to copy and refused creation stays retryable", async ({ page }) => {
  await page.route("**/assets/qrcode.js*", (route) => route.fulfill({ contentType: "text/javascript", body: "window.moniqueQrCode = { create() { throw new Error('fixture encoder failure'); } };" }));
  await page.reload();
  await open(page);
  await page.locator("#pairing-manage-work").check();
  await page.locator("#pairing-method-scan").click();
  await page.locator("#pairing-create").click();
  await expect(page.locator("#pairing-copy-help")).toBeVisible();
  await expect(page.locator("#pairing-copy")).toBeVisible();
  await expect(page.locator("#pairing-status")).toContainText("QR encoder");
  await page.route("**/api/mobile/pairings", (route) => route.fulfill({ status: 403, json: { error: "refused" } }));
  await page.locator("#pairing-create").click();
  await expect(page.locator("#pairing-status")).toContainText("refused");
  await expect(page.locator("#pairing-result")).toBeHidden();
  await expect(page.locator("#pairing-create")).toBeEnabled();
});
