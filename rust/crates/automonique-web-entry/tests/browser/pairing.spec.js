// SPDX-License-Identifier: Elastic-2.0
import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { PNG } from "pngjs";
import jsQR from "jsqr";

const root = fileURLToPath(new URL("../../", import.meta.url));
let offer;
const sessions = [{ session: { resource: { id: "session-a" }, summary: "Release preparation" } }];

test.beforeEach(async ({ page }) => {
  offer = JSON.stringify({ exchange_endpoint: "https://cockpit.test/api/mobile/pairings/exchange", expires_at_ms: Date.now() + 300_000, origin: "https://cockpit.test", pairing_id: `pi_${"a".repeat(43)}`, pairing_token: `mp_${"b".repeat(43)}`, schema: "automonique.mobile-auth/v1", server_identity: `sha256:${"c".repeat(64)}` });
  await page.route("**/*", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/") return route.fulfill({ contentType: "text/html", body: await readFile(`${root}assets/dashboard.html`, "utf8") });
    if (path.startsWith("/assets/")) {
      const name = path.slice(8);
      const file = name === "qrcode.js" ? `${root}../../../third_party/qrcode/qrcode-core.js` : `${root}assets/${name}`;
      return route.fulfill({ contentType: name.endsWith("css") ? "text/css" : "text/javascript", body: await readFile(file, "utf8") });
    }
    if (path === "/api/mobile/pairing-sessions") return route.fulfill({ json: { sessions } });
    if (path === "/api/mobile/pairings") return route.fulfill({ contentType: "application/json", body: offer });
    return route.fulfill({ json: {} });
  });
  await page.goto("https://cockpit.test/#overview");
  await page.locator("#pairing-open").click();
  await expect(page.locator("#pairing-create")).toBeEnabled();
});

test("displays and downloads a scannable QR with the exact invitation bytes", async ({ page }, testInfo) => {
  await page.locator("#pairing-create").click();
  await expect(page.locator("#pairing-code svg")).toBeVisible();
  const downloadEvent = page.waitForEvent("download");
  await page.locator("#pairing-download").click();
  const download = await downloadEvent;
  expect(download.suggestedFilename()).toBe("monique-pairing.png");
  const png = PNG.sync.read(await readFile(await download.path()));
  expect(jsQR(new Uint8ClampedArray(png.data), png.width, png.height)?.data).toBe(offer);
  // Decode the displayed QR too, including its actual CSS size and quiet zone.
  const displayed = PNG.sync.read(await page.locator("#pairing-code").screenshot());
  expect(jsQR(new Uint8ClampedArray(displayed.data), displayed.width, displayed.height)?.data).toBe(offer);
  expect(await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth)).toBe(false);
  await page.locator("#pairing-panel").screenshot({ path: testInfo.outputPath("pairing.png") });
});

test("admin pairing grants future sessions explicitly and keeps other privileges separate", async ({ page }) => {
  await expect(page.locator("#pairing-access")).toHaveValue("selected");
  await page.locator("#pairing-access").selectOption("admin");
  await expect(page.locator("#pairing-selected-scope")).toBeHidden();
  await expect(page.locator("#pairing-admin-note")).toBeVisible();
  const request = page.waitForRequest("**/api/mobile/pairings");
  await page.locator("#pairing-create").click();
  expect((await request).postDataJSON()).toEqual({ actions: ["attach", "follow_up", "decide_approval", "stop_run", "all_sessions"], session_scope: [], limits: { max_follow_up_bytes: 65536, max_page_events: 100 } });
  await expect(page.locator("#pairing-code svg")).toBeVisible();
  await page.locator("#pairing-edit").click();
  await page.locator("#pairing-access").selectOption("selected");
  await expect(page.locator("#pairing-result")).toBeHidden();
});

test("expired invitations cannot be scanned, copied or downloaded", async ({ page }) => {
  await page.clock.install();
  await page.locator("#pairing-create").click();
  await expect(page.locator("#pairing-code svg")).toBeVisible();
  await page.clock.fastForward(301_000);
  await expect(page.locator("#pairing-expiry")).toContainText("expired");
  await expect(page.locator("#pairing-code svg")).toHaveCount(0);
  await expect(page.locator("#pairing-copy")).toBeHidden();
  await expect(page.locator("#pairing-download")).toBeHidden();
  await expect(page.locator("#pairing-create")).toBeEnabled();
});

test("closing during creation never restores the secret after a late response", async ({ page }) => {
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  await page.route("**/api/mobile/pairings", async (route) => {
    await pending;
    await route.fulfill({ body: offer });
  });
  const requested = page.waitForRequest("**/api/mobile/pairings");
  await page.locator("#pairing-create").click();
  await requested;
  await page.locator("#pairing-close").click();
  const completed = page.waitForResponse("**/api/mobile/pairings");
  release();
  await completed;
  await expect(page.locator("#pairing-result")).toBeHidden();
  await expect(page.locator("#pairing-code svg")).toHaveCount(0);
});

test("QR failures preserve the copy fallback and its visible error", async ({ page }) => {
  await page.evaluate(() => { window.moniqueQrCode = null; });
  await page.locator("#pairing-create").click();
  await expect(page.locator("#pairing-status")).toContainText("Use Copy invite instead");
  await expect(page.locator("#pairing-copy")).toBeVisible();
  await expect(page.locator("#pairing-download")).toBeHidden();
});

test("selected access requires a selection but admin access works with no sessions", async ({ page }) => {
  await page.locator("#pairing-sessions").selectOption([]);
  await expect(page.locator("#pairing-create")).toBeDisabled();
  await page.locator("#pairing-start-task").check();
  await expect(page.locator("#pairing-create")).toBeEnabled();
  await page.locator("#pairing-close").click();
  await page.route("**/api/mobile/pairing-sessions", (route) => route.fulfill({ json: { sessions: [] } }));
  await page.locator("#pairing-open").click();
  await page.locator("#pairing-start-task").uncheck();
  await expect(page.locator("#pairing-create")).toBeDisabled();
  await page.locator("#pairing-access").selectOption("admin");
  await expect(page.locator("#pairing-create")).toBeEnabled();
});

test("pairing steps and download are translated in French", async ({ page }) => {
  await page.evaluate(() => localStorage.setItem("monique-language", "fr"));
  await page.reload();
  await page.locator("#pairing-open").click();
  await expect(page.locator("#pairing-title")).toHaveText("Associer un téléphone");
  await expect(page.locator(".pairing-steps")).toContainText("Choisissez les accès");
  await page.locator("#pairing-create").click();
  await expect(page.locator("#pairing-download")).toHaveText("Télécharger le QR code");
});
