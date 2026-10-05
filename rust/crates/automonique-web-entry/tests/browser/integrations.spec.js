// SPDX-License-Identifier: Elastic-2.0
import { test, expect } from "@playwright/test";
import { readFile } from "node:fs/promises";

let actions, data, fail;
test.beforeEach(async ({ page }) => {
  actions = []; fail = false;
  const scopes = ["artifacts:read", "artifacts:write", "artifacts:visibility", "artifacts:delete", "jobs:read", "jobs:write", "events:read"];
  data = { scopes, event_types: ["job.succeeded", "job.failed", "artifact.version_published"],
    apps: [{ id: "app-fixture", name: "Reports", projects: ["Reports"], scopes, expires_at: "2099-01-01T00:00:00Z", usage: { calls: 12, errors: 1, latency_ms: 480, upload_bytes: 512, recent: [{ operation: "artifacts.begin", status: 200, duration_ms: 40, at: new Date().toISOString() }] } }],
    subscriptions: [], deliveries: [{ id: "delivery-fixture", url: "https://example.test/events", state: "failed", attempts: 8, status: 503 }],
    jobs: [{ id: "job-fixture", title: "Quarterly report", project: "Reports", state: "queued", created_at: new Date().toISOString() }],
    worker: { ready: true, provider: "codex", checked_at: new Date().toISOString() } };
  const files = Object.fromEntries(await Promise.all(["dashboard.html", "dashboard.css", "dashboard.js", "platform-cockpit-core.js"].map(async name => [name, await readFile(new URL(`../../assets/${name}`, import.meta.url), "utf8")])));
  await page.route("**/*", async route => {
    const { pathname } = new URL(route.request().url());
    if (pathname === "/") return route.fulfill({ contentType: "text/html", body: files["dashboard.html"] });
    if (pathname.startsWith("/assets/")) return route.fulfill({ contentType: pathname.endsWith(".css") ? "text/css" : "text/javascript", body: files[pathname.split("/").pop()] || "" });
    if (pathname === "/api/configuration") return route.fulfill({ json: { agent_authentication: {}, manage: {}, providers: {}, connectors: {}, memory: {}, governance: {}, extensions: {} } });
    if (pathname === "/api/integrations") {
      const body = route.request().postDataJSON();
      if (body.action === "overview") return route.fulfill({ json: data });
      actions.push(body);
      if (fail) return route.fulfill({ status: 503, json: { error: { code: "service_unavailable" } } });
      if (body.action === "revoke") data.apps[0].revoked_at = new Date().toISOString();
      return route.fulfill({ json: { ok: true, token: body.action === "create" ? "fixture-secret-once" : undefined, signing_secret: body.action === "subscribe" ? "fixture-signature-once" : undefined } });
    }
    return route.fulfill({ json: {} });
  });
  await page.goto("https://integration.test/#configuration");
  await expect(page.locator("#integration-manager h2")).toHaveText("Applications & API");
});

test("creates explicitly scoped access and clears the one-time secret on close", async ({ page }) => {
  await page.getByRole("button", { name: "Connecter une application", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Nom de l’application").fill("New app");
  await dialog.getByLabel("Projets autorisés").fill("Reports, Website");
  await dialog.getByLabel("Créer et modifier les versions").check();
  await dialog.getByRole("button", { name: "Créer la connexion" }).click();
  await expect(dialog.getByLabel("Clé à copier")).toHaveValue("fixture-secret-once");
  expect(actions[0]).toMatchObject({ section: "apps", action: "create", projects: ["Reports", "Website"], expires_in_days: 90 });
  expect(actions[0].scopes).toContain("artifacts:write");
  expect(actions[0].scopes).not.toContain("artifacts:delete");
  await dialog.getByRole("button", { name: "Fermer" }).click();
  await expect(dialog).toHaveCount(0);
  expect(await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))).not.toContain("fixture-secret-once");
});

test("tests, revokes, exposes usage and retries individual deliveries without overflow", async ({ page }) => {
  const root = page.locator("#integration-manager");
  await expect(root).toContainText("12 appels · 1 erreurs · 40 ms");
  await root.getByRole("button", { name: "Tester", exact: true }).click();
  expect(actions.at(-1)).toEqual({ action: "test", id: "app-fixture" });
  await root.getByRole("tab", { name: "Activité", exact: true }).click();
  await expect(root).toContainText("artifacts.begin");
  await root.getByRole("tab", { name: "Événements", exact: true }).click();
  await root.getByRole("button", { name: "Réessayer", exact: true }).click();
  expect(actions.at(-1)).toEqual({ section: "events", action: "retry", id: "delivery-fixture" });
  await root.getByRole("tab", { name: "Demandes", exact: true }).click();
  await root.getByRole("button", { name: "Annuler", exact: true }).click();
  expect(actions.at(-1)).toEqual({ section: "jobs", action: "cancel", id: "job-fixture" });
  await root.getByRole("tab", { name: "Applications", exact: true }).click();
  await root.getByRole("button", { name: "Révoquer", exact: true }).click();
  await expect(root.getByRole("button", { name: "Renouveler la clé" })).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test("keeps failed forms editable and exposes only safe error text", async ({ page }) => {
  fail = true;
  await page.locator("#integration-manager").getByRole("button", { name: "Événements", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("URL HTTPS de réception").fill("https://example.test/events");
  await dialog.getByRole("button", { name: "Enregistrer" }).click();
  await expect(dialog.getByRole("alert")).toHaveText("Le service est temporairement indisponible.");
  await expect(dialog.getByRole("button", { name: "Enregistrer" })).toBeEnabled();
  fail = false;
  await dialog.getByRole("button", { name: "Enregistrer" }).click();
  await expect(dialog.getByLabel("Clé à copier")).toHaveValue("fixture-signature-once");
});
