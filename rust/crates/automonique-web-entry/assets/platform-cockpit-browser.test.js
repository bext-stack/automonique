// SPDX-License-Identifier: Elastic-2.0

import { expect, test } from "bun:test";
import "./platform-cockpit-core.js";

const cockpit = globalThis.AutomoniquePlatformCockpit;
const html = await Bun.file(new URL("./dashboard.html", import.meta.url)).text();
const css = await Bun.file(new URL("./dashboard.css", import.meta.url)).text();
const script = await Bun.file(new URL("./dashboard.js", import.meta.url)).text();

test("desktop workspace shell keeps context, conversation, and inspector in a deterministic order", () => {
  expect(cockpit.browserProfile(1440).layout).toBe("desktop");
  expect(cockpit.browserProfile(1440).focusOrder).toEqual([
    "workspace-navigation",
    "workspace-summary",
    "workspace-inspector",
    "conversation",
  ]);
  expect(html.indexOf('id="cockpit-workspace-navigation"')).toBeLessThan(html.indexOf('id="cockpit-workspace-summary"'));
  expect(html.indexOf('id="cockpit-workspace-summary"')).toBeLessThan(html.indexOf('id="cockpit-workspace-inspector"'));
  expect(html.indexOf('id="cockpit-workspace-inspector"')).toBeLessThan(html.indexOf('id="cockpit-conversation"'));
});

test("mobile shell stacks the same truthful regions into one responsive column", () => {
  expect(cockpit.browserProfile(390)).toEqual({
    layout: "mobile",
    focusOrder: ["workspace-navigation", "workspace-summary", "workspace-inspector", "conversation"],
    shortcuts: { workspace: "w", conversation: "c", activity: "a" },
  });
  expect(css).toContain("@media (max-width: 760px)");
  expect(css).toContain(".hosted-workspace-grid { grid-template-columns: 1fr; }");
  expect(css).toContain("@media (max-width: 460px)");
  expect(css).toContain(".cockpit-signal-grid, .cockpit-read-model-grid { grid-template-columns: 1fr; }");
});

test("workspace shell exposes accessible tabs, live receipt state, and keyboard targets", () => {
  expect(html).toContain('role="tablist" aria-label="Selected workspace surfaces"');
  expect(html).toContain('role="listbox" aria-label="Hosted workspaces"');
  expect(html).toContain('id="cockpit-action-receipt" data-state="idle" role="status" aria-live="polite"');
  expect(html).toContain('id="cockpit-workspace-navigation" aria-label="Project, host, and workspace navigation" tabindex="-1"');
  expect(script).toContain('event.key.toLowerCase() === "w"');
  expect(script).toContain('event.key.toLowerCase() === "c"');
  expect(script).toContain('event.key.toLowerCase() === "a"');
  expect(script).toContain('["ArrowLeft", "ArrowRight", "Home", "End"]');
  expect(css).toContain("button:focus-visible");
});

test("preview is inert and confirmed controls persist their receipt before sending", () => {
  const start = script.indexOf("function previewCockpitAction(action)");
  const end = script.indexOf("function newCockpitReceiptId", start);
  const preview = script.slice(start, end);
  expect(preview).toContain("no mutation sent");
  expect(preview).not.toContain("fetch(");
  expect(preview).not.toContain("api(");
  expect(preview).not.toContain("platformPost(");
  const submitStart = script.indexOf("async function submitCockpitIntent(action)");
  const submitEnd = script.indexOf("async function submitCockpitReview", submitStart);
  const submit = script.slice(submitStart, submitEnd);
  expect(submit.indexOf("persistCockpitControl(handle)")).toBeLessThan(submit.indexOf('api("/api/platform/cockpit"'));
  expect(script).toContain("Only receipt lookup is allowed now");
  expect(html).toContain('id="cockpit-create-preview" type="button" disabled');
  expect(html).toContain('id="cockpit-resume-preview" type="button" disabled');
});

test("generic recovery remains secondary to the hosted workspace surface", () => {
  expect(html.indexOf('data-panel="sessions"')).toBeLessThan(html.indexOf('data-panel="chat"'));
  expect(html).toContain("SECONDARY / RECOVERY");
  expect(html).toContain("This assistant is not attached to an authority-qualified Platform session.");
});
