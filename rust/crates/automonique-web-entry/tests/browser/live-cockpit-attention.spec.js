// SPDX-License-Identifier: Elastic-2.0

/**
 * LIVE-GUI-2 of epic #163, performed by a browser instead of a human.
 *
 * The operator step reads: sign in to the hosted cockpit and confirm the same
 * attention item renders with the same source and generation ShellDeck showed,
 * with no review state the source did not assert; evidence required is a
 * screenshot showing the source and the generation.
 *
 * A browser can do all of that, and the only way it is worth anything is if it
 * can fail. So nothing here is a constant. Every expectation is derived, in
 * this file, from the `/api/platform/cockpit` document the deployment itself
 * answered with during this very page load — captured off the wire, not read
 * back out of the page. A test that asserted a hardcoded revision would pass on
 * a page showing anything at all; a test that asked the page what it thinks it
 * rendered would only prove the page agrees with itself.
 *
 * The two halves:
 *
 *   1. The attention item the deployment served must render, and the source
 *      kind, source revision (the generation) and item revision in the DOM must
 *      be the ones that document carries. Every rendered item must correspond
 *      to a served one and every served one must be rendered, so an item cannot
 *      be dropped or invented.
 *
 *   2. No review state the source did not assert. The review semantics are
 *      re-derived here from the raw served review document, under the same
 *      contract `projectReviewSemantics` implements, and the rendered text and
 *      `data-semantic-key` of all four review read models must match exactly.
 *      A refused or unavailable review source must render as `Unavailable` with
 *      no semantic key at all: an inferred review state is the defect this half
 *      exists to catch.
 *
 * Modes. With `AUTOMONIQUE_LIVE_COCKPIT_PROOF_DOCUMENT` set, the real cockpit
 * assets are served locally against that document, optionally with a named
 * mutation applied to the real render path, so the assertions above can be
 * shown to fail. Without it, this runs against a deployment over the network.
 * The assertion code is the same in both modes; that is the point of the proof.
 *
 * Credentials. The operator credential is read from the environment by name and
 * handed to Playwright as context `httpCredentials`. It is never printed, never
 * written to the evidence, and never placed in the Playwright config, which
 * reporters serialize. Tracing and video are refused outright, because a trace
 * records request headers and would carry the `Authorization` header into an
 * artefact. A screenshot of a signed-in page carries no header and is fine.
 *
 * Running it. From this crate, with the operator credential exported as
 * `AUTOMONIQUE_OPS_BASIC_AUTH`:
 *
 *     bun install
 *     bunx playwright install chromium
 *     AUTOMONIQUE_LIVE_COCKPIT_ORIGIN=https://monique.1clic.pro \
 *       bun run test:browser:live
 *
 * Or, folded into the epic #163 acceptance report, from the repository root:
 *
 *     python3 tools/run_attention_live_acceptance.py --cockpit-render-check
 *
 * To prove the assertions can fail, no credential and no deployment needed:
 *
 *     AUTOMONIQUE_LIVE_COCKPIT_PROOF_DOCUMENT=$PWD/fixtures/cockpit-render-proof-v1.json \
 *       AUTOMONIQUE_LIVE_COCKPIT_PROOF_MUTATION=generation \
 *       bun run test:browser:live
 *
 * with `generation`, `review_inference`, `review_decision` or `dropped_item`;
 * each must fail, and `none` must pass.
 */

import { expect, test } from "@playwright/test";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const EVIDENCE_SCHEMA = "automonique.cockpit-render-evidence/v1";
const COCKPIT_SCHEMA = "automonique.dashboard.cockpit/v2";
const COCKPIT_PATH = "/api/platform/cockpit";
const DEFAULT_ORIGIN = "https://monique.1clic.pro";
const PROOF_ORIGIN = "https://cockpit.proof";

const crate = fileURLToPath(new URL("../../", import.meta.url));
const asset = (name) => readFile(path.join(crate, "assets", name), "utf8");

const environment = {
  origin: process.env.AUTOMONIQUE_LIVE_COCKPIT_ORIGIN || DEFAULT_ORIGIN,
  credentialEnv:
    process.env.AUTOMONIQUE_LIVE_COCKPIT_CREDENTIAL_ENV || "AUTOMONIQUE_OPS_BASIC_AUTH",
  evidenceDir:
    process.env.AUTOMONIQUE_LIVE_COCKPIT_EVIDENCE_DIR
    || path.join(crate, "test-results", "live-cockpit-evidence"),
  proofDocument: process.env.AUTOMONIQUE_LIVE_COCKPIT_PROOF_DOCUMENT || null,
  proofMutation: process.env.AUTOMONIQUE_LIVE_COCKPIT_PROOF_MUTATION || "none",
};

// ---------------------------------------------------------------------------
// The render contract, re-derived rather than borrowed.
//
// These are the enumerations and coherence rules `projectReviewSemantics` in
// assets/platform-cockpit-core.js applies to a review document. They are
// restated here on purpose: importing that module would make this check assert
// the page against its own projection, which proves nothing about whether the
// page renders what the server asserted.
// ---------------------------------------------------------------------------

const WORKSPACE_ATTENTION_STATES = ["idle", "needs_you", "working", "blocked", "done"];
const REVIEW_DECISIONS = ["pending", "approved", "changes_requested", "dismissed"];
const CHECK_STATES = ["queued", "running", "passed", "failed", "cancelled", "unavailable"];
const PULL_REQUEST_STATES = ["absent", "draft", "open", "closed", "merged"];
const MERGE_READINESS_STATES = ["unknown", "blocked", "ready", "stale"];
const DELIVERY_STATES = ["not_delivered", "pending", "delivered", "failed"];
const PREVIEW_KINDS = ["none", "text", "binary", "image", "html"];
const FRESHNESS_STATES = ["fresh", "stale", "unknown"];
const ATTENTION_REASON_STATES = {
  review_requested: "needs_you",
  comment_reply: "needs_you",
  approval_required: "needs_you",
  check_running: "working",
  delivery_pending: "working",
  check_failed: "blocked",
  conflict: "blocked",
  external_blocker: "blocked",
  complete: "done",
};

const decimal = (value, allowZero = true) =>
  typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value) && (allowZero || value !== "0");

const greater = (left, right) =>
  decimal(left) && decimal(right) && (left.length !== right.length ? left.length > right.length : left > right);

const bounded = (value, maximum) =>
  typeof value === "string" && value.length > 0 && value.length <= maximum ? value : null;

const oneOf = (value, values) => (values.includes(value) ? value : null);

/** The English rendering of a semantic key: `pull_request.open.blocked` reads "open · blocked". */
const semanticWords = (key) => key.split(".").slice(1).map((part) => part.replaceAll("_", " ")).join(" · ");

function freshnessOf(value, rootRevision) {
  const state = oneOf(value?.state, FRESHNESS_STATES);
  const observed = decimal(value?.observed_revision, false) ? value.observed_revision : null;
  if (!state || !observed || greater(observed, rootRevision)) return null;
  return { freshness_key: `freshness.${state}`, source_revision: observed };
}

/**
 * Re-derive what the cockpit is permitted to render for a review document.
 *
 * Returns `null` when the document does not cohere, which is exactly when the
 * cockpit must render `Unavailable` and assert nothing.
 */
function deriveReviewSemantics(document) {
  const root = decimal(document?.revision, false) ? document.revision : null;
  if (!root || !Array.isArray(document?.checks) || document.checks.length > 128) return null;
  if (!Array.isArray(document?.files) || document.files.length > 128) return null;

  const attentionState = oneOf(document?.attention?.state, WORKSPACE_ATTENTION_STATES);
  const attentionReason =
    document?.attention?.reason === null ? null : bounded(document?.attention?.reason, 64);
  const attentionSource =
    document?.attention?.source_revision === null
      ? null
      : decimal(document?.attention?.source_revision, false)
        ? document.attention.source_revision
        : null;
  const unread = decimal(document?.attention?.unread) ? document.attention.unread : null;
  const idle =
    attentionState === "idle" && attentionReason === null && attentionSource === null && unread === "0";
  const active =
    attentionState
    && attentionState !== "idle"
    && attentionReason
    && ATTENTION_REASON_STATES[attentionReason] === attentionState
    && attentionSource
    && !greater(attentionSource, root)
    && unread !== null;
  if (!idle && !active) return null;

  const decision = oneOf(document?.review?.decision, REVIEW_DECISIONS);
  const reviewFreshness = freshnessOf(document?.review?.freshness, root);
  if (!decision || !reviewFreshness) return null;

  const checkIds = new Set();
  const checks = [];
  for (const value of document.checks) {
    const id = bounded(value?.id, 256);
    const state = oneOf(value?.state, CHECK_STATES);
    const freshness = freshnessOf(value?.freshness, root);
    if (!id || checkIds.has(id) || !state || typeof value?.required !== "boolean" || !freshness) return null;
    checkIds.add(id);
    checks.push({ semantic_key: `check.${state}.${value.required ? "required" : "optional"}`, ...freshness });
  }

  const pullRequestState = oneOf(document?.pull_request?.state, PULL_REQUEST_STATES);
  const readiness = oneOf(document?.pull_request?.readiness, MERGE_READINESS_STATES);
  const pullRequestFreshness = freshnessOf(document?.pull_request?.freshness, root);
  if (!pullRequestState || !readiness || !pullRequestFreshness) return null;

  const deliveryState = oneOf(document?.delivery?.state, DELIVERY_STATES);
  const deliveryFreshness = freshnessOf(document?.delivery?.freshness, root);
  if (!deliveryState || !deliveryFreshness) return null;

  const fileIds = new Set();
  const previews = [];
  for (const value of document.files) {
    const id = bounded(value?.id, 256);
    const kind = oneOf(value?.preview?.kind, PREVIEW_KINDS);
    const sanitized = value?.preview?.sanitized;
    const coherent = kind === "none" || kind === "binary" ? sanitized === false : sanitized === true;
    if (!id || fileIds.has(id) || !kind || !coherent) return null;
    fileIds.add(id);
    previews.push({ semantic_key: `preview.${kind}.${sanitized ? "sanitized" : "raw"}` });
  }

  return {
    source_revision: root,
    attention: {
      semantic_key: `attention.${attentionState}`,
      reason_key: attentionReason ? `attention_reason.${attentionReason}` : null,
    },
    review: { semantic_key: `review.${decision}`, ...reviewFreshness },
    checks,
    pull_request: { semantic_key: `pull_request.${pullRequestState}.${readiness}`, ...pullRequestFreshness },
    delivery: { semantic_key: `delivery.${deliveryState}`, ...deliveryFreshness },
    previews,
  };
}

/** The exact strings the cockpit must render for a derived set of semantics. */
function expectedReadModels(semantics) {
  if (semantics === null) {
    return {
      "cockpit-files-state": { text: "Unavailable", semanticKey: null },
      "cockpit-review-state": { text: "Unavailable", semanticKey: null },
      "cockpit-checks-state": { text: "Unavailable", semanticKey: null },
      "cockpit-delivery-state": { text: "Unavailable", semanticKey: null },
    };
  }
  const withSource = (value) =>
    `${semanticWords(value.semantic_key)} · ${semanticWords(value.freshness_key)} · source revision ${value.source_revision}`;
  const reason = semantics.attention.reason_key ? ` · ${semanticWords(semantics.attention.reason_key)}` : "";
  return {
    "cockpit-files-state": {
      text: semantics.previews.length
        ? `${semantics.previews.map((value) => semanticWords(value.semantic_key)).join(" · ")} · source revision ${semantics.source_revision}`
        : `No previews · source revision ${semantics.source_revision}`,
      semanticKey: semantics.previews.map((value) => value.semantic_key).join(" ") || null,
    },
    "cockpit-review-state": {
      text: `${semanticWords(semantics.attention.semantic_key)}${reason} · ${withSource(semantics.review)} · ${withSource(semantics.pull_request)}`,
      semanticKey: `${semantics.attention.semantic_key} ${semantics.review.semantic_key} ${semantics.pull_request.semantic_key}`,
    },
    "cockpit-checks-state": {
      text: semantics.checks.length
        ? semantics.checks.map(withSource).join(" · ")
        : `No checks · source revision ${semantics.source_revision}`,
      semanticKey: semantics.checks.map((value) => value.semantic_key).join(" ") || null,
    },
    "cockpit-delivery-state": {
      text: withSource(semantics.delivery),
      semanticKey: semantics.delivery.semantic_key,
    },
  };
}

// ---------------------------------------------------------------------------
// Proof mode: the real assets, a real projected document, and a named mutation
// of the real render path so the assertions above can be shown to fail.
// ---------------------------------------------------------------------------

const MUTATIONS = {
  none: null,
  generation: {
    asset: "dashboard.js",
    describes: "the inbox renders the item revision where the source generation belongs",
    from: "source revision ${entry.source_revision} · item revision ${entry.item_revision}",
    to: "source revision ${entry.item_revision} · item revision ${entry.item_revision}",
  },
  review_inference: {
    asset: "platform-cockpit-core.js",
    describes: "review semantics are projected from a source that refused to assert them",
    from: 'const reviewDocument = document?.review?.state === "available" ? document?.review?.document : null;',
    to: "const reviewDocument = document?.review?.document ?? null;",
    // A refused review source that still carries a payload is the shape the
    // guard exists for: the cockpit must assert nothing from it.
    document: (value) => ({ ...value, review: { ...value.review, state: "refused", category: "review_authority_refused" } }),
  },
  review_decision: {
    asset: "platform-cockpit-core.js",
    describes: "the review decision rendered is not the decision the source asserted",
    from: "const review = Object.freeze({ semantic_key: `review.${reviewState}`, ...reviewFreshness });",
    to: 'const review = Object.freeze({ semantic_key: "review.approved", ...reviewFreshness });',
  },
  dropped_item: {
    asset: "platform-cockpit-core.js",
    describes:
      "an attention item the source asserted is silently discarded by the client normaliser — the shape of the"
      + " defect that projected `unread` as a bool and emptied every inbox the cockpit could serve",
    from: "const unread = validDecimal(value?.unread) ? value.unread : null;",
    to: "const unread = validDecimal(value?.unread_absent_field) ? value.unread : null;",
  },
};

function mutation(name) {
  if (!(name in MUTATIONS)) {
    throw new Error(`unknown proof mutation ${name}; expected one of ${Object.keys(MUTATIONS).join(", ")}`);
  }
  return MUTATIONS[name];
}

async function mutatedAsset(name, applied) {
  const source = await asset(name);
  if (!applied || applied.asset !== name) return source;
  if (!source.includes(applied.from)) {
    throw new Error(
      `the proof mutation no longer matches ${name}; it cannot prove anything about a render path it does not touch`,
    );
  }
  return source.replaceAll(applied.from, applied.to);
}

async function serveProof(page, documentPath, applied) {
  const served = JSON.parse(await readFile(documentPath, "utf8"));
  const document = applied?.document ? applied.document(served) : served;
  const [html, css, dashboard, core] = await Promise.all([
    asset("dashboard.html"),
    asset("dashboard.css"),
    mutatedAsset("dashboard.js", applied),
    mutatedAsset("platform-cockpit-core.js", applied),
  ]);
  await page.route("**/*", async (route) => {
    const { pathname } = new URL(route.request().url());
    if (pathname === "/") return route.fulfill({ contentType: "text/html", body: html });
    if (pathname === "/assets/dashboard.css") return route.fulfill({ contentType: "text/css", body: css });
    if (pathname === "/assets/dashboard.js") return route.fulfill({ contentType: "text/javascript", body: dashboard });
    if (pathname === "/assets/platform-cockpit-core.js") {
      return route.fulfill({ contentType: "text/javascript", body: core });
    }
    if (pathname === "/assets/qrcode.js") return route.fulfill({ contentType: "text/javascript", body: "" });
    if (pathname === COCKPIT_PATH) {
      return route.fulfill({ contentType: "application/json", body: JSON.stringify(document) });
    }
    return route.fulfill({ contentType: "application/json", body: "{}" });
  });
}

// ---------------------------------------------------------------------------

const sha256 = (value) => createHash("sha256").update(value, "utf8").digest("hex");

/**
 * Refuse to run under any artefact setting that records request headers.
 *
 * A Playwright trace carries the `Authorization` header of every request it
 * captures. This check signs in with an operator credential, so a trace of it
 * would be a credential on disk. Video is refused for the same reason it is
 * pointless here: it is a large artefact nobody asked for.
 */
function refuseHeaderCapturingArtefacts(project) {
  for (const setting of ["trace", "video"]) {
    const value = project.use?.[setting];
    const off = value === undefined || value === "off" || value?.mode === "off";
    if (!off) {
      throw new Error(
        `${setting} is enabled for this project; a trace or video of a signed-in run can carry the `
        + "Authorization header into an artefact, so this check refuses to run under it",
      );
    }
  }
}

test.describe("hosted cockpit attention render", () => {
  test("renders the attention item the deployment served, and no review state it did not assert", async ({
    browser,
  }, testInfo) => {
    refuseHeaderCapturingArtefacts(testInfo.project);

    const proofPath = environment.proofDocument;
    const applied = proofPath ? mutation(environment.proofMutation) : null;
    const origin = proofPath ? PROOF_ORIGIN : environment.origin;
    const raw = proofPath ? null : process.env[environment.credentialEnv];

    const evidence = {
      schema: EVIDENCE_SCHEMA,
      mode: proofPath ? "proof" : "live",
      origin,
      proof_mutation: proofPath ? environment.proofMutation : null,
      captured_at_ms: Date.now(),
      assertions: [],
    };
    await mkdir(environment.evidenceDir, { recursive: true });
    const evidencePath = path.join(environment.evidenceDir, "live-cockpit-attention.json");
    const screenshotPath = path.join(environment.evidenceDir, "live-cockpit-attention.png");
    const reviewShotPath = path.join(environment.evidenceDir, "live-cockpit-review.png");
    const write = () => writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, "utf8");

    // A missing credential is a fact about this host, not about the deployment.
    // It is recorded as `blocked` and skipped with the reason, never passed: an
    // unobserved render must not read as an observed one, here or in the
    // acceptance report that folds this in.
    if (!proofPath && !raw) {
      evidence.state = "blocked";
      evidence.reason =
        `no operator credential in $${environment.credentialEnv}; the hosted cockpit could not be signed into `
        + "from this host, so nothing about its render was observed";
      await write();
      test.skip(true, evidence.reason);
      return;
    }
    // A credential on a cleartext hop is a credential on the wire. Loopback is
    // the one exception, and it exists so this check can be exercised end to end
    // against a local stand-in without a deployment.
    const loopback = /^http:\/\/(127\.0\.0\.1|\[::1\]|localhost)(:\d+)?$/.test(origin);
    if (!proofPath && !origin.startsWith("https://") && !loopback) {
      throw new Error(`refusing to send an operator credential to a non-TLS origin: ${origin}`);
    }

    const separator = raw ? raw.indexOf(":") : -1;
    if (raw && separator <= 0) {
      throw new Error(`$${environment.credentialEnv} is not in user:password form`);
    }

    const context = await browser.newContext({
      ...(raw
        ? { httpCredentials: { username: raw.slice(0, separator), password: raw.slice(separator + 1), origin } }
        : {}),
      locale: "en-US",
      reducedMotion: "reduce",
    });
    // The cockpit translates its enum vocabulary through a stored language
    // preference. Every string this check compares is pinned to English by it.
    await context.addInitScript(() => {
      try {
        window.localStorage.setItem("monique-language", "en");
      } catch (_error) {
        // A storage-hardened context still defaults to the navigator locale.
      }
    });

    try {
      const page = await context.newPage();
      if (proofPath) await serveProof(page, proofPath, applied);

      const answered = page.waitForResponse(
        (response) => new URL(response.url()).pathname === COCKPIT_PATH,
        { timeout: 60_000 },
      );
      await page.goto(`${origin}/#sessions`, { waitUntil: "domcontentloaded", timeout: 60_000 });
      const response = await answered;
      expect(
        response.status(),
        `${origin}${COCKPIT_PATH} did not answer the signed-in cockpit read`,
      ).toBe(200);
      const served = await response.json();

      // Everything below is derived from `served`. Nothing is a constant.
      expect(served?.schema, "the deployment served a cockpit document under an unknown schema").toBe(
        COCKPIT_SCHEMA,
      );
      await expect(page.getByRole("heading", { name: "Cockpit", exact: true })).toBeVisible();
      await page.getByRole("tab", { name: "Activity" }).click();

      const items = Array.isArray(served?.inbox?.items) ? served.inbox.items : [];
      evidence.cockpit_schema = served.schema;
      evidence.inbox_state = served?.inbox?.state ?? null;
      evidence.inbox_total = served?.inbox?.total ?? null;

      // The screenshot is the evidence the operator step demands, and it is
      // taken before the assertions so a failing run still leaves a picture of
      // what was actually on screen.
      await page.screenshot({ path: screenshotPath, fullPage: true });
      evidence.screenshot = path.basename(screenshotPath);

      if (items.length === 0) {
        evidence.state = "blocked";
        evidence.reason =
          "the deployment served no attention item"
          + (served?.inbox?.state ? ` (inbox ${served.inbox.state})` : "")
          + ", so there is nothing for this surface to render and nothing to compare with the other clients";
        await write();
        test.skip(true, evidence.reason);
        return;
      }

      // --- 1. the served attention items render, with their source and generation
      const inbox = page.locator("#cockpit-inbox-list");
      await expect(inbox).toBeVisible();
      const rendered = await inbox.locator("li").evaluateAll((nodes) =>
        nodes.map((node) => ({
          text: node.textContent ?? "",
          label: node.querySelector("a")?.getAttribute("aria-label") ?? null,
          href: node.querySelector("a")?.getAttribute("href") ?? null,
        })),
      );
      const bearing = rendered.filter((node) => node.text.includes("source revision "));
      expect(
        bearing.length,
        `the deployment served ${items.length} attention item(s) but the cockpit rendered ${bearing.length}; `
          + "an item the source asserted must not be dropped, and one it did not must not appear",
      ).toBe(items.length);

      evidence.attention_items = [];
      for (const item of items) {
        const detail =
          `${String(item.source_kind).replaceAll("_", " ")} · observed ${item.observed_at_ms} ms`
          + ` · source revision ${item.source_revision} · item revision ${item.item_revision}`
          + ` · ${item.unread} unread`;
        const title = `${String(item.state).replaceAll("_", " ")} · ${String(item.reason).replaceAll("_", " ")}`;
        const match = bearing.find((node) => node.text.includes(detail));
        expect(
          match,
          `no rendered attention item carries the source and generation the deployment served: ${detail}`,
        ).toBeTruthy();
        expect(match.text, "the rendered attention item does not carry the served state and reason").toContain(
          title,
        );
        expect(
          match.label,
          "the exact-context link does not name the generation the source asserted",
        ).toContain(`at source revision ${item.source_revision}`);
        expect(match.href, "the exact-context link does not resolve to the workspace the source named").toContain(
          `workspace=${item.link.workspace}`,
        );
        evidence.attention_items.push({
          source_kind: item.source_kind,
          source_id: item.source_id,
          source_revision: item.source_revision,
          item_revision: item.item_revision,
          state: item.state,
          reason: item.reason,
          unread: item.unread,
          rendered_detail_sha256: sha256(detail),
        });
      }
      evidence.assertions.push(
        "every attention item the deployment served renders with the source kind, source revision and item"
          + " revision that document carries, and no item is rendered that it does not",
      );

      // --- 2. no review state the source did not assert
      // The review read models live on a different surface, so the evidence
      // needs its own picture of them; it is taken before the assertions for
      // the same reason as the first one.
      await page.getByRole("tab", { name: "Files & review" }).click();
      await page.screenshot({ path: reviewShotPath, fullPage: true });
      evidence.review_screenshot = path.basename(reviewShotPath);

      const reviewAvailable = served?.review?.state === "available";
      const semantics = reviewAvailable ? deriveReviewSemantics(served.review.document) : null;
      const expected = expectedReadModels(semantics);
      for (const [id, want] of Object.entries(expected)) {
        const node = page.locator(`#${id}`);
        await expect(node, `${id} does not render what the source asserted`).toHaveText(want.text);
        if (want.semanticKey === null) {
          await expect(
            node,
            `${id} carries a review semantic key the source did not assert`,
          ).not.toHaveAttribute("data-semantic-key", /.*/);
        } else {
          await expect(node, `${id} renders review semantics the source did not assert`).toHaveAttribute(
            "data-semantic-key",
            want.semanticKey,
          );
        }
      }
      evidence.review = {
        source_state: served?.review?.state ?? "absent",
        source_revision: semantics?.source_revision ?? null,
        derived: semantics === null ? "no_review_state_assertable" : "exact_semantics",
        semantic_keys: Object.fromEntries(
          Object.entries(expected).map(([id, want]) => [id, want.semanticKey]),
        ),
      };
      evidence.assertions.push(
        reviewAvailable && semantics !== null
          ? "the four review read models render exactly the semantics re-derived from the served review document,"
            + " and no others"
          : "the served review source asserts no review state, and the cockpit renders none",
      );

      evidence.state = "asserted";
      await write();
      testInfo.attach("live-cockpit-attention", { path: screenshotPath, contentType: "image/png" });
      testInfo.attach("live-cockpit-review", { path: reviewShotPath, contentType: "image/png" });
    } finally {
      await context.close();
    }
  });
});
