// SPDX-License-Identifier: Elastic-2.0

import { defineConfig, devices } from "@playwright/test";

const FIXTURE_SPECS = "**/platform-cockpit.spec.js";
const LIVE_SPEC = "**/live-cockpit-attention.spec.js";

export default defineConfig({
  testDir: "./tests/browser",
  timeout: 30_000,
  fullyParallel: true,
  use: { locale: "en-US", reducedMotion: "reduce" },
  projects: [
    { name: "desktop", testMatch: FIXTURE_SPECS, use: { ...devices["Desktop Chrome"] } },
    { name: "mobile", testMatch: FIXTURE_SPECS, use: { ...devices["Pixel 5"] } },
    // Opt-in, and never part of `bun run test:browser`: this project talks to a
    // deployment. It is run by `bun run test:browser:live` or by
    // `tools/run_attention_live_acceptance.py --cockpit-render-check`, and it
    // skips with a reason rather than passing when no credential is available.
    //
    // Tracing and video are pinned off here and refused at runtime by the spec:
    // a trace of a signed-in run records the `Authorization` header, and this is
    // the one project that carries an operator credential.
    {
      name: "live-cockpit",
      testMatch: LIVE_SPEC,
      timeout: 120_000,
      use: { ...devices["Desktop Chrome"], trace: "off", video: "off" },
    },
  ],
});
