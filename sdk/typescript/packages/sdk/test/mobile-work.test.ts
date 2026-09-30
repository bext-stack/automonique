// SPDX-License-Identifier: Apache-2.0
import {expect, test} from "bun:test";
import {parseCanonical} from "../../protocol/src/index.js";
import {decodeMobileWorkView, encodeMobileWorkRequest} from "../src/mobile-work.js";
const json = (value: unknown) => parseCanonical(new TextEncoder().encode(JSON.stringify(value, (_, child) => child && typeof child === "object" && !Array.isArray(child) ? Object.fromEntries(Object.entries(child).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) : child)));
test("work request refuses redirect-shaped issue URLs and empty rejection reasons", () => {
  expect(() => encodeMobileWorkRequest({action:"dispatch",issue_url:"https://github.com.attacker.test/a/b/issues/1",idempotency_key:"key"})).toThrow();
  expect(() => encodeMobileWorkRequest({action:"decide",job_id:"job",source_key:"slack:fixture",idempotency_key:"key",decision:"reject",reason:" "})).toThrow();
});
test("work receipt must match the intended job and decision", () => {
  const request = {action:"decide",job_id:"job",source_key:"slack:fixture",idempotency_key:"key",decision:"reject",reason:"Not needed"} as const;
  expect(() => decodeMobileWorkView(json({schema:"automonique.mobile-work/v1",job_id:"foreign",job_status:"cancelled",duplicate:false}),request)).toThrow();
  expect(() => decodeMobileWorkView(json({schema:"automonique.mobile-work/v1",job_id:"job",job_status:"running",duplicate:false}),request)).toThrow();
  expect(decodeMobileWorkView(json({schema:"automonique.mobile-work/v1",job_id:"job",job_status:"cancelled",duplicate:true}),request)).toEqual({kind:"receipt",jobId:"job",status:"cancelled",duplicate:true});
});
test("queue distinguishes claimed from running and refuses duplicate job identities", () => {
  const row = {job_id:"job",source_key:"slack:fixture",issue_url:"https://github.com/example/repo/issues/1",issue_title:"Fixture",job_status:"claimed",updated_at:"2026-09-30T12:00:00Z"};
  const request = {action:"snapshot"} as const;
  expect(decodeMobileWorkView(json({schema:"automonique.mobile-work/v1",items:[row],has_more:false}),request).kind).toBe("queue");
  expect(() => decodeMobileWorkView(json({schema:"automonique.mobile-work/v1",items:[row,row],has_more:false}),request)).toThrow();
});
