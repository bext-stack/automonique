// SPDX-License-Identifier: Apache-2.0
import {expect, test} from "bun:test";
import {parseCanonical, toCanonicalBytes} from "../../protocol/src/index.js";
import {decodeMobileTaskView, encodeMobileTaskRequest, type MobileTaskRequest} from "../src/mobile-task.js";
const request: MobileTaskRequest = {action:"submit",node_id:"daemon-1",expected_revision:"9007199254740995",idempotency_key:"mobile-task-1",text:"write a script"};
const wire = (value: unknown) => parseCanonical(new TextEncoder().encode(JSON.stringify(value, (_, child) => child && typeof child === "object" && !Array.isArray(child) ? Object.fromEntries(Object.entries(child).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) : child)));
const receipt = {schema:"automonique.mobile-task/v1",state:"receipt",receipt:{action:"submit_request",target:{authority:"automonique",kind:"node",id:"daemon-1"},outcome:"completed",explanation:"run=run-1;session=session-1"},session_id:"session-1"};
test("task requests preserve exact revisions and completed receipts bind node and session",()=>{
 expect(new TextDecoder().decode(toCanonicalBytes(encodeMobileTaskRequest(request)))).toContain('"expected_revision":"9007199254740995"');
 expect(decodeMobileTaskView(wire(receipt),request)).toMatchObject({state:"receipt",outcome:"completed",sessionId:"session-1"});
 expect(()=>encodeMobileTaskRequest({...request,expected_revision:"1e3"})).toThrow();
 expect(()=>encodeMobileTaskRequest({...request,node_id:"node/current"})).toThrow();
 expect(()=>encodeMobileTaskRequest({...request,text:" "})).toThrow();
});
test("foreign, malformed and premature task sessions cannot become navigation targets",()=>{
 for(const changed of [
  {...receipt,session_id:"session-2"},
  {...receipt,receipt:{...receipt.receipt,action:"follow_up"}},
  {...receipt,receipt:{...receipt.receipt,target:{...receipt.receipt.target,id:"daemon-2"}}},
  {...receipt,receipt:{...receipt.receipt,outcome:"accepted"}},
  {...receipt,schema:"other"},
 ]) expect(()=>decodeMobileTaskView(wire(changed),request)).toThrow();
 expect(decodeMobileTaskView(wire({schema:receipt.schema,state:"ambiguous"}),request)).toEqual({state:"ambiguous"});
});
