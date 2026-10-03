// SPDX-License-Identifier: Elastic-2.0
import { test, expect } from "@playwright/test";
import { readFile } from "node:fs/promises";
let actions, view, memories, accounts, refuse;
const now=1791025200000;
const memory=(id,extra={})=>({reference:`M-${id}`,content:"Remember the shared preference",kind:"user_profile",status:"active",confidence:900,sensitivity:"internal",visibility:"private",provenance:"dashboard",revision:1,editable:true,updated_at_ms:now,...extra});
test.beforeEach(async({page})=>{
 actions=[];refuse=false;memories=[memory(1),memory(2),memory(3,{editable:false})];
 accounts={providers:[],accounts:[{id:"one",provider:"codex",label:"Test account",status:"authenticated",selected:true,worker_selected:true,usage:{status:"available",windows:[]}}],login_sessions:[]};
 view={mcp:{status:"ready",servers:["sample"]},automations:{status:"ready",items:[{id:"daily-check",revision:4,state:"enabled",schedule:"every@86400000",scope:"test",last_result:"failed",next_run_at_ms:now+86400000}]},backups:{timer:{status:"not_configured"},items:[{id:"recovery-example",created_at_ms:now,databases:2,bytes:2048,verification:{status:"not_checked"}}]}};
 const files=Object.fromEntries(await Promise.all(["dashboard.html","dashboard.css","dashboard.js","platform-cockpit-core.js"].map(async name=>[name,await readFile(new URL(`../../assets/${name}`,import.meta.url),"utf8")])));
 await page.route("**/*",async route=>{
  const path=new URL(route.request().url()).pathname;
  if(path==="/")return route.fulfill({contentType:"text/html",body:files["dashboard.html"]});
  if(path.startsWith("/assets/"))return route.fulfill({contentType:path.endsWith(".css")?"text/css":"text/javascript",body:files[path.split("/").pop()]||""});
  if(path==="/api/configuration")return route.fulfill({json:{agent_authentication:{status:"authenticated"},manage:{},providers:{},connectors:{},memory:{},governance:{},extensions:{}}});
  if(path==="/api/controls")return route.fulfill({json:view});
  if(path==="/api/agent-accounts")return route.fulfill({json:accounts});
  if(path==="/api/agent-accounts/action"){
   const action=route.request().postDataJSON();actions.push(action);accounts.accounts[0].response_test={status:"verified",reason:"response_verified",model:"test-model",duration_ms:420,checked_at_ms:now};return route.fulfill({json:accounts});
  }
  if(path==="/api/memory"||path==="/api/memory/search")return route.fulfill({json:{entries:memories,counts:{active:3,messages:0}}});
  if(path==="/api/controls/action"){
   const action=route.request().postDataJSON();actions.push(action);
   if(refuse)return route.fulfill({status:409,json:{error:"automation_revision_stale"}});
   if(action.action==="preview_automation")return route.fulfill({json:{id:action.id,prompt:'<img src=x onerror="alert(1)"> Check work',schedule:"every@86400000",scope:"test",preview_only:true}});
   if(action.action==="set_automation"){view.automations.items[0].state=action.paused?"paused":"enabled";view.automations.items[0].revision++;return route.fulfill({json:{ok:true}});}
   if(action.action==="discover_mcp")return route.fulfill({json:{status:"verified",checked_at_ms:now,tools:[{name:"read_records",description:"Read records",read_only:true},{name:"write_record",description:"Write a record",read_only:false}]}});
   if(action.action==="verify_backup"){view.backups.items[0].verification={status:"verified",checked_at_ms:now};return route.fulfill({json:{status:"checking"}});}
   if(action.action==="retrieve_memory")return route.fulfill({json:{entries:[memories[0]],limit:6,checked_at_ms:now}});
   if(action.action==="find_duplicates")return route.fulfill({json:{groups:[memories],truncated:false,checked_at_ms:now}});
   if(action.action==="archive_memories"){memories=memories.map(e=>action.entries.some(s=>s.reference===e.reference)?{...e,status:"deleted",revision:2}:e);return route.fulfill({json:{archived:action.entries.length}});}
  }
  return route.fulfill({json:{}});
 });
 await page.goto("https://controls.test/#configuration");
 await expect(page.locator('[data-control-card="automations"]')).toBeVisible();
});
test("previews without executing and pauses/resumes with the displayed revision",async({page})=>{
 const row=page.locator('[data-automation-id="daily-check"]');
 await expect(row).toContainText("Last result: Failed");
 await row.getByRole("button",{name:"Preview",exact:true}).click();
 await expect(row).toContainText("Preview only · nothing will run");await expect(row.locator("img")).toHaveCount(0);
 expect(actions).toEqual([{action:"preview_automation",id:"daily-check"}]);
 await row.getByRole("button",{name:"Pause",exact:true}).click();await expect(row.getByRole("button",{name:"Resume",exact:true})).toBeVisible();
 expect(actions[1]).toEqual({action:"set_automation",id:"daily-check",revision:4,paused:true});
 await row.getByRole("button",{name:"Resume",exact:true}).click();await expect(row.getByRole("button",{name:"Pause",exact:true})).toBeVisible();expect(actions[2].revision).toBe(5);
});
test("retains automation state after a stale-revision refusal",async({page})=>{
 refuse=true;const row=page.locator('[data-automation-id="daily-check"]');await row.getByRole("button",{name:"Pause",exact:true}).click();await expect(page.locator("#toast-region")).toContainText("This automation changed");await expect(row.getByRole("button",{name:"Pause",exact:true})).toBeEnabled();
});
test("expands MCP tools and distinguishes read and write permissions",async({page})=>{
 const card=page.locator('[data-control-card="mcp"]');await card.locator("summary").click();await card.getByRole("button",{name:"Refresh tools"}).click();await expect(card).toContainText("Tools discovered: 2");await expect(card).toContainText("Read only");await expect(card).toContainText("Changes data");expect(actions).toEqual([{action:"discover_mcp",server:"sample"}]);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
});
test("shows an absent backup schedule and verifies the selected recovery set",async({page})=>{
 const card=page.locator('[data-control-card="backups"]');await expect(card).toContainText("Automatic backups are not configured.");await card.getByRole("button",{name:"Verify backup"}).click();await expect(card).toContainText("Backup verified");expect(actions).toEqual([{action:"verify_backup",id:"recovery-example"}]);
});
test("response tests identify the account and render actual model and latency",async({page})=>{
 const account=page.locator('[data-account-id="one"]');await account.getByRole("button",{name:"Test response",exact:true}).click();await expect(account).toContainText("Response verified");await expect(account).toContainText("test-model");await expect(account).toContainText("0.4 s");expect(actions).toEqual([{action:"test_response",account_id:"one"}]);
});
test("retrieval previews never submit a chat message",async({page})=>{
 await page.goto("https://controls.test/#memory");await page.locator("#memory-query").fill("shared preference");await page.locator("#memory-retrieval-test").click();await expect(page.locator("#memory-inspection")).toContainText("M-1");await expect(page.locator("#memory-inspection")).toContainText("No message was sent.");expect(actions).toEqual([{action:"retrieve_memory",query:"shared preference"}]);
});
test("bulk archiving requires explicit selection and can be cancelled",async({page})=>{
 await page.goto("https://controls.test/#memory");await page.locator("#memory-select-visible").click();await expect(page.locator("#memory-selected-count")).toHaveText("2 selected");await page.locator("#memory-archive-selected").click();await page.getByRole("dialog").getByRole("button",{name:"Cancel",exact:true}).click();expect(actions).toEqual([]);
 await page.locator("#memory-archive-selected").click();await page.getByRole("dialog").getByRole("button",{name:"Archive",exact:true}).click();await expect(page.locator("#memory-selected-count")).toHaveText("0 selected");expect(actions[0]).toEqual({action:"archive_memories",entries:[{reference:"M-1",revision:1},{reference:"M-2",revision:1}]});
});
test("duplicates remain a review list with inaccessible memories disabled",async({page})=>{
 await page.goto("https://controls.test/#memory");await page.locator("#memory-duplicates").click();const panel=page.locator("#memory-inspection");await expect(panel).toContainText("Review each group before archiving.");await expect(panel.getByRole("checkbox",{name:"Select M-3",exact:true})).toBeDisabled();await panel.getByRole("checkbox",{name:"Select M-2",exact:true}).check();await expect(page.locator("#memory-selected-count")).toHaveText("1 selected");expect(actions).toEqual([{action:"find_duplicates"}]);
});

test("French controls remain compact on the smallest layout",async({page})=>{
 await page.evaluate(()=>localStorage.setItem("monique-language","fr"));await page.reload();
 await expect(page.locator('[data-control-card="automations"]')).toContainText("Automatisations");
 await expect(page.locator('[data-control-card="backups"]')).toContainText("Les sauvegardes automatiques ne sont pas configurées.");
 await expect(page.locator('[data-account-id="one"]').getByRole("button",{name:"Tester une réponse"})).toBeVisible();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
});

test("MCP network failures clear a previous verified result and allow retry",async({page})=>{
 const card=page.locator('[data-control-card="mcp"]');await card.locator("summary").click();await card.getByRole("button",{name:"Refresh tools"}).click();await expect(card).toContainText("Tools discovered: 2");
 await page.route("**/api/controls/action",route=>route.fulfill({status:503,json:{error:"unavailable"}}));
 await card.getByRole("button",{name:"Refresh tools"}).click();await expect(card).toContainText("Discovery failed");await expect(card).not.toContainText("Tools discovered: 2");await expect(card.getByRole("button",{name:"Refresh tools"})).toBeEnabled();
});

test("finishing one response test unlocks unchanged accounts",async({page})=>{
 await page.evaluate(()=>{
  const view={...agentAccountsView,accounts:[...agentAccountsView.accounts,{...agentAccountsView.accounts[0],id:"two",provider:"claude",label:"Second account"}]};
  renderAgentAccounts(view);
  view.accounts[0].response_test={status:"checking"};renderAgentAccounts(view);
 });
 await expect(page.locator('[data-agent-response-test="two"]')).toBeDisabled();
 await page.evaluate(()=>{agentAccountsView.accounts[0].response_test={status:"verified",model:"test-model"};renderAgentAccounts(agentAccountsView);});
 await expect(page.locator('[data-agent-response-test="one"]')).toBeEnabled();
 await expect(page.locator('[data-agent-response-test="two"]')).toBeEnabled();
});
