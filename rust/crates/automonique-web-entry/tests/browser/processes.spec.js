// SPDX-License-Identifier: Elastic-2.0
import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";

async function openProcesses(page, snapshot) {
  const files = Object.fromEntries(await Promise.all(["dashboard.html", "dashboard.css", "dashboard.js", "platform-cockpit-core.js"].map(async (name) => [name, await readFile(new URL(`../../assets/${name}`, import.meta.url), "utf8")])));
  await page.route("**/*", async (route) => {
    const { pathname } = new URL(route.request().url());
    if (pathname === "/") return route.fulfill({ contentType: "text/html", body: files["dashboard.html"] });
    if (pathname.startsWith("/assets/")) return route.fulfill({ contentType: pathname.endsWith(".css") ? "text/css" : "text/javascript", body: files[pathname.split("/").pop()] || "" });
    return route.fulfill({ json: pathname === "/api/processes" ? snapshot : {} });
  });
  await page.goto("https://processes.test/#operations");
  await page.locator('[data-process-id="fixture-job-0001"]').click();
}

function fixture(age = 0) {
  return { health: "ready", observed_at_ms: Date.now() - age,
    stats: { total: 1, running: 1, queued: 0, completed: 0, failed: 0 }, worker: {status:"online",provider:"jcode",runtime:"native",active_jobs:1,concurrency:2},
    jobs: [{ id: "fixture-job-0001", status: "running", provider: "jcode", runtime: "native",
      issue_url: "https://github.com/example/site/issues/1", assigned_to_worker: true, approved: true,
      created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T01:00:00Z", decision_count: 1,
      output: [{ at_ms: 1767229200000, kind: "tool_input", text: "Preparing the final report", truncated: false }] }] };
}

test("old snapshots never claim that an agent is currently running", async ({ page }) => {
  await openProcesses(page, fixture(2 * 60 * 60 * 1000));
  await expect(page.locator("#ops-drawer-kicker")).toHaveText("Agent run · Status unconfirmed");
  await expect(page.locator("#ops-drawer-body")).toContainText("Out-of-date snapshot");
  await expect(page.locator("#ops-drawer-body")).not.toContainText("An agent is working on this right now.");
  await expect(page.locator("#ops-drawer-body")).toContainText("Saved output · 1 events");
  await expect(page.locator("#process-running")).toHaveText("-");
  await expect(page.locator("#process-filter-active")).toHaveText("0");
});

test("a fresh completion updates an already open drawer and preserves the receipt", async ({ page }) => {
  const snapshot = fixture();
  await openProcesses(page, snapshot);
  await expect(page.locator("#ops-drawer-kicker")).toHaveText("Agent run · Running");
  snapshot.jobs[0].status = "done";
  snapshot.jobs[0].output.push({ at_ms: Date.now(), kind: "final", text: "Completed; see the GitHub report.", truncated: false });
  snapshot.stats.running = 0;
  snapshot.stats.completed = 1;
  // The drawer covers the toolbar on phones; refresh through the normal poller.
  await page.evaluate(() => loadProcesses());
  await expect(page.locator("#ops-drawer-kicker")).toHaveText("Agent run · Finished");
  await expect(page.locator("#ops-drawer-body")).toContainText("Saved output · 2 events");
  await expect(page.locator("#ops-drawer-body")).toContainText("Completed; see the GitHub report.");
  await expect(page.locator("#process-running")).toHaveText("0");
});

test("a failed refresh closes the old running drawer", async ({ page }) => {
  await openProcesses(page, fixture());
  await page.route("**/api/processes", (route) => route.fulfill({ status: 503, json: {} }));
  await page.evaluate(() => loadProcesses());
  await expect(page.locator("#ops-drawer")).not.toHaveClass(/is-open/);
  await expect(page.locator("#process-list [data-process-id]")).toHaveCount(0);
});

test("an older request cannot replace a newer completion", async ({ page }) => {
  const snapshot = fixture();
  await openProcesses(page, snapshot);
  let calls = 0;
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  await page.route("**/api/processes", async (route) => {
    if (++calls === 1) {
      await pending;
      return route.fulfill({ json: fixture() });
    }
    const completed = fixture();
    completed.jobs[0].status = "done";
    return route.fulfill({ json: completed });
  });
  await page.evaluate(() => { window.firstProcessRefresh = loadProcesses(); });
  await expect.poll(() => calls).toBe(1);
  await page.evaluate(() => loadProcesses());
  release();
  await page.evaluate(() => window.firstProcessRefresh);
  await expect(page.locator("#ops-drawer-kicker")).toHaveText("Agent run · Finished");
});

test("status checks show GitHub and worker disagreements without changing a run", async ({ page }) => {
  await openProcesses(page, fixture());
  const calls=[];
  await page.route("**/api/controls/action", route=>{
    calls.push(route.request().postDataJSON());
    return route.fulfill({json:{checked_at_ms:Date.now(),manage:{status:"running",fresh:true,observed_at_ms:Date.now(),last_activity:"2026-01-01T01:00:00Z"},github:{status:"verified",state:"closed"},worker:{status:"online",active_jobs:0},disagreement:true,issue_conflict:true,worker_conflict:true}});
  });
  await page.locator("#ops-drawer").getByRole("button",{name:"Check latest status"}).click();
  const result=page.locator('[data-run-check="fixture-job-0001"]');
  await expect(result.locator(".run-fact").filter({hasText:"GitHub"})).toContainText("Closed");
  await expect(result).toContainText("These sources disagree");
  await expect(result).toContainText("assigned worker reports no active jobs");
  expect(calls).toEqual([{action:"check_run",id:"fixture-job-0001"}]);
  await page.evaluate(()=>loadProcesses());
  await expect(result).toContainText("These sources disagree");
});

function detailedFixture() {
  const snapshot=fixture();const job=snapshot.jobs[0];
  job.status="done";job.issue_id="fixture-ticket-0001";job.manage_url="https://manage.example.test/jobs/fixture-job-0001";
  job.output=[
    {at_ms:1767229200000,kind:"tool_start",text:"started tool bash",truncated:false},
    {at_ms:1767229201000,kind:"tool_input",text:"Run the deployment checks",truncated:false},
    {at_ms:1767229202000,kind:"error",text:"Preview check needs a retry",truncated:false},
    {at_ms:1767229203000,kind:"final",text:"The page is published.\nDesktop and mobile checks passed.\n<img src=x onerror=alert(1)>",truncated:false},
  ];snapshot.stats.running=0;snapshot.worker.active_jobs=0;return snapshot;
}

test("the final response is visible first and raw tool output stays in Activity",async({page})=>{
  await openProcesses(page,detailedFixture());
  const overview=page.locator('#run-pane-overview');
  await expect(overview).toBeVisible();await expect(overview.locator('.run-outcome')).toContainText("The page is published.");
  await expect(overview.locator('img')).toHaveCount(0);
  await expect(page.locator('#run-pane-activity')).toBeHidden();
  await expect(page.locator('#run-pane-details')).toBeHidden();
  await expect(overview).not.toContainText("started tool bash");
  await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async text=>{window.copiedRunText=text;}}}));
  await overview.getByRole('button',{name:'Copy response',exact:true}).click();
  expect(await page.evaluate(()=>window.copiedRunText)).toContain('Desktop and mobile checks passed.');
});

test("activity groups tool requests, filters and searches without executing work",async({page})=>{
  await openProcesses(page,detailedFixture());await page.getByRole('tab',{name:'Activity',exact:true}).click();
  const pane=page.locator('#run-pane-activity');
  await expect(pane.locator('.run-event')).toHaveCount(3);
  await expect(pane.locator('.run-event').first()).toContainText('The page is published.');
  await pane.getByRole('combobox',{name:'Filter activity'}).selectOption('tools');
  await expect(pane.locator('.run-event')).toHaveCount(1);await expect(pane).toContainText('started tool bash');
  await pane.getByRole('searchbox').fill('no such event');await expect(pane).toContainText('No events match your search.');
  await pane.getByRole('searchbox').fill('');await pane.getByRole('combobox').selectOption('all');
  await pane.getByRole('button',{name:'Reverse activity order'}).click();await expect(pane.locator('.run-event').first()).toContainText('Run the deployment checks');
  await expect(pane).toContainText('this may not be the full history.');
});

test("polling preserves the activity tab, search focus and text selection",async({page})=>{
  const snapshot=detailedFixture();await openProcesses(page,snapshot);
  await page.getByRole('tab',{name:'Activity',exact:true}).click();
  const search=page.getByRole('searchbox',{name:'Search activity'});await search.fill('deployment');
  await search.evaluate(node=>node.setSelectionRange(2,5));
  snapshot.jobs[0].output.push({at_ms:Date.now(),kind:'lifecycle',text:'Receipt retained',truncated:false});
  await page.evaluate(()=>loadProcesses());
  await expect(page.getByRole('tab',{name:'Activity',exact:true})).toHaveAttribute('aria-selected','true');
  await expect(search).toBeFocused();await expect(search).toHaveValue('deployment');
  expect(await search.evaluate(node=>[node.selectionStart,node.selectionEnd])).toEqual([2,5]);
  await expect(page.locator('#run-pane-activity .run-event')).toHaveCount(1);
});

test("fresh running claims still need matching worker activity",async({page})=>{
  const snapshot=fixture();snapshot.worker.active_jobs=0;await openProcesses(page,snapshot);
  await expect(page.locator('#ops-drawer-kicker')).toContainText('Status unconfirmed');
  await expect(page.locator('.run-summary')).toContainText('matching worker activity is not confirmed');
  // A worker runs each job on the engine chosen for it: a Claude job on a
  // JCode worker is confirmed by that worker's activity like any other.
  snapshot.worker.active_jobs=1;snapshot.jobs[0].provider='claude';snapshot.jobs[0].runtime='unknown';await page.evaluate(()=>loadProcesses());
  await expect(page.locator('#ops-drawer-kicker')).toHaveText('Agent run · Running');
});

test("run navigation retains each run's tab and copies exact references",async({page})=>{
  const snapshot=detailedFixture();snapshot.jobs.push({...snapshot.jobs[0],id:'fixture-job-0002',issue_url:'https://github.com/example/site/issues/2',parent_id:snapshot.jobs[0].id,output:[]});
  await openProcesses(page,snapshot);await page.getByRole('tab',{name:'Details',exact:true}).click();
  await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async text=>{window.copiedRunText=text;}}}));
  await page.getByRole('button',{name:'Copy Run ID',exact:true}).click();expect(await page.evaluate(()=>window.copiedRunText)).toBe('fixture-job-0001');
  await page.getByRole('button',{name:'Next run',exact:true}).click();await expect(page.locator('#ops-drawer-title')).toHaveText('site#2');
  await expect(page.getByRole('tab',{name:'Overview',exact:true})).toHaveAttribute('aria-selected','true');
  await page.getByRole('button',{name:'Previous run',exact:true}).click();await expect(page.locator('#run-pane-details')).toBeVisible();
});

test("long events expand as text and retain their disclosure across refresh",async({page})=>{
  const snapshot=detailedFixture();snapshot.jobs[0].output[3].text='Long response. '.repeat(80);snapshot.jobs[0].output[3].truncated=true;
  await openProcesses(page,snapshot);const details=page.locator('#run-pane-overview .run-event-disclosure');
  await details.locator('summary').click();await expect(details).toHaveAttribute('open','');
  snapshot.jobs[0].updated_at='2026-01-01T02:00:00Z';await page.evaluate(()=>loadProcesses());
  await expect(details).toHaveAttribute('open','');await expect(page.locator('#run-pane-overview')).toContainText('This event was shortened at the source.');
});

test("expanded details restore the list on close",async({page,isMobile})=>{
  test.skip(isMobile,'Expansion is a desktop control.');
  await openProcesses(page,detailedFixture());const width=await page.locator('#ops-drawer').evaluate(node=>node.clientWidth);await page.getByRole('button',{name:'Expand panel',exact:true}).click();
  expect(await page.locator('#ops-drawer').evaluate(node=>node.clientWidth)).toBeGreaterThan(width);
  await expect(page.locator('#ops-drawer')).toHaveClass(/is-expanded/);await expect(page.locator('#process-list')).toBeHidden();
  await page.getByRole('button',{name:'Close details',exact:true}).click();
  await expect(page.locator('#process-list')).toBeVisible();await expect(page.locator('.has-expanded-run')).toHaveCount(0);
});

test("tabs work with a keyboard and French layouts fit the viewport",async({page})=>{
  await openProcesses(page,detailedFixture());
  const overview=page.getByRole('tab',{name:'Overview',exact:true});await overview.focus();await overview.press('ArrowRight');
  await expect(page.getByRole('tab',{name:'Activity',exact:true})).toBeFocused();await expect(page.locator('#run-pane-activity')).toBeVisible();
  await page.evaluate(()=>{localStorage.setItem('monique-language','fr');});await page.reload();await page.locator('[data-process-id="fixture-job-0001"]').click();
  await expect(page.getByRole('tab',{name:'Vue d’ensemble',exact:true})).toBeVisible();
  await expect(page.locator('.run-outcome')).toContainText('Réponse de l’agent');
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  expect(await page.locator('#ops-drawer').evaluate(node=>node.scrollWidth<=node.clientWidth)).toBe(true);
  expect(await page.locator('#ops-drawer pre:visible').evaluateAll(nodes=>nodes.some(node=>node.scrollWidth>node.clientWidth))).toBe(false);
});

test("new activity waits while the reader is scrolled into earlier events",async({page,isMobile})=>{
  test.skip(isMobile,'Phones use the page scroll rather than the panel scroll.');
  const snapshot=detailedFixture();snapshot.jobs[0].output=Array.from({length:12},(_,i)=>({at_ms:1767229200000+i*1000,kind:'tool_input',text:`Check ${i}: `+'A useful diagnostic line. '.repeat(10),truncated:false}));
  await openProcesses(page,snapshot);await page.getByRole('tab',{name:'Activity',exact:true}).click();
  await page.locator('#ops-drawer-body').evaluate(node=>{node.scrollTop=200;});
  const before=await page.locator('#ops-drawer-body').evaluate(node=>node.scrollTop);expect(before).toBeGreaterThan(100);
  snapshot.jobs[0].output=[...snapshot.jobs[0].output.slice(1),{at_ms:Date.now(),kind:'final',text:'A newly received completion',truncated:false}];
  await page.evaluate(()=>loadProcesses());
  expect(await page.locator('#ops-drawer-body').evaluate(node=>node.scrollTop)).toBe(before);
  await expect(page.locator('#run-pane-activity')).not.toContainText('A newly received completion');
  await page.getByRole('button',{name:'Show new activity',exact:true}).click();
  await expect(page.locator('#run-pane-activity .run-event').first()).toContainText('A newly received completion');
});

test("a terminal status with no receipt never invents a completion report",async({page})=>{
  const snapshot=detailedFixture();snapshot.jobs[0].output=[];await openProcesses(page,snapshot);
  await expect(page.locator('#run-pane-overview')).toContainText('No final response is included in this snapshot.');
  snapshot.jobs[0].status='failed';await page.evaluate(()=>loadProcesses());
  await expect(page.locator('#run-pane-overview')).toContainText('No failure details are included in this snapshot.');
  await expect(page.locator('#run-pane-overview').getByRole('button',{name:'Copy response'})).toHaveCount(0);
});

test("opening a run on a phone keeps its title and close control below navigation",async({page,isMobile})=>{
  test.skip(!isMobile,'The mobile panel opens in the page flow.');
  await openProcesses(page,detailedFixture());
  await expect.poll(async()=>{
    const head=await page.locator('#ops-drawer .drawer-head').boundingBox();
    const navigation=await page.locator('.topbar').boundingBox();
    return head.y>=navigation.y+navigation.height;
  }).toBe(true);
});
