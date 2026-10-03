// SPDX-License-Identifier: Elastic-2.0
import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
const id='abcdefghijklmnopqrstuvwx';
const content='<!doctype html><html><style>body{background:rgb(245, 245, 240)}</style><h1>Verified report</h1><button onclick="this.textContent=\'Changed\'">Interactive preview</button><script>try{parent.document.body.dataset.compromised="yes"}catch(e){document.body.dataset.isolated="yes"}</script></html>';
let artifact, calls;
test.beforeEach(async({page})=>{
 calls=[];artifact={id,title:'Website delivery',description:'Verified changes and evidence',project:'Website',run_id:'fixture-job-0001',conversation_id:'chat-one',agent:'Example agent',visibility:'private',revision:1,can_manage:true,version_count:1,url:'/artifacts?id='+id,created_at:'2026-01-01T00:00:00Z',updated_at:'2026-01-01T00:00:00Z',versions:[{number:1,created_at:'2026-01-01T00:00:00Z',entry:'index.html',note:'Verified version',files:[{path:'index.html',type:'text/html',bytes:Buffer.byteLength(content),chunks:1}]}]};
 const names=['dashboard.html','dashboard.js','dashboard.css','platform-cockpit-core.js','artifacts.js','artifacts.css','artifact-preview.html'];const files=Object.fromEntries(await Promise.all(names.map(async n=>[n,await readFile(new URL('../../assets/'+n,import.meta.url),'utf8')])));
 await page.route('**/*',async route=>{
  const path=new URL(route.request().url()).pathname;
  if(path==='/')return route.fulfill({contentType:'text/html',body:files['dashboard.html']});
  if(path.startsWith('/assets/'))return route.fulfill({contentType:path.endsWith('.css')?'text/css':'text/javascript',body:files[path.split('/').pop()]||''});
  if(path==='/artifact-preview')return route.fulfill({contentType:'text/html',headers:{'Content-Security-Policy':"default-src 'none'; script-src 'unsafe-inline' data: blob:; style-src 'unsafe-inline' data: blob:; img-src data: blob:; media-src data: blob:; font-src data: blob:; frame-src blob: 'self'; connect-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'self'; sandbox allow-scripts"},body:files['artifact-preview.html']});
  if(path==='/api/artifacts'){
   const b=route.request().postDataJSON();calls.push(b);
   const base={public_base:'https://share.example.test'};
   if(b.action==='list')return route.fulfill({json:{...base,items:[artifact]}});
   if(b.action==='get')return route.fulfill({json:{...base,artifact}});
   if(b.action==='read')return route.fulfill({json:{...base,content_base64:Buffer.from(content).toString('base64'),bytes:Buffer.byteLength(content),sha256:createHash('sha256').update(content).digest('hex')}});
   if(b.action==='update'){if(b.revision!==artifact.revision)return route.fulfill({status:409,json:{error:'revision_conflict'}});artifact={...artifact,...b,revision:artifact.revision+1};return route.fulfill({json:{...base,artifact}});}
  }
  if(path==='/api/chat/history')return route.fulfill({json:{conversation_id:'chat-one',messages:[{id:1,role:'assistant',content:'Report: MONIQUE_ARTIFACT_ID: '+id,created_at_ms:Date.now()}]}});
  if(path==='/api/chat/conversations')return route.fulfill({json:{items:[{id:'chat-one',title:'Website',updated_at_ms:Date.now()}]}});
  return route.fulfill({json:{}});
 });
});
test('library opens a sandboxed interactive preview and edits sharing with a revision',async({page})=>{
 await page.goto('https://artifacts.test/#artifacts');await page.getByRole('button',{name:/Website delivery/}).click();
 const nested=page.frameLocator('.aw-preview > iframe').frameLocator('iframe');await expect(nested.locator('h1')).toHaveText('Verified report');await expect(nested.locator('body')).toHaveAttribute('data-isolated','yes');
 await nested.getByRole('button',{name:'Interactive preview'}).click();await expect(nested.getByRole('button')).toHaveText('Changed');expect(await page.locator('body').getAttribute('data-compromised')).toBeNull();
 await page.getByRole('combobox',{name:'Visibilité du bundle'}).selectOption('public');await expect(page.locator('.aw-badge').first()).toHaveText('Public');
 expect(calls.find(c=>c.action==='update')).toEqual({action:'update',id,revision:1,visibility:'public'});
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
});
test('conversation artifact card opens a modal and closing restores the chat',async({page})=>{
 await page.goto('https://artifacts.test/#chat');await page.getByRole('button',{name:'Open deliverable',exact:true}).click();await expect(page.locator('#artifact-dialog')).toBeVisible();await expect(page.locator('#artifact-dialog h1')).toHaveText('Website delivery');await page.locator('#artifact-dialog-close').click();await expect(page.locator('#artifact-dialog')).not.toBeVisible();await expect(page.locator('#chat-input')).toBeVisible();
});
test('new bundle form clearly defaults to private and accepts a supporting folder',async({page})=>{
 await page.goto('https://artifacts.test/#artifacts');await page.getByRole('button',{name:'Nouveau livrable'}).click();await expect(page.locator('.aw-form')).toContainText('Privé par défaut');await expect(page.locator('input[webkitdirectory]')).toBeVisible();await expect(page.getByRole('combobox',{name:'Fichier principal'})).toBeVisible();
});
test('a stale sharing edit keeps the conflict visible instead of claiming success',async({page})=>{
 await page.goto('https://artifacts.test/#artifacts');await page.getByRole('button',{name:/Website delivery/}).click();await expect(page.getByRole('combobox',{name:'Visibilité du bundle'})).toHaveValue('private');artifact.revision=2;
 await page.getByRole('combobox',{name:'Visibilité du bundle'}).selectOption('public');await expect(page.locator('.aw-error')).toContainText('Ce livrable a changé');await expect(page.locator('.aw-badge').first()).toHaveText('Privé');
});
