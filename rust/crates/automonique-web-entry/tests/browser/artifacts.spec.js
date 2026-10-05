// SPDX-License-Identifier: Elastic-2.0
import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
const id='abcdefghijklmnopqrstuvwx';
const content='<!doctype html><html><style>body{background:rgb(245, 245, 240)}</style><h1>Verified report</h1><button onclick="this.textContent=\'Changed\'">Interactive preview</button><script>try{parent.document.body.dataset.compromised="yes"}catch(e){document.body.dataset.isolated="yes"}</script></html>';
let artifact, calls, extra;
test.beforeEach(async({page})=>{
 calls=[];extra=[];artifact={id,title:'Website delivery',description:'Verified changes and evidence',project:'Website',run_id:'fixture-job-0001',conversation_id:'chat-one',agent:'Example agent',visibility:'private',revision:1,can_manage:true,version_count:1,url:'/artifacts?id='+id,created_at:'2026-01-01T00:00:00Z',updated_at:'2026-01-01T00:00:00Z',versions:[{number:1,created_at:'2026-01-01T00:00:00Z',entry:'index.html',note:'Verified version',files:[{path:'index.html',type:'text/html',bytes:Buffer.byteLength(content),chunks:1}]}]};
 const names=['dashboard.html','dashboard.js','dashboard.css','platform-cockpit-core.js','artifacts.js','artifacts.css','artifact-preview.html'];const files=Object.fromEntries(await Promise.all(names.map(async n=>[n,await readFile(new URL('../../assets/'+n,import.meta.url),'utf8')])));
 await page.route('**/*',async route=>{
  const path=new URL(route.request().url()).pathname;
  if(path==='/')return route.fulfill({contentType:'text/html',body:files['dashboard.html']});
  if(path.startsWith('/assets/'))return route.fulfill({contentType:path.endsWith('.css')?'text/css':'text/javascript',body:files[path.split('/').pop()]||''});
  if(path==='/artifact-preview')return route.fulfill({contentType:'text/html',headers:{'Content-Security-Policy':"default-src 'none'; script-src 'unsafe-inline' data: blob:; style-src 'unsafe-inline' data: blob:; img-src data: blob:; media-src data: blob:; font-src data: blob:; frame-src blob: 'self'; connect-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'self'; sandbox allow-scripts"},body:files['artifact-preview.html']});
  if(path==='/api/artifacts'){
   const b=route.request().postDataJSON();calls.push(b);
   const base={public_base:'https://share.example.test'};
   if(b.action==='list')return route.fulfill({json:{...base,items:[artifact,...extra]}});
   if(b.action==='get')return route.fulfill({json:{...base,artifact:extra.find(a=>a.id===b.id)||artifact}});
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
 await page.getByRole('button',{name:'Partager',exact:true}).click();await page.getByRole('combobox',{name:'Visibilité du bundle'}).selectOption('public');await expect(page.locator('.aw-badge').first()).toHaveText('Public');
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
 await page.goto('https://artifacts.test/#artifacts');await page.getByRole('button',{name:/Website delivery/}).click();await page.getByRole('button',{name:'Partager',exact:true}).click();await expect(page.getByRole('combobox',{name:'Visibilité du bundle'})).toHaveValue('private');artifact.revision=2;
 await page.getByRole('button',{name:'Partager',exact:true}).click();await page.getByRole('combobox',{name:'Visibilité du bundle'}).selectOption('public');await expect(page.locator('.aw-error')).toContainText('Ce livrable a changé');await expect(page.locator('.aw-badge').first()).toHaveText('Privé');
});
test('large bundles keep the file list compact and let users find any attachment',async({page})=>{
 artifact.versions[0].files.push(...Array.from({length:40},(_,i)=>({path:`evidence/check-${i}.txt`,type:'text/plain',bytes:0,chunks:0})));
 await page.goto('https://artifacts.test/#artifacts');await page.getByRole('button',{name:/Website delivery/}).click();await expect(page.locator('.aw-file')).toHaveCount(8);await page.getByRole('button',{name:'Afficher ou masquer les fichiers',exact:true}).click();await page.getByRole('searchbox',{name:'Rechercher un fichier'}).fill('check-39');await expect(page.locator('.aw-file')).toHaveCount(1);await expect(page.locator('.aw-file')).toContainText('check-39.txt');
});

test('preview tools preserve selection and expose source without executing it',async({page})=>{
 await page.goto('https://artifacts.test/#artifacts');await page.getByRole('button',{name:/Website delivery/}).click();
 await page.getByRole('button',{name:'Code',exact:true}).click();await expect(page.locator('.aw-preview pre')).toContainText('parent.document');
 expect(await page.locator('body').getAttribute('data-compromised')).toBeNull();
 await page.getByRole('button',{name:'Aperçu',exact:true}).click();await expect(page.locator('.aw-preview > iframe')).toBeVisible();
 await page.getByRole('button',{name:'Mobile',exact:true}).click();await expect(page.locator('.aw-preview')).toHaveClass(/aw-mobile-preview/);
 await page.getByRole('button',{name:'Afficher ou masquer les fichiers',exact:true}).click();await expect(page.locator('.aw-aside')).toBeVisible();await page.getByRole('button',{name:'Fermer le panneau du livrable'}).click();await expect(page.locator('.aw-aside')).not.toBeVisible();
 await page.getByRole('button',{name:'Partager',exact:true}).click();await expect(page.getByRole('combobox',{name:'Visibilité du bundle'})).toBeVisible();await expect(page.getByRole('tab',{name:'Partage',exact:true})).toBeFocused();
 await page.getByRole('tab',{name:'Partage',exact:true}).press('ArrowLeft');await expect(page.getByRole('tab',{name:'Versions',exact:true})).toHaveAttribute('aria-selected','true');
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
});
test('library filters can be reset and search survives opening a report',async({page})=>{
 await page.goto('https://artifacts.test/#artifacts');await page.getByRole('button',{name:/Publics/}).click();await expect(page.locator('.aw-empty')).toContainText('Aucun livrable trouvé');
 await page.getByRole('button',{name:'Effacer les filtres'}).click();await expect(page.locator('.aw-row')).toHaveCount(1);
 await page.getByRole('searchbox',{name:'Rechercher les livrables'}).fill('Website');await page.getByRole('button',{name:/Website delivery/}).click();await page.getByRole('button',{name:'← Tous les livrables'}).click();await expect(page.getByRole('searchbox',{name:'Rechercher les livrables'})).toHaveValue('Website');
});
test('version history opens the requested version and new uploads inherit access',async({page})=>{
 artifact.versions.push({...artifact.versions[0],number:2,note:'Second iteration',created_at:'2026-01-02T00:00:00Z'});artifact.version_count=2;
 await page.goto('https://artifacts.test/#artifacts');await page.getByRole('button',{name:/Website delivery/}).click();await page.getByRole('button',{name:'Afficher ou masquer les fichiers',exact:true}).click();await page.getByRole('tab',{name:'Versions',exact:true}).click();
 await expect(page.getByRole('combobox',{name:'Version du livrable'})).toHaveValue('2');await page.getByRole('combobox',{name:'Version du livrable'}).selectOption('1');await expect(page.locator('.aw-version.aw-active')).toContainText('Version 1');await expect.poll(()=>calls.filter(c=>c.action==='read').at(-1)?.version).toBe(1);
 await page.getByRole('button',{name:'＋ Nouvelle version'}).click();await expect(page.locator('.aw-form')).toContainText('La visibilité actuelle');
});
test('the workspace follows host themes without losing contrast',async({page})=>{
 await page.goto('https://artifacts.test/#artifacts');await page.getByRole('button',{name:/Website delivery/}).click();
 for(const theme of ['light','dark','sand','contrast']){
  await page.evaluate(theme=>document.documentElement.dataset.theme=theme,theme);
  const colors=await page.locator('.aw-download-all').first().evaluate(e=>{const s=getComputedStyle(e);const sample=document.createElement('span');sample.style.background='var(--panel)';e.append(sample);const bg=getComputedStyle(sample).backgroundColor;sample.remove();return {background:s.backgroundColor,foreground:s.color,host:bg};});
  expect(colors.background).toBe(colors.host);expect(colors.foreground).not.toBe(colors.background);
 }
});
test('upload shows selected files, locks edits during transfer and publishes privately',async({page})=>{
 let releaseChunk;const chunkReady=new Promise(resolve=>releaseChunk=resolve);let manifest;
 await page.route('**/api/artifacts',async route=>{
  const b=route.request().postDataJSON();
  if(b.action==='begin'){manifest=b;return route.fulfill({json:{draft_id:'draft',chunk_bytes:1048576}});}
  if(b.action==='chunk'){await chunkReady;return route.fulfill({json:{ok:true}});}
  if(b.action==='commit')return route.fulfill({json:{artifact}});
  return route.fallback();
 });
 await page.goto('https://artifacts.test/#artifacts');await page.getByRole('button',{name:'Nouveau livrable'}).click();
 await page.getByLabel('Titre',{exact:true}).fill('A report');await page.getByLabel('Choisir des fichiers',{exact:true}).setInputFiles({name:'index.html',mimeType:'text/html',buffer:Buffer.from(content)});
 await expect(page.locator('.aw-upload-zone')).toContainText('1 fichiers');await expect(page.getByRole('combobox',{name:'Fichier principal'})).toHaveValue('index.html');
 await page.getByRole('button',{name:'Créer le livrable'}).click();await expect(page.getByRole('button',{name:'Annuler',exact:true})).toBeDisabled();await expect(page.getByLabel('Choisir des fichiers',{exact:true})).toBeDisabled();
 expect(manifest.title).toBe('A report');expect(manifest.visibility).toBeUndefined();expect(manifest.entry).toBe('index.html');releaseChunk();
 await expect(page.locator('.aw-details-title h1')).toHaveText('Website delivery');await expect(page.locator('.aw-badge')).toHaveText('Privé');
});

test('deliverable navigation respects filters and keeps separate revision drafts',async({page})=>{
 extra=[{...artifact,id:'bcdefghijklmnopqrstuvwxy',title:'Website proposal',updated_at:'2026-01-02T00:00:00Z'},{...artifact,id:'cdefghijklmnopqrstuvwxyz',title:'Other report',project:'Other'}];
 await page.goto('https://artifacts.test/#artifacts');await page.getByRole('searchbox',{name:'Rechercher les livrables'}).fill('Website');await page.getByRole('combobox',{name:'Trier les livrables'}).selectOption('title');await page.getByRole('button',{name:/Website delivery/}).click();
 await expect(page.getByRole('button',{name:'Livrable précédent',exact:true})).toBeDisabled();expect(await page.locator('.aw-topbar').evaluate(bar=>[...bar.querySelectorAll('button,select')].every(e=>{const r=e.getBoundingClientRect();return !r.width||!r.height||(r.left>=0&&r.right<=innerWidth+1);}))).toBe(true);await expect(page.getByRole('combobox',{name:'Choisir un livrable'}).locator('option')).toHaveCount(2);
 await page.getByRole('button',{name:'Demander à Monique',exact:true}).click();await page.getByRole('textbox',{name:'Modifications à demander à Monique'}).fill('Change the heading');
 await page.getByRole('button',{name:'Livrable suivant',exact:true}).click();await expect(page.locator('.aw-details-title h1')).toHaveText('Website proposal');await expect(page.getByRole('button',{name:'Livrable suivant',exact:true})).toBeDisabled();await page.getByRole('button',{name:'Demander à Monique',exact:true}).click();await expect(page.getByRole('textbox',{name:'Modifications à demander à Monique'})).toHaveValue('');
 await page.getByRole('button',{name:'Livrable précédent',exact:true}).click();await page.getByRole('button',{name:'Demander à Monique',exact:true}).click();await expect(page.getByRole('textbox',{name:'Modifications à demander à Monique'})).toHaveValue('Change the heading');
 await page.getByRole('button',{name:'← Tous les livrables'}).click();await expect(page.getByRole('searchbox',{name:'Rechercher les livrables'})).toHaveValue('Website');expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
});
test('inline revision pins source version and file, retries the same job key and shows durable progress',async({page})=>{
 let requests=[],fail=true,state='queued';const jobId='a'.repeat(32);
 await page.route('**/api/integrations',route=>{const body=route.request().postDataJSON();if(body.action==='submit'){requests.push(body);if(fail)return route.fulfill({status:503,json:{error:{code:'service_unavailable'}}});}return route.fulfill({json:{job:{id:jobId,state,...(state==='succeeded'?{result:{artifact_id:id,version:3}}:{})}}});});
 artifact.versions.push({...artifact.versions[0],number:2,note:'New version'});artifact.version_count=2;artifact.versions[0].files.push({path:'styles.css',type:'text/css',bytes:0,chunks:0});
 await page.goto('https://artifacts.test/#artifacts?artifact='+id+'&revise=1');await expect(page.getByRole('tab',{name:'Monique',exact:true})).toHaveAttribute('aria-selected','true');
 await page.getByRole('tab',{name:'Versions',exact:true}).click();await page.getByRole('combobox',{name:'Version du livrable'}).selectOption('1');await page.getByRole('tab',{name:'Fichiers',exact:true}).click();await page.locator('.aw-file>button:first-child').filter({hasText:'styles.css'}).click();await page.getByRole('button',{name:'Demander à Monique',exact:true}).click();
 const input=page.getByRole('textbox',{name:'Modifications à demander à Monique'});await input.fill('Make the heading clearer');await page.getByRole('button',{name:'Envoyer à Monique',exact:true}).click();await expect(page.locator('.aw-revise-composer [role=alert]')).toBeVisible();await expect(input).toHaveValue('Make the heading clearer');
 fail=false;await page.getByRole('button',{name:'Envoyer à Monique',exact:true}).click();await expect(page.locator('.aw-revise-message.assistant')).toContainText('Demande enregistrée');await expect(input).toHaveValue('');expect(requests).toHaveLength(2);expect(requests[0].idempotency_key).toBe(requests[1].idempotency_key);expect(requests[1]).toMatchObject({artifact_id:id,version:1,path:'styles.css',prompt:'Make the heading clearer'});
 state='succeeded';await expect(page.getByRole('button',{name:'Afficher la version 3'})).toBeVisible({timeout:10000});
});
test('revision cannot double-send and retains its result when switching deliverables',async({page})=>{
 extra=[{...artifact,id:'bcdefghijklmnopqrstuvwxy',title:'Second delivery'}];let finish;const pending=new Promise(resolve=>finish=resolve);let requests=0;
 await page.route('**/api/integrations',async route=>{const b=route.request().postDataJSON();if(b.action==='submit'){requests++;await pending;}return route.fulfill({json:{job:{id:'b'.repeat(32),state:'queued'}}});});
 await page.goto('https://artifacts.test/#artifacts');await page.getByRole('button',{name:/Website delivery/}).click();await page.getByRole('button',{name:'Demander à Monique',exact:true}).click();await page.getByRole('textbox',{name:'Modifications à demander à Monique'}).fill('Improve the layout');await page.getByRole('button',{name:'Envoyer à Monique',exact:true}).click();await expect(page.getByRole('button',{name:'Envoyer à Monique',exact:true})).toBeDisabled();
 await page.getByRole('combobox',{name:'Choisir un livrable'}).selectOption(extra[0].id);await expect(page.locator('.aw-details-title h1')).toHaveText('Second delivery');finish();await expect.poll(()=>requests).toBe(1);
 await page.getByRole('combobox',{name:'Choisir un livrable'}).selectOption(id);await page.getByRole('button',{name:'Demander à Monique',exact:true}).click();await expect(page.locator('.aw-revise-message.assistant')).toContainText('Demande enregistrée');expect(requests).toBe(1);
});

test('compact reader fills the viewport, has one document toolbar and preserves drafts when closed',async({page})=>{
 await page.goto('https://artifacts.test/#artifacts?artifact='+id);const frame=page.frameLocator('.aw-preview>iframe');await expect(frame.frameLocator('iframe').locator('h1')).toHaveText('Verified report');await expect(page.locator('.aw-aside')).not.toBeVisible();await expect(page.locator('.aw-topbar .aw-preview-toolbar')).toHaveCount(1);await expect(page.locator('.aw-stage>.aw-preview-toolbar')).toHaveCount(0);
 const geometry=await page.locator('.aw-preview').evaluate(e=>({left:e.getBoundingClientRect().left,right:e.getBoundingClientRect().right,bottom:e.getBoundingClientRect().bottom,width:innerWidth,height:innerHeight,scroll:document.documentElement.scrollHeight}));expect(geometry.left).toBe(0);expect(geometry.right).toBe(geometry.width);expect(Math.abs(geometry.bottom-geometry.height)).toBeLessThan(2);expect(geometry.scroll).toBeLessThanOrEqual(geometry.height+1);
 expect(await frame.locator('body').evaluate(()=>document.documentElement.scrollHeight<=innerHeight)).toBe(true);
 await page.getByRole('button',{name:'Demander à Monique',exact:true}).click();const input=page.getByRole('textbox',{name:'Modifications à demander à Monique'});await input.fill('Keep this draft');await input.press('Escape');await expect(page.locator('.aw-aside')).not.toBeVisible();await page.getByRole('button',{name:'Demander à Monique',exact:true}).click();await expect(input).toHaveValue('Keep this draft');await page.getByRole('button',{name:'Fermer le panneau du livrable'}).click();
 await page.getByRole('button',{name:'← Tous les livrables',exact:true}).click();await expect(page.locator('.aw-row')).toHaveCount(1);await expect(page.locator('#artifact-library')).not.toHaveClass(/aw-detail-open/);
});
