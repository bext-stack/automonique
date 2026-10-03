// SPDX-License-Identifier: Elastic-2.0
import {test,expect} from '@playwright/test';
import {readFile} from 'node:fs/promises';
let calls,histories,current,turnResponse,delayTurn,releaseTurn,refuse;
const now=Date.now();
const message=(id,role,content)=>({id,role,content,created_at_ms:now+id});
test.beforeEach(async({page})=>{
 calls=[];current='chat-one';delayTurn=null;refuse=false;
 histories={'chat-one':{conversation_id:'chat-one',messages:[message(1,'user','Help me plan a website'),message(2,'assistant','## A clear plan\n\nStart with **the audience**.\n\n```js\nconst safe = "<script>";\n```\n\n<img src=x onerror=alert(1)>')],pending_actions:[],has_more:false},'chat-two':{conversation_id:'chat-two',messages:[message(4,'user','A second project'),message(5,'assistant','A retained reply')],pending_actions:[],has_more:false}};
 turnResponse={answer:'A useful answer',conversation_id:'chat-one',profile:'conversation',duration_ms:400,live_sources:[],memory_evidence:0};
 const files=Object.fromEntries(await Promise.all(['dashboard.html','dashboard.css','dashboard.js','platform-cockpit-core.js'].map(async name=>[name,await readFile(new URL(`../../assets/${name}`,import.meta.url),'utf8')])));
 await page.route('**/*',async route=>{
  const path=new URL(route.request().url()).pathname;
  if(path==='/')return route.fulfill({contentType:'text/html',body:files['dashboard.html']});
  if(path.startsWith('/assets/'))return route.fulfill({contentType:path.endsWith('.css')?'text/css':'text/javascript',body:files[path.split('/').pop()]||''});
  if(path==='/api/chat/history')return route.fulfill({json:histories[current] || {conversation_id:null,messages:[],pending_actions:[]}});
  if(path==='/api/chat/conversations')return route.fulfill({json:{current_id:current,items:[{id:'chat-one',title:'Website plan',updated_at_ms:now},{id:'chat-two',title:'Second project',updated_at_ms:now-86400000}]}});
  if(path==='/api/chat/conversations/action'){
   const request=route.request().postDataJSON();calls.push(request);
   if(request.action==='select'){current=request.id;return route.fulfill({json:histories[current]});}
   if(request.action==='older')return route.fulfill({json:{conversation_id:current,messages:[message(0,'user','An earlier question')],has_more:false}});
  }
  if(path==='/api/chat/new'){calls.push(route.request().postDataJSON());current=null;return route.fulfill({json:{conversation_id:null,messages:[],pending_actions:[],has_more:false}});}
  if(path==='/api/chat'){
   calls.push(route.request().postDataJSON());if(delayTurn)await delayTurn;
   return refuse?route.fulfill({status:409,json:{error:'chat_conversation_changed'}}):route.fulfill({json:turnResponse});
  }
  if(path==='/api/configuration')return route.fulfill({json:{agent_authentication:{},manage:{},providers:{},connectors:{},memory:{},governance:{},extensions:{}}});
  return route.fulfill({json:{}});
 });
 await page.goto('https://chat.test/#chat');await expect(page.locator('#chat-input')).toBeEnabled();await expect(page.locator('#chat-thread .message')).toHaveCount(2);
});
async function history(page){if(!await page.locator('#chat-history-search').isVisible())await page.locator('#chat-history-toggle').click();}

test('conversation switching preserves drafts and never sends a message',async({page})=>{
 await page.locator('#chat-input').fill('Unsent idea');await history(page);await page.locator('[data-conversation-id="chat-two"]').click();
 await expect(page.locator('#chat-thread')).toContainText('A retained reply');await expect(page.locator('#chat-input')).toHaveValue('');
 await history(page);await page.locator('[data-conversation-id="chat-one"]').click();await expect(page.locator('#chat-input')).toHaveValue('Unsent idea');
 expect(calls).toEqual([{action:'select',id:'chat-two',expected_conversation:'chat-one'},{action:'select',id:'chat-one',expected_conversation:'chat-two'}]);
});
test('search and new chat keep previous conversations reachable',async({page})=>{
 await history(page);await page.locator('#chat-history-search').fill('second');await expect(page.locator('.chat-history-item')).toHaveCount(1);await page.locator('#chat-history-search').fill('');
 await page.locator('#new-chat').click();await expect(page.locator('#chat-empty')).toBeVisible();await expect(page.locator('#chat-send')).toBeDisabled();
 await history(page);await page.locator('[data-conversation-id="chat-one"]').click();await expect(page.locator('#chat-thread')).toContainText('A clear plan');
 expect(calls[0]).toEqual({expected_conversation:'chat-one'});
});
test('the composer supports multiline and IME input without accidental submits',async({page,isMobile})=>{
 const input=page.locator('#chat-input');await input.fill('First line');await input.press('Shift+Enter');await input.press('A');expect(calls).toEqual([]);
 await input.dispatchEvent('keydown',{key:'Enter',code:'Enter',isComposing:true});expect(calls).toEqual([]);
 if(isMobile){await input.press('Enter');expect(calls).toEqual([]);await page.locator('#chat-send').click();}else await input.press('Enter');
 await expect(page.locator('#chat-thread')).toContainText('A useful answer');expect(calls).toHaveLength(1);expect(calls[0].expected_conversation).toBe('chat-one');
});
test('a pending reply locks conversation changes but preserves the next draft',async({page})=>{
 delayTurn=new Promise(resolve=>releaseTurn=resolve);await page.locator('#chat-input').fill('First request');await page.locator('#chat-send').click();
 await expect(page.locator('.message.pending')).toContainText('Thinking…');await expect(page.locator('#chat-new-shortcut')).toBeDisabled();await expect(page.locator('#chat-send')).toBeDisabled();
 await page.locator('#chat-input').fill('A follow-up draft');releaseTurn();await expect(page.locator('.message.pending')).toHaveCount(0);await expect(page.locator('#chat-input')).toHaveValue('A follow-up draft');await expect(page.locator('#chat-send')).toBeEnabled();
});
test('an unsuccessful turn keeps the draft and explains a cross-tab conflict',async({page})=>{
 refuse=true;await page.locator('#chat-input').fill('Keep this question');await page.locator('#chat-send').click();
 await expect(page.locator('.message.error')).toContainText('active conversation changed');await expect(page.locator('#chat-input')).toHaveValue('Keep this question');expect(calls).toHaveLength(1);
});
test('code copying is exact and message content cannot inject HTML',async({page})=>{
 await expect(page.locator('#chat-thread img')).toHaveCount(0);await expect(page.locator('.chat-code-block code')).toHaveText('const safe = "<script>";');
 await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async value=>{window.copiedText=value;}}}));
 await page.getByRole('button',{name:'Copy code',exact:true}).click();expect(await page.evaluate(()=>window.copiedText)).toBe('const safe = "<script>";');
 await page.getByRole('button',{name:'Use again',exact:true}).click();await expect(page.locator('#chat-input')).toHaveValue('Help me plan a website');expect(calls).toEqual([]);
});
test('older messages prepend once without losing the current conversation',async({page})=>{
 histories['chat-one'].has_more=true;await page.evaluate(()=>loadChatHistory(true));await page.getByRole('button',{name:'Load earlier messages'}).click();
 await expect(page.locator('#chat-thread .message')).toHaveCount(3);await expect(page.locator('#chat-thread .message').first()).toContainText('An earlier question');await expect(page.locator('#chat-older')).toHaveCount(0);
 expect(calls).toEqual([{action:'older',id:'chat-one',before:1}]);
});
test('history on mobile traps focus and closes with Escape',async({page,isMobile})=>{
 test.skip(!isMobile,'Mobile history is an overlay.');await history(page);await expect(page.locator('#chat-history-search')).toBeFocused();
 await expect(page.locator('.chat-surface')).toHaveAttribute('inert','');await page.keyboard.press('Escape');await expect(page.locator('#chat-history')).toBeHidden();await expect(page.locator('#chat-history-toggle')).toBeFocused();
});
test('French conversation layouts keep the composer visible and content contained',async({page})=>{
 await page.evaluate(()=>localStorage.setItem('monique-language','fr'));await page.reload();await expect(page.locator('#chat-input')).toBeEnabled();
 await expect(page.locator('#chat-send')).toBeInViewport();expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 await expect(page.getByRole('button',{name:'Copier le code',exact:true})).toBeVisible();
 const box=await page.locator('#chat-form').boundingBox();expect(box.y+box.height).toBeLessThanOrEqual(page.viewportSize().height);
});

test('a new reply does not pull the reader away from earlier messages',async({page})=>{
 histories['chat-one'].messages=Array.from({length:12},(_,i)=>message(i+1,i%2?'assistant':'user',`Message ${i}\n\n`+'A useful paragraph. '.repeat(35)));
 await page.evaluate(()=>loadChatHistory(true));delayTurn=new Promise(resolve=>releaseTurn=resolve);
 await page.locator('#chat-input').fill('One more answer');await page.locator('#chat-send').click();await expect(page.locator('.message.pending')).toBeVisible();
 await page.locator('#chat-thread').evaluate(node=>node.scrollTop=0);await page.waitForFunction(()=>!chatUi.follow);releaseTurn();
 await expect(page.locator('.message.pending')).toHaveCount(0);await expect(page.locator('#chat-jump')).toBeVisible();
 expect(await page.locator('#chat-thread').evaluate(node=>node.scrollTop)).toBe(0);
 await page.locator('#chat-jump').click();await expect(page.locator('#chat-jump')).toBeHidden();
});
test('the composer enforces the server byte limit without discarding Unicode text',async({page})=>{
 const input=page.locator('#chat-input');await input.fill('é'.repeat(4100));await expect(page.locator('#chat-send')).toBeDisabled();await expect(input).toHaveValue('é'.repeat(4100));
 await input.fill('A short question');await expect(page.locator('#chat-send')).toBeEnabled();expect(calls).toEqual([]);
});
test('a pending approval stays explicit and carries its conversation identity',async({page})=>{
 histories['chat-one'].pending_actions=[{id:'approval-one',title:'Update a sample record',detail:'A specific proposed change',kind:'manage',impact:'Changes the sample record.'}];
 await page.route('**/api/chat/action',async route=>{calls.push(route.request().postDataJSON());await route.fulfill({json:{answer:'The approved action finished.',duration_ms:20,live_sources:[]}});});
 await page.evaluate(()=>loadChatHistory(true));expect(calls).toEqual([]);await expect(page.locator('.action-card')).toContainText('APPROVAL REQUIRED');
 await page.getByRole('button',{name:'Approve and run',exact:true}).click();await expect(page.locator('#chat-thread')).toContainText('The approved action finished.');
 expect(calls).toEqual([{action_id:'approval-one',decision:'approve',expected_conversation:'chat-one'}]);
});

test('reloading after a conversation conflict preserves the unsent question',async({page})=>{
 refuse=true;await page.locator('#chat-input').fill('Keep my question');await page.locator('#chat-send').click();await expect(page.locator('.message.error')).toBeVisible();
 current='chat-two';await page.locator('.message.error').getByRole('button',{name:'Reload conversation'}).click();
 await expect(page.locator('#chat-thread')).toContainText('A retained reply');await expect(page.locator('#chat-input')).toHaveValue('Keep my question');
});
