/* Shared Share / Monique artifact workspace. No service credentials in the browser. */
(function(){
'use strict';
const errors={sharing_pending:'Le changement de visibilité n’est pas terminé. Réessayez le même réglage.',invalid_request:'Choisissez un titre et au moins un fichier.',unauthorized:'Connectez-vous pour retrouver vos livrables.',not_found:'Ce livrable est privé, supprimé ou inaccessible avec ce compte.',revision_conflict:'Ce livrable a changé. Rechargez-le avant de réessayer.',storage_unavailable:'Le stockage est indisponible. Réessayez dans un instant.',incomplete_upload:'Le transfert est incomplet. Réessayez la publication.',artifacts_not_configured:'Le service de livrables n’est pas encore configuré.',upload_conflict:'Le transfert a changé. Réessayez.',request_failed:'La requête a échoué.'};
function el(tag,text,cls){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;}
function bytes(n){return n<1024?n+' o':n<1048576?(n/1024).toFixed(0)+' Ko':(n/1048576).toFixed(1)+' Mo';}
function date(s){return new Date(s).toLocaleDateString('fr-FR',{day:'numeric',month:'short',year:'numeric'});}
function kind(f){const p=(f&&f.path||'').split('.').pop().toUpperCase();return p.length<7?p:'FICHIER';}
function inferType(path,type){return type||({'html':'text/html','htm':'text/html','css':'text/css','js':'text/javascript','md':'text/markdown','json':'application/json','svg':'image/svg+xml','txt':'text/plain','csv':'text/csv'}[path.split('.').pop().toLowerCase()]||'application/octet-stream');}
function mount(root,options){
 root.classList.add('aw');let items=[],current=null,version=0,selected='',urls=[],generation=0,query='',filter='all',typeFilter='all',projectFilter='all',fileQuery='',fileLimit=8;
 const api=async body=>{const result=await options.api(body);if(result.public_base)options.publicBase=result.public_base;return result;};
 function cleanup(){generation++;urls.forEach(u=>URL.revokeObjectURL(u));urls=[];}
 function objectUrl(blob){const u=URL.createObjectURL(blob);urls.push(u);return u;}
 function error(e){const prior=root.querySelector('.aw-error');if(prior)prior.remove();const n=el('p',errors[e.message]||'Impossible de terminer cette action. Réessayez.','aw-error');n.setAttribute('role','alert');root.prepend(n);}
 function button(label,fn,cls){const n=el('button',label,cls);n.type='button';n.addEventListener('click',async()=>{n.disabled=true;try{await fn();}catch(e){error(e);}finally{n.disabled=false;}});return n;}
 function link(label,href){const a=el('a',label,'aw-link');a.href=href;a.target='_blank';a.rel='noopener noreferrer';return a;}
 function badge(a){return el('span',a.visibility==='public'?'Public':'Privé','aw-badge'+(a.visibility==='public'?' aw-public':''));}
 function select(values,value,fn,label){const s=el('select');s.setAttribute('aria-label',label);values.forEach(([v,t])=>{const o=el('option',t);o.value=v;s.append(o);});s.value=value;s.addEventListener('change',()=>fn(s.value));return s;}
 function heading(title,subtitle){const head=el('div',undefined,'aw-head');const text=el('div');text.append(el('h1',title),el('p',subtitle,'aw-sub'));head.append(text);return head;}
 async function reload(){const d=await api({action:'list'});items=d.items||[];library();}
 function library(){cleanup();current=null;root.replaceChildren();const head=heading('Livrables','Rapports, documents et créations, réunis avec leurs versions.');head.append(button('Nouveau livrable',()=>uploadForm(), 'aw-primary'));root.append(head);
 const toolbar=el('div',undefined,'aw-toolbar');const search=el('input');search.type='search';search.placeholder='Rechercher un titre, un ticket, un agent…';search.setAttribute('aria-label','Rechercher les livrables');search.value=query;
 const list=el('div',undefined,'aw-list'),count=el('span',undefined,'aw-search-count');
 function draw(){list.replaceChildren();const found=items.filter(a=>(filter==='all'||a.visibility===filter)&&(projectFilter==='all'||a.project===projectFilter)&&(typeFilter==='all'||kind(a.versions[0]?.files.find(f=>f.path===a.versions[0].entry))===typeFilter)&&[a.title,a.description,a.project,a.issue_url,a.agent,a.run_id,date(a.updated_at)].join(' ').toLowerCase().includes(query.toLowerCase()));count.textContent=found.length+' livrable'+(found.length>1?'s':'');
 if(!found.length){const empty=el('div',undefined,'aw-empty');empty.append(el('h2',items.length?'Aucun résultat':'Votre prochain livrable commence ici'),el('p',items.length?'Essayez une autre recherche.':'Importez un rapport et ses fichiers. Il restera privé jusqu’à ce que vous décidiez de le partager.'));list.append(empty);return;}
 found.forEach(a=>{const row=el('div',undefined,'aw-row'),v=a.versions[0],f=v&&v.files.find(f=>f.path===v.entry);const open=button('',()=>load(a.id));open.append(el('strong',a.title),el('span',[a.project,a.agent,'v'+a.version_count,date(a.updated_at),v?.files.length+' fichiers'].filter(Boolean).join(' · '),'aw-meta'));row.append(el('span',kind(f),'aw-icon'),open,badge(a));list.append(row);});}
 search.addEventListener('input',()=>{query=search.value;draw();});toolbar.append(search,select([['all','Toute visibilité'],['private','Privés'],['public','Publics']],filter,v=>{filter=v;draw();},'Visibilité'));
 const projects=[...new Set(items.map(a=>a.project).filter(Boolean))].sort(),types=[...new Set(items.map(a=>kind(a.versions[0]?.files.find(f=>f.path===a.versions[0].entry))))].sort();
 if(projects.length)toolbar.append(select([['all','Tous les projets'],...projects.map(v=>[v,v])],projectFilter,v=>{projectFilter=v;draw();},'Projet'));
 if(types.length>1)toolbar.append(select([['all','Tous les formats'],...types.map(v=>[v,v])],typeFilter,v=>{typeFilter=v;draw();},'Format'));
 toolbar.append(count,button('Actualiser',reload));root.append(toolbar,list);draw();}
 async function load(id){cleanup();const d=await api({action:'get',id});current=d.artifact;version=current.versions.at(-1).number;selected=current.versions.at(-1).entry;detail();const heading=root.querySelector("h1");if(heading){heading.tabIndex=-1;heading.focus({preventScroll:true});}const dialog=root.closest("dialog");if(dialog)dialog.scrollTop=0;else window.scrollTo({top:0,behavior:"instant"});options.onOpen?.(current);}
 async function fileBytes(a,v,f){const pieces=[];for(let i=0;i<f.chunks;i++){const d=await api({action:'read',id:a.id,version:v,path:f.path,index:i});const raw=atob(d.content_base64);const b=Uint8Array.from(raw,c=>c.charCodeAt(0));if(b.length!==d.bytes)throw new Error('request_failed');if(globalThis.crypto?.subtle){const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',b))).map(x=>x.toString(16).padStart(2,'0')).join('');if(hash!==d.sha256)throw new Error('request_failed');}pieces.push(b);}return new Blob(pieces,{type:f.type});}
 async function downloadBundle(a,v){
  // Store-mode ZIP: no dependency or server-side public copy is needed.
  const local=[],central=[];let offset=0;const encoder=new TextEncoder();
  function record(size){const bytes=new Uint8Array(size);return {bytes,view:new DataView(bytes.buffer)};}
  function crc(bytes){let c=0xffffffff;for(const b of bytes){c^=b;for(let j=0;j<8;j++)c=(c>>>1)^((c&1)?0xedb88320:0);}return (c^0xffffffff)>>>0;}
  for(const f of v.files){const data=new Uint8Array(await (await fileBytes(a,v.number,f)).arrayBuffer()),name=encoder.encode(f.path),sum=crc(data),h=record(30+name.length),d=h.view;d.setUint32(0,0x04034b50,true);d.setUint16(4,20,true);d.setUint16(6,0x0800,true);d.setUint32(14,sum,true);d.setUint32(18,data.length,true);d.setUint32(22,data.length,true);d.setUint16(26,name.length,true);h.bytes.set(name,30);local.push(h.bytes,data);
   const c=record(46+name.length),cv=c.view;cv.setUint32(0,0x02014b50,true);cv.setUint16(4,20,true);cv.setUint16(6,20,true);cv.setUint16(8,0x0800,true);cv.setUint32(16,sum,true);cv.setUint32(20,data.length,true);cv.setUint32(24,data.length,true);cv.setUint16(28,name.length,true);cv.setUint32(42,offset,true);c.bytes.set(name,46);central.push(c.bytes);offset+=h.bytes.length+data.length;
  }
  const end=record(22),d=end.view;d.setUint32(0,0x06054b50,true);d.setUint16(8,v.files.length,true);d.setUint16(10,v.files.length,true);d.setUint32(12,central.reduce((sum,c)=>sum+c.length,0),true);d.setUint32(16,offset,true);
  const anchor=el('a');anchor.href=objectUrl(new Blob([...local,...central,end.bytes],{type:'application/zip'}));anchor.download=(a.title.replace(/[^a-zA-Z0-9_-]+/g,'-').slice(0,90)||'livrable')+'-v'+v.number+'.zip';anchor.click();
 }
 async function download(a,v,f){const blob=await fileBytes(a,v,f);const href=objectUrl(blob),anchor=el('a');anchor.href=href;anchor.download=f.path.split('/').pop();anchor.click();}
 async function preview(box,a,v,f){const token=++generation;box.replaceChildren(el('p','Chargement de l’aperçu…','aw-sub'));try{
 if(f.bytes>32*1048576){box.replaceChildren(el('p','Téléchargez ce fichier pour le consulter ('+bytes(f.bytes)+').','aw-sub'));return;}
 const blob=await fileBytes(a,v.number,f);if(token!==generation)return;
 const html=/\.html?$/i.test(f.path)||f.type==='text/html';
 if(html){
 async function dataUrl(blob){const data=new Uint8Array(await blob.arrayBuffer());let raw='';for(let i=0;i<data.length;i+=32768)raw+=String.fromCharCode(...data.subarray(i,i+32768));return 'data:'+(blob.type||'application/octet-stream')+';base64,'+btoa(raw);}
 const files=[];let budget=32*1048576-f.bytes;
 for(const dep of v.files){if(dep.path===f.path||dep.bytes>budget||dep.bytes>8*1048576)continue;budget-=dep.bytes;const data=await fileBytes(a,v.number,dep);if(token!==generation)return;files.push({path:dep.path,type:dep.type,url:await dataUrl(data),text:/\.(css|js)$/i.test(dep.path)||/javascript|text\/css/.test(dep.type)?await data.text():''});}
 const htmlText=await blob.text();if(token!==generation)return;
 const frame=el('iframe');frame.title=a.title+' — aperçu isolé';frame.setAttribute('sandbox','allow-scripts');frame.referrerPolicy='no-referrer';frame.src=options.previewUrl;
 frame.addEventListener('load',()=>frame.contentWindow?.postMessage({type:'artifact-preview',html:htmlText,files,entry:f.path},'*'),{once:true});box.replaceChildren(frame);
 }else if(f.type.startsWith('image/')&&f.type!=='image/svg+xml'){const img=el('img');img.alt=f.path;img.src=objectUrl(blob);box.replaceChildren(img);}
 else if(f.type.startsWith('video/')||f.type.startsWith('audio/')){const media=el(f.type.startsWith('video/')?'video':'audio');media.controls=true;media.src=objectUrl(blob);box.replaceChildren(media);}
 else if(f.type.startsWith('text/')||/\.(json|md|csv|txt|js|css|svg)$/i.test(f.path)){box.replaceChildren(el('pre',(await blob.text()).slice(0,500000)));}
 else {const empty=el('div',undefined,'aw-empty');empty.append(el('h2',kind(f)),el('p',f.path+' · '+bytes(f.bytes)),button('Télécharger le fichier',()=>download(a,v.number,f)));box.replaceChildren(empty);}
 }catch(e){if(token===generation)box.replaceChildren(el('p',errors[e.message]||'Aperçu indisponible. Vous pouvez télécharger le fichier.','aw-error'));}}
 function detail(){cleanup();const a=current,v=a.versions.find(v=>v.number===version)||a.versions.at(-1);root.replaceChildren();root.append(button('← Tous les livrables',reload,'aw-back'));const head=heading(a.title,a.description||'');head.classList.add('aw-details-title');const actions=el('div',undefined,'aw-actions');actions.append(badge(a));
 if(a.can_manage)actions.append(button('Nouvelle version',()=>uploadForm(a)));
 const shareUrl=(options.publicBase||'')+a.url;
 if(options.publicBase && options.publicBase!==location.origin)actions.append(link('Ouvrir dans Share ↗',shareUrl));
 if(a.legacy_url && a.visibility==='public')actions.append(link('Original historique ↗',(options.publicBase||'')+a.legacy_url+a.versions[0].entry));
 actions.append(button('Télécharger le bundle',()=>downloadBundle(a,v)));
 actions.append(button('Copier le lien',async()=>{await navigator.clipboard.writeText(shareUrl);const n=el('p',a.visibility==='private'?'Lien copié · connexion requise':'Lien public copié','aw-progress');root.prepend(n);}));
 if(options.onRevise)actions.append(button('Demander des modifications',()=>options.onRevise(a,v)));
 head.append(actions);root.append(head);const grid=el('div',undefined,'aw-detail'),main=el('div'),box=el('div',undefined,'aw-preview'),aside=el('aside',undefined,'aw-aside');main.append(box,el('p','Aperçu isolé · seules les ressources du bundle sont chargées.','aw-note'));grid.append(main,aside);root.append(grid);
 const history=el('section');history.append(el('h3','VERSION'),select(a.versions.slice().reverse().map(v=>[String(v.number),'Version '+v.number+' · '+date(v.created_at)]),String(v.number),n=>{version=Number(n);selected=a.versions.find(v=>v.number===version).entry;detail();},'Version du livrable'));if(v.note)history.append(el('p',v.note,'aw-sub'));aside.append(history);
 if(a.can_manage){const sharing=el('section');sharing.append(el('h3','PARTAGE'));if(a.sharing_pending)sharing.append(el('p','Changement de visibilité en attente. Réessayez le réglage demandé.','aw-error'));sharing.append(el('p',a.visibility==='private'?'Vous et les administrateurs autorisés pouvez consulter ce livrable.':'Toute personne disposant du lien peut consulter toutes les versions.','aw-sub'));
 sharing.append(select([['private','Privé · accès authentifié'],['public','Public · accessible avec le lien']],a.visibility,async value=>{try{current=(await api({action:'update',id:a.id,revision:a.revision,visibility:value})).artifact;detail();}catch(e){detail();error(e);}},'Visibilité du bundle'));
 if(a.legacy_notice)sharing.append(el('p',a.legacy_notice,'aw-note'));
 sharing.append(el('p','Le réglage s’applique aussi aux fichiers et aux anciennes versions. Les copies déjà téléchargées restent chez leur destinataire.','aw-sub'));aside.append(sharing);}
 const files=el('section');files.append(el('h3','FICHIERS · '+v.files.length));const fileRows=el('div');
 const search=el('input');search.type='search';search.placeholder='Rechercher un fichier…';search.setAttribute('aria-label','Rechercher un fichier');search.value=fileQuery;
 function drawFiles(){fileRows.replaceChildren();const ordered=[...v.files].sort((x,y)=>(y.path===v.entry?1:0)-(x.path===v.entry?1:0));const matches=ordered.filter(f=>f.path.toLowerCase().includes(fileQuery.toLowerCase()));
 matches.slice(0,fileLimit).forEach(f=>{const row=el('div',undefined,'aw-file');const open=button(f.path,()=>{selected=f.path;detail();},selected===f.path?'aw-active':'');open.append(el('small',bytes(f.bytes)+(f.path===v.entry?' · principal':'')));const dl=button('↓',()=>download(a,v.number,f));dl.setAttribute('aria-label','Télécharger '+f.path);row.append(open,dl);fileRows.append(row);});
 if(matches.length>fileLimit)fileRows.append(button('Afficher plus · '+(matches.length-fileLimit)+' fichiers',()=>{fileLimit+=12;drawFiles();}));
 if(!matches.length)fileRows.append(el('p','Aucun fichier trouvé.','aw-note'));
 }
 search.addEventListener('input',()=>{fileQuery=search.value;fileLimit=8;drawFiles();});if(v.files.length>8)files.append(search);files.append(fileRows);drawFiles();aside.append(files);

 if(a.can_manage){const context=el('section');context.append(el('h3','CONTEXTE'));[a.project,a.agent,a.run_id?'Exécution '+a.run_id:''].filter(Boolean).forEach(t=>context.append(el('p',t,'aw-sub')));if(a.issue_url)context.append(link('Ticket GitHub ↗',a.issue_url));context.append(button('Modifier les informations',()=>editForm(a)));aside.append(context);}
 const f=v.files.find(f=>f.path===selected)||v.files.find(f=>f.path===v.entry);if(f)preview(box,a,v,f);
 }
 function field(form,label,value='',multiline=false){const l=el('label',label),input=el(multiline?'textarea':'input');input.value=value;if(multiline)input.rows=3;const name='artifact-field-'+Math.random().toString(36).slice(2);input.id=name;l.htmlFor=name;form.append(l,input);return input;}
 function editForm(a){cleanup();root.replaceChildren();const form=el('div',undefined,'aw-form');form.append(el('h2','Informations du livrable'));const title=field(form,'Titre',a.title),description=field(form,'Description',a.description,true);const actions=el('div',undefined,'aw-actions');actions.append(button('Enregistrer',async()=>{current=(await api({action:'update',id:a.id,revision:a.revision,title:title.value,description:description.value})).artifact;detail();},'aw-primary'),button('Annuler',detail));form.append(actions);
 const deletion=el('details');deletion.append(el('summary','Supprimer ce livrable'),el('p','Le lien et toutes les versions deviendront inaccessibles.','aw-note'),button('Supprimer définitivement',async()=>{await api({action:'delete',id:a.id,revision:a.revision});await reload();},'aw-danger'));form.append(deletion);root.append(form);}
 function uploadForm(existing){cleanup();root.replaceChildren();const form=el('div',undefined,'aw-form');form.append(el('h2',existing?'Nouvelle version':'Nouveau livrable'),el('p',existing?'L’historique est conservé. La visibilité actuelle du bundle s’appliquera à cette version.':'Privé par défaut. Vous pourrez activer le partage public après la publication.','aw-note'));
 const title=existing?null:field(form,'Titre'),description=existing?null:field(form,'Description','',true),project=existing?null:field(form,'Projet'),issue=existing?null:field(form,'Ticket GitHub (facultatif)');const note=field(form,'Note de version','',true);
 const pick=el('input');pick.type='file';pick.multiple=true;pick.setAttribute('aria-label','Choisir des fichiers');const folder=el('input');folder.type='file';folder.multiple=true;folder.setAttribute('webkitdirectory','');folder.setAttribute('aria-label','Choisir un dossier');
 form.append(el('label','Fichiers'),pick,el('label','Ou un dossier complet (rapport et ressources)'),folder);const entry=el('select');entry.setAttribute('aria-label','Fichier principal');form.append(el('label','Fichier principal'),entry);let chosen=[];
 function choose(input){chosen=Array.from(input.files);const hasRoot=input===folder;chosen=chosen.map(file=>({file,path:hasRoot?file.webkitRelativePath.split('/').slice(1).join('/'):file.name}));entry.replaceChildren();chosen.forEach(f=>{const o=el('option',f.path);o.value=f.path;entry.append(o);});entry.value=(chosen.find(f=>f.path==='index.html')||chosen.find(f=>/\.html?$/i.test(f.path))||chosen[0]||{}).path||'';}
 pick.addEventListener('change',()=>choose(pick));folder.addEventListener('change',()=>choose(folder));const progress=el('p','','aw-progress');progress.setAttribute('role','status');form.append(progress);
 const actions=el('div',undefined,'aw-actions');actions.append(button(existing?'Publier la version':'Créer le livrable',async()=>{
 if(!chosen.length||(!existing&&!title.value.trim()))throw new Error('invalid_request');
 const begin=await api({action:'begin',...(existing?{id:existing.id,revision:existing.revision}:{title:title.value,description:description.value,project:project.value,issue_url:issue.value,...options.context}),entry:entry.value,note:note.value,files:chosen.map(f=>({path:f.path,bytes:f.file.size,type:inferType(f.path,f.file.type)}))});
 for(let n=0;n<chosen.length;n++){const f=chosen[n];for(let off=0,index=0;off<f.file.size;off+=begin.chunk_bytes,index++){progress.textContent='Transfert '+(n+1)+'/'+chosen.length+' · '+f.path+' · '+Math.round(off/f.file.size*100)+' %';const array=new Uint8Array(await f.file.slice(off,off+begin.chunk_bytes).arrayBuffer());let raw='';for(let i=0;i<array.length;i+=32768)raw+=String.fromCharCode(...array.subarray(i,i+32768));await api({action:'chunk',draft_id:begin.draft_id,path:f.path,index,content_base64:btoa(raw).match(/.{1,6}/g).join('\n')});}}
 progress.textContent='Publication…';const result=await api({action:'commit',draft_id:begin.draft_id});await load(result.artifact.id);
 },'aw-primary'),button('Annuler',()=>existing?detail():library()));form.append(actions);root.append(form);
 }
 async function start(){try{if(options.id)await load(options.id);else await reload();}catch(e){root.replaceChildren();error(e);if(options.signIn)root.append(link('Se connecter',options.signIn));}}
 start();return {open:load,reload,destroy:cleanup};
}
window.ArtifactWorkspace={mount};
})();
