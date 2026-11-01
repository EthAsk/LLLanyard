// The whole app UI as one page. All dynamic text is inserted with textContent (never innerHTML), so key labels, agent names
// and model output cannot inject markup. The server adds a per-run nonce so only this script and style can run.
export const PAGE = String.raw`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LLLanyard</title>
<style nonce="__NONCE__">
:root{--bg:#f6f7f9;--card:#fff;--fg:#17191c;--mut:#677;--line:#e2e5ea;--accent:#2f6fed;--accent-fg:#fff;--ok:#16794a;--warn:#b45309;--bad:#b42318;--okbg:#e6f4ec;--warnbg:#fdf0dc;--badbg:#fde8e6}
@media (prefers-color-scheme:dark){:root{--bg:#101215;--card:#181b20;--fg:#eceef1;--mut:#9aa3ad;--line:#2a2f37;--accent:#6b9bff;--accent-fg:#0b1020;--ok:#5fd39a;--warn:#f5b45a;--bad:#ff8a80;--okbg:#12281d;--warnbg:#2c2210;--badbg:#2e1513}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
header{display:flex;align-items:center;gap:12px;padding:14px 20px;background:var(--card);border-bottom:1px solid var(--line);flex-wrap:wrap}
header h1{font-size:18px;margin:0}.tier{font-size:12px;padding:2px 8px;border-radius:99px;background:var(--okbg);color:var(--ok)}
nav{display:flex;gap:4px;margin-left:auto;flex-wrap:wrap}nav button{background:none;border:0;color:var(--mut);padding:7px 12px;border-radius:8px;font:inherit;cursor:pointer}
nav button[aria-current=true]{background:var(--bg);color:var(--fg);font-weight:600}
main{max-width:920px;margin:0 auto;padding:20px 16px 60px}section{display:none}section.on{display:block}
h2{font-size:16px;margin:0 0 10px}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:middle}th{color:var(--mut);font-weight:500}
td.r,th.r{text-align:right}.badge{font-size:12px;padding:2px 8px;border-radius:99px;white-space:nowrap}
.ok{background:var(--okbg);color:var(--ok)}.due-soon{background:var(--warnbg);color:var(--warn)}.overdue{background:var(--badbg);color:var(--bad)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:end}label{display:flex;flex-direction:column;gap:3px;font-size:13px;color:var(--mut)}
input,select,textarea{font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:8px 10px;min-width:0}
input:focus,textarea:focus,select:focus,button:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
button.p{background:var(--accent);color:var(--accent-fg);border:0;border-radius:8px;padding:9px 14px;font:inherit;font-weight:600;cursor:pointer}
button.s{background:none;color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:6px 10px;font:inherit;cursor:pointer}button.d{color:var(--bad)}
.mut{color:var(--mut);font-size:13px}.err{color:var(--bad);margin:8px 0 0}.good{color:var(--ok);margin:8px 0 0}
.stats{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}.stat{background:var(--bg);border-radius:10px;padding:8px 14px;min-width:100px}.stat b{display:block;font-size:22px}
pre,.tok{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;white-space:pre-wrap;word-break:break-all;font:13px ui-monospace,Menlo,Consolas,monospace}
.answer{white-space:pre-wrap}.empty{color:var(--mut);padding:10px 0}
input.w90{width:90px}.mt8{margin-top:8px}.mt10{margin-top:10px}.mt12{margin-top:12px}.mt14{margin-top:14px}.pad{padding:10px 20px}
#gate{max-width:520px;margin:80px auto;padding:0 16px}
label.chk{flex-direction:row;align-items:center;gap:6px;color:var(--fg)}textarea{width:100%;min-height:64px;font:13px ui-monospace,Menlo,Consolas,monospace}
.grow{flex:1 1 260px}code.cl{font:12px ui-monospace,Menlo,Consolas,monospace;word-break:break-all}ul.rep{margin:6px 0 0;padding-left:18px}
</style></head><body>
<div id="gate" hidden><div class="card"><h2>Open LLLanyard from the app</h2><p>This page needs the private link that LLLanyard prints when it starts (<code>lllanyard ui</code>), or the desktop app. Opening the address by hand won't work, on purpose.</p></div></div>
<div id="app" hidden>
<header><h1>LLLanyard</h1><span class="tier" id="tier"></span><span class="mut" id="proxystat"></span>
<nav id="nav"></nav></header>
<main>
<section id="keys"><div class="card"><h2>Keys</h2><div class="mut" id="keymeter"></div><div id="keylist"></div></div>
<div class="card"><h2>Add or replace a key</h2><form id="addkey" class="row" autocomplete="off">
<label>Name<input name="provider" required list="provs" placeholder="github" maxlength="64" size="12"></label><datalist id="provs"></datalist>
<label>Label (if you have several)<input name="label" value="default" maxlength="64" size="10"></label>
<label>Variable scripts get it as<input name="envName" maxlength="128" placeholder="GITHUB_TOKEN" size="18" spellcheck="false"></label>
<label>Key (hidden, never shown again)<input name="secret" type="password" required autocomplete="off" size="26" maxlength="600" spellcheck="false"></label>
<label>Rotate after (days)<input name="rotateDays" type="number" min="1" max="3650" value="90" class="w90"></label>
<button class="p" type="submit">Save key</button></form><div id="keymsg"></div></div>
</section>
<section id="agents"><div class="card"><h2>Agents</h2><p class="mut">Each agent gets a placeholder token. The real key never leaves LLLanyard.</p><div id="agentlist"></div></div>
<div class="card"><h2>New agent token</h2><form id="addagent" class="row" autocomplete="off">
<label>Name<input name="name" required maxlength="64" placeholder="claude-code"></label>
<label>Client<input name="client" value="default" maxlength="64" size="12"></label>
<label>Providers (comma separated, blank = all)<input name="providers" maxlength="200" placeholder="openai,anthropic"></label>
<label>Expires in days<input name="expiresDays" type="number" min="1" max="3650" class="w90"></label>
<button class="p" type="submit">Create</button></form><div id="agentmsg"></div></div>
<div class="card"><h2>Services agents can call</h2><p class="mut">For agents that call an API through the proxy with their token instead of the key: http://127.0.0.1:&lt;port&gt;/&lt;service&gt;/… The service name matches the key's name. Scripts run with <code>lllanyard exec</code> don't need this.</p><div id="provlist"></div></div>
<div class="card"><h2>Add a service</h2><form id="addprov" class="row" autocomplete="off">
<label>Name<input name="id" required maxlength="64" placeholder="github" size="10"></label>
<label class="grow">API address (https)<input name="upstream" required maxlength="300" placeholder="https://api.example.com"></label>
<label>Sends the key as<select name="auth"><option value="bearer">Authorization: Bearer</option><option value="header">A named header</option></select></label>
<label>Header name<input name="header" maxlength="64" placeholder="X-API-KEY" size="12"></label>
<label>Prefix<input name="prefix" maxlength="20" size="8"></label>
<button class="p" type="submit">Save service</button></form><div id="provmsg"></div></div>
</section>
<section id="tools"><div class="card"><h2>Run any script with your keys</h2>
<p>Put <code>lllanyard exec</code> in front of the command you'd normally type:</p>
<div class="tok">lllanyard exec pwsh -File ./Deploy-App.ps1 -DryRun</div>
<p class="mut mt10">LLLanyard reads the script, and the helper files it loads, for your keys' variable names (set on the Keys tab) and passes only the keys it uses, for that run only. Keys are never printed: any that show up in its output are replaced with [REDACTED]. Every run is listed on the Usage tab.</p></div>
<div class="card"><h2>Connect AI apps</h2><p class="mut">Let Claude run your scripts with your keys without ever seeing them. This works with a normal Claude subscription: no API key and no API billing.</p><div id="applist"></div><div id="appmsg"></div></div>
<div class="card" id="toolcard" hidden><h2>Approved tools</h2><p class="mut">Pinned scripts and MCP servers set up with <code>lllanyard tool add</code>.</p><div id="toollist"></div><div id="toolmsg"></div></div></section>
<section id="backup"><div class="card"><h2>Back up</h2><p class="mut">One encrypted file with your keys, services, tools, agents and license, saved in your home folder. Keep the passphrase somewhere else: without it the file can't be restored.</p>
<form id="bk" class="row" autocomplete="off"><label>Passphrase (12+ characters)<input name="p1" type="password" required minlength="12" maxlength="1000" autocomplete="new-password"></label>
<label>Repeat<input name="p2" type="password" required maxlength="1000" autocomplete="new-password"></label><button class="p" type="submit">Create backup</button></form><div id="bkmsg"></div></div>
<div class="card"><h2>Restore</h2><p class="mut">Adds what's in the backup. Items you already have are kept unless you tick "Replace". Nothing is ever deleted.</p>
<form id="rs" autocomplete="off"><div class="row"><label class="grow">Backup file<input name="file" type="file" required accept=".enc"></label>
<label>Passphrase<input name="pass" type="password" required maxlength="1000" autocomplete="off"></label></div>
<div class="row mt10"><label class="chk"><input type="checkbox" name="overwrite"> Replace items I already have</label>
<button class="s" type="button" id="rspreview">Preview</button><button class="p" type="submit">Restore</button></div></form><div id="rsmsg"></div></div></section>
<section id="usage"><div class="card"><h2>Usage, last 7 days</h2><div id="usagebody"></div></div></section>
<section id="assistant"><div class="card"><h2>Rotation assistant</h2>
<p class="mut">Reviews key ages and usage. It only sees metadata (never keys) and only talks to a model on this computer.</p>
<div class="row"><button class="p" id="reviewrules" type="button">Quick review</button><button class="s" id="reviewmodel" type="button">Ask local model</button></div>
<label class="mt10">Optional question<input id="question" maxlength="500" placeholder="Which key is riskiest?"></label>
<div id="answer" class="answer card mt12" hidden></div></div>
<div class="card"><h2>Local model</h2><form id="aiconf" class="row">
<label>Endpoint<input name="endpoint" size="26" value="http://127.0.0.1:11434"></label><label>Model<input name="model" size="14" value="llama3.2"></label>
<label>API style<select name="kind"><option value="ollama">Ollama</option><option value="openai">OpenAI-compatible (LM Studio, llama.cpp)</option></select></label>
<button class="s" type="submit">Save</button></form><div id="aimsg"></div></div></section>
<section id="settings"><div class="card"><h2>Proxy</h2><p class="mut" id="proxyinfo"></p><button class="p" id="proxytoggle" type="button"></button><div id="proxymsg"></div></div>
<div class="card"><h2>License</h2><p id="licinfo"></p><p id="teaminfo" class="mut"></p><form id="lic" class="row"><label>License key<input name="key" size="40" maxlength="2000" autocomplete="off"></label><button class="s" type="submit">Activate</button><button class="s d" id="licremove" type="button">Remove</button></form><div id="licmsg"></div></div>
<div class="card"><h2>This computer</h2><div id="sysinfo" class="mut"></div></div></section>
</main></div>
<script nonce="__NONCE__">
(function(){
'use strict';
var SESSION=null;
(function(){var m=/(?:^|[#&])s=([A-Za-z0-9_-]{20,})/.exec(location.hash);if(m){SESSION=m[1];history.replaceState(null,'',location.pathname);}})();
var $=function(id){return document.getElementById(id)};
function h(tag,props){var e=document.createElement(tag);props=props||{};for(var k in props){if(k==='class')e.className=props[k];else if(k==='text')e.textContent=props[k];else if(k.slice(0,2)==='on')e.addEventListener(k.slice(2),props[k]);else e.setAttribute(k,props[k]);}
for(var i=2;i<arguments.length;i++){var c=arguments[i];if(c==null)continue;e.appendChild(typeof c==='string'?document.createTextNode(c):c);}return e;}
function clear(e){while(e.firstChild)e.removeChild(e.firstChild);}
function api(method,path,body){return fetch(path,{method:method,headers:{'x-lly-session':SESSION,'content-type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)}).then(function(r){return r.json().catch(function(){return{}}).then(function(j){if(!r.ok)throw new Error(j.error||('Request failed ('+r.status+')'));return j;});});}
function msg(el,text,good){clear(el);if(text)el.appendChild(h('div',{class:good?'good':'err',role:'status',text:text}));}
var S=null;
function badge(state,t){return h('span',{class:'badge '+state,text:t});}
function dueText(k){return k.state==='overdue'?('overdue by '+(-k.dueInDays)+' days'):('due in '+k.dueInDays+' days');}
function render(){
 if(!S)return;
 $('tier').textContent=S.license.tier==='free'?'Free':S.license.tier==='pro'?'Pro':'Team';
 $('proxystat').textContent=S.proxy.running?('Proxy running on port '+S.proxy.port):'Proxy stopped';
 // keys
 $('keymeter').textContent=S.keys.length+' of '+S.limits.maxKeys+' keys used'+(S.license.tier==='free'?' on the free tier':'');
 var kl=$('keylist');
 // Don't redraw the table under someone typing a variable name (the page refreshes every 15 seconds).
 var typing=document.activeElement&&document.activeElement.dataset&&document.activeElement.dataset.envfor;
 if(!typing){clear(kl);
 if(!S.keys.length)kl.appendChild(h('div',{class:'empty',text:'No keys yet. Add one below.'}));
 else{var t=h('table',{},h('thead',{},h('tr',{},h('th',{text:'Name'}),h('th',{text:'Variable scripts get'}),h('th',{text:'Key'}),h('th',{text:'Rotation'}),h('th',{class:'r',text:''}))));var tb=h('tbody');
  S.keys.forEach(function(k){tb.appendChild(h('tr',{},h('td',{text:k.provider+(k.label==='default'?'':':'+k.label)}),h('td',{},varInput(k)),h('td',{text:'…'+k.last4}),h('td',{},badge(k.state,dueText(k))),
   h('td',{class:'r'},k.rotateUrl?h('a',{href:k.rotateUrl,target:'_blank',rel:'noopener noreferrer',text:'Rotate at provider '}):null,
    h('button',{class:'s d',type:'button','aria-label':'Remove '+k.provider+' '+k.label,text:'Remove',onclick:function(){if(confirm('Remove '+k.provider+' / '+k.label+'? This deletes the stored key.'))act(api('DELETE','/api/keys',{provider:k.provider,label:k.label}),$('keymsg'),'Key removed.');}}))));});
  t.appendChild(tb);kl.appendChild(t);}}
 var dl=$('provs');clear(dl);S.providers.forEach(function(p){dl.appendChild(h('option',{value:p}));});
 // agents
 var al=$('agentlist');clear(al);
 if(!S.agents.length)al.appendChild(h('div',{class:'empty',text:'No agents yet.'}));
 else{var at=h('table',{},h('thead',{},h('tr',{},h('th',{text:'Name'}),h('th',{text:'Client'}),h('th',{text:'Providers'}),h('th',{text:'Expires'}),h('th',{}))));var ab=h('tbody');
  S.agents.forEach(function(a){ab.appendChild(h('tr',{},h('td',{text:a.name}),h('td',{text:a.client}),h('td',{text:a.providers?a.providers.join(', '):'all'}),h('td',{text:a.expiresAt?a.expiresAt.slice(0,10):'never'}),
   h('td',{class:'r'},h('button',{class:'s d',type:'button','aria-label':'Revoke '+a.name,text:'Revoke',onclick:function(){if(confirm('Revoke '+a.name+'? Tools using its token will stop working.'))act(api('DELETE','/api/agents',{name:a.name}),$('agentmsg'),'Agent revoked.');}}))));});
  at.appendChild(ab);al.appendChild(at);}
 // services and tools
 var pl=$('provlist');clear(pl);
 if(!S.customProviders.length)pl.appendChild(h('div',{class:'empty',text:'No custom services. Built in: '+S.providers.join(', ')}));
 else{var pt=h('table',{},h('thead',{},h('tr',{},h('th',{text:'Name'}),h('th',{text:'API address'}),h('th',{text:'Key sent as'}),h('th',{}))));var pb=h('tbody');
  S.customProviders.forEach(function(p){pb.appendChild(h('tr',{},h('td',{text:p.id}),h('td',{},h('code',{class:'cl',text:p.upstream})),h('td',{text:p.auth.type==='bearer'?'Authorization: Bearer':(p.auth.name+(p.auth.prefix?(' ('+p.auth.prefix+'…)'):''))}),
   h('td',{class:'r'},h('button',{class:'s d',type:'button','aria-label':'Remove '+p.id,text:'Remove',onclick:function(){if(confirm('Remove the '+p.id+' service? Its stored key is kept.'))act(api('DELETE','/api/providers',{id:p.id}),$('provmsg'),'Service removed.');}}))));});
  pt.appendChild(pb);pl.appendChild(pt);}
 $('toolcard').hidden=!S.tools.length;
 var tl=$('toollist');clear(tl);
 if(S.tools.length){var tt=h('table',{},h('thead',{},h('tr',{},h('th',{text:'Name'}),h('th',{text:'Runs'}),h('th',{text:'Keys'}),h('th',{text:'Safeguards'}),h('th',{}))));var tb2=h('tbody');
  S.tools.forEach(function(t){var keys=Object.keys(t.env).map(function(k){return k+' ← '+t.env[k];}).join('\n');
   var safe=[t.pinned?(t.pinned+' file(s) pinned'):null,t.allowArgs?'extra args allowed':null,t.allowHosts.length?('network: '+t.allowHosts.join(', ')):'network unrestricted',t.passEnv.length?('passes '+t.passEnv.join(', ')):null,t.sandbox?'OS sandbox':null].filter(Boolean).join('; ');
   tb2.appendChild(h('tr',{},h('td',{text:t.name}),h('td',{},h('code',{class:'cl',text:[t.command].concat(t.args).join(' ')})),h('td',{class:'answer',text:keys}),h('td',{class:'mut',text:safe}),
    h('td',{class:'r'},h('button',{class:'s d',type:'button','aria-label':'Remove '+t.name,text:'Remove',onclick:function(){if(confirm('Remove the approved tool '+t.name+'?'))act(api('DELETE','/api/tools',{name:t.name}),$('toolmsg'),'Tool removed.');}}))));});
  tt.appendChild(tb2);tl.appendChild(tt);}
 // connected apps
 var A=S.apps,al=$('applist');clear(al);
 var cd=A.claudeDesktop,cdb=h('button',{class:'p',type:'button',text:cd.connected?'Update':'Connect',onclick:function(){if(!desktopClosed(cd))return;act(api('POST','/api/setup',{app:'claude-desktop',restart:cd.running,scriptDirs:dirs.value.split('\n').map(function(x){return x.trim();}).filter(Boolean)}),$('appmsg'),cd.running?'Claude Desktop connected and restarted.':'Claude Desktop connected. Open it to use LLLanyard.');}});cdb.disabled=!A.canConnect;
 var dirs=h('textarea',{rows:'2',placeholder:'One folder per line, e.g. /Users/you/Scripts','aria-label':'Script folders for Claude Desktop',spellcheck:'false'});dirs.value=cd.scriptDirs.join('\n');
 al.appendChild(h('div',{class:'mt10'},h('b',{text:'Claude Desktop'}),h('span',{class:cd.connected?'good':'mut',text:cd.connected?'  Connected':'  Not connected'}),
  h('p',{class:'mut',text:'Chats can run tools you approved below, and any script in these folders after you click Run in a dialog LLLanyard shows. Leave empty to allow approved tools only.'+(cd.running?(cd.canRestart?' Claude Desktop is open: connecting will quit and reopen it.':' Quit Claude Desktop before connecting.'):'')}),
  cd.problem?h('div',{class:'err',text:cd.problem}):h('span'),dirs,
  h('div',{class:'mt10'},cdb,
   cd.connected?h('button',{class:'s d',type:'button',text:'Disconnect',onclick:function(){if(!desktopClosed(cd))return;act(api('POST','/api/setup',{app:'claude-desktop',remove:true,restart:cd.running}),$('appmsg'),'Disconnected.');}}):h('span'))));
 if(!A.canConnect)al.appendChild(h('div',{class:'mut',text:'To connect Claude Desktop, start LLLanyard with: lllanyard ui'}));
 var cc=A.claudeCode;
 al.appendChild(h('div',{class:'mt14'},h('b',{text:'Claude Code'}),h('span',{class:cc.connected?'good':'mut',text:cc.connected?'  Connected':'  Not connected'}),
  h('p',{class:'mut',text:'Adds a short section to '+cc.file+' telling Claude Code to run scripts with lllanyard exec and never read keys from .env files.'}),
  h('button',{class:cc.connected?'s d':'p',type:'button',text:cc.connected?'Disconnect':'Connect',onclick:function(){act(api('POST','/api/setup',{app:'claude-code',remove:cc.connected}),$('appmsg'),cc.connected?'Removed.':'Claude Code connected. New sessions pick it up.');}})));
 // usage
 var u=S.usage,ub=$('usagebody');clear(ub);
 ub.appendChild(h('div',{class:'stats'},stat('Requests',u.requests),stat('Server errors',u.errors),stat('Rate-limited',u.rateLimited),stat('Kill-switch trips',u.killSwitch),stat('Blocked',u.denied)));
 var sr=h('div',{},h('h2',{class:'mt14',text:'Scripts run with your keys'}));
 if(!u.scriptRuns||!u.scriptRuns.length)sr.appendChild(h('div',{class:'empty',text:'None yet'}));
 else{var st=h('table',{},h('thead',{},h('tr',{},h('th',{text:'Command'}),h('th',{class:'r',text:'Runs'}),h('th',{text:'Last run (UTC)'}))));var sb=h('tbody');
  u.scriptRuns.forEach(function(r){sb.appendChild(h('tr',{},h('td',{text:r.tool}),h('td',{class:'r',text:String(r.count)}),h('td',{text:r.last.slice(0,16).replace('T',' ')})));});st.appendChild(sb);sr.appendChild(st);}
 ub.appendChild(sr);
 ub.appendChild(rows('By provider',u.byProvider));ub.appendChild(rows('By agent',u.byAgent));
 // settings
 $('proxyinfo').textContent=S.proxy.running?('Listening on 127.0.0.1:'+S.proxy.port+'. Tools should use this address with their agent token.'):'The proxy is what tools talk to. Start it to let agents use your keys.';
 $('proxytoggle').textContent=S.proxy.running?'Stop proxy':'Start proxy';
 var T=S.team;$('teaminfo').textContent=T?('Team server: '+T.url+'. Keys here are personal and stay on this computer; anything you have no key for here goes to the team server.'+(S.license.tier!=='team'?' (Not in use until a Team license is active.)':'')):(S.license.tier==='team'?'Not linked to a team server. To use your team\'s shared keys alongside your own, run: lllanyard team join https://<team server>:3443':'');
 var L=S.license;$('licinfo').textContent=L.payload?('Active: '+L.tier+', '+L.payload.seats+' seat(s), until '+new Date(L.payload.exp*1000).toISOString().slice(0,10)+'.'):('Free tier: up to '+S.limits.maxKeys+' keys and '+S.limits.maxAgents+' agent tokens.'+(L.problem?(' Stored license not applied: '+L.problem):''));
 var sys=$('sysinfo');clear(sys);
 sys.appendChild(h('div',{text:'Key storage: '+(S.backend==='file'?'encrypted file vault':'OS keychain')}));
 sys.appendChild(h('div',{text:S.sandbox.ok?('Tool sandbox: available ('+S.sandbox.kind+')'):('Tool sandbox: not available. '+(S.sandbox.reason||''))}));
 var ac=document.forms.aiconf;ac.endpoint.value=S.assistant.endpoint;ac.model.value=S.assistant.model;ac.kind.value=S.assistant.kind||'ollama';
}
function varInput(k){var i=h('input',{value:k.envName||'',placeholder:'none',size:'22',maxlength:'128',spellcheck:'false','aria-label':'Variable for '+k.provider+' '+k.label});
 i.dataset.envfor=k.provider+':'+k.label;
 i.addEventListener('keydown',function(e){if(e.key==='Enter')i.blur();});
 i.addEventListener('change',function(){var v=i.value.trim();act(api('POST','/api/keys/env',{provider:k.provider,label:k.label,envName:v||undefined}),$('keymsg'),v?('Scripts now get '+(k.provider+(k.label==='default'?'':':'+k.label))+' as '+v+'.'):'Variable cleared.');});
 return i;}
// Claude Desktop rewrites its settings when it quits, so it must be closed while they change.
function desktopClosed(cd){if(!cd.running)return true;if(!cd.canRestart){msg($('appmsg'),'Quit Claude Desktop completely (including from the system tray), then try again. It rewrites its settings when it quits, which would undo this.',false);return false;}
 return confirm('Claude Desktop is open. LLLanyard will quit it, make the change and reopen it. Unsaved work in it may be lost. Continue?');}
function stat(l,v){return h('div',{class:'stat'},h('b',{text:String(v)}),h('span',{class:'mut',text:l}));}
function rows(title,list){var w=h('div',{},h('h2',{class:'mt14',text:title}));if(!list.length){w.appendChild(h('div',{class:'empty',text:'No data yet'}));return w;}
 var t=h('table',{},h('thead',{},h('tr',{},h('th',{text:'Name'}),h('th',{class:'r',text:'Requests'}),h('th',{class:'r',text:'Errors'}),h('th',{class:'r',text:'p95 ms'}))));var b=h('tbody');
 list.slice(0,10).forEach(function(r){b.appendChild(h('tr',{},h('td',{text:r.name}),h('td',{class:'r',text:String(r.requests)}),h('td',{class:'r',text:String(r.errors)}),h('td',{class:'r',text:String(r.p95)})));});t.appendChild(b);w.appendChild(t);return w;}
function load(){return api('GET','/api/state').then(function(s){S=s;render();}).catch(function(e){document.body.insertBefore(h('div',{class:'err pad',text:e.message}),document.body.firstChild);});}
function act(p,el,ok){return p.then(function(){msg(el,ok,true);return load();}).catch(function(e){msg(el,e.message,false);});}
function csv(v){return v.split(',').map(function(x){return x.trim();}).filter(Boolean);}
function intOrU(v){return v===''?undefined:Number(v);}
var tabs=[['keys','Keys'],['agents','Agents'],['tools','Scripts'],['usage','Usage'],['assistant','Assistant'],['backup','Backup'],['settings','Settings']];
function show(id){tabs.forEach(function(t){$(t[0]).className=t[0]===id?'on':'';});Array.prototype.forEach.call($('nav').children,function(b){b.setAttribute('aria-current',String(b.dataset.t===id));});}
tabs.forEach(function(t){var b=h('button',{type:'button',text:t[1],onclick:function(){show(t[0]);}});b.dataset.t=t[0];$('nav').appendChild(b);});
document.forms.addkey.addEventListener('submit',function(e){e.preventDefault();var f=e.target;
 act(api('POST','/api/keys',{provider:f.provider.value,label:f.label.value||'default',secret:f.secret.value,rotateDays:intOrU(f.rotateDays.value),envName:f.envName.value||undefined}),$('keymsg'),'Key saved.').then(function(){f.secret.value='';});});
document.forms.addagent.addEventListener('submit',function(e){e.preventDefault();var f=e.target,m=$('agentmsg');
 api('POST','/api/agents',{name:f.name.value,client:f.client.value||'default',providers:csv(f.providers.value),expiresDays:intOrU(f.expiresDays.value)}).then(function(r){
  clear(m);m.appendChild(h('div',{class:'good',text:'Agent created. Copy this token now. It is shown once and cannot be recovered:'}));m.appendChild(h('div',{class:'tok',text:r.token}));f.name.value='';return load();}).catch(function(er){msg(m,er.message,false);});});
function review(useModel){var a=$('answer');a.hidden=false;a.textContent='Thinking…';api('POST','/api/assistant',{useModel:useModel,question:$('question').value}).then(function(r){clear(a);a.appendChild(h('div',{text:r.text}));
 a.appendChild(h('div',{class:'mut mt8',text:(r.source==='model'?'Answer from your local model.':'Rule-based review.')+(r.note?(' '+r.note):'')}));}).catch(function(e){a.textContent=e.message;});}
$('reviewrules').addEventListener('click',function(){review(false);});$('reviewmodel').addEventListener('click',function(){review(true);});
document.forms.aiconf.addEventListener('submit',function(e){e.preventDefault();var f=e.target;act(api('POST','/api/assistant/config',{endpoint:f.endpoint.value,model:f.model.value,kind:f.kind.value}),$('aimsg'),'Saved.');});
$('proxytoggle').addEventListener('click',function(){act(api('POST','/api/proxy',{action:S.proxy.running?'stop':'start'}),$('proxymsg'),'');});
document.forms.lic.addEventListener('submit',function(e){e.preventDefault();var f=e.target;act(api('POST','/api/license',{key:f.key.value}),$('licmsg'),'License activated.').then(function(){f.key.value='';});});
document.forms.addprov.addEventListener('submit',function(e){e.preventDefault();var f=e.target;
 act(api('POST','/api/providers',{id:f.id.value,upstream:f.upstream.value,auth:f.auth.value,header:f.header.value||undefined,prefix:f.prefix.value||undefined}),$('provmsg'),'Service saved. Store its key on the Keys tab with the same name.');});
document.forms.bk.addEventListener('submit',function(e){e.preventDefault();var f=e.target,m=$('bkmsg');
 if(f.p1.value!==f.p2.value)return msg(m,'The passphrases do not match.',false);
 msg(m,'Encrypting…',true);
 api('POST','/api/backup',{passphrase:f.p1.value}).then(function(r){f.reset();clear(m);m.appendChild(h('div',{class:'good',text:'Backed up '+r.items.length+' item(s) to:'}));m.appendChild(h('div',{class:'tok',text:r.file}));
  var ul=h('ul',{class:'rep mut'});r.items.forEach(function(i){ul.appendChild(h('li',{text:i}));});m.appendChild(ul);}).catch(function(er){msg(m,er.message,false);});});
function restore(dryRun){var f=document.forms.rs,m=$('rsmsg'),file=f.file.files[0];
 if(!file||!f.pass.value)return msg(m,'Choose the backup file and enter its passphrase.',false);
 if(file.size>2*1024*1024)return msg(m,'That file is too large to be a LLLanyard backup.',false);
 msg(m,dryRun?'Checking…':'Restoring…',true);
 file.text().then(function(text){return api('POST','/api/restore',{text:text,passphrase:f.pass.value,overwrite:f.overwrite.checked,dryRun:dryRun});}).then(function(r){
  clear(m);m.appendChild(h('div',{class:'good',text:(r.dryRun?'Preview (nothing changed yet) of the backup from ':'Restored the backup from ')+r.createdAt.slice(0,16).replace('T',' ')+' UTC'}));
  var ul=h('ul',{class:'rep'});
  r.added.forEach(function(i){ul.appendChild(h('li',{text:(r.dryRun?'Would add: ':'Added: ')+i}));});
  r.replaced.forEach(function(i){ul.appendChild(h('li',{text:(r.dryRun?'Would replace: ':'Replaced: ')+i}));});
  r.kept.forEach(function(i){ul.appendChild(h('li',{class:'mut',text:'Kept yours: '+i}));});
  r.invalid.forEach(function(x){ul.appendChild(h('li',{class:'err',text:'Skipped '+x.item+': '+x.reason}));});
  m.appendChild(ul);if(!r.dryRun){f.pass.value='';return load();}
 }).catch(function(er){msg(m,er.message,false);});}
$('rspreview').addEventListener('click',function(){restore(true);});
document.forms.rs.addEventListener('submit',function(e){e.preventDefault();restore(false);});
$('licremove').addEventListener('click',function(){act(api('DELETE','/api/license'),$('licmsg'),'License removed.');});
if(!SESSION){$('gate').hidden=false;}else{$('app').hidden=false;show('keys');load();setInterval(load,15000);}
})();
</script></body></html>`;
