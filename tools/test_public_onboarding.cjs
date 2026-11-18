"use strict";
// Exercise actual console handlers with isolated HTTP responses; no live evidence or policies are written.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const test=require('node:test');
const root=path.join(__dirname,'..');
const html=fs.readFileSync(path.join(root,'web','index.html'),'utf8');
const source=fs.readFileSync(path.join(root,'web','app.js'),'utf8');
class Element {
  constructor(tag='div') {this.tagName=tag.toUpperCase();this.children=[];this.listeners={};this.dataset={};this._text='';this._value=undefined;this.hidden=false;this.disabled=false;this.classList={add(){},remove(){},toggle(){}};}
  set textContent(value){this._text=String(value);this.children=[];}
  get textContent(){return this._text+this.children.map(child=>child.textContent).join('');}
  set innerHTML(value){throw Error('Unsafe HTML: '+value);}
  append(...children){this.children.push(...children);}
  replaceChildren(...children){this._text='';this.children=[];this._value=undefined;this.append(...children);}
  get options(){return this.children.filter(child=>child.tagName==='OPTION');}
  set value(value){this._value=String(value);}
  get value(){return this._value??(this.tagName==='SELECT'?(this.options[0]?.value||''):'');}
  get childElementCount(){return this.children.length;}
  addEventListener(type,handler){(this.listeners[type]??=[]).push(handler);}
  dispatch(type='click'){return Promise.all((this.listeners[type]||[]).map(handler=>handler({preventDefault(){},submitter:this})));}
  querySelector(){return this.children.find(child=>child.tagName==='BUTTON')||new Element('button');}
}
function harness({fragment=''}={}) {
  const elements=new Map(),nav=[],go=[],requests=[],storage=new Map(),history=[];
  for(const match of html.matchAll(/<([a-z][a-z0-9]*)\b[^>]*\bid="([^"]+)"[^>]*>/g)){const element=new Element(match[1]);element.id=match[2];elements.set(element.id,element);}
  for(const match of html.matchAll(/<button\b[^>]*data-(view|goto)="([^"]+)"[^>]*>(.*?)<\/button>/gs)){const button=new Element('button');button.dataset[match[1]]=match[2];button.textContent=match[3].replace(/<[^>]+>/g,'');(match[1]==='view'?nav:go).push(button);}
  const get=id=>{assert.ok(elements.has(id),'DOM ID exists: '+id);return elements.get(id);};
  get('analyze-form').append(new Element('button'));
  const listeners=new Map();
  let reloads=0;
  const location={hash:fragment,pathname:'/',search:'',origin:'http://localhost:9081',reload(){reloads++;}};
  const context=vm.createContext({
    document:{getElementById:id=>id==='login-error'?get('login').children.find(child=>child.id===id)??null:get(id),createElement:tag=>new Element(tag),querySelectorAll:query=>query==='[data-view]'?nav:query==='[data-goto]'?go:[],querySelector:query=>nav.find(button=>query.includes('"'+button.dataset.view+'"')),visibilityState:'visible'},
    window:{addEventListener:(type,listener)=>listeners.set(type,listener)},
    location,
    history:{replaceState(...args){history.push(args);}},
    sessionStorage:{getItem:key=>storage.get(key)||'',setItem:(key,value)=>storage.set(key,value),removeItem:key=>storage.delete(key)},
    fetch(url,options){return new Promise((resolve,reject)=>requests.push({url,options,reject,reply(data,status=200){resolve({status,ok:status===200,json:async()=>data});}}));},
    setInterval(){},URLSearchParams,Date,console
  });
  vm.runInContext(source,context,{filename:'web/app.js'});
  return {get,nav,go,requests,storage,history,get reloads(){return reloads;},setHash(value){location.hash=value;listeners.get('hashchange')();},evaluate:code=>vm.runInContext(code,context),request(prefix){const index=requests.findIndex(request=>request.url==='/console/api/'+prefix);assert.notEqual(index,-1,'Expected request: '+prefix);return requests.splice(index,1)[0];}};
}
async function flush(){for(let i=0;i<15;i++)await Promise.resolve();}
function descendants(element,tag){return element.children.flatMap(child=>[...(child.tagName===tag.toUpperCase()?[child]:[]),...descendants(child,tag)]);}
const status={evidence:{record_counts:{events:0,alerts:0}},detector:{subjects:0},rules:{}};

test('first sample opens file analysis and writes only to isolated sample endpoint',async()=>{
  const h=harness();h.evaluate("token='test-key'");
  const action=h.get('first-sample').dispatch();
  assert.equal(h.evaluate('view'),'analysis');
  const request=h.request('sample');assert.equal(request.options.method,'POST');assert.equal(request.options.body,undefined);assert.equal(request.options.headers.Authorization,'Bearer test-key');
  assert.equal(h.get('sample').disabled,true);
  request.reply({events:12,alerts:[{rule_id:'RA-002',tenant_id:'sample'}],policy_actions:0});
  h.request('status').reply(status);await action;await flush();
  assert.equal(h.get('first-sample').disabled,false);assert.equal(h.get('sample').disabled,false);
  assert.match(h.get('analysis-result').textContent,/12분석 이벤트/);
  assert.match(h.get('analysis-result').textContent,/실제 수집 원장·사건 기억 변경 없음 · 정책 실행 없음/);
  assert.equal(h.requests.length,0);
  const next=descendants(h.get('analysis-result'),'button')[0];next.dispatch();
  assert.equal(h.evaluate('view'),'settings');assert.ok(h.request('settings'));
});

test('overview reports zero evidence as waiting rather than active collection',async()=>{
  const h=harness(),pending=h.evaluate('overview()');h.request('status').reply(status);await flush();h.request('stream?name=alerts').reply({rows:[]});await pending;
  assert.equal(h.get('metric-state').textContent,'수신 대기');assert.equal(h.get('metric-events').textContent,'0');
  assert.match(h.get('getting-started-status').textContent,/아직 저장된 HTTP 이벤트가 없습니다/);
  assert.match(h.get('overview-alerts').textContent,/경보 0건만으로 안전을 판단할 수 없습니다/);
  const connect=descendants(h.get('overview-alerts'),'button')[0];connect.dispatch();assert.equal(h.evaluate('view'),'settings');assert.ok(h.request('settings'));
});

test('onboarding destinations use existing screens without automatically revealing credentials or syncing cases',()=>{
  const h=harness(),destinations=h.go.map(button=>button.dataset.goto);
  for(const destination of ['settings','events','cases','assistant'])assert.ok(destinations.includes(destination));
  for(const button of h.go){assert.ok(h.nav.some(nav=>nav.dataset.view===button.dataset.goto));assert.equal(button.listeners.click.length,1);}
  h.go.find(button=>button.dataset.goto==='cases').dispatch();
  assert.equal(h.evaluate('view'),'cases');assert.ok(h.request('settings'));
  assert.ok(!h.requests.some(request=>request.options.method==='POST'||request.url.includes('sensor-credential')));
});

test('event search distinguishes no input evidence from no matching rows',()=>{
  const h=harness();h.evaluate('drawEvents()');assert.match(h.get('event-rows').textContent,/아직 수신한 HTTP 이벤트가 없습니다/);assert.ok(descendants(h.get('event-rows'),'button').length);
  h.get('event-filter').value='unknown';h.evaluate("eventRows=[{event_id:'event-1'}];drawEvents()");
  assert.match(h.get('event-rows').textContent,/검색과 일치하는 이벤트가 없습니다/);assert.equal(descendants(h.get('event-rows'),'button').length,0);
});

test('empty case response gives an actionable path and prevents an invalid model request',async()=>{
  const h=harness();h.get('ai-tenant').value='alpha';h.get('ai-model').value='qwen-local';h.evaluate('aiStatus={available:true,audit_available:true};aiDefense=true');
  const pending=h.evaluate('loadAICases()');h.request('cases?tenant=alpha').reply({cases:[]});await pending;
  assert.equal(h.get('ai-analyze').disabled,true);assert.equal(h.get('ai-contain').disabled,true);
  assert.match(h.get('ai-case-help').textContent,/실제 경보를 사건 기억에서 동기화/);
  const button=descendants(h.get('ai-case-help'),'button')[0];button.dispatch();assert.equal(h.evaluate('view'),'cases');
});

test('fragment login keeps credentials out of request URLs and logout clears the tab session',async()=>{
  const h=harness({fragment:'#token=secret-console-key'});
  assert.equal(h.history[0][2],'/');assert.equal(h.storage.get('ra-console-key'),'secret-console-key');
  const request=h.request('status');assert.equal(request.options.headers.Authorization,'Bearer secret-console-key');request.reply(status);await flush();
  assert.ok(h.requests.every(request=>!request.url.includes('secret-console-key')));
  h.get('logout').dispatch();assert.equal(h.evaluate('token'),'');assert.equal(h.storage.has('ra-console-key'),false);assert.equal(h.get('sensor-token').value,'');assert.equal(h.get('application').hidden,true);
});

test('late rejection cannot erase a new access link in the same tab',async()=>{
  const h=harness({fragment:'#token=old-key'});
  const previous=h.request('status');
  h.setHash('#help');
  assert.equal(h.reloads,0);
  h.setHash('#token=new-key');
  assert.equal(h.reloads,1);
  assert.equal(h.history.at(-1)[2],'/');
  previous.reply({},401);
  await flush();
  assert.equal(h.storage.get('ra-console-key'),'new-key');
  assert.equal(h.get('login').children.some(child=>child.id==='login-error'),false);

  const current=h.evaluate('connect()');
  const request=h.request('status');
  assert.equal(request.options.headers.Authorization,'Bearer new-key');
  request.reply({},401);
  await current;
  assert.equal(h.storage.has('ra-console-key'),false);
  assert.equal(h.get('application').hidden,true);
});
