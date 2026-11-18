'use strict';

// 실제 app.js를 실행한다. 서버·모델·외부 패키지·실제 브라우저는 사용하지 않는다.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const test=require('node:test');
const source=fs.readFileSync(path.join(__dirname,'..','web','app.js'),'utf8');

class Element {
  constructor(tag='div'){
    this.tagName=tag.toUpperCase();this.children=[];this.listeners={};this.attributes={};
    this._text='';this._value=undefined;this.hidden=false;this.disabled=false;this.open=false;
    this.classList={add(){},remove(){},toggle(){}};
  }
  set textContent(value){this._text=String(value);this.children=[];}
  get textContent(){return this._text+this.children.map(child=>child.textContent).join('');}
  set innerHTML(value){throw Error('innerHTML 사용 금지: '+value);}
  append(...children){this.children.push(...children);}
  replaceChildren(...children){this._text='';this.children=[];this._value=undefined;this.append(...children);}
  get options(){return this.children.filter(child=>child.tagName==='OPTION');}
  set value(value){this._value=String(value);}
  get value(){return this._value??(this.tagName==='SELECT'?(this.options[0]?.value||''):'');}
  get childElementCount(){return this.children.length;}
  setAttribute(name,value){this.attributes[name]=String(value);}
  addEventListener(type,handler){(this.listeners[type]??=[]).push(handler);}
  dispatch(type){for(const handler of this.listeners[type]||[])handler({preventDefault(){},submitter:this});}
  querySelector(){return this.children.find(child=>child.tagName==='BUTTON')||new Element('button');}
  scrollIntoView(){this.scrolled=true;}
  focus(){this.focused=true;}
}
function descendants(element,tag){
  return element.children.flatMap(child=>[
    ...(child.tagName===tag.toUpperCase()?[child]:[]),...descendants(child,tag)
  ]);
}
function harness(){
  const elements=new Map(),requests=[],intervals=[];
  const get=id=>{
    if(!elements.has(id)){const e=new Element();e.id=id;elements.set(id,e);}
    return elements.get(id);
  };
  for(const id of ['ai-tenant','ai-case','ai-model','case-tenant'])elements.set(id,new Element('select'));
  for(const tenant of ['alpha','beta']){const option=new Element('option');option.value=tenant;option.textContent=tenant;get('ai-tenant').append(option);}
  const context=vm.createContext({
    document:{
      getElementById:get,createElement:tag=>new Element(tag),querySelectorAll:()=>[],
      querySelector:()=>new Element('button'),visibilityState:'visible'
    },
    sessionStorage:{getItem:()=>'',setItem(){},removeItem(){}},
    window:{addEventListener(){}},
    location:{hash:'',pathname:'/console/',origin:'http://localhost'},
    history:{replaceState(){}},URLSearchParams,Date,console,
    setInterval(callback,ms){intervals.push({callback,ms});},
    fetch(url,options){
      return new Promise((resolve,reject)=>requests.push({
        url,options,reject,
        reply(data){resolve({status:200,ok:true,json:async()=>data});}
      }));
    }
  });
  vm.runInContext(source,context,{filename:'web/app.js'});
  const evaluate=code=>vm.runInContext(code,context);
  return {
    get,requests,intervals,evaluate,
    render(run){
      context.fixture=run;
      evaluate('aiRun=fixture;drawAIRun(fixture)');
    },
    tenant(value){
      // 실제 change handler를 실행하되 별도 caseAction fetch는 억제한다.
      evaluate('caseBusy=true');
      get('ai-tenant').value=value;get('ai-tenant').dispatch('change');
      evaluate('caseBusy=false');
    },
    request(prefix){
      const index=requests.findIndex(request=>request.url.startsWith('/console/api/'+prefix));
      assert.notEqual(index,-1,'대기 요청 없음: '+prefix);
      return requests.splice(index,1)[0];
    }
  };
}
function run(id='r1',tenant='alpha',state='completed'){
  return {
    run_id:id,state,started_at:'2026-11-06T01:00:00Z',model_calls:2,
    request:{tenant_id:tenant,case_id:'case-'+id,case_sha256:'case-sha-'+id,model:'qwen-local',mode:'analyze'},
    model_digest:'sha256:model-'+id,
    steps:[
      {number:9,tool:'get_evidence',state:'failed',at:'2026-11-06T01:00:02Z',started_at:'2026-11-06T01:00:01Z',duration_ms:12,arguments:{evidence_ids:['ev-2']},error:'missing evidence'},
      {number:2,tool:'get_case',state:'done',result:{case_id:'case-'+id}},
      {number:3,tool:'finish_assessment',state:'pending',arguments:{}}
    ],
    assessment:{classification:'uncertain',summary:'저장된 요약',evidence_ids:['ev-2','ev-1']}
  };
}
const status={available:true,busy:false,audit_available:true,defense_enabled:true,models:[{name:'qwen-local'}]};
const cases=id=>({cases:[{case_id:id,asset_id:'asset',evidence_count:1}]});
async function flush(){for(let i=0;i<12;i++)await Promise.resolve();}

test('실제 저장 순서·상태·결속 입력·근거와 전체 JSON을 표시하고 상세로 이동한다',()=>{
  const h=harness(),r=run();r.request.mode='release';r.request.source_run_id='source-run';
  h.render(r);
  const root=h.get('ai-steps'),flow=descendants(root,'ol')[0];
  assert.equal(flow.attributes['aria-label'],'저장 기록 기반 실행 흐름');
  const cards=flow.children;
  assert.match(cards[1].textContent,/기록 1 · 원본 근거 확인 · 실패/);
  assert.match(cards[2].textContent,/기록 2 · 사건 조회 · 완료/);
  assert.match(cards[3].textContent,/기록 3 · 판단 기록 · 실행 중/);
  assert.match(cards[1].textContent,/기록 소요: 12 ms/);
  assert.ok(cards[1].textContent.includes('기록 시각: '+h.evaluate(`time(${JSON.stringify(r.steps[0].at)})`)));
  assert.ok(cards[1].textContent.includes('시작: '+h.evaluate(`time(${JSON.stringify(r.steps[0].started_at)})`)));
  assert.ok(cards[0].textContent.includes('시작: '+h.evaluate(`time(${JSON.stringify(r.started_at)})`)));
  assert.ok(!cards[0].textContent.includes('요청 모델 digest'));
  assert.match(cards[2].textContent,/시각·소요 기록 없음/);
  for(const value of [r.run_id,'alpha',r.request.case_id,r.request.case_sha256,'qwen-local',r.model_digest,'source-run']){
    assert.ok(cards[0].textContent.includes(value),value);
  }
  const outcome=cards.at(-1),evidence=descendants(outcome,'pre')[0];
  assert.equal(evidence.textContent,JSON.stringify(r.assessment.evidence_ids,null,2));
  const traces=descendants(root,'details');
  assert.equal(descendants(traces[0],'pre')[0].textContent,JSON.stringify(r.steps[0],null,2));
  assert.equal(descendants(traces.at(-1),'pre')[0].textContent,JSON.stringify(r,null,2));
  const button=descendants(cards[1],'button')[0];button.dispatch('click');
  assert.equal(button.attributes['aria-controls'],traces[0].id);
  assert.equal(traces[0].open,true);
  assert.equal(descendants(traces[0],'summary')[0].focused,true);
});

for(const state of ['running','completed']){
  test(`${state}: Go zero time과 빈 digest는 기록된 종료·만료로 표시하지 않는다`,()=>{
    const h=harness(),r=run('go-zero','alpha',state),zero='0001-01-01T00:00:00Z';
    r.ended_at=zero;r.policy_expires_at=zero;r.model_digest='';
    h.render(r);
    const flow=descendants(h.get('ai-steps'),'ol')[0],bound=flow.children[0],outcome=flow.children.at(-1);
    const facts=descendants(bound,'dl')[0],labels=descendants(facts,'dt'),values=descendants(facts,'dd');
    assert.equal(values[labels.findIndex(label=>label.textContent==='실행 모델 digest')].textContent,'기록 없음');
    assert.ok(!bound.textContent.includes('종료:'));
    assert.ok(!bound.textContent.includes('종료 시각:'));
    const details=h.get('ai-details'),detailLabels=descendants(details,'dt'),detailValues=descendants(details,'dd');
    assert.equal(detailValues[detailLabels.findIndex(label=>label.textContent==='로컬 정책 만료')].textContent,'기록 없음');
    assert.match(outcome.textContent,/만료: 기록 없음/);
    const localizedZero=h.evaluate(`time(${JSON.stringify(zero)})`);
    for(const element of [flow,details]){
      assert.ok(!element.textContent.includes(localizedZero));
      assert.ok(!element.textContent.includes(zero));
    }
    assert.ok(flow.children[1].textContent.includes('기록 시각: '+h.evaluate(`time(${JSON.stringify(r.steps[0].at)})`)));
    assert.match(flow.children[1].textContent,/기록 소요: 12 ms/);
    // 표시만 정규화하며 원본 Run JSON은 그대로 보존한다.
    assert.equal(descendants(descendants(h.get('ai-steps'),'details').at(-1),'pre')[0].textContent,JSON.stringify(r,null,2));
  });
}

test('assistant 기록 시각의 누락·빈 값·zero time은 생략하고 0 ms는 보존한다',()=>{
  const h=harness();
  assert.equal(h.evaluate(`aiRecordedTiming({
    at:'0001-01-01T00:00:00Z',created_at:'',started_at:null,
    completed_at:undefined,finished_at:'   ',ended_at:0,duration_ms:0
  })`),'기록 소요: 0 ms');
  assert.equal(h.evaluate(`aiRecordedTiming({ended_at:'0001-01-01T00:00:00.000000000Z'})`),'시각·소요 기록 없음');
  for(const value of [undefined,null,'']){
    const r=run();
    r.model_digest=value;r.policy_expires_at=value;
    h.render(r);
    const flow=descendants(h.get('ai-steps'),'ol')[0];
    assert.match(flow.children[0].textContent,/실행 모델 digest기록 없음/);
    assert.match(h.get('ai-details').textContent,/로컬 정책 만료기록 없음/);
    assert.match(flow.children.at(-1).textContent,/만료: 기록 없음/);
  }
});

test('완료 Run의 실제 종료·정책 만료·Step.at과 소요 시간은 유지한다',()=>{
  const h=harness(),r=run('go-completed');
  r.ended_at='2026-11-06T01:00:05Z';
  r.policy_id='local-policy';r.policy_expires_at='2026-11-06T01:05:00Z';
  h.render(r);
  const flow=descendants(h.get('ai-steps'),'ol')[0];
  const ended=h.evaluate(`time(${JSON.stringify(r.ended_at)})`);
  const expiry=h.evaluate(`time(${JSON.stringify(r.policy_expires_at)})`);
  const stepAt=h.evaluate(`time(${JSON.stringify(r.steps[0].at)})`);
  assert.ok(flow.children[0].textContent.includes('종료: '+ended));
  assert.ok(flow.children[0].textContent.includes(r.model_digest));
  assert.ok(h.get('ai-details').textContent.includes('로컬 정책 만료'+expiry));
  assert.ok(flow.children.at(-1).textContent.includes('만료: '+expiry));
  assert.ok(flow.children[1].textContent.includes('기록 시각: '+stepAt));
  assert.match(flow.children[1].textContent,/기록 소요: 12 ms/);
});

for(const [state,label] of Object.entries({
  queued:'실행 대기',running:'조사 진행 중',completed:'실행 완료',
  failed:'실행 실패',cancelled:'실행 취소',interrupted:'재시작으로 중단'
})){
  test(`${state}: 판정·도구가 없으면 실제 상태만 표시한다`,()=>{
    const h=harness(),r=run('empty','alpha',state);
    r.steps=[];delete r.assessment;
    if(state==='failed')r.error='실제 실행 오류';
    h.render(r);
    assert.match(h.get('ai-steps').textContent,/기록된 도구 없음/);
    assert.ok(h.get('ai-steps').textContent.includes(label));
    assert.match(h.get('ai-steps').textContent,/저장된 판정 없음/);
    assert.equal(h.get('ai-cancel').disabled,!['queued','running'].includes(state));
    if(r.error)assert.equal(h.get('ai-summary').textContent,r.error);
    if(['queued','running'].includes(state))assert.match(h.get('ai-steps').textContent,/아직 종료되지 않은 실행/);
  });
}

for(const [label,override] of [
  ['모델 연결 불가',{available:false}],
  ['서버 실행 중',{busy:true}],
  ['감사 기록 불가',{audit_available:false}]
]){
  test(`실제 tenant change와 caseAction 종료 후에도 시작 버튼 비활성 유지: ${label}`,async()=>{
    const h=harness();
    h.get('ai-tenant').value='beta';
    // harness.tenant()와 달리 caseAction을 억제하지 않고 실제 listener를 실행한다.
    h.get('ai-tenant').dispatch('change');
    assert.equal(h.evaluate('caseBusy'),true);
    h.request('settings').reply({tenants:['alpha','beta']});
    h.request('ai/status').reply({...status,...override});
    await flush();
    h.request('cases?').reply(cases('beta-case'));
    await flush();
    h.request('ai/runs?').reply({runs:[]});
    await flush();
    assert.equal(h.evaluate('caseBusy'),false);
    assert.equal(h.get('ai-analyze').disabled,true);
    assert.equal(h.get('ai-contain').disabled,true);
    assert.equal(h.get('ai-cancel').disabled,true);
    assert.equal(h.get('ai-release').disabled,true);
    assert.equal(h.requests.length,0);
  });
}

for(const state of ['queued','running']){
  test(`${state}: 이전 status가 사용 가능이어도 로컬 실행 중에는 추가 시작만 막는다`,()=>{
    const h=harness();
    h.evaluate('aiStatus={available:true,busy:false,audit_available:true};aiDefense=true');
    h.render(run('local','alpha',state));
    assert.equal(h.get('ai-analyze').disabled,true);
    assert.equal(h.get('ai-contain').disabled,true);
    assert.equal(h.get('ai-cancel').disabled,false);
    h.render(run('local','alpha','completed'));
    assert.equal(h.get('ai-analyze').disabled,false);
    assert.equal(h.get('ai-contain').disabled,false);
    assert.equal(h.get('ai-cancel').disabled,true);
  });
}

for(const id of ['ai-analyze','ai-contain','ai-cancel','ai-release']){
  test(`${id}: 공통 action finally 이후 assistant 상태를 다시 계산한다`,async()=>{
    const h=harness();
    h.evaluate('aiStatus={available:false,busy:false,audit_available:true}');
    await h.evaluate(`caseAction($(${JSON.stringify(id)}),async()=>{})`);
    assert.equal(h.evaluate('caseBusy'),false);
    assert.equal(h.get('ai-analyze').disabled,true);
    assert.equal(h.get('ai-contain').disabled,true);
    assert.equal(h.get('ai-cancel').disabled,true);
    assert.equal(h.get('ai-release').disabled,true);
  });
}

test('HTML처럼 보이는 저장 문자열은 실행 가능한 DOM이 아닌 텍스트다',()=>{
  const h=harness(),r=run(),payload='<img src=x onerror="alert(1)"><script>bad()</script>';
  r.request.case_id=payload;r.model_digest=payload;r.assessment.summary=payload;
  r.assessment.evidence_ids=[payload];r.steps[0].tool=payload;r.steps[0].error=payload;
  h.render(r);
  assert.ok(h.get('ai-steps').textContent.includes(payload));
  assert.equal(descendants(h.get('ai-steps'),'img').length,0);
  assert.equal(descendants(h.get('ai-steps'),'script').length,0);
});

test('목록 갱신 대기 중 명시적으로 선택한 실행을 보존한다',async()=>{
  const h=harness(),a=run('a'),b=run('b','alpha','running');
  const initial=h.evaluate('loadAIRuns()');h.request('ai/runs?').reply({runs:[a,b]});await initial;
  const buttons=descendants(h.get('ai-runs'),'button');
  const pending=h.evaluate('loadAIRuns()'),request=h.request('ai/runs?');
  buttons[1].dispatch('click');
  // 새 GET이 시작되었다는 이유만으로 현재 목록 버튼이 무효가 되어서는 안 된다.
  assert.equal(h.evaluate('aiRun.run_id'),'b');
  request.reply({runs:[a,b]});await pending;
  assert.equal(h.evaluate('aiRun.run_id'),'b');
  assert.equal(h.get('ai-cancel').disabled,false);
  const missing=h.evaluate('loadAIRuns()');h.request('ai/runs?').reply({runs:[a]});await missing;
  assert.equal(h.evaluate('aiRun.run_id'),'b');
});

test('같은 tenant의 역순 cases/runs 응답은 최신 결과를 덮지 않는다',async()=>{
  const h=harness();
  const oldCases=h.evaluate('loadAICases()'),oc=h.request('cases?');
  const newCases=h.evaluate('loadAICases()'),nc=h.request('cases?');
  nc.reply(cases('new-case'));await newCases;oc.reply(cases('old-case'));await oldCases;
  assert.equal(h.get('ai-case').value,'new-case');
  const oldRuns=h.evaluate('loadAIRuns()'),or=h.request('ai/runs?');
  const newRuns=h.evaluate('loadAIRuns()'),nr=h.request('ai/runs?');
  nr.reply({runs:[run('new')]});await newRuns;or.reply({runs:[run('old')]});await oldRuns;
  assert.equal(h.evaluate('aiRun.run_id'),'new');
});

test('tenant A→B→A 이전 cases/runs 응답은 버린다',async()=>{
  const h=harness();
  const ac=h.evaluate('loadAICases()'),acr=h.request('cases?');
  const ar=h.evaluate('loadAIRuns()'),arr=h.request('ai/runs?');
  h.tenant('beta');
  const bc=h.evaluate('loadAICases()'),bcr=h.request('cases?');
  const br=h.evaluate('loadAIRuns()'),brr=h.request('ai/runs?');
  h.tenant('alpha');
  const freshCases=h.evaluate('loadAICases()');h.request('cases?').reply(cases('fresh'));await freshCases;
  const freshRuns=h.evaluate('loadAIRuns()');h.request('ai/runs?').reply({runs:[run('fresh')]});await freshRuns;
  acr.reply(cases('old-alpha'));arr.reply({runs:[run('old-alpha')]});
  bcr.reply(cases('old-beta'));brr.reply({runs:[run('old-beta','beta')]});
  await Promise.all([ac,ar,bc,br]);
  assert.equal(h.get('ai-case').value,'fresh');
  assert.equal(h.evaluate('aiRun.run_id'),'fresh');
  assert.ok(!h.get('ai-runs').textContent.includes('old-'));
});

test('tenant A→B→A 이전 settings/status는 모델·권한·후속 GET을 변경하지 않는다',async()=>{
  const h=harness();
  const a=h.evaluate('loadAssistant()'),as=h.request('settings'),ast=h.request('ai/status');
  h.tenant('beta');
  const b=h.evaluate('loadAssistant()'),bs=h.request('settings'),bst=h.request('ai/status');
  h.tenant('alpha');
  const fresh=h.evaluate('loadAssistant()');
  h.request('settings').reply({tenants:['alpha','beta']});h.request('ai/status').reply(status);
  await flush();h.request('cases?').reply(cases('fresh'));
  await flush();h.request('ai/runs?').reply({runs:[run('fresh')]});await fresh;
  as.reply({tenants:['obsolete']});ast.reply({...status,available:false,defense_enabled:false,models:[{name:'old-alpha'}]});
  bs.reply({tenants:['obsolete']});bst.reply({...status,models:[{name:'old-beta'}]});
  await Promise.all([a,b]);
  assert.equal(h.get('ai-model').value,'qwen-local');
  assert.equal(h.get('ai-connection').textContent,'로컬 모델 연결됨');
  assert.equal(h.evaluate('aiRun.run_id'),'fresh');
  assert.equal(h.requests.length,0);
});

test('취소·해제 버튼은 표시 중인 tenant/run의 메타데이터만 따른다',()=>{
  const h=harness(),active=run('active','alpha','running');
  active.request.mode='contain';active.policy_id='local-policy';active.policy_expires_at='2099-01-01T00:00:00Z';
  h.evaluate('aiDefense=true');
  h.render(active);
  assert.equal(h.get('ai-cancel').disabled,false);
  assert.equal(h.get('ai-release').disabled,false);
  assert.match(h.get('ai-steps').textContent,/실제 edge 차단·해제 효과나 서명 승인의 증거가 아닙니다/);
  h.render(run('other','alpha','cancelled'));
  assert.equal(h.get('ai-cancel').disabled,true);
  assert.equal(h.get('ai-release').disabled,true);
  h.tenant('beta');
  assert.equal(h.get('ai-cancel').disabled,true);
  assert.equal(h.get('ai-release').disabled,true);
  assert.equal(h.get('ai-steps').textContent,'');
});

test('polling 대기 중 tenant가 바뀌면 이전 실행·상태·안내를 복원하지 않는다',async()=>{
  const h=harness();h.render(run('polling','alpha','running'));
  h.evaluate("token='test-only';view='assistant'");
  const poll=h.intervals.find(interval=>interval.ms===1500);
  const pending=poll.callback(),request=h.request('ai/runs?');
  h.tenant('beta');h.tenant('alpha');
  h.evaluate("notice('새 선택 안내')");
  request.reply({runs:[run('polling','alpha','completed')]});await pending;
  assert.equal(h.evaluate('aiRun'),null);
  assert.equal(h.get('notice').textContent,'새 선택 안내');
  assert.equal(h.get('ai-cancel').disabled,true);
  assert.equal(h.requests.length,0);
});

test('polling 대기 중 선택한 다른 실행의 취소·해제 상태를 보존한다',async()=>{
  const h=harness(),a=run('a','alpha','running'),b=run('b','alpha','cancelled');
  const initial=h.evaluate('loadAIRuns()');h.request('ai/runs?').reply({runs:[a,b]});await initial;
  h.evaluate("token='test-only';view='assistant'");
  const pending=h.intervals.find(interval=>interval.ms===1500).callback();
  const request=h.request('ai/runs?');
  descendants(h.get('ai-runs'),'button')[1].dispatch('click');
  request.reply({runs:[a,b]});await pending;
  assert.equal(h.evaluate('aiRun.run_id'),'b');
  assert.equal(h.get('ai-state').textContent,'취소됨');
  assert.equal(h.get('ai-cancel').disabled,true);
  assert.equal(h.get('ai-release').disabled,true);
  assert.equal(h.requests.length,0);
});
