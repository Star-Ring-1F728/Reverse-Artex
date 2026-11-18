'use strict';

// Execute the product script without a browser, network, or third-party packages.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const source=fs.readFileSync(path.join(__dirname,'..','web','app.js'),'utf8');
const endpoints={
  candidate:'cases/learning/detail',
  candidates:'cases/learning',
  shadow:'cases/learning/shadow/detail',
  shadows:'cases/learning/shadow',
  review:'cases/learning/review',
  automatic:'cases/learning/automatic',
  advisory:'cases/learning/advisory'
};

class Element {
  constructor(tag='div'){
    this.tagName=tag;
    this.children=[];
    this.listeners=new Map();
    this.value='';
    this.textContent='';
    this.hidden=false;
    this.disabled=false;
    this.classList={add(){},remove(){},toggle(){}};
  }
  append(...children){this.children.push(...children);}
  replaceChildren(...children){this.children=[...children];}
  get options(){return this.children;}
  get childElementCount(){return this.children.length;}
  addEventListener(type,listener){
    if(!this.listeners.has(type))this.listeners.set(type,[]);
    this.listeners.get(type).push(listener);
  }
  dispatch(type){
    for(const listener of this.listeners.get(type)||[])listener({target:this});
  }
  querySelector(){return new Element('button');}
  scrollIntoView(){}
  focus(){}
}

function harness(){
  const elements=new Map(),requests=[],intervals=[];
  const element=id=>{
    if(!elements.has(id))elements.set(id,new Element());
    return elements.get(id);
  };
  element('case-tenant').value='A';
  element('case-tenant').append(new Element('option'));
  const context=vm.createContext({
    console,URLSearchParams,
    document:{
      getElementById:element,
      createElement:tag=>new Element(tag),
      querySelectorAll:()=>[],
      visibilityState:'visible'
    },
    window:{addEventListener(){}},
    location:{hash:'',pathname:'/console',origin:'http://console.invalid'},
    history:{replaceState(){}},
    sessionStorage:{getItem:()=>null,setItem(){},removeItem(){}},
    setInterval:(callback,delay)=>{intervals.push({callback,delay});return intervals.length;},
    fetch:url=>new Promise((resolve,reject)=>{
      const parsed=new URL(url,'http://console.invalid');
      requests.push({
        path:parsed.pathname.replace('/console/api/',''),
        query:parsed.searchParams,
        resolve,reject,done:false
      });
    })
  });
  vm.runInContext(source,context,{filename:'web/app.js'});
  const evaluate=expression=>vm.runInContext(expression,context);
  const pending=(endpoint,query={})=>requests.filter(request=>
    !request.done&&request.path===endpoint&&
    Object.entries(query).every(([key,value])=>request.query.get(key)===String(value))
  );
  const respond=(endpoint,data,query={},latest=false)=>{
    const matches=pending(endpoint,query);
    const request=latest?matches.at(-1):matches[0];
    assert.ok(request,`Missing pending request: ${endpoint} ${JSON.stringify(query)}`);
    request.done=true;
    request.resolve({status:200,ok:true,json:async()=>data});
  };
  const fail=(endpoint,error,query={})=>{
    const request=pending(endpoint,query)[0];
    assert.ok(request,`Missing pending request: ${endpoint} ${JSON.stringify(query)}`);
    request.done=true;
    request.reject(error);
  };
  return {
    context,element,evaluate,requests,intervals,pending,respond,fail,
    state:expression=>JSON.parse(evaluate(`JSON.stringify(${expression})`)),
    switchTenant(tenant){
      // Exercise the real change listener while an action is busy; suppress only
      // its unrelated loadCases action, not the selection reset/invalidation.
      evaluate('caseBusy=true');
      element('case-tenant').value=tenant;
      try{element('case-tenant').dispatch('change');}
      finally{evaluate('caseBusy=false');}
    }
  };
}

const flush=()=>new Promise(resolve=>setImmediate(resolve));
const metrics=()=>({compared:0,true_attack:0,false_benign:0,false_attack:0,true_benign:0});

function candidate(id){
  return {
    candidate:{
      candidate_id:id,created_at:'2026-11-06T00:00:00Z',
      training_status:'fit_complete',fit_count:2,fit_attack:1,fit_benign:1,
      config:{minimum_fit_per_class:1},
      selection:{total:2,excluded:0},rows:[{},{}],
      selected_cohort_comparison:{
        candidate:metrics(),all_alerts_suspicious_reference:metrics()
      }
    },
    trainer_current:true,reevaluation_required:false,changed_cases:[]
  };
}
function shadow(run,revision=1,candidateId='C'){
  return {
    plan:{
      run_id:run,candidate_id:candidateId,started_at:'2026-11-06T00:00:00Z',
      baseline_selection:{total:2}
    },
    snapshot:{
      revision,total:0,scored:0,awaiting_label:0,excluded:0,rows:[],
      comparison:{candidate:metrics(),all_alerts_suspicious_reference:metrics()}
    },
    history:[],reevaluation_required:false,refresh_required:false
  };
}
function review(marker='fresh'){
  return {
    marker,state:'REVIEW_PLAN_REQUIRED',plan:null,blockers:[],decisions:[],
    assessment:{reasons:[]},
    default_criteria:{
      minimum_confirmed_attack:1,minimum_confirmed_benign:1,
      minimum_observation_seconds:0,minimum_label_coverage_bps:10000,
      maximum_false_attack_bps:10000
    }
  };
}
function automatic(marker='fresh'){
  return {
    automation:{
      marker,state:'disabled',enabled:false,revision:0,
      snapshot_revision:1,blockers:[]
    },
    worker:null
  };
}
function advisory(marker='fresh'){
  return {
    marker,state:'stopped',revision:0,current:null,blockers:[],
    suggestions:[],history:[],latest_review_stale:false
  };
}

async function selectCandidate(h,id){
  const task=h.context.showLearningCandidate('A',id);
  h.respond(endpoints.candidate,candidate(id),{candidate_id:id});
  await task;
}
async function finishShadow(h,task,run,revision=1,latest=false){
  h.respond(endpoints.shadow,shadow(run,revision),{run_id:run},latest);
  await flush();
  h.respond(endpoints.review,review(),{run_id:run},latest);
  await flush();
  h.respond(endpoints.automatic,automatic(),{run_id:run},latest);
  await flush();
  h.respond(endpoints.advisory,advisory(),{},latest);
  await task;
}

async function pollingHarness(){
  const h=harness();
  const initial=h.context.showShadow('A','R',1);
  await finishShadow(h,initial,'R',1);
  h.evaluate("token='test-only';view='cases';activeAutomatic.result.enabled=true");
  const poll=h.intervals.find(interval=>interval.delay===5000);
  assert.ok(poll);
  return {h,poll};
}

const tests=[];
function test(name,body){tests.push({name,body});}

test('같은 tenant의 늦은 후보 응답은 새 후보를 덮어쓰지 않는다',async()=>{
  const h=harness();
  const old=h.context.showLearningCandidate('A','old');
  const newer=h.context.showLearningCandidate('A','new');
  h.respond(endpoints.candidate,candidate('new'),{candidate_id:'new'});
  await newer;
  h.respond(endpoints.candidate,candidate('old'),{candidate_id:'old'});
  await old;
  assert.equal(h.state('selectedLearning.id'),'new');
  assert.equal(h.state('selectedLearning.result.candidate.candidate_id'),'new');
  assert.equal(JSON.parse(h.element('learning-json').textContent).candidate.candidate_id,'new');
});

test('진행 중이던 후보 목록 갱신은 이전 후보를 다시 선택하지 않는다',async()=>{
  const h=harness();
  await selectCandidate(h,'old');
  const list=h.context.loadLearningCandidates('A');
  const newer=h.context.showLearningCandidate('A','new');
  h.respond(endpoints.candidates,{candidates:[]});
  await flush();
  h.respond(endpoints.shadows,{runs:[]});
  await flush();
  h.respond(endpoints.advisory,advisory());
  await list;
  assert.equal(h.requests.filter(r=>r.path===endpoints.candidate&&r.query.get('candidate_id')==='old').length,1);
  h.respond(endpoints.candidate,candidate('new'),{candidate_id:'new'});
  await newer;
  assert.equal(h.state('selectedLearning.id'),'new');
});

test('같은 tenant의 run 역순 응답은 선택과 하위 요청을 되돌리지 않는다',async()=>{
  const h=harness();
  const old=h.context.showShadow('A','old');
  const newer=h.context.showShadow('A','new');
  await finishShadow(h,newer,'new',2);
  h.respond(endpoints.shadow,shadow('old'),{run_id:'old'});
  await old;
  assert.equal(h.state('selectedShadow.id'),'new');
  assert.equal(h.state('activeReview.run'),'new');
  assert.equal(h.state('activeAutomatic.run'),'new');
  assert.equal(h.element('shadow-state').textContent,'저장 관측 v2');
  assert.equal(h.requests.filter(r=>r.path===endpoints.review&&r.query.get('run_id')==='old').length,0);
});

test('같은 run의 과거 revision 응답은 최신 선택을 덮어쓰지 않는다',async()=>{
  const h=harness();
  const old=h.context.showShadow('A','R',1);
  const latest=h.context.showShadow('A','R');
  h.respond(endpoints.shadow,shadow('R',3),{run_id:'R'},true);
  await flush();
  h.respond(endpoints.review,review(),{run_id:'R'});
  await flush();
  h.respond(endpoints.automatic,automatic(),{run_id:'R'});
  await flush();
  h.respond(endpoints.advisory,advisory());
  await latest;
  h.respond(endpoints.shadow,shadow('R',1),{revision:1});
  await old;
  assert.equal(h.state('selectedShadow.result.snapshot.revision'),3);
  assert.equal(h.evaluate('selectedShadow.revision'),undefined);
  assert.equal(h.element('shadow-state').textContent,'저장 관측 v3');
});

test('진행 중이던 run 목록 갱신은 이전 revision을 복원하지 않는다',async()=>{
  const h=harness();
  const initial=h.context.showShadow('A','R',1);
  await finishShadow(h,initial,'R',1);
  const list=h.context.loadShadows('A');
  const newer=h.context.showShadow('A','R',2);
  h.respond(endpoints.shadows,{runs:[]});
  await list;
  assert.equal(h.requests.filter(r=>r.path===endpoints.shadow&&r.query.get('revision')==='1').length,1);
  await finishShadow(h,newer,'R',2);
  assert.equal(h.state('selectedShadow.revision'),2);
});

test('A→B→A 전환 후 이전 후보와 목록 응답을 무시한다',async()=>{
  const h=harness();
  const old=h.context.showLearningCandidate('A','old');
  const oldList=h.context.loadLearningCandidates('A');
  const oldCases=h.context.loadCases();
  h.switchTenant('B');
  h.switchTenant('A');
  await selectCandidate(h,'new');
  h.respond(endpoints.candidate,candidate('old'),{candidate_id:'old'});
  h.respond(endpoints.candidates,{candidates:[]});
  h.respond('cases',{cases:[]});
  await Promise.all([old,oldList,oldCases]);
  assert.equal(h.state('selectedLearning.id'),'new');
  assert.equal(h.requests.filter(r=>r.path===endpoints.candidates).length,1);
  assert.equal(h.pending(endpoints.shadows).length,0);
});

test('A→B→A 전환 후 같은 run의 이전 상세 응답을 무시한다',async()=>{
  const h=harness();
  const old=h.context.showShadow('A','R',1);
  h.switchTenant('B');
  h.switchTenant('A');
  const newer=h.context.showShadow('A','R',2);
  await finishShadow(h,newer,'R',2,true);
  h.respond(endpoints.shadow,shadow('R',1),{revision:1});
  await old;
  assert.equal(h.state('selectedShadow.revision'),2);
  assert.equal(h.state('selectedShadow.result.snapshot.revision'),2);
});

test('review·automatic·advisory는 같은 선택에서도 최신 요청만 반영한다',async()=>{
  const h=harness();
  const initial=h.context.showShadow('A','R');
  await finishShadow(h,initial,'R');
  const cases=[
    ['loadReview',endpoints.review,review,'activeReview.result.marker'],
    ['loadAutomatic',endpoints.automatic,automatic,'activeAutomatic.result.marker'],
    ['loadAdvisory',endpoints.advisory,advisory,'activeAdvisory.result.marker']
  ];
  for(const [fn,endpoint,fixture,state] of cases){
    const args=fn==='loadAdvisory'?['A']:['A','R'];
    const old=h.context[fn](...args);
    const newer=h.context[fn](...args);
    h.respond(endpoint,fixture('new'),{},true);
    await newer;
    h.respond(endpoint,fixture('old'));
    await old;
    assert.equal(h.state(state),'new',fn);
  }
});

test('선택 변경 중 도착한 하위 응답은 새 선택 상태를 채우지 않는다',async()=>{
  const h=harness();
  const initial=h.context.showShadow('A','old');
  await finishShadow(h,initial,'old');
  const oldReview=h.context.loadReview('A','old');
  const oldAutomatic=h.context.loadAutomatic('A','old');
  const oldAdvisory=h.context.loadAdvisory('A');
  const newer=h.context.showShadow('A','new');
  h.respond(endpoints.review,review('old'),{run_id:'old'});
  h.respond(endpoints.automatic,automatic('old'),{run_id:'old'});
  h.respond(endpoints.advisory,advisory('old'));
  await Promise.all([oldReview,oldAutomatic,oldAdvisory]);
  assert.equal(h.evaluate('activeReview'),null);
  assert.equal(h.evaluate('activeAutomatic'),null);
  assert.equal(h.state('activeAdvisory.result.marker'),'fresh');
  await finishShadow(h,newer,'new');
  assert.equal(h.state('activeReview.run'),'new');
});

test('A→B→A 이후 이전 review·automatic·advisory 응답을 무시한다',async()=>{
  const h=harness();
  const initial=h.context.showShadow('A','R');
  await finishShadow(h,initial,'R');
  const oldReview=h.context.loadReview('A','R');
  const oldAutomatic=h.context.loadAutomatic('A','R');
  const oldAdvisory=h.context.loadAdvisory('A');
  h.switchTenant('B');
  h.switchTenant('A');
  const newer=h.context.showShadow('A','R');
  await finishShadow(h,newer,'R',2,true);
  h.respond(endpoints.review,review('old'));
  h.respond(endpoints.automatic,automatic('old'));
  h.respond(endpoints.advisory,advisory('old'));
  await Promise.all([oldReview,oldAutomatic,oldAdvisory]);
  assert.equal(h.state('activeReview.result.marker'),'fresh');
  assert.equal(h.state('activeAutomatic.result.marker'),'fresh');
  assert.equal(h.state('activeAdvisory.result.marker'),'fresh');
  assert.equal(h.state('selectedShadow.result.snapshot.revision'),2);
});

test('이전 showShadow의 review 대기는 새 선택의 후속 요청을 시작하지 않는다',async()=>{
  const h=harness();
  const old=h.context.showShadow('A','old');
  h.respond(endpoints.shadow,shadow('old'),{run_id:'old'});
  await flush();
  const newer=h.context.showShadow('A','new');
  await finishShadow(h,newer,'new',2);
  h.respond(endpoints.review,review('old'),{run_id:'old'});
  await old;
  assert.equal(h.requests.filter(r=>r.path===endpoints.automatic&&r.query.get('run_id')==='old').length,0);
  assert.equal(h.requests.filter(r=>r.path===endpoints.advisory).length,1);
  assert.equal(h.state('activeReview.run'),'new');
});

test('실제 polling callback의 늦은 응답은 사용자가 고른 revision을 복원하지 않는다',async()=>{
  const h=harness();
  const initial=h.context.showShadow('A','R',1);
  await finishShadow(h,initial,'R',1);
  h.evaluate("token='test-only';view='cases';activeAutomatic.result.enabled=true");
  const poll=h.intervals.find(interval=>interval.delay===5000);
  assert.ok(poll);
  const polling=poll.callback();
  const newer=h.context.showShadow('A','R',2);
  await finishShadow(h,newer,'R',2,true);
  h.respond(endpoints.shadow,shadow('R',1),{revision:1});
  await polling;
  assert.equal(h.state('selectedShadow.revision'),2);
  assert.equal(h.element('shadow-state').textContent,'저장 관측 v2');
  assert.equal(h.evaluate('learningPolling'),false);
  assert.equal(h.requests.filter(r=>r.path===endpoints.advisory).length,2);
});

test('같은 대상 polling 실패 후 표시 상태를 유지하고 다음 polling에서 복구한다',async()=>{
  const h=harness();
  const initial=h.context.showShadow('A','R',1);
  await finishShadow(h,initial,'R',1);
  h.evaluate("token='test-only';view='cases';activeAutomatic.result.enabled=true");
  const poll=h.intervals.find(interval=>interval.delay===5000);
  assert.ok(poll);
  const previous=h.evaluate('selectedShadow');
  const rendered=h.evaluate('selectedShadow.result');
  const previousReview=h.evaluate('activeReview');
  const previousAutomatic=h.evaluate('activeAutomatic');
  const assertPreserved=()=>{
    assert.equal(h.evaluate('selectedShadow.result'),rendered);
    assert.equal(h.evaluate('activeReview'),previousReview);
    assert.equal(h.evaluate('activeAutomatic'),previousAutomatic);
    assert.equal(h.element('shadow-state').textContent,'저장 관측 v1');
    for(const id of ['shadow-detail','review-panel','automatic-panel']){
      assert.equal(h.element(id).hidden,false,id);
    }
  };

  const failed=poll.callback();
  assert.equal(h.pending(endpoints.shadow,{run_id:'R',revision:1}).length,1);
  const failedSelection=h.evaluate('selectedShadow');
  assert.notEqual(failedSelection,previous);
  assertPreserved();
  h.fail(endpoints.shadow,new Error('일시적인 네트워크 오류'),{run_id:'R',revision:1});
  await failed;
  assert.equal(h.evaluate('learningPolling'),false);
  assert.equal(h.element('notice').textContent,'일시적인 네트워크 오류');
  assertPreserved();

  const retry=poll.callback();
  assert.equal(h.pending(endpoints.shadow,{run_id:'R',revision:1}).length,1);
  assert.notEqual(h.evaluate('selectedShadow'),failedSelection);
  assertPreserved();
  await finishShadow(h,retry,'R',1);
  assert.equal(h.evaluate('learningPolling'),false);
  assert.equal(h.state('selectedShadow.result.snapshot.revision'),1);
  assert.equal(h.state('activeReview.run'),'R');
  assert.equal(h.state('activeAutomatic.run'),'R');
  assert.equal(h.requests.filter(r=>r.path===endpoints.shadow).length,3);
  assert.equal(h.requests.filter(r=>r.path===endpoints.advisory).length,2);
  for(const id of ['shadow-detail','review-panel','automatic-panel']){
    assert.equal(h.element(id).hidden,false,id);
  }
});

test('실패한 polling이 소유한 오류 안내는 다음 interval의 성공 후 사라진다',async()=>{
  const {h,poll}=await pollingHarness();
  const failed=poll.callback();
  h.fail(endpoints.shadow,new Error('Failed to fetch'),{run_id:'R',revision:1});
  await failed;
  assert.equal(h.element('notice').textContent,'Failed to fetch');
  assert.equal(h.element('notice').hidden,false);
  assert.equal(h.evaluate('learningPollingNotice.generation===noticeGeneration'),true);

  const retry=poll.callback();
  assert.equal(h.element('notice').textContent,'Failed to fetch');
  await finishShadow(h,retry,'R',1);
  assert.equal(h.element('notice').textContent,'');
  assert.equal(h.element('notice').hidden,true);
  assert.equal(h.evaluate('learningPollingNotice'),null);
  assert.equal(h.evaluate('learningPolling'),false);
  for(const id of ['shadow-detail','review-panel','automatic-panel']){
    assert.equal(h.element(id).hidden,false,id);
  }
});

test('복구 중 새 사용자 안내는 같은 오류 문구여도 polling이 지우지 않는다',async()=>{
  const {h,poll}=await pollingHarness();
  const failed=poll.callback();
  h.fail(endpoints.shadow,new Error('Failed to fetch'));
  await failed;
  const ownedGeneration=h.evaluate('noticeGeneration');

  const retry=poll.callback();
  h.context.notice('Failed to fetch');
  assert.ok(h.evaluate('noticeGeneration')>ownedGeneration);
  await finishShadow(h,retry,'R',1);
  assert.equal(h.element('notice').textContent,'Failed to fetch');
  assert.equal(h.element('notice').hidden,false);
});

test('polling 도중 생긴 사용자 안내를 늦은 실패가 덮어쓰지 않는다',async()=>{
  const {h,poll}=await pollingHarness();
  const pending=poll.callback();
  h.context.notice('사용자 작업 완료');
  h.fail(endpoints.shadow,new Error('늦은 네트워크 오류'));
  await pending;
  assert.equal(h.element('notice').textContent,'사용자 작업 완료');
  assert.equal(h.evaluate('learningPollingNotice'),null);
  assert.equal(h.evaluate('learningPolling'),false);
});

for(const transition of ['run','tenant']){
  test(`${transition} 전환 후 이전 polling 실패는 새 선택의 안내를 덮어쓰지 않는다`,async()=>{
    const {h,poll}=await pollingHarness();
    const pending=poll.callback();
    if(transition==='tenant'){
      h.switchTenant('B');
      h.switchTenant('A');
    }
    const run=transition==='run'?'new':'R';
    const newer=h.context.showShadow('A',run,2);
    await finishShadow(h,newer,run,2,true);
    h.context.notice('새 선택의 안내');
    const generation=h.evaluate('noticeGeneration');

    h.fail(endpoints.shadow,new Error('이전 선택의 오류'),{run_id:'R',revision:1});
    await pending;
    assert.equal(h.element('notice').textContent,'새 선택의 안내');
    assert.equal(h.evaluate('noticeGeneration'),generation);
    assert.equal(h.state('selectedShadow.id'),run);
    assert.equal(h.state('selectedShadow.revision'),2);
    assert.equal(h.evaluate('learningPollingNotice'),null);
    assert.equal(h.evaluate('learningPolling'),false);
  });
}

test('같은 대상의 더 최신 상세 요청 이후 이전 polling 실패도 무시한다',async()=>{
  const {h,poll}=await pollingHarness();
  const pending=poll.callback();
  const newer=h.context.showShadow('A','R',1);
  await finishShadow(h,newer,'R',1,true);
  const generation=h.evaluate('noticeGeneration');
  h.fail(endpoints.shadow,new Error('이전 요청의 오류'),{run_id:'R',revision:1});
  await pending;
  assert.equal(h.evaluate('noticeGeneration'),generation);
  assert.equal(h.element('notice').textContent,'');
  assert.equal(h.evaluate('learningPollingNotice'),null);
});

test('다른 선택의 성공은 이전 polling 오류 안내의 소유권을 가져가지 않는다',async()=>{
  const {h,poll}=await pollingHarness();
  const failed=poll.callback();
  h.fail(endpoints.shadow,new Error('이전 관측 오류'));
  await failed;
  const generation=h.evaluate('noticeGeneration');
  const newer=h.context.showShadow('A','new',2);
  await finishShadow(h,newer,'new',2);
  h.evaluate('activeAutomatic.result.enabled=true');
  const polling=poll.callback();
  await finishShadow(h,polling,'new',2);
  assert.equal(h.element('notice').textContent,'이전 관측 오류');
  assert.equal(h.evaluate('noticeGeneration'),generation);
});

test('작업 안내는 다른 run의 검토·자동 관측 상태를 사용하지 않는다',async()=>{
  const h=harness();
  await selectCandidate(h,'C');
  const initial=h.context.showShadow('A','R');
  await finishShadow(h,initial,'R');
  h.evaluate(`
    activeReview={tenant:'A',run:'other',result:{
      state:'APPROVED_FOR_EVALUATION',plan:{}
    }};
    activeAutomatic={tenant:'A',run:'other',result:{
      state:'blocked',enabled:true
    }};
    drawLearningWorkbench();
  `);
  assert.equal(h.state('workbenchTarget'),'review-register');
  assert.equal(h.element('lifecycle-stage').textContent,'새 사건 관측');
  h.evaluate(`
    activeReview.run='R';
    activeAutomatic.run='R';
    drawLearningWorkbench();
  `);
  assert.equal(h.state('workbenchTarget'),'automatic-disable');
});

test('작업 안내는 관측 대기·재검토보다 중단 상태를 우선한다',async()=>{
  const h=harness();
  await selectCandidate(h,'C');
  const initial=h.context.showShadow('A','R');
  await finishShadow(h,initial,'R');
  h.evaluate(`
    activeAdvisory.result.state='blocked';
    activeAdvisory.result.current={request:{run_id:'R'}};
    drawLearningWorkbench();
  `);
  assert.equal(h.element('lifecycle-stage').textContent,'추천 검토 필요');
  assert.equal(h.state('workbenchTarget'),'review-panel');
  h.evaluate(`
    selectedShadow.result.reevaluation_required=true;
    activeAutomatic.result.state='blocked';
    activeAutomatic.result.enabled=true;
    drawLearningWorkbench();
  `);
  assert.equal(h.state('workbenchTarget'),'automatic-disable');
});

(async()=>{
  let failures=0;
  for(const {name,body} of tests){
    try{
      await body();
      console.log(`PASS ${name}`);
    }catch(error){
      failures++;
      console.error(`FAIL ${name}`);
      console.error(error);
    }
  }
  console.log(`${tests.length-failures} pass / ${failures} fail`);
  if(failures)process.exitCode=1;
})().catch(error=>{
  console.error(error);
  process.exitCode=1;
});
