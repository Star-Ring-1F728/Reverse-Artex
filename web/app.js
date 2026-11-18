'use strict';
const $=id=>document.getElementById(id);
const titles={overview:['방어 현황','수집기 상태와 실제 관측 증거를 확인합니다.'],alerts:['탐지 경보','수집된 증거에 기반한 HTTP 경보를 검토합니다.'],events:['이벤트 탐색','실제 수집된 HTTP 이벤트와 관측 범위를 확인합니다.'],cases:['사건 기억','증거와 판정 이력을 보존하고 학습 대상을 선정합니다.'],assistant:['Qwen 사건 조사','로컬 모델이 사건 근거를 확인하고 허용된 도구를 실행합니다.'],analysis:['파일 분석','정규화 이벤트를 별도 탐지 엔진에서 분석합니다.'],settings:['연결 설정','센서 연결 정보와 현재 배포 설정을 확인합니다.']};
const ruleNames={'RA-001':'사용자 에이전트 신호','RA-002':'경로 탐색·오류 집중','RA-003':'탐색·검증·권한 연쇄','RA-004':'리소스 권한 위반','RA-005':'검증 실패 패턴','RA-006':'프로세스·네트워크','RA-007':'데이터 반출 예산','RA-008':'카나리 접근'};
let token=sessionStorage.getItem('ra-console-key')||'',view='overview',eventRows=[];
function consumeConsoleLink(){
  const key=new URLSearchParams(location.hash.slice(1)).get('token');
  if(!key)return false;
  token=key;
  sessionStorage.setItem('ra-console-key',key);
  history.replaceState(null,'',location.pathname+location.search);
  return true;
}
consumeConsoleLink();
window.addEventListener('hashchange',()=>{
  // Restart the page so pending requests cannot clear the newly supplied key.
  if(consumeConsoleLink())location.reload();
});
let noticeGeneration=0;
function notice(message){noticeGeneration++;$('notice').textContent=message;$('notice').hidden=!message;}
function node(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=String(text);if(cls)e.className=cls;return e;}
function gotoButton(label,destination){const button=node('button',label,'secondary');button.addEventListener('click',()=>select(destination));return button;}
function empty(target,title,subtitle,actions=[]){target.replaceChildren();const box=node('div',undefined,'empty');box.append(node('strong',title),node('span',subtitle));if(actions.length){const links=node('div',undefined,'empty-actions');for(const [label,destination] of actions)links.append(gotoButton(label,destination));box.append(links);}target.append(box);}
function time(value){if(!value)return '—';const t=new Date(value);return Number.isNaN(t.valueOf())?String(value):t.toLocaleString('ko-KR',{hour12:false});}
function number(value){return Number(value||0).toLocaleString('ko-KR');}
async function api(path,options={}){
  const requestKey=token;
  const response=await fetch('/console/api/'+path,{...options,headers:{...options.headers,Authorization:'Bearer '+requestKey}});
  if(response.status===401){
    if(requestKey===token){
      sessionStorage.removeItem('ra-console-key');
      $('application').hidden=true;
      $('login').hidden=false;
    }
    throw Error('콘솔 접속 키를 확인하세요. 서버 재시작 후에는 새 접속 링크를 사용하세요.');
  }
  if(!response.ok)throw Error((await response.text()).slice(0,300));
  return response.json();
}
function details(target,values){target.replaceChildren();for(const [label,value] of values){target.append(node('dt',label),node('dd',value??'—'));}}
function alerts(target,rows){target.replaceChildren();if(!rows.length){empty(target,'아직 수집된 HTTP 경보가 없습니다.','센서에서 이벤트를 수신하고 탐지 조건이 충족되면 표시됩니다. 경보 0건만으로 안전을 판단할 수 없습니다. 샘플 결과는 이 목록에 들어오지 않습니다.',[['센서 연결 설정','settings'],['파일 분석 체험','analysis']]);return;}for(const row of rows){const item=node('details'),summary=node('summary');summary.append(node('span',row.rule_id||'HOST','rule-badge'));const main=node('span',undefined,'record-main');main.append(node('b',ruleNames[row.rule_id]||row.case_id||'경보'),node('small',`${row.tenant_id||'—'} / ${row.asset_id||'—'} · ${row.confidence||'관측'}`));summary.append(main,node('span',time(row.alert_time),'record-time'));item.append(summary,node('pre',JSON.stringify(row,null,2)));target.append(item);}}
async function overview(){const s=await api('status');const received=Number(s.evidence?.record_counts?.events||0);$('metric-state').textContent=s.ingest_degraded?'점검 필요':received?'수집 기록 있음':'수신 대기';$('getting-started-status').textContent=received?'실제 HTTP 이벤트 '+number(received)+'건이 저장되어 있습니다. 경보를 확인한 뒤 사건 기억에서 수집 증거를 동기화하세요.':'아직 저장된 HTTP 이벤트가 없습니다. 샘플 체험은 센서 없이 가능하며, 실제 관측을 시작하려면 센서를 연결하세요.';$('metric-mode').textContent=s.policy_forwarding_configured?'관측 모드 · 정책 전달 설정됨':'관측 모드';$('metric-events').textContent=number(s.evidence?.record_counts?.events);$('metric-alerts').textContent=number(s.evidence?.record_counts?.alerts);$('metric-subjects').textContent=number(s.detector?.subjects);details($('telemetry-details'),[['수집 주소',location.origin],['상관 범위',s.correlation_scope],['이벤트 보존',s.data_dir||'data/collector'],['정책 전달',s.policy_forwarding_configured?'설정됨':'미설정'],['마지막 조회',new Date().toLocaleTimeString('ko-KR')]]);$('rules').replaceChildren();for(const [id,name] of Object.entries(ruleNames)){const card=node('div',undefined,'rule-card');card.append(node('b',id),node('span',name),node('small',(s.rules?.[id]||'관측 조건 확인').replaceAll('_',' ')));$('rules').append(card);}const a=await api('stream?name=alerts');alerts($('overview-alerts'),a.rows.slice(0,4));}
function drawEvents(){const term=$('event-filter').value.trim().toLowerCase(),body=$('event-rows');body.replaceChildren();for(const e of eventRows.filter(x=>!term||JSON.stringify(x).toLowerCase().includes(term))){const row=node('tr');for(const val of [time(e.event_time),e.event_id,e.tenant_id,e.route_template,e.status])row.append(node('td',val??'—'));body.append(row);}if(!body.childElementCount){const row=node('tr'),cell=node('td');cell.colSpan=5;if(term)empty(cell,'검색과 일치하는 이벤트가 없습니다.','검색어를 지우거나 테넌트, 경로, 이벤트 ID를 다시 확인하세요.');else empty(cell,'아직 수신한 HTTP 이벤트가 없습니다.','센서를 POST /v1/events에 연결하면 이 목록에서 확인할 수 있습니다. 샘플·파일 분석은 실제 수집 이벤트에 포함되지 않습니다.',[['센서 연결 설정','settings']]);row.append(cell);body.append(row);}}
async function settings(){const s=await api('settings');details($('settings-details'),[['수집 주소',s.endpoint],['센서 ID',s.sensor_id],['자산 ID',s.asset_id],['테넌트',s.tenants],['수집 API','POST /v1/events'],['상관 범위',s.correlation_scope],['데이터 경로',s.data_dir]]);$('sensor-token').value='';$('sensor-token').hidden=true;$('token-label').hidden=true;}
async function refresh(){try{if(view==='overview')await overview();else if(view==='alerts'){const d=await api('stream?name=alerts');alerts($('alert-records'),d.rows);}else if(view==='events'){const d=await api('stream?name=events');eventRows=d.rows;drawEvents();}else if(view==='settings')await settings();else if(view==='cases')await loadCases();else if(view==='assistant')await loadAssistant();else await api('status');$('connection-label').textContent='콘솔 서버 연결됨';$('connection-dot').classList.remove('disconnected');}catch(e){notice(e.message);$('connection-label').textContent='연결 확인 필요';}}
function select(name){view=name;for(const [id,value] of Object.entries(titles)){$('view-'+id).hidden=id!==name;document.querySelector(`[data-view="${id}"]`).classList.toggle('active',id===name);}[$('page-title').textContent,$('page-description').textContent]=titles[name];$('breadcrumb').textContent=document.querySelector(`[data-view="${name}"]`).textContent.trim();notice('');refresh();}
async function connect(){
  const attemptKey=token;
  try{
    await api('status');
    if(attemptKey!==token)return;
    sessionStorage.setItem('ra-console-key',attemptKey);
    $('login').hidden=true;
    $('application').hidden=false;
    select('overview');
  }catch(e){
    if(attemptKey!==token)return;
    $('login').hidden=false;
    $('application').hidden=true;
    let error=$('login-error');
    if(!error){error=node('p',undefined,'muted');error.id='login-error';$('login').append(error);}
    error.textContent=e.message;
  }
}
async function analyze(path,body){const button=path==='sample'?$('sample'):$('analyze-form').querySelector('button');button.disabled=true;notice('');try{const result=await api(path,{method:'POST',body,headers:{'Content-Type':'application/x-ndjson'}}),target=$('analysis-result');target.className='';target.replaceChildren();const stats=node('div',undefined,'analysis-stats');for(const [n,label] of [[result.events,'분석 이벤트'],[result.alerts.length,'탐지 경보'],[result.policy_actions,'정책 실행']]){const stat=node('div');stat.append(node('strong',n),node('span',label));stats.append(stat);}target.append(stats,node('p','별도 분석 완료 · 실제 수집 원장·사건 기억 변경 없음 · 정책 실행 없음','muted'));const next=node('div',undefined,'empty-actions');next.append(gotoButton('다음 · 내 센서 연결','settings'),gotoButton('실제 수집 이벤트 보기','events'));target.append(next);const list=node('div',undefined,'records');if(result.alerts.length)alerts(list,result.alerts);else empty(list,'탐지된 경보가 없습니다.','분석 입력과 탐지 조건을 함께 확인하세요.');target.append(list);}catch(e){notice(e.message);}finally{button.disabled=false;}}
document.querySelectorAll('[data-view]').forEach(button=>button.addEventListener('click',()=>select(button.dataset.view)));
document.querySelectorAll('[data-goto]').forEach(button=>button.addEventListener('click',()=>select(button.dataset.goto)));
$('login-form').addEventListener('submit',e=>{e.preventDefault();token=$('access-key').value.trim();connect();});
$('refresh').addEventListener('click',()=>{notice('');refresh();});$('event-filter').addEventListener('input',drawEvents);
$('sample').addEventListener('click',()=>analyze('sample'));
$('first-sample').addEventListener('click',async()=>{const button=$('first-sample');if(button.disabled)return;button.disabled=true;select('analysis');try{await analyze('sample');}finally{button.disabled=false;}});
$('analyze-form').addEventListener('submit',async e=>{e.preventDefault();const file=$('event-file').files[0];if(!file)return;if(file.size>1048576){notice('1 MiB 이하의 JSONL 파일을 선택하세요.');return;}analyze('analyze',await file.text());});
$('credential').addEventListener('click',async()=>{try{const data=await api('sensor-credential');$('sensor-token').value=data.token;$('sensor-token').hidden=false;$('token-label').hidden=false;$('sensor-token').type='text';}catch(e){notice(e.message);}});
$('logout').addEventListener('click',()=>{token='';$('connection-label').textContent='연결 해제';sessionStorage.removeItem('ra-console-key');$('sensor-token').value='';$('application').hidden=true;$('login').hidden=false;$('access-key').value='';});

let selectedCase=null,savedSelection=null,selectedLearning=null,selectedShadow=null,activeReview=null,activeAutomatic=null,activeAdvisory=null,caseBusy=false;
const labelNames={confirmed_attack:'공격 확인',confirmed_benign:'정상 확인',uncertain:'보류',disputed:'상충'};
let learningEpoch=0;
const learningRequestVersions=Object.create(null);
function learningRequestGuard(scope,tenant,selection=undefined){
  const epoch=learningEpoch,version=(learningRequestVersions[scope]||0)+1;
  learningRequestVersions[scope]=version;
  return ()=>epoch===learningEpoch&&tenant===$('case-tenant').value&&version===learningRequestVersions[scope]&&(selection===undefined||selection===selectedShadow);
}
function caseQuery(id){return new URLSearchParams({tenant:$('case-tenant').value,...(id?{case_id:id}:{})}).toString();}
async function caseAction(button,action){if(caseBusy)return;caseBusy=true;button.disabled=true;notice('');try{await action();}catch(e){notice(e.message);}finally{caseBusy=false;button.disabled=false;if(['ai-analyze','ai-contain','ai-cancel','ai-release'].includes(button.id))syncAIButtons();if(button.id==='automatic-enable'||button.id==='automatic-disable')syncAutomaticButtons();}}
async function loadCases(){
  const epoch=learningEpoch;
  if(!$('case-tenant').options.length){const s=await api('settings');if(epoch!==learningEpoch)return;const tenants=Array.isArray(s.tenants)?s.tenants:String(s.tenants||'').split(',');for(const tenant of tenants.filter(Boolean)){const option=node('option',tenant);option.value=tenant;$('case-tenant').append(option);}}
  if(!$('case-tenant').value)return;
  void loadContextShadow();
  const tenant=$('case-tenant').value,current=learningRequestGuard('cases',tenant),d=await api('cases?'+caseQuery()),target=$('case-list');if(!current())return;target.replaceChildren();await loadLearningCandidates(tenant);if(!current())return;
  if(!d.cases.length){empty(target,'저장한 사건이 없습니다.','먼저 실제 HTTP 경보가 있는지 확인한 뒤 위의 ‘수집 증거 동기화’를 누르세요. 샘플·파일 분석 결과는 동기화되지 않습니다.',[['실제 HTTP 경보 확인','alerts'],['센서 연결 설정','settings']]);return;}
  for(const entry of d.cases){const c=entry,l=entry.label,item=node('div',undefined,'case-row'),button=node('button',c.case_id,'text-button');button.addEventListener('click',()=>caseAction(button,()=>showCase(c.case_id)));item.append(button,node('span',`${c.asset_id} · 증거 ${c.evidence_count}건 · ${l?labelNames[l.value]:'미분류'}${l&&!entry.label_current?' / 재검토 필요':''}`,'muted'));target.append(item);}
}
async function showCase(id){const tenant=$('case-tenant').value,d=await api('cases/detail?'+caseQuery(id));if(tenant!==$('case-tenant').value)return;selectedCase=d;const c=d.current.case;$('case-detail').hidden=false;$('case-heading').textContent=c.case_id;$('case-revision').textContent='사건 v'+d.current.revision;details($('case-facts'),[['Tenant',c.tenant_id],['자산',c.asset_id],['첫 경보',time(c.first_alert_at)],['마지막 경보',time(c.last_alert_at)],['저장 시각',time(d.current.saved_at)],['증거 버전',d.current.case_sha256]]);$('case-evidence').textContent=JSON.stringify(d.case_revisions,null,2);const latest=d.label_history.at(-1);$('case-label-state').textContent=latest?(d.label_current?'현재 증거에 대한 판정: ':'새 증거로 재검토 필요: ')+labelNames[latest.value]:'아직 판정하지 않은 사건입니다.';$('case-label').value=latest?.value||'uncertain';$('case-reason').value='';const history=$('case-label-history');history.replaceChildren();for(const label of [...d.label_history].reverse()){const item=node('details'),title=node('summary',`v${label.revision} · ${labelNames[label.value]} · ${time(label.created_at)}`);item.append(title,node('p',label.reason),node('pre',JSON.stringify(label,null,2)));history.append(item);}}
$('case-tenant').addEventListener('change',()=>{learningEpoch++;selectedCase=null;savedSelection=null;selectedLearning=null;selectedShadow=null;activeReview=null;activeAutomatic=null;activeAdvisory=null;$('automatic-panel').hidden=true;$('advisory-suggestions').replaceChildren();$('advisory-history').replaceChildren();$('review-panel').hidden=true;$('shadow-detail').hidden=true;$('shadow-list').replaceChildren();$('case-detail').hidden=true;$('selection-panel').hidden=true;$('learning-detail').hidden=true;$('learning-list').replaceChildren();drawLearningWorkbench();caseAction($('case-sync'),loadCases);});
$('case-sync').addEventListener('click',()=>caseAction($('case-sync'),async()=>{const result=await api('cases/sync',{method:'POST'});await loadCases();if(selectedCase)await showCase(selectedCase.current.case.case_id);notice(`사건 동기화 완료 · 변경 ${result.changed_cases}건`);}));
$('case-label-form').addEventListener('submit',e=>{e.preventDefault();const button=e.submitter;if(!selectedCase)return;const current=selectedCase,tenant=current.current.case.tenant_id,id=current.current.case.case_id;caseAction(button,async()=>{try{await api('cases/label?'+new URLSearchParams({tenant,case_id:id}),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({expected_label_revision:current.label_history.length,case_sha256:current.current.case_sha256,value:$('case-label').value,reason:$('case-reason').value})});await loadCases();await showCase(id);notice('라벨 이력을 저장했습니다. 기존 선정 기록은 재평가 여부를 확인하세요.');}catch(error){await showCase(id);throw error;}});});
$('case-selection').addEventListener('click',()=>caseAction($('case-selection'),async()=>{const tenant=$('case-tenant').value,result=await api('cases/selection?'+caseQuery(),{method:'POST'});savedSelection={tenant,sha:result.selection_sha256};$('selection-panel').hidden=false;$('selection-summary').textContent=`전체 ${result.total}건 · 선정 ${result.eligible}건 · 제외 ${result.excluded}건`;drawSelection(result);await loadCases();}));
$('selection-check').addEventListener('click',()=>caseAction($('selection-check'),async()=>{if(!savedSelection)return;await api('cases/sync',{method:'POST'});const result=await api('cases/selection/saved?'+new URLSearchParams({tenant:savedSelection.tenant,sha256:savedSelection.sha}));$('selection-summary').textContent=result.reevaluation_required?'재평가 필요 · 변경 사건 '+result.changed_cases.join(', '):'저장한 선정 이후 사건·라벨 변경 없음';drawSelection(result);}));

let aiCaseRows=[],aiRun=null,aiDefense=false,aiPolling=false,aiRequestedCase=null;
let aiEpoch=0,aiStatus=null,aiCasesLoaded=false;
const aiRequestVersions=Object.create(null);
function aiRequestGuard(scope){
  const epoch=aiEpoch,tenant=$('ai-tenant').value,version=(aiRequestVersions[scope]||0)+1;
  aiRequestVersions[scope]=version;
  return ()=>epoch===aiEpoch&&tenant===$('ai-tenant').value&&version===aiRequestVersions[scope];
}
function syncAIButtons(){
  const selected=aiRun?.request.tenant_id===$('ai-tenant').value?aiRun:null;
  const active=!!selected&&['queued','running'].includes(selected.state);
  $('ai-analyze').disabled=!aiStatus?.available||aiStatus.busy||!aiStatus.audit_available||(aiCasesLoaded&&(!$('ai-case').value||!$('ai-model').value))||active;
  $('ai-contain').disabled=$('ai-analyze').disabled||!aiDefense;
  $('ai-cancel').disabled=!selected||!['queued','running'].includes(selected.state);
  $('ai-release').disabled=!selected||!aiDefense||!selected.policy_id||selected.request.mode!=='contain'||!selected.policy_expires_at||!(new Date(selected.policy_expires_at)>new Date());
}
function resetAITenant(){
  aiEpoch++;aiRun=null;aiCaseRows=[];aiStatus=null;aiDefense=false;aiCasesLoaded=false;
  $('ai-case').replaceChildren();$('ai-runs').replaceChildren();$('ai-steps').replaceChildren();$('ai-details').replaceChildren();
  $('ai-state').textContent='미선택';$('ai-summary').textContent='현재 tenant의 저장 실행을 선택하세요.';
  $('ai-connection').textContent='연결 확인 필요';
  $('ai-response-note').textContent='현재 tenant의 연결 상태를 새로고침하여 확인하세요.';
  syncAIButtons();
}
const aiStates={queued:'대기',running:'조사 중',completed:'완료',failed:'실패',cancelled:'취소됨',interrupted:'재시작으로 중단'};
const aiTools={get_case:'사건 조회',get_evidence:'원본 근거 확인',apply_temporary_deny:'임시 차단 적용',release_policy:'임시 차단 해제',finish_assessment:'판단 기록'};
async function loadAssistant(){
  const version=(aiRequestVersions.assistant||0)+1,requested=aiRequestedCase;
  aiRequestVersions.assistant=version;
  let epoch=aiEpoch,tenant=$('ai-tenant').value;
  const current=()=>epoch===aiEpoch&&tenant===$('ai-tenant').value&&version===aiRequestVersions.assistant;
  let settings,status;
  try{[settings,status]=await Promise.all([api('settings'),api('ai/status')]);}catch(error){if(current())throw error;return;}
  if(!current())return;
  if(!$('ai-tenant').options.length){const tenants=Array.isArray(settings.tenants)?settings.tenants:String(settings.tenants||'').split(',');for(const t of tenants.filter(Boolean)){const o=node('option',t);o.value=t;$('ai-tenant').append(o);}}
  if(requested)$('ai-tenant').value=requested.tenant;
  if(tenant!==$('ai-tenant').value){resetAITenant();epoch=aiEpoch;tenant=$('ai-tenant').value;}
  const chosen=$('ai-model').value;$('ai-model').replaceChildren();for(const m of status.models||[]){const option=node('option',m.name);option.value=m.name;$('ai-model').append(option);}if([...$('ai-model').options].some(o=>o.value===chosen))$('ai-model').value=chosen;else if([...$('ai-model').options].some(o=>o.value==='hauhaucs-aggressive:9b-8k'))$('ai-model').value='hauhaucs-aggressive:9b-8k';
  aiStatus=status;aiDefense=status.defense_enabled;
  $('ai-connection').textContent=status.available?'로컬 모델 연결됨':'Ollama 연결 필요';
  $('ai-response-note').textContent=aiDefense?'임시 대응은 제한된 범위·기간의 로컬 정책 설치를 요청합니다. 실제 edge 효과나 서명 승인을 뜻하지 않으며 업무 응답으로 별도 확인해야 합니다.':'분석은 정책을 변경하지 않습니다. 임시 대응을 사용하려면 운영 설정에서 정책 제어기와 권한을 연결하세요.';
  syncAIButtons();
  try{
    await loadAICases();if(!current())return;
    if(requested&&aiRequestedCase===requested){$('ai-case').value=requested.id;aiRequestedCase=null;}
    await loadAIRuns();if(!current())return;
    if(!status.available&&status.error)notice('Ollama를 실행한 뒤 새로고침하세요. '+status.error);
  }catch(error){if(current())throw error;}
}
async function loadAICases(){
  const current=aiRequestGuard('cases'),tenant=$('ai-tenant').value;
  let d;try{d=await api('cases?'+new URLSearchParams({tenant}));}catch(error){if(current())throw error;return;}
  if(!current())return;
  const previous=$('ai-case').value;aiCasesLoaded=true;aiCaseRows=d.cases;$('ai-case').replaceChildren();
  for(const c of d.cases){const o=node('option',`${c.case_id.slice(0,12)} · ${c.asset_id} · 증거 ${c.evidence_count}건`);o.value=c.case_id;$('ai-case').append(o);}
  if(d.cases.some(c=>c.case_id===previous))$('ai-case').value=previous;
  const help=$('ai-case-help');help.replaceChildren();if(!d.cases.length){help.append(node('p','선택한 Tenant에 조사할 사건이 없습니다. 실제 경보를 사건 기억에서 동기화한 뒤 돌아오세요.'),gotoButton('사건 기억으로 이동','cases'));}else help.append(node('p','저장된 사건 '+number(d.cases.length)+'건 중 조사할 사건을 선택하세요. 분석은 정책을 변경하지 않습니다.'));
  syncAIButtons();
}
async function loadAIRuns(){
  const current=aiRequestGuard('runs'),tenant=$('ai-tenant').value;
  let d;try{d=await api('ai/runs?'+new URLSearchParams({tenant}));}catch(error){if(current())throw error;return;}
  if(!current())return;
  const target=$('ai-runs'),runs=d.runs.filter(run=>run.request.tenant_id===tenant);target.replaceChildren();
  for(const run of runs){
    const item=node('div',undefined,'case-row'),button=node('button',`${aiStates[run.state]||run.state} · ${run.request.case_id.slice(0,12)}`,'text-button');
    const renderedEpoch=aiEpoch;
    button.addEventListener('click',()=>{
      if(renderedEpoch!==aiEpoch||tenant!==$('ai-tenant').value)return;
      aiRun=run;drawAIRun(run);
    });
    item.append(button,node('span',time(run.started_at),'muted'));target.append(item);
  }
  if(!runs.length)empty(target,'아직 실행한 조사가 없습니다.','사건 분석을 시작하면 판단과 도구 기록이 여기에 남습니다.');
  // 응답 대기 중 사용자가 선택한 실행을 기준으로 갱신한다. 목록에서 빠져도 다른 실행으로 바꾸지 않는다.
  if(aiRun?.request.tenant_id===tenant)aiRun=runs.find(run=>run.run_id===aiRun.run_id)||aiRun;
  else aiRun=runs[0]||null;
  if(aiRun)drawAIRun(aiRun);else syncAIButtons();
}
function aiHasRecordedTime(value){
  const normalized=typeof value==='string'?value.trim():value;
  return !!normalized&&!/^0001-01-01T00:00:00(?:\.0+)?(?:Z|\+00:00)$/.test(String(normalized));
}
function aiRecordedTiming(record){
  const values=[];
  for(const [key,label] of [['at','기록 시각'],['created_at','생성'],['started_at','시작'],['completed_at','완료 시각'],['finished_at','종료 시각'],['ended_at','종료']]){
    if(aiHasRecordedTime(record[key]))values.push(`${label}: ${time(record[key])}`);
  }
  if(record.duration_ms!=null)values.push(`기록 소요: ${record.duration_ms} ms`);
  return values.length?values.join(' · '):'시각·소요 기록 없음';
}
function drawAIRun(run){
  if(run.request.tenant_id!==$('ai-tenant').value||aiRun?.run_id!==run.run_id)return;
  const state=aiStates[run.state]||run.state,assessment=run.assessment;
  const policyExpiry=aiHasRecordedTime(run.policy_expires_at)?time(run.policy_expires_at):'기록 없음';
  const noAssessment={queued:'실행 대기 · 저장된 판정 없음',running:'조사 진행 중 · 저장된 판정 없음',completed:'실행 완료 · 저장된 판정 없음',failed:'실행 실패 · 저장된 판정 없음',cancelled:'실행 취소 · 저장된 판정 없음',interrupted:'재시작으로 중단 · 저장된 판정 없음'};
  $('ai-state').textContent=state;
  $('ai-summary').textContent=run.error||assessment?.summary||noAssessment[run.state]||'저장된 판정 없음';
  details($('ai-details'),[['실행 ID',run.run_id],['모델',run.request.model],['실행 모드',{analyze:'근거 분석',contain:'임시 대응 요청',release:'해제 요청'}[run.request.mode]||run.request.mode],['기록된 모델 호출',run.model_calls],['로컬 정책 ID',run.policy_id||'없음'],['로컬 정책 만료',policyExpiry],['판정',assessment?.classification||'저장된 판정 없음']]);
  syncAIButtons();

  const target=$('ai-steps'),flow=node('ol',undefined,'records'),traces=node('div',undefined,'records');
  flow.setAttribute('aria-label','저장 기록 기반 실행 흐름');
  traces.setAttribute('aria-label','실행 상세 추적');
  target.replaceChildren(node('h3','저장 실행 흐름'),node('p','저장된 Run/Step만 표시합니다. 도구 완료는 전체 실행 완료나 실제 edge 효과·서명 승인을 뜻하지 않습니다.','muted'),flow);

  const bound=node('li',undefined,'rule-card'),facts=node('dl');
  bound.append(node('h4','실행에 결속된 입력'));
  details(facts,[['실행 ID',run.run_id],['Tenant',run.request.tenant_id],['사건',run.request.case_id],['사건 SHA-256',run.request.case_sha256],['요청 모델',run.request.model],['실행 모델 digest',run.model_digest||'기록 없음'],['원본 실행 ID (해제)',run.request.source_run_id||'기록 없음']]);
  bound.append(facts,node('p',aiRecordedTiming(run),'muted'));flow.append(bound);

  const steps=Array.isArray(run.steps)?run.steps:[];
  if(!steps.length){const item=node('li',undefined,'rule-card');item.append(node('h4','기록된 도구 없음'),node('p',`현재 상태: ${state}. 도구가 실행되었거나 완료되었다고 추정하지 않습니다.`));flow.append(item);}
  steps.forEach((step,index)=>{
    const stepState={pending:'실행 중',done:'완료',failed:'실패'}[step.state]||step.state||'상태 기록 없음';
    const title=`기록 ${index+1} · ${aiTools[step.tool]||step.tool||'도구명 기록 없음'} · ${stepState}`;
    const item=node('li',undefined,'rule-card'),trace=node('details'),summary=node('summary',title),button=node('button',`기록 ${index+1} 상세 열기`,'text-button');
    trace.id=`ai-trace-step-${index+1}`;
    button.type='button';button.setAttribute('aria-controls',trace.id);
    button.addEventListener('click',()=>{trace.open=true;trace.scrollIntoView({behavior:'smooth',block:'nearest'});summary.focus();});
    // 배열의 기록 순서를 그대로 사용하며 step.number로 재정렬하지 않는다.
    item.append(node('h4',title),node('p',`도구: ${step.tool??'기록 없음'} · 저장 번호: ${step.number??'기록 없음'}`),node('p',aiRecordedTiming(step),'muted'),button);
    trace.append(summary,node('pre',JSON.stringify(step,null,2)));flow.append(item);traces.append(trace);
  });

  const outcome=node('li',undefined,'rule-card');
  outcome.append(node('h4',`저장 판정·실행 상태: ${state}`));
  if(assessment){
    outcome.append(node('p',`저장 판정: ${assessment.classification??'분류 기록 없음'}`),node('p',assessment.summary??'요약 기록 없음'),node('h4','판정 evidence_ids (저장값 그대로)'),node('pre',assessment.evidence_ids===undefined?'evidence_ids 기록 없음':JSON.stringify(assessment.evidence_ids,null,2)));
  }else outcome.append(node('p',noAssessment[run.state]||'저장된 판정 없음'));
  if(['queued','running'].includes(run.state))outcome.append(node('p','아직 종료되지 않은 실행입니다. 저장 판정이 있어도 완료로 간주하지 않습니다.','muted'));
  if(run.error)outcome.append(node('h4','실행 오류'),node('pre',run.error));
  outcome.append(node('p',`로컬 정책 ID: ${run.policy_id||'없음'} · 만료: ${policyExpiry}`),node('p','정책 ID·만료는 로컬 설치 메타데이터입니다. 실제 edge 차단·해제 효과나 서명 승인의 증거가 아닙니다.','muted'));
  flow.append(outcome);

  const provenance=node('details');
  provenance.append(node('summary','원본 Run JSON · 출처 및 전체 기록'),node('pre',JSON.stringify(run,null,2)));
  target.append(node('h3','상세 추적'),traces,provenance);
}
async function startAIRun(mode){const epoch=aiEpoch,selection=aiRun;const c=aiCaseRows.find(c=>c.case_id===$('ai-case').value);if(!c)throw Error('수집 증거를 동기화하고 조사할 사건을 선택하세요.');const tenant=mode==='release'?aiRun.request.tenant_id:$('ai-tenant').value,id=mode==='release'?aiRun.request.case_id:c.case_id,d=await api('cases/detail?'+new URLSearchParams({tenant,case_id:id}));if(epoch!==aiEpoch||tenant!==$('ai-tenant').value||selection!==aiRun)return;const run=await api('ai/runs?'+new URLSearchParams({tenant}),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tenant_id:tenant,case_id:id,case_sha256:d.current.case_sha256,model:$('ai-model').value,mode,...(mode==='release'?{source_run_id:aiRun.run_id}:{})})});if(epoch!==aiEpoch||tenant!==$('ai-tenant').value||selection!==aiRun)return;aiRun=run;drawAIRun(run);await loadAIRuns();}
$('ai-analyze').addEventListener('click',()=>caseAction($('ai-analyze'),()=>startAIRun('analyze')));
$('ai-contain').addEventListener('click',()=>caseAction($('ai-contain'),()=>startAIRun('contain')));
$('ai-release').addEventListener('click',()=>caseAction($('ai-release'),()=>startAIRun('release')));
$('ai-cancel').addEventListener('click',()=>caseAction($('ai-cancel'),async()=>{if(aiRun)await api('ai/cancel?'+new URLSearchParams({tenant:aiRun.request.tenant_id,id:aiRun.run_id}),{method:'POST'});}));
$('ai-tenant').addEventListener('change',()=>{resetAITenant();caseAction($('ai-analyze'),async()=>{try{await loadAssistant();}finally{syncAIButtons();}});});
$('case-assistant').addEventListener('click',()=>{if(selectedCase){aiRequestedCase={tenant:selectedCase.current.case.tenant_id,id:selectedCase.current.case.case_id};select('assistant');}});
setInterval(async()=>{
  if(aiPolling||!token||view!=='assistant'||document.visibilityState!=='visible'||aiRun?.request.tenant_id!==$('ai-tenant').value||!['queued','running'].includes(aiRun.state))return;
  aiPolling=true;
  const epoch=aiEpoch,tenant=$('ai-tenant').value,id=aiRun.run_id;
  const current=()=>epoch===aiEpoch&&tenant===$('ai-tenant').value&&id===aiRun?.run_id;
  try{await loadAIRuns();if(current()&&!['queued','running'].includes(aiRun.state))await loadAssistant();}
  catch(e){if(current())notice(e.message);}
  finally{aiPolling=false;}
},1500);
if(token)connect();
setInterval(()=>{if(token&&!$('application').hidden&&document.visibilityState==='visible'&&view==='overview')refresh();},15000);

function drawSelection(result){
  const selection=result.selection||result,target=$('selection-result'),table=node('table'),head=node('thead'),headRow=node('tr'),body=node('tbody');
  for(const title of ['사건','판정','선정 결과'])headRow.append(node('th',title));head.append(headRow);table.append(head,body);
  const reasons={unlabeled:'미분류',stale_label:'증거 변경 · 재검토 필요',uncertain:'보류',disputed:'상충',duplicate_evidence:'중복 증거',conflicting_labels:'같은 증거에 대한 판정 상충'};
  for(const item of selection.items){const row=node('tr');row.append(node('td',item.case_id),node('td',labelNames[item.label]||'미분류'),node('td',item.exclusion_reason?'제외 · '+(reasons[item.exclusion_reason]||item.exclusion_reason):'선정'));body.append(row);}
  target.replaceChildren(table);if(!selection.items.length)empty(target,'선정할 사건이 없습니다.','먼저 수집 증거를 동기화하세요.');$('selection-json').textContent=JSON.stringify(result,null,2);
}

async function loadLearningCandidates(tenant){
  if(tenant!==$('case-tenant').value)return;
  const current=learningRequestGuard('candidates',tenant),chosen=selectedLearning?.result?selectedLearning:null;
  const result=await api('cases/learning?'+new URLSearchParams({tenant}));if(!current())return;
  const target=$('learning-list');target.replaceChildren();
  for(const c of result.candidates){const item=node('div',undefined,'case-row'),button=node('button',time(c.created_at),'text-button');button.addEventListener('click',()=>caseAction(button,()=>showLearningCandidate(tenant,c.candidate_id)));item.append(button,node('span',`${c.training_status==='fit_complete'?'학습 완료':'학습 자료 부족'} · 학습 ${c.fit_count}건 / 전체 ${c.selection_total}건${c.reevaluation_required?' · 재평가 필요':''}`,'muted'));target.append(item);}
  if(!result.candidates.length)empty(target,'저장한 학습 후보가 없습니다.','학습 대상을 선정한 뒤 후보를 생성하세요.');
  if(chosen?.tenant===tenant&&selectedLearning===chosen)await showLearningCandidate(tenant,chosen.id);
  if(!current())return;
  await loadShadows(tenant);
  if(!current())return;
  await loadAdvisory(tenant);
}
async function showLearningCandidate(tenant,id){
  if(tenant!==$('case-tenant').value)return;
  const current=learningRequestGuard('candidate',tenant),chosen={tenant,id};
  selectedLearning=chosen;$('learning-detail').hidden=true;$('shadow-start').disabled=true;drawLearningWorkbench();
  const result=await api('cases/learning/detail?'+new URLSearchParams({tenant,candidate_id:id}));if(!current())return;
  chosen.result=result;const c=result.candidate;$('learning-detail').hidden=false;$('learning-state').textContent='검토용 후보';
  $('learning-summary').textContent=c.training_status==='fit_complete'?`학습 ${c.fit_count}건 · 공격 확인 ${c.fit_attack}건 / 정상 확인 ${c.fit_benign}건. 같은 선정 자료의 비교이며 독립 평가 결과는 아닙니다.`:`학습 보류 · 학습 상한 적용 후 공격·정상 확정 사건이 각각 ${c.config.minimum_fit_per_class}건 이상 필요합니다. 현재 공격 ${c.fit_attack}건 / 정상 ${c.fit_benign}건입니다.`;
  $('learning-freshness').textContent=result.reevaluation_required?'재평가 필요 · '+(result.changed_cases.length?'변경 사건 '+result.changed_cases.join(', '):'학습 구현 버전 변경'):'마지막 동기화한 사건·라벨과 일치합니다.';
  details($('learning-facts'),[['선정 전체',c.selection.total+'건'],['선정 제외',c.selection.excluded+'건'],['선정 후 학습 상한 제외',(c.rows.length-c.fit_count)+'건'],['비교한 확정 사건',c.selected_cohort_comparison.candidate.compared+'건'],['운영 적용','미적용 · 독립 평가·검토 필요']]);
  const table=node('table'),head=node('thead'),h=node('tr'),body=node('tbody');for(const title of ['같은 선정 자료 비교','공격→의심','공격→정상','정상→의심','정상→정상'])h.append(node('th',title));head.append(h);table.append(head,body);
  for(const [name,m] of [['경보 전체를 의심으로 보는 참고 기준',c.selected_cohort_comparison.all_alerts_suspicious_reference],['검토용 후보',c.selected_cohort_comparison.candidate]]){const row=node('tr');for(const value of [name,m.true_attack,m.false_benign,m.false_attack,m.true_benign])row.append(node('td',value));body.append(row);}
  drawLearningWorkbench();$('learning-comparison').replaceChildren(table);$('learning-json').textContent=JSON.stringify(result,null,2);$('shadow-start').disabled=c.training_status!=='fit_complete'||!result.trainer_current;
}
$('learning-create').addEventListener('click',()=>caseAction($('learning-create'),async()=>{if(!savedSelection)return;const selection=savedSelection,result=await api('cases/learning?'+new URLSearchParams({tenant:selection.tenant}),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({selection_sha256:selection.sha})});if(selection.tenant!==$('case-tenant').value)return;await loadLearningCandidates(selection.tenant);await showLearningCandidate(selection.tenant,result.candidate.candidate_id);notice(result.candidate.training_status==='fit_complete'?'오프라인 후보와 비교 결과를 저장했습니다.':'자료 부족 상태와 선정 근거를 저장했습니다. 확정 사건을 더 검토하세요.');}));
$('learning-refresh').addEventListener('click',()=>caseAction($('learning-refresh'),()=>loadLearningCandidates($('case-tenant').value)));
$('learning-check').addEventListener('click',()=>caseAction($('learning-check'),async()=>{if(!selectedLearning)return;const c=selectedLearning;await api('cases/sync',{method:'POST'});await loadLearningCandidates(c.tenant);}));

async function loadShadows(tenant){
  if(tenant!==$('case-tenant').value)return;
  const current=learningRequestGuard('shadows',tenant),chosen=selectedShadow?.result?selectedShadow:null;
  const result=await api('cases/learning/shadow?'+new URLSearchParams({tenant}));if(!current())return;
  const target=$('shadow-list');target.replaceChildren();
  for(const run of result.runs){const item=node('div',undefined,'case-row'),button=node('button',time(run.started_at),'text-button');button.addEventListener('click',()=>caseAction(button,()=>showShadow(tenant,run.run_id)));item.append(button,node('span',`관측 ${run.total}건 · 판정 비교 ${run.scored}건 · v${run.revision}${run.reevaluation_required?' · 학습 재평가 필요':run.refresh_required?' · 갱신 필요':''}`,'muted'));target.append(item);}
  if(!result.runs.length)empty(target,'새 사건 관측을 시작하지 않았습니다.','학습을 마친 후보를 열고 관측 시작을 선택하세요.');
  if(chosen?.tenant===tenant&&selectedShadow===chosen)await showShadow(tenant,chosen.id,chosen.revision);
}
async function showShadow(tenant,id,revision){
  if(tenant!==$('case-tenant').value)return;
  const previous=selectedShadow,sameTarget=previous?.tenant===tenant&&previous.id===id&&previous.revision===revision;
  const current=learningRequestGuard('shadow',tenant),chosen={tenant,id,revision,...(sameTarget?{result:previous.result}:{})};
  selectedShadow=chosen;
  if(!sameTarget){
    activeReview=null;activeAutomatic=null;
    $('shadow-detail').hidden=true;$('review-panel').hidden=true;$('automatic-panel').hidden=true;
  }
  drawLearningWorkbench();
  const result=await api('cases/learning/shadow/detail?'+new URLSearchParams({tenant,run_id:id,...(revision?{revision}: {})}));if(!current())return;
  chosen.result=result;const snapshot=result.snapshot;$('shadow-detail').hidden=false;$('shadow-state').textContent=snapshot?'저장 관측 v'+snapshot.revision:'첫 관측 대기';
  $('shadow-freshness').textContent=result.reevaluation_required?'학습 자료·구현이 바뀌어 관측 갱신이 중단됐습니다. 새 후보가 필요합니다.':result.refresh_required?'저장 관측 이후 사건·라벨이 변경됐거나 과거 이력을 보고 있습니다. 최신 자료로 갱신할 수 있습니다.':'마지막으로 동기화한 사건 기억과 일치합니다.';
  $('shadow-capture').disabled=result.reevaluation_required;
  details($('shadow-facts'),[['관측 시작',time(result.plan.started_at)],['시작 전 제외 사건',result.plan.baseline_selection.total+'건'],['새 사건 관측',(snapshot?.total||0)+'건'],['라벨과 비교',(snapshot?.scored||0)+'건'],['라벨 대기',(snapshot?.awaiting_label||0)+'건'],['제외',(snapshot?.excluded||0)+'건'],['운영 적용','미적용 · 별도 관측 결과']]);
  const comparisons=$('shadow-comparison'),rows=$('shadow-rows');comparisons.replaceChildren();rows.replaceChildren();
  if(snapshot){
    const table=node('table'),head=node('thead'),h=node('tr'),body=node('tbody');for(const title of ['판정 가능한 관측만 비교','공격→의심','공격→정상','정상→의심','정상→정상'])h.append(node('th',title));head.append(h);table.append(head,body);
    for(const [name,m] of [['모든 경보를 의심으로 보는 참고 기준',snapshot.comparison.all_alerts_suspicious_reference],['고정한 후보 예측',snapshot.comparison.candidate]]){const row=node('tr');for(const value of [name,m.true_attack,m.false_benign,m.false_attack,m.true_benign])row.append(node('td',value));body.append(row);}comparisons.append(table);
    const list=node('table'),thead=node('thead'),header=node('tr'),tbody=node('tbody');for(const title of ['사건','고정 예측','운영자 판정','비교 상태'])header.append(node('th',title));thead.append(header);list.append(thead,tbody);
    const states={scored:'판정 비교',awaiting_label:'판정 대기',prelabeled_before_prediction:'예측 전 라벨 존재',preexisting_observation:'관측 시작 전 증거',evidence_changed:'예측 후 증거 변경',overlapping_evidence:'중복 증거',stale_label:'오래된 판정',uncertain:'보류',disputed:'상충'};
    for(const entry of snapshot.rows){const row=node('tr');for(const value of [entry.case_id,{suspicious:'의심',benign:'정상 제안'}[entry.suggested_disposition]||'미예측',labelNames[entry.label]||'없음',states[entry.status]||entry.status])row.append(node('td',value));tbody.append(row);}rows.append(list);
    if(!snapshot.rows.length)empty(rows,'새로 관측한 사건이 없습니다.','시작 이후 수집된 별도 사건이 있어야 비교할 수 있습니다.');
  }
  const history=$('shadow-history');history.replaceChildren();for(const item of result.history){const button=node('button',`v${item.revision} · ${time(item.captured_at)} · 전체 ${item.total} / 비교 ${item.scored}`,'text-button');button.addEventListener('click',()=>caseAction(button,()=>showShadow(tenant,id,item.revision)));history.append(button);}
  $('shadow-json').textContent=JSON.stringify(result,null,2);drawLearningWorkbench();
  await loadReview(tenant,id);
  if(!current())return;
  await loadAutomatic(tenant,id);
  if(!current())return;
  await loadAdvisory(tenant);
}
$('shadow-start').addEventListener('click',()=>caseAction($('shadow-start'),async()=>{if(!selectedLearning)return;const chosen=selectedLearning,result=await api('cases/learning/shadow?'+new URLSearchParams({tenant:chosen.tenant}),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({candidate_id:chosen.id})});if(chosen.tenant!==$('case-tenant').value)return;await loadShadows(chosen.tenant);await showShadow(chosen.tenant,result.plan.run_id);notice('새 사건 관측 계획을 저장했습니다. 새 사건의 라벨을 기록하기 전에 현재 사건 관측·평가를 누르세요.');}));
$('shadow-refresh').addEventListener('click',()=>caseAction($('shadow-refresh'),()=>loadShadows($('case-tenant').value)));
$('shadow-capture').addEventListener('click',()=>caseAction($('shadow-capture'),async()=>{if(!selectedShadow)return;const chosen=selectedShadow;await api('cases/learning/shadow/capture?'+new URLSearchParams({tenant:chosen.tenant}),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({run_id:chosen.id})});await showShadow(chosen.tenant,chosen.id);await loadShadows(chosen.tenant);}));
$('shadow-latest').addEventListener('click',()=>caseAction($('shadow-latest'),async()=>{if(selectedShadow)await showShadow(selectedShadow.tenant,selectedShadow.id);}));

const reviewStates={REVIEW_PLAN_REQUIRED:'관측 전 기준 등록 필요',CRITERIA_NOT_MET:'기준 미충족',READY_FOR_LOCAL_REVIEW:'운영자 검토 가능',APPROVED_FOR_EVALUATION:'다음 평가 승인',REJECTED:'반려',DEFERRED:'보류',REVIEW_STALE:'검토 근거 갱신 필요'};
const reviewReasons={preregistration_required:'관측 전에 검토 기준을 등록해야 합니다',observation_required:'저장 관측이 필요합니다',insufficient_confirmed_attack:'공격 판정 표본 부족',insufficient_confirmed_benign:'정상 판정 표본 부족',observation_window_too_short:'관측 기간 부족',label_coverage_below_minimum:'라벨 확보율 부족',false_benign_regression:'참고 기준보다 공격→정상 증가',false_attack_regression:'참고 기준보다 정상→의심 증가',false_attack_rate_above_maximum:'정상→의심 비율 상한 초과',shadow_refresh_required:'현재 사건·라벨로 관측을 갱신해야 합니다',training_or_observer_changed:'학습 원본·관측 구현 변경',review_implementation_changed:'검토 구현 변경',observation_precedes_review_plan:'관측 시각이 검토 기준 등록 전입니다'};
async function loadReview(tenant,run){
  const selection=selectedShadow;
  if(tenant!==$('case-tenant').value||selection?.tenant!==tenant||selection.id!==run||!selection.result)return;
  const current=learningRequestGuard('review',tenant,selection);
  const result=await api('cases/learning/review?'+new URLSearchParams({tenant,run_id:run}));if(!current())return;
  activeReview={tenant,run,result};$('review-panel').hidden=false;$('review-state').textContent=reviewStates[result.state]||result.state;
  $('review-summary').textContent=result.plan?'등록한 기준은 변경할 수 없습니다. 기준 충족과 운영자 결정을 각각 기록합니다.':'첫 관측과 새 사건·라벨 변경 전에 기준을 고정하세요. 이미 관측했다면 새 계획이 필요합니다.';
  $('review-blockers').textContent=[...result.blockers,...(result.assessment.reasons||[])].map(reason=>reviewReasons[reason]||reason).join(' · ');
  const criteria=result.plan?.criteria||result.default_criteria;
  $('review-min-attack').value=criteria.minimum_confirmed_attack;$('review-min-benign').value=criteria.minimum_confirmed_benign;$('review-min-seconds').value=criteria.minimum_observation_seconds;$('review-coverage').value=criteria.minimum_label_coverage_bps/100;$('review-max-fp').value=criteria.maximum_false_attack_bps/100;
  $('review-plan-fields').disabled=!!result.plan||result.refresh_required||result.reevaluation_required||!!result.latest_shadow_snapshot_sha256;
  $('review-decision-fields').disabled=!result.plan;$('review-approve-option').disabled=!result.approval_for_evaluation_available;
  if(!result.approval_for_evaluation_available&&$('review-decision').value==='approve_for_evaluation')$('review-decision').value='defer';
  const a=result.assessment;details($('review-facts'),[['현재 표본',`${a.scored||0} / ${a.total||0}건`],['공격 / 정상 판정',`${a.confirmed_attack||0} / ${a.confirmed_benign||0}건`],['라벨 확보율',((a.label_coverage_bps||0)/100)+'%'],['저장 관측 기간',(a.observation_seconds||0)+'초'],['운영 모델·정책 적용','미적용']]);
  const history=$('review-history');history.replaceChildren();for(const decision of [...result.decisions].reverse()){const item=node('details'),title=node('summary',`검토 v${decision.revision} · ${{approve_for_evaluation:'다음 평가 승인',reject:'반려',defer:'보류'}[decision.request.decision]} · 관측 v${decision.shadow_revision}`);item.append(title,node('p',decision.request.reason),node('pre',JSON.stringify(decision,null,2)));history.append(item);}
  if(!result.decisions.length)empty(history,'저장한 검토 결정이 없습니다.','기준과 최신 관측을 확인한 뒤 근거와 결정을 기록하세요.');
  $('review-json').textContent=JSON.stringify(result,null,2);drawLearningWorkbench();
}
$('review-plan-form').addEventListener('submit',event=>{event.preventDefault();caseAction($('review-register'),async()=>{if(!activeReview)return;const chosen=activeReview,criteria={minimum_confirmed_attack:Number($('review-min-attack').value),minimum_confirmed_benign:Number($('review-min-benign').value),minimum_observation_seconds:Number($('review-min-seconds').value),minimum_label_coverage_bps:Math.round(Number($('review-coverage').value)*100),maximum_false_attack_bps:Math.round(Number($('review-max-fp').value)*100)};await api('cases/learning/review/plan?'+new URLSearchParams({tenant:chosen.tenant,run_id:chosen.run}),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(criteria)});await loadReview(chosen.tenant,chosen.run);await loadAutomatic(chosen.tenant,chosen.run);notice('관측 전 검토 기준을 고정했습니다. 이후 기준 변경은 허용되지 않습니다.');});});
$('review-decision-form').addEventListener('submit',event=>{event.preventDefault();caseAction($('review-submit'),async()=>{if(!activeReview?.result.plan)return;const chosen=activeReview;try{await api('cases/learning/review?'+new URLSearchParams({tenant:chosen.tenant,run_id:chosen.run}),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({expected_review_revision:chosen.result.expected_review_revision,review_plan_sha256:chosen.result.plan.review_plan_sha256,shadow_snapshot_sha256:chosen.result.latest_shadow_snapshot_sha256,decision:$('review-decision').value,reason:$('review-reason').value})});$('review-reason').value='';await loadReview(chosen.tenant,chosen.run);await loadAdvisory(chosen.tenant);notice('검토 결정과 근거를 저장했습니다.');}catch(error){await loadReview(chosen.tenant,chosen.run);throw error;}});});

const lifecycleReasons={training_or_observer_changed:'학습 자료 또는 관측 구현이 변경됐습니다',snapshot_capacity_reached:'이 계획의 관측 저장 한도에 도달했습니다',journal_capacity_near_limit:'원장 저장 한도에 가까워 관측을 중지했습니다',automation_implementation_changed:'자동 관측 구현이 변경돼 다시 검토해야 합니다',shadow_refresh_required:'새 근거의 관측을 저장해야 합니다',advisory_implementation_changed:'추천 구현이 변경돼 다시 검토해야 합니다',review_withdrawn:'검토 승인이 철회되거나 보류됐습니다',latest_review_required:'최신 관측의 검토 승인이 필요합니다'};
async function loadAutomatic(tenant,run){
  const selection=selectedShadow;
  if(tenant!==$('case-tenant').value||selection?.tenant!==tenant||selection.id!==run||!selection.result)return;
  const current=learningRequestGuard('automatic',tenant,selection);
  const result=await api('cases/learning/automatic?'+new URLSearchParams({tenant,run_id:run}));
  if(!current())return;
  activeAutomatic={tenant,run,result:result.automation};const a=result.automation,w=result.worker;
  $('automatic-panel').hidden=false;$('automatic-state').textContent={disabled:'중지',observing:'관측 중',blocked:'관측 중단'}[a.state]||a.state;
  $('automatic-summary').textContent=`저장 관측 ${a.snapshot_revision}회 · `+(a.blockers.length?a.blockers.map(r=>lifecycleReasons[r]||r).join(' · '):'검증한 사건 기억의 변경만 관측합니다.');
  $('automatic-worker').textContent=w?`동기화 시도 ${w.attempts}회 · 실패 ${w.failures}회 · 마지막 성공 ${time(w.last_success)}${w.error?' · '+w.error:''}`:'백그라운드 동기화 상태를 제공하지 않는 실행 환경입니다.';
  syncAutomaticButtons();$('automatic-json').textContent=JSON.stringify(result,null,2);drawLearningWorkbench();
}
function syncAutomaticButtons(){if(!activeAutomatic)return;const a=activeAutomatic.result;$('automatic-enable').disabled=a.enabled||!activeReview?.result.plan||activeReview.result.reevaluation_required;$('automatic-disable').disabled=!a.enabled;}
async function changeAutomatic(enabled){
  if(!activeAutomatic)return;const chosen=activeAutomatic,reason=$('automatic-reason').value.trim();if(!reason)throw Error('자동 관측 변경 근거를 입력하세요.');
  await api('cases/learning/automatic?'+new URLSearchParams({tenant:chosen.tenant,run_id:chosen.run}),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({expected_revision:chosen.result.revision,enabled,reason})});
  await showShadow(chosen.tenant,chosen.run);notice(enabled?'자동 관측을 시작했습니다.':'자동 관측을 중지했습니다.');
}
$('automatic-enable').addEventListener('click',()=>caseAction($('automatic-enable'),()=>changeAutomatic(true)));
$('automatic-disable').addEventListener('click',()=>caseAction($('automatic-disable'),()=>changeAutomatic(false)));
async function loadAdvisory(tenant){
  if(tenant!==$('case-tenant').value)return;
  const currentRequest=learningRequestGuard('advisory',tenant,selectedShadow);
  const result=await api('cases/learning/advisory?'+new URLSearchParams({tenant}));if(!currentRequest())return;
  activeAdvisory={tenant,result};const current=result.current;
  $('advisory-state').textContent={stopped:'미사용',canary:'제한 비교',activate:'추천 사용 중',rollback:'복원한 추천 사용 중',blocked:'추천 중단'}[result.state]||result.state;
  $('advisory-summary').textContent=result.blockers.length?result.blockers.map(r=>lifecycleReasons[r]||r).join(' · '):'운영 방어 정책과 실제 모델에는 적용하지 않습니다.';
  const a=result.canary_assessment;details($('advisory-facts'),[['추천 버전',current?.model_sha256||'없음'],['후보 추천 비율',(current?.request.percent||0)+'%'],['추천 사건',result.suggestions.length+'건'],['제한 비교의 공격 / 정상 판정',a?`${a.confirmed_attack} / ${a.confirmed_benign}건`:'—'],['제한 비교 기준',a?(a.local_criteria_met?'충족':a.reasons.map(r=>reviewReasons[r]||r).join(' · ')):'—'],['최신 검토',result.latest_review_stale?'새 근거에 대한 검토 필요':'저장 검토와 일치']]);
  const table=node('table'),body=node('tbody'),head=node('tr');for(const title of ['사건','추천 출처','제안','관측 상태'])head.append(node('th',title));table.append(head,body);
  for(const item of result.suggestions){const row=node('tr');for(const value of [item.case_id,{candidate:'선택 후보',reference:'단순 참고 기준',excluded:'제외'}[item.route],{suspicious:'의심',benign:'정상 제안'}[item.suggested_disposition]||'미제안',item.shadow_status])row.append(node('td',value));body.append(row);}$('advisory-suggestions').replaceChildren(table);
  const history=$('advisory-history');history.replaceChildren();const restored=new Set();for(const change of [...result.history].reverse()){
    const item=node('div',undefined,'case-row');item.append(node('span',`v${change.revision} · ${change.request.action} · ${time(change.changed_at)} · ${change.request.reason}`));
    if(change.request.action==='activate'&&!restored.has(change.request.run_id)){restored.add(change.request.run_id);const button=node('button','이 추천 버전 복원','secondary');button.addEventListener('click',()=>caseAction(button,()=>changeAdvisory('rollback',change.request.run_id)));item.append(button);}history.append(item);
  }
  $('advisory-json').textContent=JSON.stringify(result,null,2);drawLearningWorkbench();
}
async function changeAdvisory(action,run){
  const chosen=activeAdvisory,tenant=$('case-tenant').value;if(!chosen||chosen.tenant!==tenant)return;
  const reason=$('advisory-reason').value.trim();if(!reason)throw Error('추천 버전 변경 근거를 입력하세요.');
  const q={expected_revision:chosen.result.revision,action,run_id:'',review_decision_sha256:'',shadow_snapshot_sha256:'',percent:0,reason};
  if(action!=='stop'){
    run=run||selectedShadow?.id;if(!run)throw Error('추천에 사용할 섀도 관측 계획을 먼저 여세요.');
    const review=await api('cases/learning/review?'+new URLSearchParams({tenant,run_id:run}));if(review.state!=='APPROVED_FOR_EVALUATION')throw Error('최신 관측을 검토하고 다음 평가를 위한 승인을 먼저 저장하세요.');
    Object.assign(q,{run_id:run,review_decision_sha256:review.decisions.at(-1).decision_sha256,shadow_snapshot_sha256:review.latest_shadow_snapshot_sha256,percent:action==='canary'?Number($('advisory-percent').value):100});
  }
  try{await api('cases/learning/advisory?'+new URLSearchParams({tenant}),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(q)});notice('검토용 추천 버전과 변경 근거를 저장했습니다.');}finally{await loadAdvisory(tenant);}
}
for(const action of ['canary','activate','stop'])$('advisory-'+action).addEventListener('click',()=>caseAction($('advisory-'+action),()=>changeAdvisory(action)));
$('advisory-refresh').addEventListener('click',()=>caseAction($('advisory-refresh'),()=>loadAdvisory($('case-tenant').value)));
let learningPolling=false,learningPollingNotice=null;
setInterval(async()=>{
  if(learningPolling||caseBusy||!token||view!=='cases'||document.visibilityState!=='visible'||!selectedShadow?.result||activeAutomatic?.tenant!==selectedShadow.tenant||activeAutomatic?.run!==selectedShadow.id||!activeAutomatic?.result.enabled)return;
  learningPolling=true;
  const chosen=selectedShadow,epoch=learningEpoch,startingNoticeGeneration=noticeGeneration;
  const task=showShadow(chosen.tenant,chosen.id,chosen.revision);
  const selection=selectedShadow,version=learningRequestVersions.shadow;
  const current=()=>epoch===learningEpoch&&chosen.tenant===$('case-tenant').value&&selection===selectedShadow&&version===learningRequestVersions.shadow;
  try{
    await task;
    const owned=learningPollingNotice;
    if(current()&&owned&&owned.epoch===epoch&&owned.tenant===chosen.tenant&&owned.id===chosen.id&&owned.revision===chosen.revision&&owned.generation===noticeGeneration){
      notice('');
      learningPollingNotice=null;
    }
  }catch(error){
    if(current()&&noticeGeneration===startingNoticeGeneration){
      notice(error.message);
      learningPollingNotice={epoch,tenant:chosen.tenant,id:chosen.id,revision:chosen.revision,generation:noticeGeneration};
    }
  }finally{
    learningPolling=false;
  }
},5000);

let workbenchTarget='case-list';
function drawLearningWorkbench(){
  const tenant=$('case-tenant').value,c=selectedLearning?.tenant===tenant?selectedLearning.result?.candidate:null;
  const shadow=selectedShadow?.tenant===tenant?selectedShadow.result:null;
  const review=activeReview?.tenant===tenant&&activeReview.run===shadow?.plan.run_id?activeReview.result:null;
  const automatic=activeAutomatic?.tenant===tenant&&activeAutomatic.run===shadow?.plan.run_id?activeAutomatic.result:null;
  const advisory=activeAdvisory?.tenant===tenant?activeAdvisory.result:null;
  let stage='사건 검토',next='사건 라벨을 검토하고 학습 대상을 선정한 뒤 후보를 여세요.',target='case-list';
  if(c){stage='후보 선택';next='학습한 후보로 별도 신규 사건의 관측 계획을 시작하세요.';target='shadow-start';
    if(c.training_status!=='fit_complete'){next='확정 공격·정상 자료가 부족합니다. 원본을 검토한 뒤 새 선정을 만드세요.';target='case-list';}
    else if(shadow&&shadow.plan.candidate_id===c.candidate_id){
      stage='새 사건 관측';
      if(automatic?.state==='blocked'){next='자동 관측의 중단 사유를 확인하고 관측을 중지하세요.';target='automatic-disable';}
      else if(shadow.reevaluation_required){next='학습 자료나 구현이 변경됐습니다. 원본을 검토한 뒤 새 후보·계획이 필요합니다.';target='learning-list';}
      else if(advisory?.state==='blocked'&&advisory.current?.request.run_id===shadow.plan.run_id){stage='추천 검토 필요';next='추천 중단 사유와 최신 관측의 검토 상태를 확인하세요.';target='review-panel';}
      else if(!review?.plan){next='첫 관측과 새 사건 변경 전에 검토 기준을 고정하세요.';target='review-register';}
      else if(!shadow.snapshot||shadow.snapshot.total===0){next=automatic?.enabled?'별도 신규 사건의 수집을 기다린 뒤 저장 관측을 확인하세요.':'자동 관측을 시작하거나 새 사건의 라벨보다 먼저 수동 관측하세요.';target=automatic?.enabled?'shadow-latest':'automatic-enable';}
      else if(shadow.snapshot.awaiting_label>0){stage='후속 판정';next='고정한 예측의 원본을 별도로 검토하고 사건 라벨을 기록하세요.';target='case-list';}
      else if(review.state!=='APPROVED_FOR_EVALUATION'){stage='관측 검토';next='최신 표본·제외·기준과 근거를 확인하고 승인·반려·보류를 선택하세요.';target='review-decision';}
      else if(advisory?.current?.request.run_id!==shadow.plan.run_id||advisory.state==='stopped'){stage='추천 제한 비교';next='승인한 후보의 추천 비율과 근거를 정해 제한 비교를 시작할 수 있습니다.';target='advisory-canary';}
      else if(advisory.state==='canary'){stage='추천 제한 비교';next=advisory.canary_assessment?.local_criteria_met?'별도 신규 표본과 최신 승인을 충족했습니다. 추천 100% 사용 여부를 검토하세요.':'제한 비교 이후의 별도 신규 표본·판정이 더 필요합니다.';target=advisory.canary_assessment?.local_criteria_met?'advisory-activate':'shadow-list';}
      else{stage='검토용 추천 사용';next='현재 추천과 원본을 검토하세요. 필요하면 추천을 중지하거나 호환 버전을 복원할 수 있습니다.';target='advisory-suggestions';}
    }
  }
  $('lifecycle-stage').textContent=stage;$('lifecycle-next').textContent=next;workbenchTarget=target;
  details($('lifecycle-facts'),[['선택 후보',c?time(c.created_at):'미선택'],['선택 관측',shadow?'저장 v'+(shadow.snapshot?.revision||0):'미선택'],['검토',review?(reviewStates[review.state]||review.state):'계획 선택 필요'],['운영 모델·정책 적용','미적용']]);
}
$('lifecycle-next-action').addEventListener('click',()=>{const target=$(workbenchTarget);if(target){target.scrollIntoView({behavior:'smooth',block:'center'});target.focus({preventScroll:true});}});

let contextShadowStatus=null,contextShadowVersion=0,contextShadowWorking=false,contextShadowHistorySequence=null;
function contextShadowButtons(){const s=contextShadowStatus,disabled=!s?.configured||contextShadowWorking;for(const id of ['start','capture'])$('context-shadow-'+id).disabled=disabled||['full','failed'].includes(s?.storage?.state)||s?.busy||s?.queued||(id==='start'&&s?.enabled);$('context-shadow-stop').disabled=disabled||(!s?.enabled&&!s?.busy&&!s?.queued);}
function drawContextReceipt(record){
 $('context-shadow-result-label').textContent=record?'저장 관측 #'+record.sequence+' · '+time(record.finished_at):'아직 저장한 관측이 없습니다.';
 $('context-shadow-json').textContent=record?JSON.stringify(record,null,2):'';
 const target=$('context-shadow-rows');target.replaceChildren();
 if(!record)return;if(record.error){target.append(node('p','관측 실패: '+record.error));return;}
 const receipt=record.receipt;target.append(node('p',`전체 ${number(receipt.planned)}건 · 예측 ${number(receipt.observed)}건 · 관측 불가 ${number(receipt.unavailable)}건 · 관측률 ${(receipt.coverage_bps/100).toFixed(2)}%`));
 const table=node('table'),head=node('tr');for(const label of ['사건','예측','관측 상태'])head.append(node('th',label));table.append(head);
 const reasons={training_evidence_overlap:'학습 증거와 겹침',incomplete_or_invalid_v2_context:'권한·행위 맥락 부족 또는 지원 범위 밖',invalid_feature_vector:'특징 검증 실패'};
 for(const row of receipt.rows){const tr=node('tr');tr.append(node('td',row.case_id),node('td',({suspicious:'의심',benign:'정상 추정',unknown:'관측 불가'})[row.prediction]||'관측 불가'),node('td',row.status==='observed'?'예측 저장':reasons[row.reason]||row.reason));table.append(tr);}target.append(table);
}
async function loadContextShadow(){
 const tenant=$('case-tenant').value,epoch=learningEpoch,version=++contextShadowVersion;if(!tenant)return;
 const current=()=>tenant===$('case-tenant').value&&epoch===learningEpoch&&version===contextShadowVersion;
 try{const s=await api('cases/context-shadow/status?'+new URLSearchParams({tenant}));if(!current())return;contextShadowStatus=s;
 $('context-shadow-state').textContent=!s.configured?'미설정':s.storage?.state==='full'?'저장 공간 대기':s.storage?.state==='failed'?'저장 확인 필요':s.busy?'관측 중':s.queued?'관측 대기':s.enabled?'자동 관측 실행 중':s.error?'확인 필요':'중지됨';
 $('context-shadow-summary').textContent=!s.configured?'운영자가 v2 관측 후보와 센서 신뢰 설정을 먼저 연결해야 합니다.':s.storage?.state==='full'?'보관 상한에 도달해 관측을 멈췄습니다. 수집은 계속됩니다. 이력을 보존한 뒤 운영자가 새 저장 설정을 준비해야 합니다.':s.error?'관측이 중단됐습니다: '+s.error:'자동 관측은 2초마다 확인합니다. 재시작하면 중지 상태로 열리며 저장 이력을 유지합니다.';
 details($('context-shadow-facts'),s.configured?[['고정 후보',s.candidate_sha256],['마지막 확인',time(s.last_checked&&!s.last_checked.startsWith('0001-')?s.last_checked:null)],['확인 횟수',number(s.checks)],['운영 적용','관측만 수행'],['활성 / 보관 관측',s.storage?`${s.storage.active_attempts} / ${s.storage.archived_attempts}건`:'—'],['보관 구간',s.storage?`${s.storage.archive_segments} / ${s.storage.limits.archive_segments}`:'—'],['관측 이력 용량',s.storage?`${(s.storage.total_bytes/1048576).toFixed(2)} / ${(s.storage.limits.total_bytes/1048576).toFixed(2)} MiB`:'—']]:[]);
 if(contextShadowHistorySequence===null)drawContextReceipt(s.latest);
 const history=$('context-shadow-history');history.replaceChildren();for(const a of s.history||[]){const button=node('button',`#${a.sequence} · ${time(a.finished_at)} · ${a.error?'실패':'관측 저장'}`,'secondary');button.addEventListener('click',async()=>{const e=learningEpoch,t=$('case-tenant').value;try{const record=await api('cases/context-shadow/history?'+new URLSearchParams({tenant:t,sequence:a.sequence}));if(e!==learningEpoch||t!==$('case-tenant').value)return;contextShadowHistorySequence=a.sequence;drawContextReceipt(record);}catch(err){notice(err.message);}});history.append(button);}contextShadowButtons();
 }catch(error){if(current()){contextShadowStatus=null;contextShadowButtons();details($('context-shadow-facts'),[]);$('context-shadow-state').textContent='사용 불가';$('context-shadow-summary').textContent=error.message;drawContextReceipt(null);$('context-shadow-history').replaceChildren();}}
}
async function contextShadowAction(action){if(contextShadowWorking)return;contextShadowWorking=true;contextShadowButtons();const tenant=$('case-tenant').value;try{await api('cases/context-shadow/'+action+'?'+new URLSearchParams({tenant}),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(action==='stop'?{}:{candidate_sha256:contextShadowStatus.candidate_sha256})});contextShadowHistorySequence=null;await loadContextShadow();}catch(err){notice(err.message);}finally{contextShadowWorking=false;contextShadowButtons();}}
for(const action of ['start','stop','capture'])$('context-shadow-'+action).addEventListener('click',()=>contextShadowAction(action));
$('context-shadow-refresh').addEventListener('click',()=>{contextShadowHistorySequence=null;loadContextShadow();});
$('case-tenant').addEventListener('change',()=>{contextShadowVersion++;contextShadowStatus=null;contextShadowHistorySequence=null;contextShadowButtons();details($('context-shadow-facts'),[]);$('context-shadow-state').textContent='설정 확인 중';$('context-shadow-summary').textContent='';drawContextReceipt(null);$('context-shadow-history').replaceChildren();});
let contextShadowPolling=false;
setInterval(async()=>{if(contextShadowPolling||contextShadowWorking||!token||view!=='cases'||document.visibilityState!=='visible'||!(contextShadowStatus?.enabled||contextShadowStatus?.busy||contextShadowStatus?.queued))return;contextShadowPolling=true;try{await loadContextShadow();}finally{contextShadowPolling=false;}},3000);
