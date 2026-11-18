package responsev2

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func localHost(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
func sameOrigin(q *http.Request) bool {
	if !localHost(q.Host) {
		return false
	}
	origin := q.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && u.Scheme == "http" && u.Host == q.Host && u.Path == "" && u.RawQuery == "" && u.Fragment == ""
}
func console(w http.ResponseWriter, q *http.Request) {
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	tag := base64.RawStdEncoding.EncodeToString(nonce)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; script-src 'nonce-"+tag+"'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	_, _ = w.Write([]byte(strings.ReplaceAll(consoleHTML, "NONCE_VALUE", tag)))
}

const consoleHTML = `<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Reverse Artex v2</title>
<style>body{font:15px system-ui;max-width:1040px;margin:30px auto;padding:0 20px;color:#18232d;background:#f5f7f9}h1{font-size:24px}h2{font-size:19px;margin-top:28px}label{display:block;margin:12px 0}input,select{padding:9px;min-width:260px;max-width:90%}button{padding:9px 14px;margin:5px 5px 5px 0}pre{background:white;white-space:pre-wrap;overflow-wrap:anywhere;padding:16px;border:1px solid #d5dce4}#cases button{display:block;text-align:left}</style>
<h1>Reverse Artex v2</h1><p>등록된 객체 조회의 사건·제한 대응·Decisions 분류와 명시적 L3 조사를 제공합니다. 명령 수락이나 로컬 설치는 실제 방어 효과의 증명이 아닙니다.</p>
<label>로컬 관리 토큰 (OpenAI API 키가 아닙니다)<br><input id="token" type="password" autocomplete="off"></label>
<label>등록된 테넌트<br><input id="tenant" autocomplete="off"></label>
<button id="status">상태</button><button id="list">사건 목록</button><button id="policies">현재 정책</button><button id="pause">새 대응 중지</button><button id="resume">재개</button>
<div id="cases"></div><label>선택한 사건의 서버 검증 후보<br><select id="candidate"><option value="">사건을 선택하세요</option></select></label>
<button id="classify">Decisions 분류 실행</button><button id="apply">선택 후보 임시 제한</button><button id="release">이 화면에서 적용한 제한 해제</button><button id="job">마지막 분류 결과</button>
<h2>명시적 L3 조사</h2>
<label>L3 모드<br><select id="l3mode"><option value="analyze">분석</option><option value="contain">제한 후보 적용 허용</option><option value="release">선택한 L3 실행이 적용한 제한 해제</option></select></label>
<label>L3 원본 실행 ID (해제 모드 또는 직접 해제)<br><input id="l3source" autocomplete="off"></label>
<label>L3 실행 ID<br><input id="l3run" autocomplete="off"></label>
<button id="l3start">선택한 사건의 L3 조사 시작</button><button id="l3query">L3 실행 조회</button><button id="l3cancel">L3 실행 취소</button>
<label>정확한 정책 ID<br><input id="l3policy" autocomplete="off"></label>
<label>정확한 정책 적용 회차 ID (episode_id)<br><input id="l3episode" autocomplete="off"></label>
<button id="l3release">선택한 L3 실행의 제한 직접 해제</button><button id="l3outcome">선택한 정책의 적용 결과 조회</button>
<p id="notice">토큰은 현재 화면 메모리에만 보관됩니다. API 키는 서버 환경변수로만 사용합니다.</p><pre id="output">상태를 조회하거나 사건을 선택하세요.</pre>
<script nonce="NONCE_VALUE">
const el=id=>document.getElementById(id);let selected=null,lastJob=null,lastL3Run='';const run='ui-'+crypto.randomUUID();let epoch=0;
async function call(path,body){const options={headers:{Authorization:'Bearer '+el('token').value}};if(body){options.method='POST';options.headers['Content-Type']='application/json';options.body=JSON.stringify(body)}const r=await fetch(path,options);const text=await r.text();if(!r.ok)throw Error('HTTP '+r.status+': '+text);const v=JSON.parse(text);el('output').textContent=JSON.stringify(v,null,2);return v}
const tenant=()=>el('tenant').value.trim();const wrap=fn=>async()=>{try{await fn()}catch(e){el('output').textContent=String(e)}};const l3id=()=>el('l3run').value.trim();const l3source=()=>el('l3source').value.trim();
el('status').onclick=wrap(async()=>{const s=await call('/v2/status');epoch=(s.decisions&&s.decisions.epoch)||s.epoch||0});
el('list').onclick=wrap(async()=>{const rows=await call('/v2/cases?tenant='+encodeURIComponent(tenant()));el('cases').replaceChildren();for(const row of rows){const b=document.createElement('button');b.textContent='사건 '+row.case_id+' · 리비전 '+row.revision;b.onclick=wrap(async()=>{selected=await call('/v2/case?tenant='+encodeURIComponent(tenant())+'&id='+encodeURIComponent(row.case_id));el('candidate').replaceChildren();for(const c of selected.candidates){const o=document.createElement('option');o.value=c.candidate_id;o.textContent=c.scope.route_id+' · '+c.scope.method+' · 객체 '+c.scope.resource_hmac.slice(0,12);el('candidate').append(o)}});el('cases').append(b)}});
el('policies').onclick=wrap(()=>call('/v2/policies?tenant='+encodeURIComponent(tenant())));
el('pause').onclick=wrap(async()=>{const s=await call('/v2/pause',{});epoch=s.epoch});
el('resume').onclick=wrap(async()=>{const s=await call('/v2/resume',{});epoch=s.epoch});
el('classify').onclick=wrap(async()=>{if(!selected)throw Error('사건을 먼저 선택하세요');const j=await call('/v2/decisions',{tenant:tenant(),case_id:selected.case.case_id,case_sha256:selected.case.case_sha256,request_id:'ui-'+crypto.randomUUID()});lastJob=j.job_id});
el('apply').onclick=wrap(async()=>{if(!selected||!el('candidate').value)throw Error('서버 후보를 선택하세요');const status=await call('/v2/status');epoch=(status.decisions&&status.decisions.epoch)||status.epoch||0;await call('/v2/apply',{tenant:tenant(),intent:{intent_id:'ui-'+crypto.randomUUID(),case_id:selected.case.case_id,case_sha256:selected.case.case_sha256,candidate_id:el('candidate').value,owner:'operator',run_id:run,cancel_epoch:epoch}})});
el('release').onclick=wrap(async()=>{const rows=await call('/v2/policies?tenant='+encodeURIComponent(tenant()));const own=rows.filter(p=>p.claims.some(c=>c.owner==='operator'&&c.run_id===run));if(own.length!==1)throw Error('이 화면 소유 정책 1개를 확인할 수 없습니다. CLI에서 정확한 제한 기록을 확인하세요');const p=own[0];await call('/v2/release',{tenant:tenant(),policy_id:p.policy_id,owner:'operator',run_id:run,generation:p.generation,request_id:'ui-'+crypto.randomUUID()})});
el('job').onclick=wrap(async()=>{if(!lastJob)throw Error('아직 분류 요청이 없습니다');await call('/v2/job?tenant='+encodeURIComponent(tenant())+'&id='+encodeURIComponent(lastJob))});
el('l3start').onclick=wrap(async()=>{if(!selected)throw Error('사건을 먼저 선택하세요');const mode=el('l3mode').value;const source=l3source();if(mode==='release'&&!source)throw Error('해제 모드에는 정확한 원본 실행 ID가 필요합니다');const id='ui-l3-'+crypto.randomUUID();el('l3run').value=id;const req={tenant:tenant(),case_id:selected.case.case_id,case_sha256:selected.case.case_sha256,request_id:id,mode:mode};if(mode==='release')req.source_run=source;const result=await call('/v2/l3',req);lastL3Run=(result.request&&result.request.run_id)||id;el('l3run').value=lastL3Run});
el('l3query').onclick=wrap(async()=>{const id=l3id();if(!tenant()||!id)throw Error('테넌트와 정확한 L3 실행 ID가 필요합니다');await call('/v2/l3-run?tenant='+encodeURIComponent(tenant())+'&id='+encodeURIComponent(id))});
el('l3cancel').onclick=wrap(async()=>{const id=l3id();if(!tenant()||!id)throw Error('테넌트와 정확한 L3 실행 ID가 필요합니다');await call('/v2/l3-cancel',{tenant:tenant(),run_id:id})});
el('l3release').onclick=wrap(async()=>{const source=l3source(),policy=el('l3policy').value.trim(),episode=el('l3episode').value.trim();if(!tenant()||!source||!policy||!episode)throw Error('테넌트, 원본 실행 ID, 정확한 정책 ID와 적용 회차 ID를 모두 지정하세요');if(!selected)throw Error('원본 실행의 현재 사건을 먼저 선택하세요');const sourceRun=await call('/v2/l3-run?tenant='+encodeURIComponent(tenant())+'&id='+encodeURIComponent(source));const binding=sourceRun.owned_binding;if(!binding||binding.policy_id!==policy||binding.episode_id!==episode)throw Error('선택한 정책 ID와 적용 회차 ID가 원본 실행의 제한 기록과 일치하지 않습니다');if(sourceRun.request.case_id!==selected.case.case_id)throw Error('선택한 사건이 원본 실행의 사건과 일치하지 않습니다');const policies=await call('/v2/policies?tenant='+encodeURIComponent(tenant()));const current=policies.find(p=>p.policy_id===policy&&p.episode_id===episode);if(!current)throw Error('해당 적용 회차의 유효한 정책을 확인할 수 없습니다');const status=await call('/v2/status');epoch=Number((status.decisions&&status.decisions.epoch)||status.epoch||0);if(epoch<1)throw Error('현재 취소 세대 번호를 확인할 수 없습니다');await call('/v2/l3-release',{tenant:tenant(),source_run:source,case_sha256:selected.case.case_sha256,request_id:'ui-'+crypto.randomUUID(),epoch:epoch,generation:current.generation})});
el('l3outcome').onclick=wrap(async()=>{const policy=el('l3policy').value.trim(),episode=el('l3episode').value.trim();if(!tenant()||!policy||!episode)throw Error('테넌트, 정확한 정책 ID와 적용 회차 ID를 모두 지정하세요');await call('/v2/outcome?tenant='+encodeURIComponent(tenant())+'&id='+encodeURIComponent(policy)+'&episode='+encodeURIComponent(episode))});
</script></html>`
