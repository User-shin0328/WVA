'use strict';
const $ = id => document.getElementById(id);
const severityNames = {CRITICAL:'심각',HIGH:'높음',MEDIUM:'중간',LOW:'낮음',INFO:'정보'};
const severityRank = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
const typeNames = {MISSING_SECURITY_HEADER:'보안 헤더 누락',EXPOSED_DEBUG_ENDPOINT:'디버그 정보 노출',INFO_DISCLOSURE:'민감 정보 노출',BOLA_IDOR:'객체 접근 통제 누락',PRIVILEGE_ESCALATION:'유출 키로 관리자 응답 접근',CORS_MISCONFIGURATION:'외부 출처 접근 허용',COOKIE_SECURITY_FLAG:'쿠키 보안 속성 누락',AUTH_BYPASS:'인증 우회',PARAMETER_REFLECTION:'입력값 반사',SECRET_LEAK:'클라이언트 스크립트 시크릿 노출',TLS_EXPIRING:'SSL/TLS 인증서 만료 임박',PATH_TRAVERSAL:'경로 조작 및 시스템 파일 접근 (Path Traversal / LFI)',COMMAND_INJECTION:'OS 시스템 명령어 삽입 (Command Injection / RCE)',SSRF:'서버 측 요청 위조 (SSRF)',ARBITRARY_FILE_UPLOAD:'위험 확장자 파일 무제한 업로드 (Arbitrary File Upload)',SQL_INJECTION:'SQL 주입 (SQL Injection)'};
const statusNames = {idle:'진단 대기',running:'진단 중',completed:'진단 완료',stopped:'진단 중단 · 부분 결과',error:'진단 실패'};
const views = {overview:'웹 대상 진단',chains:'취약점 연계 경로',endpoints:'공격 표면',logs:'진단 로그',save:'정보 저장'};
const exportNames = {summary:'진단 요약',findings:'발견 항목',chains:'연계 경로',endpoints:'공격 표면',logs:'진단 로그'};
const phases = ['연결','표면 탐색','설정 점검','접근 제어','경로 분석'];
const sources = {surface_discovery:'경로 탐색',link_parser:'HTML 링크',form_parser:'HTML 폼',openapi:'API 문서',script_parser:'스크립트'};
let snapshot=null,findings=[],chains=[],endpoints=[],logs=[],consentLogs=[],surface={},diffData=null,selected=null;
let renderKey='',refreshing=false,starting=false,stopping=false,shuttingDown=false,exporting=false,activeView='overview';

function el(tag,className,text){const n=document.createElement(tag);if(className)n.className=className;if(text!==undefined)n.textContent=text;return n;}
function label(f){if(['SQL_INJECTION','XSS'].includes(f.vuln_type))return f.title;if(f.id.startsWith('VULN-CSP'))return '콘텐츠 보안 정책(CSP) 누락';if(f.id.startsWith('VULN-HSTS'))return 'HTTPS 강제 정책(HSTS) 누락';if(f.id.startsWith('VULN-SECRET-LEAK'))return '클라이언트 스크립트 API 키/시크릿 노출';if(f.id.startsWith('VULN-TLS-EXPIRING'))return 'SSL/TLS 인증서 만료 임박';return typeNames[f.vuln_type]||f.title;}
function error(message){$('error').textContent=message||'';$('error').hidden=!message;}
async function responseError(response){let msg='요청을 처리하지 못했습니다.';try{const body=await response.json();msg=Array.isArray(body.detail)?body.detail.map(x=>x.msg.replace(/^Value error, /,'')).join(' '):body.detail||msg;}catch(_){}return new Error(msg);}
async function api(path,options){const response=await fetch(path,options);if(!response.ok)throw await responseError(response);return response.json();}
const post=(path,body={})=>api(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
function timeLabel(value){return value?new Date(value).toLocaleTimeString('ko-KR',{timeZone:'Asia/Seoul',hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'}):'—';}
function duration(){if(!snapshot?.started_at)return '—';const end=snapshot.finished_at?new Date(snapshot.finished_at):new Date();const seconds=Math.max(0,(end-new Date(snapshot.started_at))/1000);return (snapshot.status==='running'?'경과 ':'소요 ')+(seconds>=60?Math.floor(seconds/60)+'분 ':'')+(seconds<10?seconds.toFixed(1):Math.round(seconds%60))+'초';}
function setView(name,updateHash=true){
  if(!(name in views))name='overview';activeView=name;
  for(const key of Object.keys(views))$(key+'-view').hidden=key!==name;
  for(const b of document.querySelectorAll('[data-view]')){const current=b.dataset.view===name;b.classList.toggle('active',current);if(current)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');}
  $('page-title').textContent=views[name];
  $('target-section').hidden=!['overview','chains'].includes(name);$('scan-state').hidden=!['overview','chains'].includes(name);$('metrics').hidden=name!=='overview';$('go-save').hidden=name==='save';
  if(updateHash)history.replaceState(null,'','#'+name);
  if(name==='overview')requestAnimationFrame(renderCharts);
}
function renderStatus(){
  const s=snapshot;if(!s)return;const running=s.status==='running'||starting;
  const displayState=running?'running':s.status;
  if($('scan-state').dataset.state!==displayState)$('scan-state').dataset.state=displayState;
  $('status').textContent=running?'진단 중':statusNames[s.status]||s.status;$('scope').textContent=s.target_url?(s.demo?'로컬 데모 · ':s.mode==='deep'?'[로컬 심화] ':'')+s.target_url:'—';$('elapsed').textContent=duration();
  $('count-findings').textContent=s.findings_count.toLocaleString();$('count-chains').textContent=s.chains_count.toLocaleString();$('count-endpoints').textContent=s.endpoints_count.toLocaleString();
  const gradeEl=$('security-grade');
  if(gradeEl){
    if(!running&&s.status==='completed'){
      const grade=s.grade||(s.checks?.length?'보류':'—');gradeEl.textContent=grade;
      if(grade==='A'||grade==='B')gradeEl.style.color='var(--accent)';
      else if(grade==='C')gradeEl.style.color='#ffd43b';
      else if(grade==='D'||grade==='F')gradeEl.style.color='var(--danger)';
      else gradeEl.style.color='';
    }else{
      gradeEl.textContent='—';gradeEl.style.color='';
    }
  }
  const scoreEl=$('security-score');
  if(scoreEl)scoreEl.textContent=!running&&s.status==='completed'&&Number.isFinite(s.score)?(s.score+'점'):'—';
  for(const button of document.querySelectorAll('.finding-name,.chain-step'))button.disabled=running;renderChecks();
  $('start').disabled=running;$('start').textContent=running?'진단 중…':'진단 시작';$('target').disabled=running;$('scope-mode').disabled=running;if($('scan-mode'))$('scan-mode').disabled=running;$('demo').disabled=running;$('stop').hidden=!running;$('stop').disabled=starting||stopping;
  for(const input of document.querySelectorAll('.scan-option-fields input,.scan-option-fields button'))input.disabled=running;
  $('scan-phases').hidden=!running;
  const phase=starting?0:(s.phase||0);$('scan-phases').replaceChildren(...phases.map((name,index)=>{const item=el('li',index<phase?'done':index===phase&&running?'current':'',name);if(index===phase&&running)item.setAttribute('aria-current','step');return item;}));
  for(const n of document.querySelectorAll('.current-target'))n.textContent=s.target_url||'—';
  $('scan-log-path').textContent=s.log_path||'—';$('app-log-path').textContent=s.app_log_path||'—';$('log-error').textContent=s.log_error||'';$('log-error').hidden=!s.log_error;$('save-scan-id').textContent=s.scan_id||'';
  if(s.error)error(s.error);updateExport();
}
const checkNames={PASS:'확인 완료',FINDING:'발견',SIGNAL:'판정 보류',NOT_RUN:'미실행',ERROR:'오류',NOT_SUPPORTED:'미지원'};
function renderChecks(){
  const rows=snapshot?.checks||[];$('check-count').textContent=rows.length+'개';
  $('checks-body').replaceChildren(...rows.map(r=>{const tr=el('tr');tr.append(el('td','',r.title),el('td',r.status==='FINDING'?'severity HIGH':'',(checkNames[r.status]||r.status)+(r.errors?' · 일부 미완료':'')+(r.inconclusive?' · 일부 미확정':'')),el('td','numeric',String(r.tested)),el('td','check-reason',r.reason));return tr;}));
  $('assessment-note').hidden=snapshot?.status!=='completed';$('assessment-note').textContent=snapshot?.assessment_note||'';
}
if($('clear-profile'))$('clear-profile').addEventListener('click',()=>{$('option-profile').value='';});
function svg(tag,attributes={},text){const n=document.createElementNS('http://www.w3.org/2000/svg',tag);for(const [k,v]of Object.entries(attributes))n.setAttribute(k,String(v));if(text!==undefined)n.textContent=text;return n;}
function pieChart(host,entries,title){
  const width=Math.max(290,Math.round(host.getBoundingClientRect().width)-32),stacked=width<440;
  const radius=80,cx=stacked?width/2:100,cy=100,row=30;
  const legendTop=stacked?210:Math.max(36,(200-entries.length*row)/2+16),legendLeft=stacked?20:220;
  const height=stacked?legendTop+entries.length*row+12:220;
  const colors=['#ff4055','#ff922b','#ffd43b','#22d3c5','#4dabf7'];
  const total=entries.reduce((sum,item)=>sum+item.value,0);
  const chart=svg('svg',{viewBox:`0 0 ${width} ${height}`,role:'img','aria-label':title+' · '+entries.map(x=>x.name+' '+x.value+'건').join(', ')});
  let angle=-Math.PI/2;
  for(const [index,item]of entries.entries()){
    const color=colors[index%colors.length],ratio=total?item.value/total:0;
    if(item.value>0){
      const end=angle+ratio*Math.PI*2;
      const slice=ratio===1?svg('circle',{cx,cy,r:radius,fill:color,class:'chart-slice','data-count':item.value}):svg('path',{d:`M ${cx} ${cy} L ${cx+radius*Math.cos(angle)} ${cy+radius*Math.sin(angle)} A ${radius} ${radius} 0 ${ratio>.5?1:0} 1 ${cx+radius*Math.cos(end)} ${cy+radius*Math.sin(end)} Z`,fill:color,class:'chart-slice','data-count':item.value});
      slice.append(svg('title',{},item.name+' · '+item.value+'건 · '+(ratio*100).toFixed(1)+'%'));chart.append(slice);angle=end;
    }
    const y=legendTop+index*row;
    chart.append(svg('rect',{x:legendLeft,y:y-8,width:8,height:8,fill:color}),svg('text',{x:legendLeft+18,y},item.name),svg('text',{x:width-65,y,'text-anchor':'end',class:'chart-value'},item.value+'건'),svg('text',{x:width-8,y,'text-anchor':'end'},(ratio*100).toFixed(0)+'%'));
  }
  if(total===0)chart.append(svg('circle',{cx,cy,r:radius,class:'chart-empty'}),svg('text',{x:cx,y:cy+5,'text-anchor':'middle',class:'chart-value'},'0건'));
  host.replaceChildren(chart);
}
function renderCharts(){
  const show=snapshot?.status==='completed';$('risk-charts').hidden=!show;if(!show||activeView!=='overview')return;
  const severity=Object.keys(severityNames).map(key=>({name:severityNames[key],value:findings.filter(f=>f.severity===key).length}));
  const ranges=[{name:'심각 9.0–10.0',min:9,max:10.1},{name:'높음 7.0–8.9',min:7,max:9},{name:'중간 4.0–6.9',min:4,max:7},{name:'낮음 0–3.9',min:0,max:4}];
  pieChart($('severity-chart'),severity,'위험도별 발견 항목');pieChart($('cvss-chart'),ranges.map(r=>({name:r.name,value:findings.filter(f=>Number.isFinite(f.cvss_score)&&f.cvss_score>=r.min&&f.cvss_score<r.max).length})),'CVSS 점수 분포');
}
function createFindingRow(f){
  const row=el('tr','finding-row');row.addEventListener('click',()=>openFinding(f.id));
  const severity=el('td');severity.append(el('span','severity '+f.severity,severityNames[f.severity]));
  const main=el('td');const button=el('button','finding-name',label(f));button.type='button';button.setAttribute('aria-haspopup','dialog');button.title=f.title;
  if(diffData?.new_ids?.includes(f.id)){
    button.append(el('span','badge-new','신규'));
  }
  main.append(button,el('span','subline',f.cwe_id||'—'));
  const route=el('td');route.append(el('span','endpoint',f.endpoint),el('span','subline',f.method));
  const evidence=el('td');evidence.append(el('span','cell-summary',f.evidence));const action=el('td');action.append(el('span','cell-summary',f.remediation_details?.summary||f.remediation));
  row.append(severity,main,route,el('td','numeric score',Number.isFinite(f.cvss_score)?f.cvss_score.toFixed(1):'—'),evidence,action);return row;
}
function renderFindings(){
  const query=$('search').value.trim().toLowerCase(),severity=$('severity').value;
  const list=findings.filter(f=>(!severity||severity===f.severity)&&(!query||[label(f),f.title,f.endpoint,f.id,f.evidence,f.cwe_id].join(' ').toLowerCase().includes(query)));
  $('findings-body').replaceChildren(...list.map(createFindingRow));$('findings-empty').hidden=list.length>0;$('findings-empty').textContent=findings.length?'검색 결과 0건':'발견 항목 0건';$('finding-total').textContent=list.length===findings.length?findings.length+'건':list.length+' / '+findings.length+'건';
}
function detailBlock(title){const section=el('section','detail-block');section.append(el('h3','',title));return section;}
function openFinding(id){
  const f=findings.find(x=>x.id===id);if(!f)return;selected=id;
  $('detail-title').textContent=label(f);$('detail-id').textContent=f.id;
  const risk=f.risk_context||{summary:f.remediation_details?.impact||f.description,observation:'관찰 증거 원문을 확인하세요.',assessment:'추가 검토 필요',attacks:[],limits:[],references:[]};
  const overview=detailBlock('문제 요약');overview.classList.add('detail-overview');overview.append(el('p','detail-lead',risk.summary));
  const metrics=el('dl','detail-metrics');
  for(const [name,value,cls]of [['위험도',severityNames[f.severity],'severity '+f.severity],['CVSS 참고 점수',f.cvss_score.toFixed(1),'mono']]){const cell=el('div');cell.append(el('dt','',name),el('dd',cls,value));metrics.append(cell);}
  const observed=detailBlock('확인한 내용');observed.append(el('p','detail-assessment',risk.assessment),el('p','',risk.observation));
  const requestUrl=new URL(f.request_url||f.endpoint,snapshot?.target_url||window.location.href);const entryUrl=new URL(snapshot?.target_url||window.location.href);if(!f.request_url&&requestUrl.pathname===entryUrl.pathname)requestUrl.search=entryUrl.search;observed.append(el('p','mono detail-request',f.method+' '+requestUrl.href));
  const evidence=el('details','detail-evidence');evidence.append(el('summary','','관찰 증거 원문'),el('pre','',f.evidence));observed.append(evidence);
  const limits=detailBlock('판정 범위');const limitList=el('ul','detail-limits');for(const limit of risk.limits)limitList.append(el('li','',limit));limits.append(limitList);
  const attacks=detailBlock('가능한 공격');const scenarios=el('ol','attack-scenarios');
  for(const attack of risk.attacks){const item=el('li');item.append(el('h4','',attack.name),el('p','',attack.scenario),el('p','conditions-label','성립 조건'));const conditions=el('ul');for(const condition of attack.conditions)conditions.append(el('li','',condition));item.append(conditions);scenarios.append(item);}
  attacks.append(risk.attacks.length?scenarios:el('p','','이 유형의 공격 설명은 아직 등록되지 않았습니다. 증거를 추가 검토해야 합니다.'));
  const remediation=detailBlock('권고사항 · 조치 순서');const actionsToggle=el('button','text-button','모든 조치 펼치기');actionsToggle.type='button';actionsToggle.id='toggle-actions';actionsToggle.setAttribute('aria-expanded','false');const heading=el('div','detail-section-heading');heading.append(remediation.firstChild,actionsToggle);remediation.append(heading,el('p','',f.remediation_details?.summary||f.remediation));
  const actions=el('ol','remediation-steps');
  const steps=f.remediation_details?.steps||(f.remediation_details?.actions||[f.remediation]).map((action,index)=>({order:index+1,title:'조치 '+(index+1),action}));
  const updateToggle=()=>{const all=[...actions.querySelectorAll('details')].every(n=>n.open);actionsToggle.textContent=all?'모든 조치 접기':'모든 조치 펼치기';actionsToggle.setAttribute('aria-expanded',String(all));};
  for(const [index,step]of steps.entries()){const item=el('li');item.value=step.order;const fold=el('details','action-step');fold.open=index===0;const title=el('summary');title.append(el('span','step-order',step.order+'.'),el('h4','',step.title));const body=el('div','action-step-body');body.append(el('p','',step.action));if(step.expected_result)body.append(el('p','step-result','완료 기준: '+step.expected_result));fold.append(title,body);fold.addEventListener('toggle',updateToggle);item.append(fold);actions.append(item);}
  actionsToggle.addEventListener('click',()=>{const expand=actionsToggle.getAttribute('aria-expanded')!=='true';for(const n of actions.querySelectorAll('details'))n.open=expand;updateToggle();});
  remediation.append(actions);
  const verify=detailBlock('수정 후 확인');const checks=el('ul');for(const check of f.remediation_details?.verification||[])checks.append(el('li','',check));verify.append(checks);
  const original=el('details','detail-original');original.append(el('summary','','기술 정보 및 원문'),el('p','mono',f.id),el('p','mono','CWE: '+(f.cwe_id||'—')+' · '+f.method),el('p','',f.description),el('p','',f.remediation));
  for(const reference of risk.references){const p=el('p');const link=el('a','',reference.title);link.href=reference.url;link.target='_blank';link.rel='noopener noreferrer';p.append(link);original.append(p);}
  const contentItems=[overview,metrics,observed,attacks,limits,remediation,verify];
  const aiPrompt=f.ai_prompt||f.remediation_details?.ai_prompt;
  if(aiPrompt){const ai=el('details','detail-ai');ai.append(el('summary','','AI 수정 프롬프트'),el('pre','',aiPrompt));const copy=el('button','button secondary','프롬프트 복사');copy.type='button';copy.id='copy-ai-prompt';copy.addEventListener('click',async()=>{try{if(navigator.clipboard?.writeText)await navigator.clipboard.writeText(aiPrompt);else{const input=el('textarea');input.value=aiPrompt;document.body.append(input);input.select();const copied=document.execCommand('copy');input.remove();if(!copied)throw new Error('copy failed');}copy.textContent='복사 완료';}catch(_){copy.textContent='복사 실패 · 내용을 직접 선택하세요.';}});ai.append(copy);contentItems.push(ai);}
  contentItems.push(original);$('detail-content').replaceChildren(...contentItems);
  if(!$('finding-dialog').open)$('finding-dialog').showModal();
  $('detail-content').scrollTop=0;requestAnimationFrame(()=>{$('detail-content').scrollTop=0;});
}
function renderChains(){
  const blocks=chains.map(chain=>{
    const article=el('article','chain-entry');const header=el('div','chain-entry-heading');header.append(el('h3','',chain.steps.length+'단계 · '+chain.initial_privilege+' → '+chain.attained_privilege),el('span','',chain.chain_id));
    const steps=el('div','chain-steps');for(const step of chain.steps){const f=findings.find(x=>x.id===step.finding_id);const b=el('button','chain-step');b.type='button';b.setAttribute('aria-haspopup','dialog');b.append(el('span','step-number','STEP '+step.step_number),el('h3','',f?label(f):step.action_description),el('p','',f?.endpoint||step.finding_id));b.addEventListener('click',()=>openFinding(step.finding_id));steps.append(b);}
    article.append(header,steps);return article;
  });
  if(!blocks.length)blocks.push(el('p','empty-text','연계 경로 0건'));$('chains-list').replaceChildren(...blocks);$('chain-count').textContent=chains.length+'건';
  const ids=new Set(chains.flatMap(c=>c.steps.map(s=>s.finding_id)));const related=findings.filter(f=>ids.has(f.id));$('related-body').replaceChildren(...related.map(createFindingRow));$('related-count').textContent=related.length+'건';$('related-empty').hidden=related.length>0;
}
function renderEndpoints(){
  $('surface-measured').textContent=surface.measured_count||0;$('surface-unmeasured').textContent=surface.schema_only_count||0;$('surface-auth').textContent=surface.auth_response_count||0;$('surface-tech').textContent=surface.tech_stack?.join(' · ')||'—';
  const query=$('endpoint-search').value.trim().toLowerCase();const list=endpoints.filter(ep=>!query||[ep.path,...ep.parameters,ep.method,...ep.sources||[]].join(' ').toLowerCase().includes(query));
  $('endpoints-body').replaceChildren(...list.map(ep=>{
    const row=el('tr');const method=el('td');method.append(el('span','mono',ep.method),el('span','subline',ep.status_code===null?'미측정':'HTTP '+ep.status_code));
    const route=el('td');route.append(el('span','endpoint',ep.path+new URL(ep.url).search));
    const parameters=el('td','',ep.parameters.join(', ')||'—');const size=el('td','numeric');size.append(el('span','mono',ep.response_time_ms===null?'—':ep.response_time_ms.toFixed(1)),el('span','subline',ep.response_bytes===null?'—':ep.response_bytes.toLocaleString()+' B'));
    const source=el('td');source.append(el('span','',([...new Set([ep.source,...ep.sources||[]])]).map(s=>sources[s]||s).join(' · ')),el('span','subline',timeLabel(ep.checked_at)));
    const count=findings.filter(f=>f.endpoint===ep.path&&f.method===ep.method).length;
    row.append(method,route,parameters,el('td','',ep.content_type||'—'),size,source,el('td','numeric mono',count));return row;
  }));$('endpoints-empty').hidden=list.length>0;$('endpoints-empty').textContent=endpoints.length?'검색 결과 0개':'엔드포인트 0개';
  const measured=list.filter(ep=>ep.status_code!==null);
  $('headers-body').replaceChildren(...measured.map(ep=>{const row=el('tr');row.append(el('td','endpoint',ep.path));for(const key of ['content-security-policy','strict-transport-security','x-content-type-options','x-frame-options','access-control-allow-origin']){let value=ep.headers[key]||'—';if(key==='strict-transport-security'&&ep.url.startsWith('http:'))value='HTTP 대상';if(key==='x-frame-options'&&!ep.headers[key]&&ep.headers['content-security-policy']?.includes('frame-ancestors'))value='CSP frame-ancestors';const cell=el('td',value==='—'?'header-absent':'header-present',value);cell.title=value;row.append(cell);}return row;}));
}
function renderLogs(){
  $('logs').replaceChildren(...logs.slice(-100).reverse().map(event=>{const row=el('li');row.append(el('time','',timeLabel(event.timestamp)),el('span','',event.data));return row;}));
  $('logs-empty').hidden=logs.length>0;
  if($('consent-logs')){
    const clogs=consentLogs||[];
    $('consent-logs').replaceChildren(...clogs.slice(-50).reverse().map(entry=>{
      const row=el('li');
      const modeTag=entry.mode==='deep'?'[로컬 심화]':'[운영 안전]';
      const text=`${modeTag} ${entry.target_url} · ${entry.statement||'동의 완료'} (${entry.scan_id||''})`;
      row.append(el('time','',timeLabel(entry.timestamp)),el('span','',text));
      return row;
    }));
    if($('consent-logs-empty'))$('consent-logs-empty').hidden=clogs.length>0;
  }
}
function initExport(){for(const [key,title]of Object.entries(exportNames)){const label=el('label');const input=el('input');input.type='checkbox';input.name='sections';input.value=key;input.checked=true;const count=el('small');count.id='export-count-'+key;label.append(input,el('span','',title),count);$('export-sections').append(label);}for(const input of $('export-form').querySelectorAll('input'))input.addEventListener('change',updateExport);}
function updateExport(){
  const chosen=[...$('export-sections').querySelectorAll('input:checked')];const format=$('export-form').querySelector('input[name="format"]:checked')?.value||'json';
  $('export-summary').textContent=chosen.length+'개 항목 · '+({json:'JSON',md:'Markdown',csv:'CSV'})[format];
  const counts={summary:snapshot?.scan_id?1:0,findings:findings.length,chains:chains.length,endpoints:endpoints.length,logs:logs.length};for(const [key,count]of Object.entries(counts)){const n=$('export-count-'+key);if(n)n.textContent=count;}
  $('export-button').disabled=!chosen.length||snapshot?.status!=='completed'||exporting;
  if(!chosen.length)$('save-result').textContent='저장할 정보를 선택하세요.';else if(snapshot?.status!=='completed')$('save-result').textContent='진단 완료 후 저장 가능';else if($('save-result').textContent==='진단 완료 후 저장 가능'||$('save-result').textContent==='저장할 정보를 선택하세요.')$('save-result').textContent='';
}
function renderAll(){renderFindings();renderCharts();renderChains();renderEndpoints();renderLogs();updateExport();}
async function updateDiff(){
  if(snapshot?.status==='completed'){
    try{
      diffData=await api('/api/scan/diff');
      const banner=$('diff-banner');
      if(banner){
        if(diffData?.has_previous){
          banner.hidden=false;
          const sign=diffData.score_diff>0?'+':'';
          $('diff-summary-text').textContent=`${sign}${diffData.score_diff}점 변동 (이전 ${diffData.previous_score}점/${diffData.previous_grade||'보류'} → 현재 ${diffData.current_score}점/${diffData.current_grade||'보류'})`;
          $('diff-chip-fixed').textContent=`이번에 미발견 ${diffData.fixed_count}건`;
          $('diff-chip-new').textContent=`신규 발생 ${diffData.new_count}건`;
          $('diff-chip-persistent').textContent=`유지 ${diffData.persistent_count}건`;
        }else{
          banner.hidden=true;
        }
      }
    }catch(_){if($('diff-banner'))$('diff-banner').hidden=true;}
  }else{
    diffData=null;if($('diff-banner'))$('diff-banner').hidden=true;
  }
}
async function refresh(force=false){
  if(refreshing||shuttingDown)return;refreshing=true;
  try{
    const s=await api('/api/scan/status');if(!snapshot&&s.scan_id){$('scope-mode').value=s.scope_mode||'path';if($('scan-mode')&&s.mode)$('scan-mode').value=s.mode;if(!s.demo)$('target').value=s.target_url;}const key=[s.scan_id,s.status,s.findings_count,s.chains_count,s.endpoints_count].join('|');const changed=force||key!==renderKey;snapshot=s;
    if(changed||s.status==='running'){
      const data=await Promise.all(['/api/scan/findings','/api/scan/chains','/api/scan/endpoints','/api/scan/logs','/api/scan/surface','/api/scan/consent_log'].map(p=>api(p)));
      [findings,chains,endpoints,logs,surface,consentLogs]=data;findings.sort((a,b)=>severityRank[a.severity]-severityRank[b.severity]);
      if(s.status==='completed'){
        await updateDiff();
      }else{
        diffData=null;
        if($('diff-banner'))$('diff-banner').hidden=true;
      }
      renderKey=key;renderAll();
    }
    renderStatus();
  }catch(exc){error('서버 연결 실패: '+exc.message);}finally{refreshing=false;}
}
async function start(demo=false){
  if(starting||snapshot?.status==='running')return;
  if(!demo&&$('scan-consent')&&!$('scan-consent').checked){
    error('점검 권한 확인에 동의해야 시작할 수 있습니다.');
    return;
  }
  starting=true;error('');if($('finding-dialog').open)$('finding-dialog').close();
  $('start').disabled=true;$('demo').disabled=true;$('scope-mode').disabled=true;if($('scan-mode'))$('scan-mode').disabled=true;$('scan-state').dataset.state='running';$('status').textContent='진단 중';if(snapshot)renderStatus();
  try{
    const target=demo?'http://127.0.0.1:8989':$('target').value.trim();
    const scopeMode=demo?'path':$('scope-mode').value;const mode=demo?'safe':($('scan-mode')?.value||'safe');
    const consent=demo?true:Boolean($('scan-consent')?.checked);
    let profile={};const file=$('option-profile').files[0];
    if(!demo&&file){
      if(file.size>256000)throw new Error('프로필 파일은 256KB 이하여야 합니다.');
      try{profile=JSON.parse(await file.text());}catch(_){throw new Error('JSON 프로필 형식을 확인하세요.');}
      if(!profile||Array.isArray(profile)||typeof profile!=='object')throw new Error('프로필은 JSON 객체여야 합니다.');
    }
    const options=demo?{}:{...profile,sql:$('option-sql').checked,xss:$('option-browser').checked,browser:$('option-browser').checked,max_requests:Number($('option-limit').value),parameters:$('option-params').value.split(',').map(s=>s.trim()).filter(Boolean)};
    const result=await post('/api/scan/start',{target_url:target,demo,scope_mode:scopeMode,mode,consent,options});
    selected=null;findings=[];chains=[];endpoints=[];logs=[];surface={};diffData=null;renderKey='';$('save-result').textContent='진단 완료 후 저장 가능';
    if($('diff-banner'))$('diff-banner').hidden=true;
    snapshot={...snapshot,status:'running',scan_id:result.scan_id,target_url:result.target_url,scope_mode:result.scope_mode,mode:result.mode||mode,demo,findings_count:0,chains_count:0,endpoints_count:0,phase:0,started_at:new Date().toISOString(),finished_at:null,error:'',log_path:''};renderStatus();renderAll();await refresh(true);
  }catch(exc){error(exc.message);}finally{starting=false;if(snapshot)renderStatus();else{$('start').disabled=false;$('demo').disabled=false;$('scope-mode').disabled=false;if($('scan-mode'))$('scan-mode').disabled=false;$('scan-phases').hidden=true;$('scan-state').dataset.state='idle';$('status').textContent='진단 대기';}}
}
async function saveSelected(event){
  event.preventDefault();if(exporting)return;const sections=[...$('export-sections').querySelectorAll('input:checked')].map(n=>n.value);if(!sections.length)return;
  exporting=true;error('');updateExport();
  try{
    const format=$('export-form').querySelector('input[name="format"]:checked').value;
    const response=await fetch('/api/scan/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sections,format,scan_id:snapshot.scan_id})});if(!response.ok)throw await responseError(response);
    const filename='WVA_'+snapshot.scan_id+'.'+format;const url=URL.createObjectURL(await response.blob());const link=el('a');link.href=url;link.download=filename;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);$('save-result').textContent=filename+' 저장 요청 완료';
  }catch(exc){error(exc.message);}finally{exporting=false;updateExport();}
}
$('scan-form').addEventListener('submit',event=>{event.preventDefault();start(false);});$('demo').addEventListener('click',()=>start(true));
$('stop').addEventListener('click',async()=>{if(starting||stopping)return;stopping=true;renderStatus();try{await post('/api/scan/stop');await refresh(true);}catch(exc){error(exc.message);}finally{stopping=false;renderStatus();}});
$('search').addEventListener('input',renderFindings);$('severity').addEventListener('change',renderFindings);$('endpoint-search').addEventListener('input',renderEndpoints);
$('go-save').addEventListener('click',()=>setView('save'));for(const b of document.querySelectorAll('[data-view]'))b.addEventListener('click',()=>setView(b.dataset.view));
$('close-detail').addEventListener('click',()=>$('finding-dialog').close());$('finding-dialog').addEventListener('close',()=>{selected=null;});
$('finding-dialog').addEventListener('click',event=>{if(event.target===$('finding-dialog')){const rect=$('finding-dialog').getBoundingClientRect();if(event.clientX<rect.left||event.clientX>rect.right||event.clientY<rect.top||event.clientY>rect.bottom)$('finding-dialog').close();}});
$('export-form').addEventListener('submit',saveSelected);
$('shutdown').addEventListener('click',async()=>{try{await post('/api/app/shutdown');shuttingDown=true;$('status').textContent='앱 종료';for(const b of document.querySelectorAll('button'))b.disabled=true;}catch(exc){error(exc.message);}});
window.addEventListener('hashchange',()=>setView(location.hash.slice(1),false));let resizeTimer;window.addEventListener('resize',()=>{clearTimeout(resizeTimer);resizeTimer=setTimeout(renderCharts,100);});
function updateConsentLabel(){const mode=$('scan-mode')?.value||'safe';const lbl=$('consent-label');if(!lbl)return;if(mode==='deep')lbl.textContent='로컬 실습 대상이며 선택한 심화 검사와 테스트 데이터 생성을 승인합니다';else lbl.textContent='소유하거나 진단 허가를 받은 대상입니다';}
$('scan-mode')?.addEventListener('change',updateConsentLabel);updateConsentLabel();
initExport();setView(location.hash.slice(1)||'overview',false);refresh(true);setInterval(()=>refresh(),700);setInterval(()=>{if(snapshot)$('elapsed').textContent=duration();},500);
