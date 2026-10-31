'use strict';
const $ = id => document.getElementById(id);
const severityNames = {CRITICAL:'심각',HIGH:'높음',MEDIUM:'중간',LOW:'낮음',INFO:'정보'};
const severityRank = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
const typeNames = {MISSING_SECURITY_HEADER:'보안 헤더 누락',EXPOSED_DEBUG_ENDPOINT:'디버그 정보 노출',INFO_DISCLOSURE:'민감 정보 노출',BOLA_IDOR:'객체 접근 통제 누락',PRIVILEGE_ESCALATION:'유출 키로 관리자 응답 접근',CORS_MISCONFIGURATION:'외부 출처 접근 허용',COOKIE_SECURITY_FLAG:'쿠키 보안 속성 누락',AUTH_BYPASS:'인증 우회',PARAMETER_REFLECTION:'입력값 반사'};
const statusNames = {idle:'진단 대기',running:'진단 중',completed:'진단 완료',stopped:'진단 중단 · 부분 결과',error:'진단 실패'};
const views = {overview:'웹 대상 진단',chains:'취약점 연계 경로',endpoints:'공격 표면',logs:'진단 로그',save:'정보 저장'};
const exportNames = {summary:'진단 요약',findings:'발견 항목',chains:'연계 경로',endpoints:'공격 표면',logs:'진단 로그'};
const phases = ['연결','표면 탐색','설정 점검','접근 제어','경로 분석'];
const sources = {surface_discovery:'경로 탐색',link_parser:'HTML 링크',form_parser:'HTML 폼',openapi:'API 문서'};
let snapshot=null,findings=[],chains=[],endpoints=[],logs=[],surface={},selected=null;
let renderKey='',refreshing=false,starting=false,shuttingDown=false,exporting=false,activeView='overview';

function el(tag,className,text){const n=document.createElement(tag);if(className)n.className=className;if(text!==undefined)n.textContent=text;return n;}
function label(f){if(f.id.startsWith('VULN-CSP'))return '콘텐츠 보안 정책(CSP) 누락';if(f.id.startsWith('VULN-HSTS'))return 'HTTPS 강제 정책(HSTS) 누락';return typeNames[f.vuln_type]||f.title;}
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
  $('status').textContent=running?'진단 중':statusNames[s.status]||s.status;$('scope').textContent=s.target_url?(s.demo?'로컬 데모 · ':'')+s.target_url:'—';$('elapsed').textContent=duration();
  $('count-findings').textContent=s.findings_count.toLocaleString();$('count-chains').textContent=s.chains_count.toLocaleString();$('count-endpoints').textContent=s.endpoints_count.toLocaleString();
  $('start').disabled=running;$('start').textContent=running?'진단 중…':'진단 시작';$('target').disabled=running;$('demo').disabled=running;$('stop').hidden=!running;
  $('scan-phases').hidden=!s.scan_id&&!starting;
  $('scan-phases').replaceChildren(...phases.map((name,index)=>{const item=el('li',s.status==='completed'||index<(s.phase||0)?'done':index===(s.phase||0)&&running?'current':'',name);if(index===(s.phase||0)&&running)item.setAttribute('aria-current','step');return item;}));
  for(const n of document.querySelectorAll('.current-target'))n.textContent=s.target_url||'—';
  $('scan-log-path').textContent=s.log_path||'—';$('app-log-path').textContent=s.app_log_path||'—';$('log-error').textContent=s.log_error||'';$('log-error').hidden=!s.log_error;$('save-scan-id').textContent=s.scan_id||'';
  if(s.error)error(s.error);updateExport();
}
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
  const main=el('td');const button=el('button','finding-name',label(f));button.type='button';button.setAttribute('aria-haspopup','dialog');button.title=f.title;main.append(button,el('span','subline',f.cwe_id||'—'));
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
  const metrics=el('dl','detail-metrics');
  for(const [name,value,cls]of [['위험도',severityNames[f.severity],'severity '+f.severity],['CVSS',f.cvss_score.toFixed(1),'mono'],['CWE',f.cwe_id||'—','mono'],['메서드',f.method,'mono']]){const cell=el('div');cell.append(el('dt','',name),el('dd',cls,value));metrics.append(cell);}
  const location=detailBlock('요청 경로');location.append(el('p','mono',f.method+' '+(snapshot?.target_url||'')+f.endpoint));
  const impact=detailBlock('영향과 관찰 범위');impact.append(el('p','',f.remediation_details?.impact||f.description));
  const evidence=detailBlock('관찰 증거');evidence.append(el('pre','',f.evidence));
  const remediation=detailBlock('권고사항 · 조치 순서');remediation.append(el('p','',f.remediation_details?.summary||f.remediation));
  const actions=el('ol','remediation-steps');
  const steps=f.remediation_details?.steps||(f.remediation_details?.actions||[f.remediation]).map((action,index)=>({order:index+1,title:'조치 '+(index+1),action}));
  for(const step of steps){const item=el('li');item.value=step.order;item.append(el('h4','',step.title),el('p','',step.action));if(step.expected_result)item.append(el('p','step-result','완료 기준: '+step.expected_result));actions.append(item);}
  remediation.append(actions);
  const verify=detailBlock('수정 후 확인');const checks=el('ul');for(const check of f.remediation_details?.verification||[])checks.append(el('li','',check));verify.append(checks);
  const original=el('details','detail-original');original.append(el('summary','','원문 설명 및 권고'),el('p','',f.description),el('p','',f.remediation));
  $('detail-content').replaceChildren(metrics,location,impact,evidence,remediation,verify,original);$('detail-content').scrollTop=0;
  if(!$('finding-dialog').open)$('finding-dialog').showModal();
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
    const route=el('td');route.append(el('span','endpoint',ep.path));
    const parameters=el('td','',ep.parameters.join(', ')||'—');const size=el('td','numeric');size.append(el('span','mono',ep.response_time_ms===null?'—':ep.response_time_ms.toFixed(1)),el('span','subline',ep.response_bytes===null?'—':ep.response_bytes.toLocaleString()+' B'));
    const source=el('td');source.append(el('span','',([...new Set([ep.source,...ep.sources||[]])]).map(s=>sources[s]||s).join(' · ')),el('span','subline',timeLabel(ep.checked_at)));
    const count=findings.filter(f=>f.endpoint===ep.path&&f.method===ep.method).length;
    row.append(method,route,parameters,el('td','',ep.content_type||'—'),size,source,el('td','numeric mono',count));return row;
  }));$('endpoints-empty').hidden=list.length>0;$('endpoints-empty').textContent=endpoints.length?'검색 결과 0개':'엔드포인트 0개';
  const measured=list.filter(ep=>ep.status_code!==null);
  $('headers-body').replaceChildren(...measured.map(ep=>{const row=el('tr');row.append(el('td','endpoint',ep.path));for(const key of ['content-security-policy','strict-transport-security','x-content-type-options','x-frame-options','access-control-allow-origin']){let value=ep.headers[key]||'—';if(key==='strict-transport-security'&&ep.url.startsWith('http:'))value='HTTP 대상';if(key==='x-frame-options'&&!ep.headers[key]&&ep.headers['content-security-policy']?.includes('frame-ancestors'))value='CSP frame-ancestors';const cell=el('td',value==='—'?'header-absent':'header-present',value);cell.title=value;row.append(cell);}return row;}));
}
function renderLogs(){$('logs').replaceChildren(...logs.slice(-100).reverse().map(event=>{const row=el('li');row.append(el('time','',timeLabel(event.timestamp)),el('span','',event.data));return row;}));$('logs-empty').hidden=logs.length>0;}
function initExport(){for(const [key,title]of Object.entries(exportNames)){const label=el('label');const input=el('input');input.type='checkbox';input.name='sections';input.value=key;input.checked=true;const count=el('small');count.id='export-count-'+key;label.append(input,el('span','',title),count);$('export-sections').append(label);}for(const input of $('export-form').querySelectorAll('input'))input.addEventListener('change',updateExport);}
function updateExport(){
  const chosen=[...$('export-sections').querySelectorAll('input:checked')];const format=$('export-form').querySelector('input[name="format"]:checked')?.value||'json';
  $('export-summary').textContent=chosen.length+'개 항목 · '+({json:'JSON',md:'Markdown',csv:'CSV'})[format];
  const counts={summary:snapshot?.scan_id?1:0,findings:findings.length,chains:chains.length,endpoints:endpoints.length,logs:logs.length};for(const [key,count]of Object.entries(counts)){const n=$('export-count-'+key);if(n)n.textContent=count;}
  $('export-button').disabled=!chosen.length||snapshot?.status!=='completed'||exporting;
  if(!chosen.length)$('save-result').textContent='저장할 정보를 선택하세요.';else if(snapshot?.status!=='completed')$('save-result').textContent='진단 완료 후 저장 가능';else if($('save-result').textContent==='진단 완료 후 저장 가능'||$('save-result').textContent==='저장할 정보를 선택하세요.')$('save-result').textContent='';
}
function renderAll(){renderFindings();renderCharts();renderChains();renderEndpoints();renderLogs();updateExport();}
async function refresh(force=false){
  if(refreshing||shuttingDown)return;refreshing=true;
  try{
    const s=await api('/api/scan/status');const key=[s.scan_id,s.status,s.findings_count,s.chains_count,s.endpoints_count].join('|');const changed=force||key!==renderKey;snapshot=s;renderStatus();
    if(changed||s.status==='running'){
      const data=await Promise.all(['/api/scan/findings','/api/scan/chains','/api/scan/endpoints','/api/scan/logs','/api/scan/surface'].map(p=>api(p)));
      [findings,chains,endpoints,logs,surface]=data;findings.sort((a,b)=>severityRank[a.severity]-severityRank[b.severity]);renderKey=key;renderAll();
    }
  }catch(exc){error('서버 연결 실패: '+exc.message);}finally{refreshing=false;}
}
async function start(demo=false){
  if(starting||snapshot?.status==='running')return;starting=true;error('');if($('finding-dialog').open)$('finding-dialog').close();
  $('start').disabled=true;$('demo').disabled=true;$('scan-state').dataset.state='running';$('status').textContent='진단 중';
  try{
    const target=demo?'http://127.0.0.1:8989':$('target').value.trim();const result=await post('/api/scan/start',{target_url:target,demo});
    selected=null;findings=[];chains=[];endpoints=[];logs=[];surface={};renderKey='';$('save-result').textContent='진단 완료 후 저장 가능';
    snapshot={...snapshot,status:'running',scan_id:result.scan_id,target_url:result.target_url,demo,findings_count:0,chains_count:0,endpoints_count:0,phase:0,started_at:new Date().toISOString(),finished_at:null,error:'',log_path:''};renderStatus();renderAll();await refresh(true);
  }catch(exc){error(exc.message);}finally{starting=false;if(snapshot)renderStatus();else{$('start').disabled=false;$('demo').disabled=false;$('scan-state').dataset.state='idle';$('status').textContent='진단 대기';}}
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
$('stop').addEventListener('click',async()=>{try{$('stop').disabled=true;await post('/api/scan/stop');await refresh(true);}catch(exc){error(exc.message);}finally{$('stop').disabled=false;}});
$('search').addEventListener('input',renderFindings);$('severity').addEventListener('change',renderFindings);$('endpoint-search').addEventListener('input',renderEndpoints);
$('go-save').addEventListener('click',()=>setView('save'));for(const b of document.querySelectorAll('[data-view]'))b.addEventListener('click',()=>setView(b.dataset.view));
$('close-detail').addEventListener('click',()=>$('finding-dialog').close());$('finding-dialog').addEventListener('close',()=>{selected=null;});
$('finding-dialog').addEventListener('click',event=>{if(event.target===$('finding-dialog')){const rect=$('finding-dialog').getBoundingClientRect();if(event.clientX<rect.left||event.clientX>rect.right||event.clientY<rect.top||event.clientY>rect.bottom)$('finding-dialog').close();}});
$('export-form').addEventListener('submit',saveSelected);
$('shutdown').addEventListener('click',async()=>{try{await post('/api/app/shutdown');shuttingDown=true;$('status').textContent='앱 종료';for(const b of document.querySelectorAll('button'))b.disabled=true;}catch(exc){error(exc.message);}});
window.addEventListener('hashchange',()=>setView(location.hash.slice(1),false));let resizeTimer;window.addEventListener('resize',()=>{clearTimeout(resizeTimer);resizeTimer=setTimeout(renderCharts,100);});
initExport();setView(location.hash.slice(1)||'overview',false);refresh(true);setInterval(()=>refresh(),700);setInterval(()=>{if(snapshot)$('elapsed').textContent=duration();},500);
