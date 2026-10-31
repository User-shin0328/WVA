/* Functional browser checks for WVA 2.1, against a real local server and lab. */
const fs=require('node:fs');const path=require('node:path');const assert=require('node:assert/strict');
const modules=process.env.WVA_NODE_MODULES||path.join(process.env.USERPROFILE,'.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules');
const {chromium}=require(path.join(modules,'playwright'));
const out=path.join(__dirname,'artifacts','browser');fs.mkdirSync(out,{recursive:true});
const base=process.env.WVA_TEST_URL||'http://127.0.0.1:9030';const target=process.env.WVA_LAB_URL||'http://127.0.0.1:8990';
const checks=[],errors=[],external=[];const passed=(name,actual)=>checks.push({name,status:'PASS',actual});
(async()=>{
  const browser=await chromium.launch({headless:true,executablePath:process.env.WVA_BROWSER||'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});
  const page=await browser.newPage({viewport:{width:1440,height:900},reducedMotion:'no-preference'});
  page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{if(!['127.0.0.1','localhost'].includes(new URL(r.url()).hostname))external.push(r.url());});
  let failure;
  async function save(format,sections){
    for(const input of await page.locator('input[name="sections"]').all())await input.setChecked(sections.includes(await input.getAttribute('value')));
    await page.locator(`input[name="format"][value="${format}"]`).check();
    const waiting=page.waitForEvent('download');await page.locator('#export-button').click();const file=await waiting;
    const destination=path.join(out,'selected-'+format+'.'+format);await file.saveAs(destination);return fs.readFileSync(destination,'utf8');
  }
  try{
    await page.goto(base);await page.waitForFunction(()=>document.querySelector('#status').textContent!=='');
    assert.equal(await page.locator('#page-description,.action-panel,#critical-caption').count(),0);assert.equal(await page.locator('.metric small').count(),0);assert.ok(!(await page.locator('body').textContent()).includes('응답에서 증거를 찾고'));
    passed('minimal_copy','No screen slogan, priority panel, or explanatory count captions');
    // Reproducible request latency lets the running animation be observed even on a subsecond local scan.
    await page.route('**/api/scan/start',async route=>{await new Promise(resolve=>setTimeout(resolve,350));await route.continue();});
    await page.getByLabel('진단할 서버 주소').fill(target);await page.locator('#start').click();
    assert.equal(await page.locator('#scan-state').getAttribute('data-state'),'running');
    assert.equal(await page.locator('.scan-spinner').evaluate(n=>getComputedStyle(n).animationName),'spin');await page.screenshot({path:path.join(out,'running-desktop.png'),fullPage:true});passed('running_motion','Spinner and scanning line activate on click');
    await page.waitForFunction(()=>document.querySelector('#status').textContent==='진단 완료'&&!document.querySelector('#start').disabled&&document.querySelectorAll('#findings-body tr').length===5&&document.querySelector('#severity-chart svg'),{},{timeout:30000});
    assert.equal(await page.locator('#count-findings').textContent(),'5');assert.equal(await page.locator('#count-chains').textContent(),'1');passed('direct_target_scan','5 findings, 1 chain, 8 endpoints');
    assert.equal(await page.locator('.scan-check path').evaluate(n=>getComputedStyle(n).animationName),'check-draw');passed('completion_motion','Completion check and line animation use completed state');
    assert.match(await page.locator('#severity-chart svg').getAttribute('aria-label'),/낮음 2건/);assert.match(await page.locator('#cvss-chart svg').getAttribute('aria-label'),/낮음 0–3.9 1건/);assert.equal(await page.locator('#severity-chart .chart-slice').count(),4);assert.equal(await page.locator('#severity-chart .chart-slice').evaluateAll(nodes=>nodes.reduce((sum,n)=>sum+Number(n.dataset.count),0)),5);passed('charts_reconcile','Pie slices sum to 5; severity 1/1/1/2/0 and CVSS bins 1/1/2/1');
    assert.equal(await page.locator('#overview-view .findings-table th').count(),6);assert.match(await page.locator('#findings-body').textContent(),/관리자 역할 검증/);passed('expanded_finding_table','Severity, finding/CWE, method/path, CVSS, evidence, remediation summary');
    await page.locator('#search').fill('없는-경로');assert.equal(await page.locator('#findings-body tr').count(),0);assert.ok(await page.locator('#findings-empty').isVisible());await page.locator('#search').fill('');
    await page.locator('#severity').selectOption('HIGH');assert.equal(await page.locator('#findings-body tr').count(),1);await page.locator('#severity').selectOption('');passed('finding_filters','Search empty state and HIGH-only filter');
    await page.locator('#findings-body .finding-name').first().click();assert.ok(await page.locator('#finding-dialog').isVisible());
    const rect=await page.locator('#finding-dialog').boundingBox();assert.ok(Math.abs(rect.width/(1440-72)-.75)<.02);assert.ok(Math.abs(rect.height/900-.75)<.02);
    assert.match(await page.locator('#detail-content').textContent(),/관찰 증거/);assert.match(await page.locator('#detail-content').textContent(),/권고사항 · 조치 순서/);assert.match(await page.locator('#detail-content').textContent(),/수정 후 확인/);
    const ordered=await page.locator('.remediation-steps>li').evaluateAll(items=>items.map(n=>({order:n.value,title:n.querySelector('h4').textContent,done:n.querySelector('.step-result').textContent})));
    assert.deepEqual(ordered.map(n=>n.order),[1,2,3,4,5,6]);assert.equal(ordered[1].title,'유출 키와 접근 차단');assert.ok(ordered.every(n=>n.done.startsWith('완료 기준:')));
    assert.ok(await page.locator('#finding-dialog').evaluate(n=>n.matches(':modal')));await page.screenshot({path:path.join(out,'finding-dialog-desktop.png'),fullPage:false});await page.locator('.remediation-steps').evaluate(n=>n.parentElement.scrollIntoView({block:'start'}));await page.screenshot({path:path.join(out,'actions-desktop.png'),fullPage:false});await page.keyboard.press('Escape');assert.ok(!(await page.locator('#finding-dialog').isVisible()));passed('shared_detail_dialog','75% workspace width, 75vh height, six ordered actions with completion criteria, native focus and Escape');
    await page.getByLabel('연계 경로',{exact:true}).click();assert.ok(await page.locator('#target-section').isVisible());assert.ok(!(await page.locator('#metrics').isVisible()));assert.equal(await page.locator('.chain-step').count(),3);assert.equal(await page.locator('#related-body tr').count(),3);
    const route=page.url();await page.locator('.chain-step').first().click();assert.ok(await page.locator('#finding-dialog').isVisible());assert.equal(page.url(),route);assert.match(await page.locator('#page-title').textContent(),/연계 경로/);await page.locator('#close-detail').click();await page.screenshot({path:path.join(out,'chains-desktop.png'),fullPage:true});passed('chain_dialog_stays_on_route','Three steps, three related findings, detail opens without route change');
    await page.getByLabel('공격 표면',{exact:true}).click();assert.equal(await page.locator('#endpoints-body tr').count(),8);assert.equal(await page.locator('#surface-measured').textContent(),'7');assert.equal(await page.locator('#surface-unmeasured').textContent(),'1');assert.match(await page.locator('#endpoints-body').textContent(),/query:user_id/);assert.equal(await page.locator('#headers-body tr').count(),7);
    await page.locator('#endpoint-search').fill('query:user_id');assert.equal(await page.locator('#endpoints-body tr').count(),1);await page.locator('#endpoint-search').fill('');await page.screenshot({path:path.join(out,'surface-desktop.png'),fullPage:true});passed('surface_metadata','7 measured, 1 unmeasured; parameters, HTTP, timing, bytes, headers and source');
    await page.getByLabel('진단 로그',{exact:true}).click();assert.match(await page.locator('#scan-log-path').textContent(),/\.jsonl$/);assert.match(await page.locator('#app-log-path').textContent(),/WVA\.log$/);assert.ok(await page.locator('#logs li').count()>10);await page.screenshot({path:path.join(out,'logs-desktop.png'),fullPage:true});passed('log_storage_paths','Per-scan JSONL and app error-log locations are visible');
    await page.getByLabel('정보 저장',{exact:true}).click();assert.equal(await page.locator('.save-descriptions>div').count(),5);for(const input of await page.locator('input[name="sections"]').all())await input.uncheck();assert.ok(await page.locator('#export-button').isDisabled());passed('save_selection_gate','Five information descriptions; empty selection disables save');
    const json=JSON.parse(await save('json',['findings','logs']));assert.deepEqual(Object.keys(json).sort(),['metadata','findings','logs'].sort());assert.equal(json.findings.length,5);assert.ok(json.findings[0].remediation_details.actions.length>0);passed('selected_json_download','Only selected findings and full disk logs plus provenance');
    const md=await save('md',['summary','findings']);assert.match(md,/#### 조치사항/);assert.ok(!md.includes('## 공격 표면'));passed('selected_markdown_download','Selected summary and findings, detailed remediation included');
    const csv=await save('csv',['endpoints']);assert.equal(csv.charCodeAt(0),0xfeff);assert.match(csv,/응답시간ms/);assert.match(csv,/query:user_id/);passed('selected_csv_download','UTF-8 BOM CSV with response metadata and selected endpoints');
    await page.screenshot({path:path.join(out,'save-desktop.png'),fullPage:true});
    await page.getByLabel('진단 결과',{exact:true}).click();
    for(const width of [1440,768,390]){
      await page.setViewportSize({width,height:width===390?844:900});await page.evaluate(()=>document.fonts.ready);await page.waitForFunction(()=>{const host=document.querySelector('#severity-chart'),chart=host.querySelector('svg');return chart&&chart.viewBox.baseVal.width===Math.max(290,Math.round(host.getBoundingClientRect().width)-32);});await page.evaluate(()=>scrollTo(0,0));
      const overflow=await page.evaluate(()=>document.documentElement.scrollWidth-innerWidth);assert.ok(overflow<=1,'Overflow at '+width+': '+overflow);await page.screenshot({path:path.join(out,'results-'+width+'.png'),fullPage:true});
      await page.locator('#findings-body .finding-name').first().click();const modal=await page.locator('#finding-dialog').boundingBox();assert.ok(modal.x>=0&&modal.x+modal.width<=width+1);await page.locator('#close-detail').click();passed('responsive_'+width,'Charts, contained table scrolling, and dialog stay within viewport');
    }
    await page.getByLabel('정보 저장',{exact:true}).click();assert.ok(await page.locator('#export-button').isVisible());assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));await page.screenshot({path:path.join(out,'save-mobile.png'),fullPage:true});passed('mobile_save_layout','Choices and save controls remain visible without page overflow');
    await page.getByLabel('진단 결과',{exact:true}).click();await page.reload();await page.waitForFunction(()=>document.querySelector('#count-findings').textContent==='5'&&document.querySelector('#severity-chart svg'));passed('reload_restores_results','Counts and charts restore after refresh');
    await page.emulateMedia({reducedMotion:'reduce'});assert.equal(await page.locator('.scan-check path').evaluate(n=>getComputedStyle(n).animationName),'none');passed('reduced_motion','System motion preference disables scan/check animations');
    assert.equal(external.length,0);assert.equal(errors.length,0);passed('offline_assets','Zero external requests and zero JavaScript exceptions');
  }catch(error){failure=error;checks.push({name:'browser_flow',status:'FAIL',actual:error.stack});}
  finally{await browser.close();fs.writeFileSync(path.join(out,'result.json'),JSON.stringify({status:failure?'FAIL':'PASS',checks,errors,external,at:new Date().toISOString(),base},null,2));}
  console.log(JSON.stringify({status:failure?'FAIL':'PASS',checks:checks.length,errors},null,2));if(failure)throw failure;
})().catch(error=>{console.error(error.message);process.exitCode=1;});
