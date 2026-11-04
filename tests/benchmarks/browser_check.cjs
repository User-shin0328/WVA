/* Ground truth only: runs a local marker in an isolated browser, never reads cookies. */
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const modules=process.env.WVA_NODE_MODULES||path.join(process.env.USERPROFILE,'.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules');
const {chromium}=require(path.join(modules,'playwright'));
const out=path.resolve(__dirname,'../artifacts/benchmark');fs.mkdirSync(out,{recursive:true});
(async()=>{
  const browser=await chromium.launch({headless:true,executablePath:process.env.WVA_BROWSER||'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});
  const checks=[],requests=[],blocked=[];let error;
  try{
    for(const [name,port,expected] of [['dvwa-low',18910,true],['dvwa-safe',18911,false],['juice-shop',18912,true]]){
      const context=await browser.newContext({serviceWorkers:'block'});
      const origin='http://127.0.0.1:'+port,marker='WVA_LOCAL_'+name.replaceAll('-','_');
      await context.route('**/*',route=>{
        const req=route.request(),url=new URL(req.url());
        if(url.origin===origin&&['GET','HEAD'].includes(req.method())){requests.push({name,url:req.url(),method:req.method()});return route.continue();}
        blocked.push({name,url:req.url(),method:req.method()});return route.abort();
      });
      const page=await context.newPage();
      let url=name==='juice-shop'
        ? origin+'/#/search?'+new URLSearchParams({q:`<iframe src="javascript:parent.__wvaXss='${marker}'"></iframe>`})
        : origin+'/vulnerabilities/xss_r/?'+new URLSearchParams({name:`<script>window.__wvaXss=${JSON.stringify(marker)}</script>`});
      if(name==='dvwa-safe'){
        await page.goto(origin+'/vulnerabilities/xss_r/',{waitUntil:'domcontentloaded'});
        const token=await page.locator('input[name="user_token"]').inputValue();
        assert.ok(token);url+='&'+new URLSearchParams({user_token:token});
      }
      const response=await page.goto(url,{waitUntil:'domcontentloaded',timeout:30000});
      assert.equal(response.status(),200);
      if(expected)await page.waitForFunction(value=>window.__wvaXss===value,marker,{timeout:15000});
      const actual=await page.evaluate(()=>window.__wvaXss??null);
      assert.equal(actual,expected?marker:null);
      const body=await page.locator('body').textContent();
      if(!expected)assert.ok(body.includes('<script>window.__wvaXss='));
      assert.ok(!body.includes('Undefined array key'),'Ground truth must use a valid CSRF session');
      if(name==='juice-shop'){
        const dismiss=page.getByRole('button',{name:'Dismiss',exact:true});if(await dismiss.isVisible())await dismiss.click();
      }
      await page.screenshot({path:path.join(out,name+'-xss.png'),fullPage:true});
      checks.push({name:name+(name==='juice-shop'?'_dom_xss_ground_truth':'_reflected_xss_ground_truth'),status:'PASS',expected_execution:expected,executed:actual!==null,marker:actual,url});
      await context.close();
    }
  }catch(e){error=e;}
  finally{await browser.close();fs.writeFileSync(path.join(out,'browser-ground-truth.json'),JSON.stringify({status:error?'FAIL':'PASS',checks,requests,blocked,error:error?.stack,at:new Date().toISOString()},null,2));}
  if(error)throw error;console.log(JSON.stringify({status:'PASS',checks:checks.length,blocked:blocked.length}));
})().catch(e=>{console.error(e);process.exitCode=1;});
