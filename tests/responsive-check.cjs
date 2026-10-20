const pw=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const fs=require('fs'),crypto=require('crypto');
const base=process.env.POSTMARK_URL||'http://127.0.0.1:18766';
fs.mkdirSync('work/browser',{recursive:true});
const digest=f=>crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
(async()=>{
const browser=await pw.chromium.launch({headless:true,executablePath:process.env.PW_CHROME||undefined}),page=await browser.newPage({acceptDownloads:true});
const runs=[],errors=[],external=[];page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{if(!r.url().startsWith(base))external.push(r.url());});
const check=(c,m)=>{if(!c)throw Error(m);};
const ready=async()=>page.waitForFunction(()=>{const b=document.querySelector('#analyze');return !b.disabled&&b.textContent==='Inspect this email';});
const overflow=async()=>page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth+1);
const capture=async(name)=>{const path='work/browser/responsive-'+name+'.png';await page.screenshot({path,fullPage:true});return path;};
const sizes=[[320,850],[390,844],[759,900],[760,900],[761,900],[768,1024],[999,900],[1000,900],[1001,900],[1024,900],[1440,1080],[1920,1080],[844,390]];
for(const [width,height] of sizes){
 await page.setViewportSize({width,height});await page.goto(base);await page.locator('[data-sample="0"]').waitFor();
 check(!await overflow(),'Empty overflow at '+width);const empty=await capture(width+'x'+height+'-empty');
 const target=await page.locator('#analyze').boundingBox();check(target.height>=44,'Primary hit area below 44px');
 await page.locator('[data-sample="0"]').click();await ready();await page.getByRole('heading',{name:'High concern',exact:true}).waitFor();
 check(!await overflow(),'Result overflow at '+width);const result=await capture(width+'x'+height+'-result');
 runs.push({viewport:{width,height},states:['empty','populated'],outcome:'passed',method:'Chromium CSS viewport emulation; full-page screenshots and page-overflow/hit-area checks',screenshots:[empty,result]});
}
await page.setViewportSize({width:390,height:844});await page.goto(base);await page.locator('[data-sample="0"]').waitFor();
const longName='synthetic-inspection-'+('long-filename-'.repeat(10))+'.eml';
const domain='long-subdomain-'.repeat(6)+'example.org';
const raw='Subject: '+('Long evidence subject '.repeat(12))+'\nContent-Type: text/plain\n\n'+Array.from({length:100},(_,i)=>'https://'+domain+'/'+('segment'.repeat(10))+'/'+i).join('\n');
await page.locator('#file').setInputFiles({name:longName,mimeType:'message/rfc822',buffer:Buffer.from(raw)});await ready();await page.locator('#analyze').click();await ready();
check(!await overflow(),'Long content result overflow');await page.getByRole('tab',{name:'Links (100)',exact:true}).click();
check(!await overflow(),'Long links overflow');check(await page.locator('.link-row').count()===100,'Large link set missing');
await page.locator('.link-row').last().scrollIntoViewIfNeeded();check(await page.locator('.link-row').last().isVisible(),'End of link list unreachable');
runs.push({viewport:{width:390,height:844},states:['long subject','long filename','long domain','100 link entries','missing optional From header'],outcome:'passed',screenshot:await capture('390-long-content')});
await page.locator('#source-panel > summary').click();await page.locator('#raw').fill('Subject: No link example\n\nAn ordinary note.');await page.locator('#analyze').click();await ready();await page.getByRole('tab',{name:'Links (0)',exact:true}).click();
await page.getByText('No links found in inspected text.',{exact:true}).waitFor();runs.push({viewport:{width:390,height:844},states:['no-match','missing optional headers'],outcome:'passed',screenshot:await capture('390-no-links')});
// Simulated failed request and retry preserve the user's source and block stale exports.
await page.locator('#source-panel > summary').click();const kept=await page.locator('#raw').inputValue();
await page.route('**/api/analyze',route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:'Temporary local failure. Try again.'})}),{times:1});
await page.locator('#analyze').click();await ready();await page.getByRole('alert').filter({hasText:'Temporary local failure'}).waitFor();
check(await page.locator('#raw').inputValue()===kept,'Failed request discarded draft');
check(await page.locator('#export-report').isDisabled(),'Failed request allowed an old export');
runs.push({viewport:{width:390,height:844},states:['failed request'],outcome:'passed',screenshot:await capture('390-failed-request')});
await page.locator('#analyze').click();await ready();check(!await page.locator('#export-report').isDisabled(),'Retry did not restore current export');
runs.push({viewport:{width:390,height:844},states:['retry'],outcome:'passed'});
// Delay a request to capture genuine loading UI and prove repeated click cannot duplicate it.
await page.locator('#source-panel > summary').click();let release,entered,count=0;const gate=new Promise(r=>release=r),seen=new Promise(r=>entered=r);
await page.route('**/api/analyze',async route=>{count++;const response=await route.fetch();entered();await gate;await route.fulfill({response});},{times:1});
await page.locator('#analyze').click();await seen;check(await page.locator('#analyze').isDisabled(),'Pending submit not disabled');check(await page.locator('#export-report').isDisabled(),'Pending export not disabled');
await page.locator('#analyze').evaluate(el=>el.click());check(count===1,'Repeated submit duplicated request');
runs.push({viewport:{width:390,height:844},states:['loading','repeated submit'],outcome:'passed',screenshot:await capture('390-loading')});release();await ready();
// Keyboard-only first inspection: Tab through actual controls, type source and activate submit.
await page.setViewportSize({width:1440,height:1080});await page.goto(base);await page.locator('[data-sample="0"]').waitFor();
let reached=false;for(let i=0;i<30;i++){await page.keyboard.press('Tab');if(await page.evaluate(()=>document.activeElement.id==='raw')){reached=true;break;}}
check(reached,'Textarea unreachable by keyboard');await page.keyboard.type('Subject: Keyboard example\n\nA note.');await page.keyboard.press('Tab');check(await page.evaluate(()=>document.activeElement.id==='analyze'),'Submit not next keyboard control');await page.keyboard.press('Enter');await ready();await page.getByRole('heading',{name:'Keyboard example',exact:true}).waitFor();
runs.push({viewport:{width:1440,height:1080},states:['keyboard-only inspection'],outcome:'passed',screenshot:await capture('keyboard')});
await page.emulateMedia({reducedMotion:'reduce'});check(await page.evaluate(()=>matchMedia('(prefers-reduced-motion: reduce)').matches),'Reduced motion not active');check(await page.evaluate(()=>document.getAnimations().length===0),'Unexpected motion');runs.push({method:'Chromium prefers-reduced-motion=reduce; no active animations',outcome:'passed'});
// Explicit text enlargement: snapshot computed sizes and double each element size, rather than shrinking layout.
for(const width of [320,390,1440]){
 await page.setViewportSize({width,height:1000});await page.goto(base);await page.locator('[data-sample="0"]').waitFor();await page.locator('[data-sample="0"]').click();await ready();
 await page.evaluate(()=>{const rows=[...document.querySelectorAll('body,body *')].map(el=>[el,parseFloat(getComputedStyle(el).fontSize)]);rows.forEach(([el,size])=>{el.style.fontSize=(size*2)+'px';el.style.fontFamily=el.matches('code,textarea')?'monospace':'Arial,sans-serif';});});
 check(!await overflow(),'200% text overflow at '+width);const primary=await page.locator('#export-report').boundingBox();check(primary.height>=44,'Enlarged text control below 44px');for(const selector of ['nav','.report-actions','.assessment','.finding-head','.report-tabs']){check(await page.locator(selector).evaluateAll(els=>els.every(el=>el.scrollWidth<=el.clientWidth+1)),'Text clipped inside '+selector+' at '+width);}
 runs.push({viewport:{width,height:1000},method:'200% text enlargement by doubling snapshotted computed font sizes for every element, combined with Arial/monospace fallback; not browser zoom',states:['populated','enlarged text'],outcome:'passed',screenshot:await capture(width+'-text200')});
}
for(const view of ['inspect','evaluation','monitor']){
 await page.setViewportSize({width:320,height:1000});await page.goto(base);await page.locator('[data-sample="0"]').waitFor();
 if(view!=='inspect'){await page.locator('[data-view="'+view+'"]').click();await page.waitForFunction(v=>document.querySelector('#'+v+' .content-panel').textContent.trim()&&!document.querySelector('#'+v+' .content-panel').textContent.includes('Loading'),view);}
 await page.evaluate(()=>{const rows=[...document.querySelectorAll('body,body *')].map(el=>[el,parseFloat(getComputedStyle(el).fontSize)]);rows.forEach(([el,size])=>{el.style.fontSize=size*2+'px';el.style.fontFamily=el.matches('code,textarea')?'monospace':'Arial,sans-serif';});});
 check(!await overflow(),'200% text '+view+' overflow at 320');
 for(const selector of ['nav','.toolbar'])check(await page.locator(selector+':visible').evaluateAll(els=>els.every(el=>el.scrollWidth<=el.clientWidth+1)),'200% text controls clipped in '+view);
 runs.push({viewport:{width:320,height:1000},states:[view==='inspect'?'empty':view,'enlarged text','fallback fonts'],method:'200% snapshotted computed text with Arial/monospace fallback',outcome:'passed',screenshot:await capture('320-text200-'+view)});
}
await page.setViewportSize({width:390,height:844});await page.goto(base);await page.locator('[data-sample="0"]').waitFor();await page.locator('[data-sample="0"]').click();await ready();
await page.evaluate(()=>document.querySelectorAll('body,body *').forEach(el=>el.style.fontFamily=el.matches('code,textarea')?'monospace':'Arial,sans-serif'));check(!await overflow(),'Fallback font overflow');
runs.push({viewport:{width:390,height:844},method:'Forced local Arial/sans-serif and monospace fallbacks; no font downloads',states:['fallback fonts'],outcome:'passed',screenshot:await capture('390-fallback-font')});
await page.setViewportSize({width:1024,height:900});await page.emulateMedia({media:'print'});
runs.push({method:'Chromium print media screenshot of current view; complete export is JSON, browser print is not a complete report',states:['print current view'],outcome:'inspected-limited',screenshot:await capture('print-current-view')});
const engines={};for(const name of ['firefox','webkit']){
 const installed=fs.existsSync(pw[name].executablePath());engines[name]={installed,tested:false};
 if(!installed)continue;
 const secondary=await pw[name].launch({headless:true}),tab=await secondary.newPage({acceptDownloads:true});
 tab.on('pageerror',e=>errors.push(name+': '+e.message));tab.on('request',r=>{if(!r.url().startsWith(base))external.push(r.url());});
 for(const width of [390,1440]){
  await tab.setViewportSize({width,height:900});await tab.goto(base);await tab.locator('[data-sample="0"]').waitFor();
  check(await tab.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),name+' empty overflow');
  await tab.locator('[data-sample="0"]').click();await tab.getByRole('heading',{name:'High concern',exact:true}).waitFor();await tab.waitForFunction(()=>!document.querySelector('#export-report').disabled);
  check(await tab.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),name+' result overflow');
  const download=tab.waitForEvent('download');await tab.locator('#export-report').click();const out=await download;check(out.suggestedFilename().endsWith('.json'),name+' export missing');
  const screenshot='work/browser/responsive-'+name+'-'+width+'.png';await tab.screenshot({path:screenshot,fullPage:true});
  if(width<761)await tab.locator('#source-panel > summary').click();await tab.locator('#raw').fill('not an email');await tab.locator('#analyze').click();await tab.getByRole('alert').waitFor();
  check(await tab.locator('#raw').inputValue()==='not an email',name+' error discarded draft');check(await tab.locator('#export-report').isDisabled(),name+' stale export enabled');
  runs.push({browser:name+' '+secondary.version(),viewport:{width,height:900},states:['empty','populated','JSON download','invalid input','draft retention','stale export disabled'],outcome:'passed',screenshot});
 }
 engines[name].tested=true;engines[name].version=secondary.version();await secondary.close();
}
check(errors.length===0,'Browser exceptions: '+errors.join(';'));check(external.length===0,'External requests in responsive test');
const sources=['static/index.html','static/style.css','static/app.js','tests/responsive-check.cjs'];
const report={timestamp:new Date().toISOString(),browser:'Chromium '+browser.version(),platform:process.platform,methods:'CSS viewport emulation; DOM assertions; screenshot capture. Physical devices were not used.',runs,source_sha256:Object.fromEntries(sources.map(f=>[f,digest(f)])),errors,external_requests:external,other_engines:engines,untested:['Physical phones/tablets and touch hardware','Screen reader software and formal WCAG audit','Native browser zoom; computed text-size enlargement used instead','Live provider accounts and real email outcomes','Complete browser-print report: JSON is the complete report export']};
fs.writeFileSync('work/browser/responsive-verification.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({runs:runs.length,engines,errors,external_requests:external},null,2));await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
