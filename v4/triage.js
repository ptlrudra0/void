// Void v4: triage workbench (batch, email, report export, history). Runs in the browser only.
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const defang=u=>u.replace(/^http/i,"hxxp").replace(/\./g,"[.]");
const FEAT={host_hyphens:v=>v+" hyphen"+(v==1?"":"s")+" in the domain name",susp_tokens:v=>v+" scam-style word"+(v==1?"":"s")+" (login, verify, secure, account...)",is_https:v=>v?null:"does not use HTTPS",path_length:v=>"long path ("+v+" characters)",query_length:v=>"long query string ("+v+" characters)",url_length:v=>"long link ("+v+" characters)",host_length:v=>"long domain name ("+v+" characters)",subdomain_count:v=>v+" subdomain level"+(v==1?"":"s"),has_ip:v=>v?"raw IP address instead of a domain name":null,at_count:v=>v?"contains an @ sign (can hide the real destination)":null,host_digits:v=>v+" digits in the domain name",digit_ratio:v=>"many digits in the link",host_entropy:v=>"random-looking domain name",punycode:v=>v?"punycode (look-alike characters)":null,has_hex_enc:v=>v?"hex-encoded characters (%xx)":null,special_ratio:v=>"many special characters",dot_count:v=>v+" dots in the link",slash_count:v=>v+" slashes (deep path)",longest_token:v=>"very long unbroken word ("+v+" characters)",double_slash_path:v=>v?"extra // inside the path":null,has_port:v=>v?"non-standard port":null,query_params:v=>null};
function whyFlagged(r){
 const z=r._x.map((v,i)=>(v-M.mean[i])/M.scale[i]);
 const c=z.map((v,i)=>({n:M.features[i],c:v*M.lr.w[i],v:r._x[i]})).filter(o=>o.c>0.35&&FEAT[o.n]).sort((a,b)=>b.c-a.c);
 const out=[];for(const o of c){const t=FEAT[o.n](o.v);if(t)out.push(t);if(out.length>=4)break}return out;
}
function analyze(u){
 const r=predict(M,u);const names=Object.keys(r).filter(k=>k[0]!=="_");
 const avg=names.reduce((s,k)=>s+r[k],0)/names.length;const votes=names.filter(k=>r[k]>=0.5).length;
 const tr=trusted(u),host=hostOf(u);const la=tr?null:lookalike(host);
 const blSnap=!tr&&BL?blocklisted(BL,host):false;const blLive=!tr&&OP?(OP.urls.has(nurl(u))||OP.hosts.has(host)):false;
 const reasons=[];let tier,verdict;
 if(tr){tier="Low";verdict="trusted domain";reasons.push("on the trusted list: "+tr.domain+" ("+tr.kind+")")}
 else if(blLive||blSnap){tier="High";verdict="known phishing";reasons.push((blLive?"listed in the live OpenPhish feed":"listed in the saved Phishing.Database snapshot"))}
 else if(avg>=0.8){tier="High";verdict="phishing"}
 else if(avg>=0.5){tier="Medium";verdict="phishing"}
 else if(avg>=0.4||la){tier="Medium";verdict=la&&avg<0.5?"suspicious":"uncertain"}
 else{tier="Low";verdict="looks safe"}
 if(la)reasons.push("look-alike: "+host+" "+la.why);
 if(!tr)for(const t of whyFlagged(r))reasons.push(t);
 return {url:u,host,score:avg,votes,tier,verdict,reasons,blocklisted:!!(blLive||blSnap),lookalike:la?la.why:""};
}
function tierHtml(a){
 const why=a.reasons.length?"<ul>"+a.reasons.map(x=>"<li>"+esc(x)+"</li>").join("")+"</ul>":"<div>No single signal stands out.</div>";
 return '<div class="sig"><div class="sh">Risk tier: <span class="flag">'+a.tier.toUpperCase()+'</span> '+a.votes+' of 6 models say phishing</div><div class="srow"><span class="st">Why</span>'+why+'</div></div>';
}
// ---------- history (device only) ----------
const HK="void_history_v4";
function histGet(){try{return JSON.parse(localStorage.getItem(HK)||"[]")}catch(e){return[]}}
function histAdd(items){try{const h=items.map(a=>({t:new Date().toISOString(),u:defang(a.url).slice(0,120),tier:a.tier,s:+a.score.toFixed(3)})).concat(histGet()).slice(0,60);localStorage.setItem(HK,JSON.stringify(h))}catch(e){}histShow()}
function histShow(){const el=document.getElementById("hist");if(!el)return;const h=histGet();el.innerHTML=h.length?h.slice(0,12).map(x=>'<div class="hrow"><b>'+x.tier+'</b> '+(x.s*100).toFixed(0)+'% <code>'+esc(x.u)+'</code></div>').join(""):'<div class="hrow">No scans yet.</div>'}
function histClear(){try{localStorage.removeItem(HK)}catch(e){}histShow()}
// ---------- batch & email ----------
let LAST=null;
const TIERORD={High:0,Medium:1,Low:2};
function extractUrls(t){const m=t.match(/(?:https?:\/\/|hxxps?:\/\/)[^\s<>"')\]]+/gi)||[];return [...new Set(m.map(x=>x.replace(/^hxxp/i,"http").replace(/\[\.\]/g,".").replace(/[.,;]+$/,"")))]}
function batchBare(t){return t.split(/\s+/).map(x=>x.trim()).filter(x=>/^[a-z0-9.-]+\.[a-z]{2,}(\/\S*)?$/i.test(x)||/^https?:\/\//i.test(x))}
function dom(a){const m=(a||"").match(/@([A-Za-z0-9.-]+)/);return m?m[1].toLowerCase():""}
function emailChecks(t){
 const f=[];const hdr=t.split(/\r?\n\r?\n/)[0];const get=n=>{const m=hdr.match(new RegExp("^"+n+":\\s*(.+(?:\\r?\\n[ \\t].+)*)","im"));return m?m[1].replace(/\s+/g," ").trim():""};
 const from=get("From"),rt=get("Reply-To"),ret=get("Return-Path"),auth=get("Authentication-Results")+" "+get("Received-SPF");
 const fd=dom(from);const hasHdr=!!from;
 if(!hasHdr)return {flags:[{t:"No email headers found, so sender checks were skipped. Paste the full message with its headers (From, Reply-To) for those.",sev:0}],hdr:false};
 const rd=dom(rt),td=dom(ret);
 if(rd&&fd&&regDomain(rd)!==regDomain(fd))f.push({t:"Reply-To domain ("+rd+") differs from the From domain ("+fd+"). Replies would go somewhere else.",sev:2});
 if(td&&fd&&regDomain(td)!==regDomain(fd))f.push({t:"Return-Path domain ("+td+") differs from the From domain ("+fd+"). Can be normal for mailing services.",sev:1});
 const disp=from.replace(/<.*$/,"").replace(/["']/g,"").toLowerCase();
 for(const b of Object.keys(BRANDS)){if(b.length>=4&&disp.includes(b)&&fd&&!BRANDS[b].some(d=>fd===d||fd.endsWith("."+d))){f.push({t:"Display name mentions \""+b+"\" but the sender domain is "+fd+", not a "+b+" domain.",sev:2});break}}
 const la=fd&&lookalike(fd);if(la)f.push({t:"Sender domain "+fd+" "+la.why+".",sev:2});
 if(/(spf|dkim|dmarc)\s*=\s*(fail|softfail|none|permerror)/i.test(auth))f.push({t:"Authentication results show a failure: "+(auth.match(/(spf|dkim|dmarc)\s*=\s*(fail|softfail|none|permerror)/i)||[""])[0]+".",sev:2});
 const body=t.slice(hdr.length);
 const urg=(body.toLowerCase().match(/urgent|immediately|within 24 hours|account (?:will be )?(?:suspended|locked|closed)|verify your|confirm your|unusual activity|password expires|final notice/g)||[]);
 if(urg.length>=2)f.push({t:"Pressure language ("+[...new Set(urg)].slice(0,4).join(", ")+").",sev:1});
 if(/\.(html?|exe|scr|iso|zip|js|vbs|lnk)\b/i.test(t.replace(/https?:\/\/\S+/g,"")))f.push({t:"Mentions an attachment type often used to deliver malware or fake login pages (.html, .zip, .exe...).",sev:1});
 const hrefs=[...t.matchAll(/<a[^>]+href=["']([^"']+)["'][^>]*>([^<]+)<\/a>/gi)];
 for(const m of hrefs){const vis=m[2].trim();if(/^(https?:\/\/|www\.)/i.test(vis)){const a=hostOf(vis),b=hostOf(m[1]);if(a&&b&&regDomain(a)!==regDomain(b)){f.push({t:"Link text shows "+a+" but the link goes to "+b+".",sev:2});break}}}
 return {flags:f,hdr:true,from:fd};
}
function runTriage(mode){
 const ta=document.getElementById("tri-in");const txt=ta.value;if(!txt.trim()){document.getElementById("tri-out").innerHTML='<div class="cap">Paste something first.</div>';return}
 let urls,email=null;
 if(mode==="email"){urls=extractUrls(txt);email=emailChecks(txt)}else{urls=[...new Set([...extractUrls(txt),...batchBare(txt).filter(x=>!/^https?:\/\//i.test(x)).map(x=>"http://"+x)])]}
 const cut=urls.length>500;urls=urls.slice(0,500);
 const items=urls.map(analyze).sort((a,b)=>TIERORD[a.tier]-TIERORD[b.tier]||b.score-a.score);
 const n={High:0,Medium:0,Low:0};items.forEach(a=>n[a.tier]++);
 let etier=null;if(email){const hs=email.flags.reduce((s,x)=>s+x.sev,0);etier=(n.High>0||hs>=3)?"High":(n.Medium>0||hs>=1)?"Medium":"Low"}
 LAST={mode,items,email,etier,n,cut};
 let h="";
 if(email){h+='<div class="rep"><div class="sh">Email verdict: <span class="flag">'+etier.toUpperCase()+'</span></div><div class="cap" style="margin:4px 0 8px">Header and wording checks are simple rules and are not measured. Link checks use the models.</div>'+(email.flags.length?"<ul>"+email.flags.map(x=>"<li>"+esc(x.t)+"</li>").join("")+"</ul>":"<div>No sender or wording problems found.</div>")+"</div>"}
 h+='<div class="rep"><div class="sh">'+items.length+' link'+(items.length==1?"":"s")+' scanned: '+n.High+' high, '+n.Medium+' medium, '+n.Low+' low'+(cut?" (first 500 only)":"")+'</div></div>';
 if(items.length){h+='<div class="tbl"><table><caption class="cap">Sorted by risk. Links are shown defanged (hxxp, [.]) so they cannot be clicked by accident.</caption><tr><th>Tier</th><th>Score</th><th>Link</th><th>Why</th></tr>'+items.map(a=>'<tr><td><b>'+a.tier+'</b></td><td>'+(a.score*100).toFixed(0)+'%</td><td class="lk">'+esc(defang(a.url).slice(0,90))+'</td><td class="wy">'+esc(a.reasons.join("; ")||"-")+'</td></tr>').join("")+"</table></div>";
  h+='<div class="btns"><button onclick="exportCSV()">Download CSV</button><button onclick="exportJSON()">Download JSON report</button><button onclick="copyReport()">Copy incident summary</button></div><div id="tri-msg" class="cap"></div>'}
 else h+='<div class="cap">No links found.</div>';
 document.getElementById("tri-out").innerHTML=h;histAdd(items);
}
function dl(name,mime,text){const b=new Blob([text],{type:mime});const a=document.createElement("a");a.href=URL.createObjectURL(b);a.download=name;document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove()},500)}
function csvq(s){return '"'+String(s).replace(/"/g,'""')+'"'}
function exportCSV(){if(!LAST)return;const rows=[["tier","score_percent","models_saying_phishing","verdict","url_defanged","reasons"].join(",")].concat(LAST.items.map(a=>[a.tier,(a.score*100).toFixed(1),a.votes,a.verdict,csvq(defang(a.url)),csvq(a.reasons.join("; "))].join(",")));dl("void-triage.csv","text/csv",rows.join("\n"));msg("CSV downloaded.")}
function report(){const X=M.results.results.domain.metrics.XGBoost;return {tool:"void",version:"v4",generated_at:new Date().toISOString(),mode:LAST.mode,summary:{links:LAST.items.length,high:LAST.n.High,medium:LAST.n.Medium,low:LAST.n.Low,email_tier:LAST.etier},email_findings:LAST.email?LAST.email.flags.map(x=>x.t):undefined,items:LAST.items.map(a=>({url_defanged:defang(a.url),tier:a.tier,score:+a.score.toFixed(4),models_saying_phishing:a.votes,verdict:a.verdict,reasons:a.reasons})),method:{models:["Logistic Regression","Decision Tree","Random Forest","SVM (linear)","Neural Net (MLP)","XGBoost"],features:29,note:"URL text only; the page was never opened",blocklist_snapshot:BL?{domains:BL.n,date:BL.date}:null,xgboost_unseen_domain_test:{accuracy:+X.accuracy.toFixed(3),auc:+X.roc_auc.toFixed(3)}},limits:"Student prototype. Scores are estimates, not proof. Verify before blocking or reporting."}}
function exportJSON(){if(!LAST)return;dl("void-report.json","application/json",JSON.stringify(report(),null,2));msg("JSON report downloaded.")}
function summaryText(){const L=LAST;let t="Void triage summary ("+new Date().toISOString().slice(0,16).replace("T"," ")+" UTC)\n";if(L.email)t+="Email verdict: "+L.etier+"\n"+(L.email.flags.map(x=>"- "+x.t).join("\n")||"- no sender or wording problems found")+"\n";t+="Links scanned: "+L.items.length+" (high "+L.n.High+", medium "+L.n.Medium+", low "+L.n.Low+")\n";L.items.filter(a=>a.tier!=="Low").slice(0,10).forEach(a=>{t+="- ["+a.tier+"] "+defang(a.url).slice(0,100)+" ("+(a.score*100).toFixed(0)+"%) "+(a.reasons[0]?"- "+a.reasons[0]:"")+"\n"});t+="Method: 6 ML models on URL text, blocklist snapshot, look-alike rules. Estimates, not proof.";return t}
function msg(t){const e=document.getElementById("tri-msg");if(e)e.textContent=t}
function copyReport(){if(!LAST)return;const t=summaryText();const done=()=>msg("Summary copied. Paste it into your ticket or chat.");if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(t).then(done,()=>fb(t,done));else fb(t,done)}
function fb(t,done){const a=document.createElement("textarea");a.value=t;document.body.appendChild(a);a.select();try{document.execCommand("copy");done()}catch(e){msg("Copy failed. Select the text manually.")}a.remove()}
function fillSample(kind){const ta=document.getElementById("tri-in");if(kind==="email")ta.value='From: "PayPal Support" <service@paypa1-secure.top>\nReply-To: helpdesk@mail-center.xyz\nReturn-Path: <bounce@mail-center.xyz>\nSubject: Urgent: your account will be suspended\nAuthentication-Results: mx.example.com; spf=fail; dkim=none\n\nDear customer, we noticed unusual activity. Verify your account immediately or your account will be suspended within 24 hours.\nhttp://paypal-secure-login.verify-account.xyz/signin\nhttps://www.wikipedia.org/wiki/Phishing\n';else ta.value="http://paypal-secure-login.verify-account.xyz/signin\nhttps://www.wikipedia.org/wiki/Phishing\nhttps://support.charusat.edu.in/egov/home.aspx\nhttps://paypall.com/login\nhttp://192.168.4.5/secure/login.php\nhttps://docs.python.org/3/library/re.html"}
document.addEventListener("DOMContentLoaded",histShow);
if("serviceWorker"in navigator)window.addEventListener("load",()=>navigator.serviceWorker.register("sw.js").catch(()=>{}));
