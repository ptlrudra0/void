const SUSP=["login","verify","secure","account","update","banking","signin","confirm","password","wallet","auth","credential","recover","webscr","billing","unlock","suspend","alert","support","paypal","free","bonus"];
function entropy(s){if(!s)return 0;const c={};for(const ch of s)c[ch]=(c[ch]||0)+1;const n=[...s].length;let h=0;for(const k in c){const p=c[k]/n;h-=p*Math.log2(p)}return h}
function cnt(s,ch){return s.split(ch).length-1}
function extract(raw){
 const u=raw.trim(),low=u.toLowerCase();
 const m=low.match(/^[a-z][a-z0-9+.\-]*:\/\//);
 const https=low.startsWith("https://")?1:0;
 const rest=m?low.slice(m[0].length):low;
 let i=rest.length;for(const ch of "/?#"){const j=rest.indexOf(ch);if(j!==-1&&j<i)i=j}
 let auth=rest.slice(0,i);const tail=rest.slice(i);
 if(auth.includes("@"))auth=auth.slice(auth.lastIndexOf("@")+1);
 let port=0;const pm=auth.match(/:(\d+)$/);if(pm){port=1;auth=auth.slice(0,pm.index)}
 const host=auth;
 const h=tail.indexOf("#");const pathq=h===-1?tail:tail.slice(0,h);
 const qi=pathq.indexOf("?");const path=qi===-1?pathq:pathq.slice(0,qi);const query=qi===-1?"":pathq.slice(qi+1);
 const parts=host?host.split("."):[];
 const isip=/^(\d{1,3}\.){3}\d{1,3}$/.test(host)?1:0;
 const tld=parts.length>1?parts[parts.length-1]:"";
 const sub=isip?0:Math.max(0,parts.length-2);
 const chars=[...low];const L=Math.max(1,[...u].length);
 const digits=chars.filter(c=>c>="0"&&c<="9").length,letters=chars.filter(c=>c>="a"&&c<="z").length,special=chars.filter(c=>!/[\p{L}\p{N}]/u.test(c)).length;
 const toks=low.split(/[^a-z0-9]+/).filter(Boolean);
 const susp=SUSP.filter(t=>low.includes(t)).length;
 return [[...u].length,[...host].length,[...path].length,[...query].length,cnt(low,"."),sub,cnt(host,"-"),[...host].filter(c=>c>="0"&&c<="9").length,cnt(low,"@"),cnt(low,"?"),cnt(low,"="),cnt(low,"&"),cnt(path,"/"),digits/L,letters/L,special/L,entropy(host),isip,https,susp,[...tld].length,port,cnt(path,"."),cnt(host,"."),Math.max(0,...toks.map(t=>t.length)),query?cnt(query,"&")+1:0,(low.match(/%[0-9a-f]{2}/g)||[]).length,path.includes("//")?1:0,host.includes("xn--")?1:0];
}
function hostOf(raw){
 const low=raw.trim().toLowerCase();const m=low.match(/^[a-z][a-z0-9+.\-]*:\/\//);const rest=m?low.slice(m[0].length):low;
 let i=rest.length;for(const ch of "/?#"){const j=rest.indexOf(ch);if(j!==-1&&j<i)i=j}
 let a=rest.slice(0,i);if(a.includes("@"))a=a.slice(a.lastIndexOf("@")+1);return a.replace(/:\d+$/,"").replace(/\.$/,"");
}
const TRUSTED_CHARUSAT=["charusat.ac.in","charusat.edu.in","charusat.online"];
const TRUSTED_STANDARD=["google.com","youtube.com","gmail.com","github.com","wikipedia.org","microsoft.com","live.com","office.com","apple.com","icloud.com","amazon.com","amazon.in","python.org","mozilla.org","stackoverflow.com","linkedin.com","paypal.com","netflix.com","whatsapp.com","instagram.com","facebook.com","x.com","twitter.com","cloudflare.com","arxiv.org","ieee.org","acm.org","coursera.org","edx.org","kaggle.com","scikit-learn.org","xgboost.ai","numpy.org","pandas.pydata.org","irctc.co.in","sbi.co.in","onlinesbi.sbi","hdfcbank.com","icicibank.com","gov.in","nic.in","ac.in","edu.in"];
const UNTRUSTED_SUBS=["sites.google.com","docs.google.com","drive.google.com","script.google.com","forms.google.com","storage.googleapis.com","googleusercontent.com","github.io","githubusercontent.com","pages.dev","vercel.app","netlify.app","blogspot.com","weebly.com","wixsite.com"];
function trusted(raw){
 const h=hostOf(raw);if(!h||/^(\d{1,3}\.){3}\d{1,3}$/.test(h))return null;
 const under=(d)=>h===d||h.endsWith("."+d);
 if(UNTRUSTED_SUBS.some(under))return null;
 const c=TRUSTED_CHARUSAT.find(under);if(c)return {kind:"CHARUSAT university",domain:c};
 const s=TRUSTED_STANDARD.filter(d=>!["gov.in","nic.in","ac.in","edu.in"].includes(d)).find(under);if(s)return {kind:"well-known standard domain",domain:s};
 return null;
}
const sig=z=>1/(1+Math.exp(-z));
function tree(T,x){let n=0;while(T.l[n]!==-1){n=x[T.f[n]]<=T.t[n]?T.l[n]:T.r[n]}return T.p[n]}
function xgbTree(node,x){while(node.leaf===undefined){const f=+node.split.slice(1);const nx=x[f]<Math.fround(node.split_condition)?node.yes:node.no;node=node.children.find(c=>c.nodeid===nx)}return node.leaf}
function predict(M,raw){
 const xr=extract(raw);const x=xr.map((v,i)=>(v-M.mean[i])/M.scale[i]);
 const xf=x.map(Math.fround);const dot=(w,b)=>x.reduce((a,v,i)=>a+v*w[i],b);
 let a=x;for(let k=0;k<M.mlp.W.length;k++){const W=M.mlp.W[k],b=M.mlp.b[k];const o=b.map((bb,j)=>bb+a.reduce((s,v,i)=>s+v*W[i][j],0));a=k<M.mlp.W.length-1?o.map(v=>Math.max(0,v)):o}
 const xg=M.xgb.trees.reduce((s,t)=>s+xgbTree(t,xf),Math.log(M.xgb.base/(1-M.xgb.base)));
 return {"Logistic Regression":sig(dot(M.lr.w,M.lr.b)),"Decision Tree":tree(M.dt,xf),"Random Forest":M.rf.reduce((s,t)=>s+tree(t,xf),0)/M.rf.length,"SVM (linear)":sig(dot(M.svm.w,M.svm.b)),"Neural Net (MLP)":sig(a[0]),"XGBoost":sig(xg),_x:xr};
}
if(typeof module!=="undefined")module.exports={extract,predict,trusted,hostOf};
