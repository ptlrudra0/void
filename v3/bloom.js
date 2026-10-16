// Void v3: compact blocklist snapshot (Bloom filter). Exact-hostname lookups only.
function h1(s){let h=0x811c9dc5;for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,0x01000193)>>>0}return h>>>0}
function h2(s){let h=0x9747b28c;for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,0x5bd1e995)>>>0;h^=h>>>15}h=Math.imul(h^(h>>>13),0xc2b2ae35)>>>0;return ((h^(h>>>16))|1)>>>0}
function bloomHas(B,s){for(let i=0;i<B.k;i++){const p=((h1(s)+Math.imul(i,h2(s)))>>>0)%B.m;if(!(B.bits[p>>3]&(1<<(p&7))))return false}return true}
function bloomLoad(j){const bin=typeof atob==="function"?Uint8Array.from(atob(j.b64),c=>c.charCodeAt(0)):new Uint8Array(Buffer.from(j.b64,"base64"));return {m:j.m,k:j.k,bits:bin,n:j.n,date:j.date,source:j.source}}
function blocklisted(B,host){if(!B||!host)return false;const h=host.replace(/^www\./,"");return bloomHas(B,h)||bloomHas(B,"www."+h)}
if(typeof module!=="undefined")module.exports={bloomLoad,blocklisted,bloomHas,h1,h2};
