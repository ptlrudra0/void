const C="void-v4-1";
self.addEventListener("install",e=>{self.skipWaiting();e.waitUntil(caches.open(C).then(c=>c.addAll(["./","./triage.js","../engine.js","../model.json","../v3/lookalike.js","../v3/bloom.js","../v3/blocklist_meta.json","../v3/bl0.json","../v3/bl1.json","../v3/bl2.json"]).catch(()=>{})))});
self.addEventListener("activate",e=>e.waitUntil(clients.claim()));
self.addEventListener("fetch",e=>{const u=new URL(e.request.url);if(e.request.method!=="GET"||u.origin!==location.origin)return;e.respondWith(caches.match(e.request).then(c=>{const n=fetch(e.request).then(r=>{if(r.ok){const cp=r.clone();caches.open(C).then(x=>x.put(e.request,cp))}return r}).catch(()=>c);return c||n}))});
