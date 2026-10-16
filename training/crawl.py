import requests, re, random, json, concurrent.futures as cf, time
from urllib.parse import urljoin
doms=[l.split(",")[1].strip() for l in open("top-1m.csv").read().split("\n")[:8000] if l]
random.seed(2); random.shuffle(doms); doms=doms[:2500]
H={"User-Agent":"Mozilla/5.0 (research crawler; academic project)"}
def get(d):
    try:
        r=requests.get("https://"+d,headers=H,timeout=(3,4),allow_redirects=True)
        if r.status_code!=200 or "text/html" not in r.headers.get("content-type",""): return []
        base=r.url; hs=re.findall(r'href=["\']([^"\'#]+)["\']',r.text[:400000])
        out=[]
        for h in hs:
            u=urljoin(base,h)
            if re.match(r'^https?://',u) and not re.search(r'\.(css|js|png|jpg|ico|svg|woff2?)(\?|$)',u,re.I): out.append(u)
        random.shuffle(out); return [(d,u) for u in out[:14]]
    except Exception: return []
res=[]; t=time.time()
with cf.ThreadPoolExecutor(150) as ex:
    futs=[ex.submit(get,d) for d in doms]
    for f in cf.as_completed(futs):
        res+=f.result()
        if len(res)%500<14: json.dump(res,open("legit_crawl.json","w"))
json.dump(res,open("legit_crawl.json","w")); print(len(res))
