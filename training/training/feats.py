import re, math
SUSP = ["login","verify","secure","account","update","banking","signin","confirm","password","wallet","auth","credential","recover","webscr","billing","unlock","suspend","alert","support","paypal","free","bonus"]
NAMES = ["url_length","host_length","path_length","query_length","dot_count","subdomain_count","host_hyphens","host_digits","at_count","qmark_count","eq_count","amp_count","slash_count","digit_ratio","letter_ratio","special_ratio","host_entropy","has_ip","is_https","susp_tokens","tld_length","has_port","path_dots","host_dots","longest_token","num_params","has_hex_enc","double_slash_path","punycode"]
def entropy(s):
    if not s: return 0.0
    n=len(s); c={}
    for ch in s: c[ch]=c.get(ch,0)+1
    return -sum(v/n*math.log2(v/n) for v in c.values())
def feats(raw):
    u=raw.strip()
    low=u.lower()
    m=re.match(r'^[a-z][a-z0-9+.\-]*://',low)
    https=1 if low.startswith("https://") else 0
    rest=low[m.end():] if m else low
    i=len(rest)
    for ch in "/?#":
        j=rest.find(ch)
        if j!=-1 and j<i: i=j
    auth=rest[:i]; tail=rest[i:]
    if "@" in auth: auth=auth[auth.rfind("@")+1:]
    port=0
    pm=re.search(r':(\d+)$',auth)
    if pm: port=1; auth=auth[:pm.start()]
    host=auth
    q=tail.find("?")
    h=tail.find("#")
    pathq=tail if h==-1 else tail[:h]
    qi=pathq.find("?")
    path=pathq if qi==-1 else pathq[:qi]
    query="" if qi==-1 else pathq[qi+1:]
    parts=host.split(".") if host else []
    isip=1 if re.match(r'^(\d{1,3}\.){3}\d{1,3}$',host) else 0
    tld=parts[-1] if len(parts)>1 else ""
    sub=max(0,len(parts)-2) if not isip else 0
    L=max(1,len(u))
    digits=sum(c.isdigit() for c in low)
    letters=sum(('a'<=c<='z') for c in low)
    special=sum((not c.isalnum()) for c in low)
    toks=[t for t in re.split(r'[^a-z0-9]+',low) if t]
    susp=sum(1 for t in SUSP if t in low)
    return [len(u),len(host),len(path),len(query),low.count("."),sub,host.count("-"),sum(c.isdigit() for c in host),low.count("@"),low.count("?"),low.count("="),low.count("&"),path.count("/"),digits/L,letters/L,special/L,entropy(host),isip,https,susp,len(tld),port,path.count("."),host.count("."),max([len(t) for t in toks] or [0]),(query.count("&")+1 if query else 0),len(re.findall(r'%[0-9a-f]{2}',low)),1 if "//" in path else 0,1 if "xn--" in host else 0]
