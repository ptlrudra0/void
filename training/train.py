import pandas as pd, numpy as np, json, time
from feats import feats, NAMES
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score,precision_score,recall_score,f1_score,roc_auc_score
import re
from sklearn.neural_network import MLPClassifier
pt=pd.read_csv("/tmp/pt.csv"); pt=pt[pt.verified=="yes"]
ph=pt["url"].dropna().drop_duplicates()
lg=pd.DataFrame(json.load(open("legit_crawl.json")),columns=["d","url"])["url"].drop_duplicates()
n0=len(ph)+len(lg)
ph_s=ph.sample(min(20000,len(ph)),random_state=3)
fresh_pool=ph.drop(ph_s.index).sample(3000,random_state=4)
df=pd.concat([pd.DataFrame({"URL":ph_s,"y":1}),pd.DataFrame({"URL":lg,"y":0})]).drop_duplicates("URL").reset_index(drop=True)
def regd(u):
    h=re.sub(r'^[a-z]+://','',u.lower()); h=re.split(r'[/?#]',h)[0].split("@")[-1].split(":")[0]; p=h.split("."); return ".".join(p[-2:])
df["Domain"]=df.URL.map(regd); n1=len(df)
X=np.array([feats(u) for u in df["URL"]],dtype=float); y=df["y"].values
dom=df["Domain"].str.lower().values
print(n0,n1,y.sum(),len(y)-y.sum())
def split(kind):
    if kind=="domain":
        g=GroupShuffleSplit(1,test_size=0.2,random_state=42); tr,te=next(g.split(X,y,dom))
    else:
        tr,te=train_test_split(np.arange(len(y)),test_size=0.2,random_state=42,stratify=y)
    return tr,te
out={"n_raw":int(n0),"n_dedup":int(n1),"n_phish":int(y.sum()),"n_legit":int(len(y)-y.sum()),"results":{}}
sc=None;models={}
for kind in ["domain","random"]:
    tr,te=split(kind)
    sc=StandardScaler().fit(X[tr]); Xtr,Xte=sc.transform(X[tr]),sc.transform(X[te])
    ms={"Logistic Regression":LogisticRegression(max_iter=2000),
        "Decision Tree":DecisionTreeClassifier(max_depth=10,random_state=42),
        "Random Forest":RandomForestClassifier(n_estimators=40,max_depth=10,random_state=42,n_jobs=-1),
        "SVM (linear)":LinearSVC(C=1.0,max_iter=5000),
        "Neural Net (MLP)":MLPClassifier(hidden_layer_sizes=(32,16),max_iter=300,random_state=42),
        "XGBoost":XGBClassifier(n_estimators=60,max_depth=4,learning_rate=0.2,n_jobs=-1,eval_metric="logloss")}
    res={}
    for k,m in ms.items():
        t=time.time(); m.fit(Xtr,y[tr]); p=m.predict(Xte)
        s=m.decision_function(Xte) if hasattr(m,"decision_function") else m.predict_proba(Xte)[:,1]
        res[k]={"accuracy":accuracy_score(y[te],p),"precision":precision_score(y[te],p),"recall":recall_score(y[te],p),"f1":f1_score(y[te],p),"roc_auc":roc_auc_score(y[te],s)}
        print(kind,k,{a:round(b,4) for a,b in res[k].items()},round(time.time()-t,1))
    out["results"][kind]={"train":int(len(tr)),"test":int(len(te)),"metrics":res}
    if kind=="domain": models=ms; msc=sc
    del ms
# ---- export domain-split models (retrain? use the domain-split trained ones)
sc=msc
exp={"features":NAMES,"mean":sc.mean_.tolist(),"scale":sc.scale_.tolist()}
lr=models["Logistic Regression"]; exp["lr"]={"w":lr.coef_[0].tolist(),"b":float(lr.intercept_[0])}
sv=models["SVM (linear)"]; exp["svm"]={"w":sv.coef_[0].tolist(),"b":float(sv.intercept_[0])}
def tree(t):
    T=t.tree_
    return {"f":T.feature.tolist(),"t":T.threshold.round(6).tolist(),"l":T.children_left.tolist(),"r":T.children_right.tolist(),"p":(T.value[:,0,1]/T.value[:,0,:].sum(1)).round(4).tolist()}
exp["dt"]=tree(models["Decision Tree"])
exp["rf"]=[tree(e) for e in models["Random Forest"].estimators_]
xb=models["XGBoost"].get_booster()
mlp=models["Neural Net (MLP)"]; exp["mlp"]={"W":[w.tolist() for w in mlp.coefs_],"b":[b.tolist() for b in mlp.intercepts_]}
exp["xgb"]={"trees":[json.loads(s) for s in xb.get_dump(dump_format="json")]}
b=json.loads(xb.save_config())["learner"]["learner_model_param"]["base_score"]
exp["xgb"]["base"]=float(str(b).strip("[]"))
# sample parity data
idx=np.random.RandomState(1).choice(len(y),30,replace=False)
exp["parity"]=[{"url":df["URL"].iloc[i],"x":X[i].tolist(),
 "lr":float(lr.predict_proba(sc.transform(X[i:i+1]))[0,1]),"dt":float(models["Decision Tree"].predict_proba(sc.transform(X[i:i+1]))[0,1]),
 "rf":float(models["Random Forest"].predict_proba(sc.transform(X[i:i+1]))[0,1]),"svm":float(sv.decision_function(sc.transform(X[i:i+1]))[0]),
 "mlp":float(mlp.predict_proba(sc.transform(X[i:i+1]))[0,1]),"xgb":float(models["XGBoost"].predict_proba(sc.transform(X[i:i+1]))[0,1])} for i in idx]
# importance
out["xgb_importance"]=sorted(zip(NAMES,models["XGBoost"].feature_importances_.tolist()),key=lambda a:-a[1])[:8]
# fresh phishtank check
op=pd.read_csv("/tmp/openphish.txt",header=None)[0].drop_duplicates(); op=op[~op.isin(df.URL)]
out["openphish_unseen"]={"n":int(len(op)),"recall":{k:float(m.predict(sc.transform(np.array([feats(u) for u in op],dtype=float))).mean()) for k,m in models.items()}}
print(out["openphish_unseen"])
pu=fresh_pool
Xp=sc.transform(np.array([feats(u) for u in pu],dtype=float))
out["heldout_phishtank_unseen"]={"n":int(len(pu)),"recall":{k:float(m.predict(Xp).mean()) for k,m in models.items()}}

json.dump(out,open("results.json","w"),indent=1); json.dump(exp,open("model.json","w"),separators=(",",":"))
