"""Reproducible multinomial Naive Bayes baseline with family/duplicate grouped holdout."""
import argparse, collections, hashlib, json, math, re
from pathlib import Path
from analyzer import parse_email, rules
ROOT=Path(__file__).resolve().parent

def tokens(message):
    text=(message['subject']+' '+message['body']).lower()
    text=re.sub(r'https?://\S+|www\.\S+|\S+@\S+',' ',text)
    return collections.Counter(re.findall(r"[a-z]{3,24}",text))

def train(rows):
    classes={'benign':collections.Counter(),'phishing':collections.Counter()}; docs=collections.Counter(); df=collections.Counter()
    for row in rows:
        t=tokens(row['parsed']); df.update(t.keys())
        classes[row['label']].update({k:min(3,v) for k,v in t.items()}); docs[row['label']]+=1
    vocabulary=sorted(w for w,n in df.items() if n>=2)[:5000]
    return {'algorithm':'multinomial-naive-bayes','alpha':1.0,'vocabulary':vocabulary,'counts':{c:{w:counts[w] for w in vocabulary} for c,counts in classes.items()},'documents':dict(docs),'synthetic_only':True,'threshold':0.5,'training_rows':len(rows)}

def predict(model,message):
    ts=tokens(message); scores={}; total=sum(model['documents'].values()); contributions=[]
    vocab=set(model['vocabulary']); denom={c:sum(counts.values())+len(vocab) for c,counts in model['counts'].items()}
    for c in ('benign','phishing'):
        scores[c]=math.log(model['documents'][c]/total)+sum(min(3,n)*math.log((model['counts'][c].get(w,0)+1)/denom[c]) for w,n in ts.items() if w in vocab)
    delta=max(-60,min(60,scores['phishing']-scores['benign'])); p=1/(1+math.exp(-delta))
    for w,n in ts.items():
        if w in vocab:
            effect=min(3,n)*math.log(((model['counts']['phishing'].get(w,0)+1)/denom['phishing'])/((model['counts']['benign'].get(w,0)+1)/denom['benign']))
            contributions.append({'token':w,'log_odds':round(effect,3),'direction':'phishing' if effect>0 else 'benign'})
    return {'label':'phishing' if p>=model.get('threshold',.5) else 'benign','score':round(p,6),'score_meaning':'Uncalibrated synthetic-training model output; not a real-world phishing probability.','top_features':sorted(contributions,key=lambda x:abs(x['log_odds']),reverse=True)[:8],'known_tokens':sum(n for w,n in ts.items() if w in vocab),'synthetic_only':True}

def canonical(message):
    return hashlib.sha256(' '.join(sorted(tokens(message).elements())).encode()).hexdigest()

def split(rows):
    # Union families linked by a canonical token-content duplicate. Labels cannot split a duplicate.
    parent={r['family']:r['family'] for r in rows}; seen={}
    def find(x):
        while parent[x]!=x: parent[x]=parent[parent[x]]; x=parent[x]
        return x
    for r in rows:
        fingerprint=canonical(r['parsed'])
        if fingerprint in seen: parent[find(r['family'])]=find(seen[fingerprint])
        seen[fingerprint]=r['family']
    groups=collections.defaultdict(list)
    for r in rows: groups[find(r['family'])].append(r)
    bylabel=collections.defaultdict(list)
    for g,rs in groups.items():
        labels={r['label'] for r in rs}
        if len(labels)>1: raise ValueError('Conflicting labels in duplicate/family group: '+g)
        bylabel[next(iter(labels))].append(g)
    selected=set()
    for label,gs in bylabel.items():
        ordered=sorted(gs,key=lambda g:hashlib.sha256(('selbi-holdout-v1:'+g).encode()).hexdigest())
        selected.update(ordered[:max(1,round(len(gs)*.3))])
    trainrows=[r for r in rows if find(r['family']) not in selected]
    testrows=[r for r in rows if find(r['family']) in selected]
    return trainrows,testrows

def metrics(predictions):
    cm={'true_positive':0,'false_positive':0,'true_negative':0,'false_negative':0}
    for p in predictions:
        key=('true_positive' if p['prediction']=='phishing' else 'false_negative') if p['label']=='phishing' else ('false_positive' if p['prediction']=='phishing' else 'true_negative')
        cm[key]+=1
    tp,fp,tn,fn=(cm[x] for x in ('true_positive','false_positive','true_negative','false_negative'))
    div=lambda a,b:round(a/b,4) if b else 0.0
    return {**cm,'precision':div(tp,tp+fp),'recall':div(tp,tp+fn),'accuracy':div(tp+tn,len(predictions)),'false_positive_rate':div(fp,fp+tn),'f1':div(2*tp,2*tp+fp+fn),'n':len(predictions)}

def run():
    rows=json.loads((ROOT/'corpus/manifest.json').read_text())
    for r in rows: r['parsed']=parse_email((ROOT/'corpus'/r['file']).read_bytes())
    tr,te=split(rows); model=train(tr)
    a=[{'id':r['id'],'family':r['family'],'label':r['label'],'prediction':predict(model,r['parsed'])['label'],'score':predict(model,r['parsed'])['score']} for r in te]
    b=[{'id':r['id'],'label':r['label'],'prediction':'phishing' if rules(r['parsed'])['score']>=20 else 'benign'} for r in te]
    trainfp={canonical(r['parsed']) for r in tr}; testfp={canonical(r['parsed']) for r in te}
    report={'dataset':'160 locally authored synthetic emails, 40 scenario families, four variants per family','scope':'Synthetic holdout only. No real inbox, beta user, click reduction, or production performance was measured.','split':'Deterministic 70/30 per-class family grouping after unioning canonical-content duplicates; vocabulary fitted only on training data. Threshold fixed at 0.5 before evaluation.','training_rows':len(tr),'test_rows':len(te),'training_families':sorted(set(r['family'] for r in tr)),'test_families':sorted(set(r['family'] for r in te)),'family_overlap':len(set(r['family'] for r in tr)&set(r['family'] for r in te)),'canonical_duplicate_overlap':len(trainfp&testfp),'model_metrics':metrics(a),'rules_metrics':metrics(b),'predictions':a,'rules_threshold':20,'model_threshold':.5,'corpus_sha256':hashlib.sha256((ROOT/'corpus/manifest.json').read_bytes()).hexdigest(),'corpus_content_sha256':hashlib.sha256(b''.join((ROOT/'corpus'/r['file']).read_bytes() for r in rows)).hexdigest()}
    (ROOT/'model/baseline.json').write_text(json.dumps(model,indent=2)+'\n')
    (ROOT/'evidence/evaluation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ['training_rows','test_rows','family_overlap','canonical_duplicate_overlap','model_metrics','rules_metrics']},indent=2))

if __name__=='__main__': run()
