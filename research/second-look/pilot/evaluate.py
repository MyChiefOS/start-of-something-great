"""Does the open model's material make a small classifier better? Judged ONLY on comments people labelled that no seed
came from (videos 04 and 05). "Clearing" = calling a comment not spam; what matters for Second Look is how much it can
clear while staying within 1 wrong clear in 80 (precision of "not spam" >= 98.75%), and AUC.
Arms, each repeated over 10 random draws of the real examples:
  - few real: n real labelled comments from videos 01-03 (n = 50, 100, 200), the scarce case Second Look starts in
  - few real + synthetic: the same, plus the variations of those same seeds (only seeds in the draw)
  - all real (videos 01-03), with and without all synthetic, for reference
  - all real + public SMS spam (another human-labelled source), for reference"""
import csv, json, random, re, sys
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from scipy.sparse import hstack

def load(files):
    out = []
    for f in files:
        for r in csv.DictReader(open('data-yt/' + f, encoding='utf-8', errors='replace')):
            t = re.sub(r'<[^>]+>', ' ', r['CONTENT']).strip()
            out.append({'id': r['COMMENT_ID'], 'text': t, 'label': int(r['CLASS'])})
    return out
train_all = load(['Youtube01-Psy.csv', 'Youtube02-KatyPerry.csv', 'Youtube03-LMFAO.csv'])
test = load(['Youtube04-Eminem.csv', 'Youtube05-Shakira.csv'])
syn = [json.loads(l) for l in open('pilot/synthetic-clean.jsonl')]
seed_ids = {s['seed_id'] for s in syn}
sms = []
for line in open('data-sms/SMSSpamCollection', encoding='utf-8', errors='replace'):
    lab, _, t = line.rstrip('\n').partition('\t'); sms.append({'text': t, 'label': 1 if lab == 'spam' else 0})

def fit_score(train):
    X = [r['text'] for r in train]; y = [r['label'] for r in train]
    w = TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True); c = TfidfVectorizer(analyzer='char_wb', ngram_range=(2, 5), min_df=1, sublinear_tf=True)
    Xtr = hstack([w.fit_transform(X), c.fit_transform(X)])
    m = LogisticRegression(C=4.0, max_iter=2000, class_weight='balanced').fit(Xtr, y)
    Xte = hstack([w.transform([r['text'] for r in test]), c.transform([r['text'] for r in test])])
    return m.predict_proba(Xte)[:, 0]  # probability "not spam"

def metrics(p_ok):
    y_ok = np.array([1 - r['label'] for r in test])
    auc = roc_auc_score(y_ok, p_ok)
    order = np.argsort(-p_ok); best = 0
    tp = np.cumsum(y_ok[order]); k = np.arange(1, len(order) + 1)
    ok = tp / k >= 1 - 1 / 80
    best = int(k[ok].max()) if ok.any() else 0  # largest top-k (most confident first) within 1 wrong clear in 80
    return auc, best / y_ok.sum()

res = {}
seeded = [r for r in train_all if r['id'] in seed_ids]
for n in (50, 100, 200):
    a, b = [], []
    for rep in range(10):
        rnd = random.Random(rep)
        pick = rnd.sample(seeded, min(n, len(seeded)))
        ids = {r['id'] for r in pick}
        a.append(metrics(fit_score(pick)))
        b.append(metrics(fit_score(pick + [{'text': s['text'], 'label': s['label']} for s in syn if s['seed_id'] in ids])))
    f = lambda xs, i: round(float(np.mean([x[i] for x in xs])), 3)
    res[f'{n} real'] = {'AUC': f(a, 0), 'share of fine comments cleared within 1 in 80': f(a, 1)}
    res[f'{n} real + their synthetic variations'] = {'AUC': f(b, 0), 'share of fine comments cleared within 1 in 80': f(b, 1)}
for name, tr in (('all real (1,138)', train_all), ('all real + all synthetic', train_all + syn), ('all real + SMS spam set', train_all + sms)):
    m = metrics(fit_score(tr)); res[name] = {'AUC': round(m[0], 3), 'share of fine comments cleared within 1 in 80': round(m[1], 3)}
print(json.dumps(res, indent=1))
