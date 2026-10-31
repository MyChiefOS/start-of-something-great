"""Follow-up: the scarce case with the public SMS set too, and how much each number moves between draws (spread)."""
import random, json, numpy as np
exec(open('pilot/evaluate.py').read().split('res = {}')[0])
res = {}
seeded = [r for r in train_all if r['id'] in seed_ids]
for n in (50, 100, 200):
    arms = {'real': [], 'real + synthetic': [], 'real + SMS': [], 'real + SMS + synthetic': []}
    for rep in range(10):
        pick = random.Random(rep).sample(seeded, min(n, len(seeded))); ids = {r['id'] for r in pick}
        sy = [{'text': s['text'], 'label': s['label']} for s in syn if s['seed_id'] in ids]
        arms['real'].append(metrics(fit_score(pick))); arms['real + synthetic'].append(metrics(fit_score(pick + sy)))
        arms['real + SMS'].append(metrics(fit_score(pick + sms))); arms['real + SMS + synthetic'].append(metrics(fit_score(pick + sms + sy)))
    for k, v in arms.items():
        c = [x[1] for x in v]
        res[f'{n} real: {k}'] = {'AUC': round(float(np.mean([x[0] for x in v])), 3), 'cleared within 1 in 80 (mean)': round(float(np.mean(c)), 3),
                                'spread (sd)': round(float(np.std(c)), 3)}
print(json.dumps(res, indent=1))
