"""Figures for sections 6 and 8: paired step values, one-at-a-time sensitivity, and the review break-even curve."""
import json
import numpy as np
import loop_sim as M, sensitivity as S

# Paired step values: points of loss reduction lost when one step is removed from the tiered loop.
rng = np.random.default_rng(20261015); reps, n = 40, 5000
allp = {**M.POLICIES, **M.ABLATIONS}
rows = {k: [] for k in allp}
for _ in range(reps):
    d = M.draw(n, M.BASE, rng)
    res = {k: M.summarise(M.run(d, M.BASE, *v)) for k, v in allp.items()}
    for k in allp:
        rows[k].append(1 - res[k]['loss'] / res['No loop']['loss'])
t = np.array(rows['Tiered loop (adopted)'])
ablation = {s: (float(100 * (t - np.array(rows[f'Tiered without {s}'])).mean()),
                float(196 * (t - np.array(rows[f'Tiered without {s}'])).std(ddof=1) / np.sqrt(reps))) for s in M.STEPS}

# One-at-a-time sensitivity, 200,000 decisions per setting.
def red(p):
    r = S.evaluate(p, 1.0, 200000, np.random.default_rng(11))
    return 1 - r['Tiered loop (adopted)']['loss'] / r['No loop']['loss']
base = red(dict(M.BASE))
tornado = []
for k, (lo, hi) in S.RANGES.items():
    a = dict(M.BASE); a[k] = lo; b = dict(M.BASE); b[k] = hi
    tornado.append((k, lo, hi, red(a), red(b)))
tornado.sort(key=lambda x: -abs(x[4] - x[3]))

# Break-even curve: loss avoided per decision by review, by reviewer false-alarm rate.
curve = []
for fa in np.round(np.arange(0, 0.401, 0.025), 3):
    p = dict(M.BASE); p['p_fa'] = fa
    r = S.evaluate(p, 1.0, 200000, np.random.default_rng(3))
    curve.append(dict(fa=float(fa),
                      gc=r['Light loop on every decision']['loss'] - r['Tiered loop (adopted)']['loss'],
                      rt=r['Tiered loop (adopted)']['loss'] - r['Full loop on every decision']['loss']))
json.dump(dict(ablation=ablation, oat_base=base, tornado=tornado, curve=curve), open('final_numbers.json', 'w'), indent=1)
print({k: (round(a, 2), round(b, 2)) for k, (a, b) in ablation.items()}, round(base, 4))
print([(x[0], round(x[3], 3), round(x[4], 3)) for x in tornado[:8]])
print([(c['fa'], round(c['gc'], 4), round(c['rt'], 4)) for c in curve[8:11]])
