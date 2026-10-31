"""What data gets Second Look to its 1-in-80 proof soonest? Built on sim_sl.py (same model of skill and the gate).
The gate counts only real held posts Aaron decides (the proof must come from the live stream). Other data only makes
the model better sooner (a head start n0, in "equivalent decisions", discounted for not being our stream).
Operating point: it clears only where it is 99.7% sure, so that the proof (300 would-be clears, 95% lower bound of
agreement >= 1 - 1/80 = 98.75%) can be passed."""
import json, sys
import numpy as np
from math import exp
import sim_sl as s
s.PRECISION, s.M, s.LB = 0.997, 300, 1 - 1 / 80

def months_to_live(prm, n0, months=36):
    held_m = prm['posts_per_day'] * 30 * prm['hold_rate']
    n = n0; clears = 0; agree = 0.0
    for mo in range(1, months + 1):
        auc = prm['auc0'] + (prm['auc_max'] - prm['auc0']) * (1 - exp(-n / prm['k']))
        rate, bad = s.clear_rate(auc, prm['ok_share'])
        clears += held_m * rate; agree += held_m * rate * (1 - bad); n += held_m
        if clears >= s.M and s.wilson_lb(agree / clears, int(clears)) >= s.LB:
            return mo
    return None

STRATEGIES = {  # head start in equivalent decisions, and what it asks of whom
    'wait for real held posts only': 0,
    'Aaron labels 300 public posts from other sites (about 2 hours)': 150,
    'Aaron labels 300 realistic made-up cases (about 2 hours)': 200,
    'both (about 4 hours)': 300,
}
base = {k: v[1] for k, v in s.R.items()}
out = {}
for ppd in (30, 100, 300, 1000):
    for name, n0 in STRATEGIES.items():
        out.setdefault(f'{ppd} posts/day', {})[name] = months_to_live(dict(base, posts_per_day=ppd), n0)
# Doubling traffic (inviting more people and agents) at 100 posts/day.
out['200 posts/day (more people invited), labels from both'] = months_to_live(dict(base, posts_per_day=200), 300)
rng = np.random.default_rng(7); N = 400
for name, n0 in (('wait', 0), ('both', 300)):
    got = []
    for _ in range(N):
        p = {k: float(np.exp(rng.uniform(np.log(lo), np.log(hi)))) if k == 'posts_per_day' else float(rng.uniform(lo, hi)) for k, (lo, _, hi) in s.R.items()}
        got.append(months_to_live(p, n0))
    live = [g for g in got if g]
    out[f'random settings, {name}'] = {'passes within 3 years': f'{len(live) / N * 100:.0f}%', 'median months when it passes': float(np.median(live)) if live else None}
print(json.dumps(out, indent=1))
