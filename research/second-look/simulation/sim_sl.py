"""Second Look, decide within limits: when may it clear held posts on its own, how wrong will it be, and what does it
save Aaron? A Monte Carlo over the unknowns; every number is an assumption with a range (none is measured: the site
has had 0 held posts). Second Look may only CLEAR a held post (it goes live); everything else stays with Aaron.

Per month: held = posts_per_day * 30 * hold_rate. Of held posts a share ok_share is fine (JEVs held them by caution).
Second Look gives each held post a score; fine posts score higher. Its skill (AUC) grows with the number n of Aaron's
decisions it has learned from: auc(n) = auc0 + (auc_max - auc0) * (1 - exp(-n / k)), auc0 from public pre-training.
It clears a post only above a threshold set so that, among posts it would clear, the share Aaron would also clear is
at least the target precision (calibrated on his past decisions).
The gate (shadow mode until passed): on at least m posts it would have cleared, the 95% lower bound (Wilson) of its
agreement with Aaron is at least lb_target. After go-live: Aaron reviews a random audit share of its clears, and the
daily cap limits clears.
"""
import json
import numpy as np
from math import sqrt, exp
from scipy.stats import norm

R = {  # low, base, high
    'posts_per_day': (10, 300, 10000),
    'hold_rate':     (0.005, 0.015, 0.04),
    'ok_share':      (0.5, 0.75, 0.9),
    'auc0':          (0.6, 0.75, 0.85),   # from public human-labelled data alone (spam/phishing/abuse)
    'auc_max':       (0.88, 0.94, 0.98),
    'k':             (50, 150, 400),      # decisions for ~63% of the way to auc_max
    'aaron_min':     (1.0, 2.0, 4.0),     # minutes per held post
    'audit':         (0.05, 0.1, 0.2),    # share of its clears Aaron spot-checks after go-live
}
PRECISION = 0.99   # target: of what it clears, Aaron would have cleared 99%
M, LB = 300, 0.99  # gate: at least 300 would-be clears in shadow, 95% lower bound of agreement >= 99% (false clears under 1%)

def binormal(auc):
    # Scores: fine ~ N(d,1), bad ~ N(0,1); AUC = Phi(d / sqrt 2).
    return sqrt(2) * norm.ppf(auc)

def clear_rate(auc, ok_share, precision=PRECISION):
    """Share of all held posts it clears, and the share of its clears that are bad, at the threshold that meets the
    precision target (or none if it can't)."""
    d = binormal(auc)
    t = np.linspace(-2, 6, 400)
    tp = ok_share * norm.sf(t - d); fp = (1 - ok_share) * norm.sf(t); tot = tp + fp
    ok = (tot > 1e-12) & (tp >= precision * np.maximum(tot, 1e-12))
    if not ok.any(): return (0.0, 0.0)
    i = int(np.argmax(np.where(ok, tot, -1)))
    return (float(tot[i]), float(fp[i] / tot[i]))

def wilson_lb(p, n, z=1.96):
    if n == 0: return 0.0
    c = p + z * z / (2 * n); r = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (c - r) / (1 + z * z / n)

def run(prm, months=24, cap_per_day=200):
    held_m = prm['posts_per_day'] * 30 * prm['hold_rate']
    n = 0; shadow_clears = 0; agree = 0.0; live_at = None
    out = []
    for mo in range(1, months + 1):
        auc = prm['auc0'] + (prm['auc_max'] - prm['auc0']) * (1 - exp(-n / prm['k']))
        rate, bad_share = clear_rate(auc, prm['ok_share'])
        if live_at is None:
            # Shadow: Aaron decides every held post; its would-be clears are compared with him.
            shadow_clears += held_m * rate; agree += held_m * rate * (1 - bad_share)
            n += held_m
            if shadow_clears >= M and wilson_lb(agree / shadow_clears, int(shadow_clears)) >= LB:
                live_at = mo
            aaron_items, bad_live = held_m, 0.0
        else:
            clears = min(held_m * rate, cap_per_day * 30)
            aaron_items = held_m - clears + clears * prm['audit']   # the rest, plus the audit sample
            bad_live = clears * bad_share * (1 - prm['audit'])      # bad posts it released that no audit caught
            n += held_m - clears + clears * prm['audit']             # it keeps learning from what Aaron decides
        out.append({'month': mo, 'auc': round(auc, 3), 'aaron_hours': aaron_items * prm['aaron_min'] / 60,
                    'bad_live': bad_live, 'live': live_at is not None})
    return live_at, out

def base(): return {k: v[1] for k, v in R.items()}

def main():
    rng = np.random.default_rng(20261030)
    res = {}
    # Base case and by volume.
    for ppd in (10, 100, 300, 1000, 10000):
        p = dict(base(), posts_per_day=ppd)
        live, out = run(p)
        held = ppd * 30 * p['hold_rate']
        last = out[-1]
        res[f'{ppd} posts/day'] = {'held/month': round(held, 1), 'goes live in month': live,
            'Aaron hours/month: today (all held)': round(held * p['aaron_min'] / 60, 1),
            'Aaron hours/month: month 24': round(last['aaron_hours'], 1),
            'bad posts it released in month 24': round(last['bad_live'], 2), 'skill (AUC) month 24': last['auc']}
    # Random settings: how often the gate is passed within 24 months, and how bad it is when live.
    N = 600; passed = 0; bad_rates = []; saved = []
    for _ in range(N):
        p = {k: float(np.exp(rng.uniform(np.log(lo), np.log(hi)))) if k == 'posts_per_day' else float(rng.uniform(lo, hi)) for k, (lo, _, hi) in R.items()}
        live, out = run(p)
        if live:
            passed += 1
            last = out[-1]; held = p['posts_per_day'] * 30 * p['hold_rate']
            clears = held - (last['aaron_hours'] * 60 / p['aaron_min'])
            bad_rates.append(last['bad_live'] / max(held, 1e-9))
            saved.append(1 - last['aaron_hours'] / (held * p['aaron_min'] / 60))
    pct = lambda a, q: round(float(np.percentile(a, q)), 4) if a else None
    res['random settings'] = {'gate passed within 24 months': f'{passed / N * 100:.0f}%',
        'bad posts released per held post (median, 95th pct)': [pct(bad_rates, 50), pct(bad_rates, 95)],
        'share of Aaron\'s held-post time saved (median, 5th pct)': [pct(saved, 50), pct(saved, 5)]}
    # The gate itself: how many wrong clears could slip through it (the worst true agreement that still passes 5% of the time).
    worst = None
    for true_p in np.linspace(0.90, 0.99, 91):
        sims = rng.binomial(M, true_p, 4000) / M
        pass_rate = np.mean([wilson_lb(s, M) >= LB for s in sims])
        if pass_rate >= 0.05 and worst is None: worst = round(float(true_p), 3)
    res['gate check'] = {'gate': f'{M} would-be clears, 95% lower bound of agreement >= {LB}',
                         'lowest true agreement that passes it at least 5% of the time': worst}
    print(json.dumps(res, indent=1))

if __name__ == '__main__':
    import sys
    if len(sys.argv) == 4:
        PRECISION, M, LB = float(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
    main()
