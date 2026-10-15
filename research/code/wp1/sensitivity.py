"""Global and one-at-a-time sensitivity for the decision-loop model (paper section 8)."""
import json
import numpy as np
from scipy.stats import spearmanr
import loop_sim as M

RANGES = dict(g=(0.05, 0.40), stakes_gc=(3, 20), sigma=(0.3, 1.0), phi=(0.1, 0.5), sigma_b=(0.2, 0.8),
              rho=(0.3, 0.9), p_stale_gc=(0.15, 0.5), p_stale_rt=(0.05, 0.30), delta=(0.75, 2.5),
              d_research=(0.4, 0.85), p_mis=(0.05, 0.25), q_intent=(0.3, 0.7), q_intent_rev=(0.1, 0.5),
              p_def_gc=(0.3, 0.7), p_def_rt=(0.1, 0.35), defect_cost=(0.4, 1.5), q_self=(0.1, 0.35),
              q_rev=(0.3, 0.8), h_base=(0.10, 0.30), h_loop=(0.10, 0.40), hm_base=(0.2, 0.4), hm_loop=(0.25, 0.55),
              p_badsrc=(0.0, 0.15), p_misspec=(0.0, 0.25), delta_m=(0.5, 2.0), p_fa=(0.0, 0.40),
              p_oc=(0.0, 0.15), kappa=(0.0, 0.5))
HOURS0 = dict(M.HOURS)


def evaluate(p, hour_factor, n, rng):
    M.HOURS = {k: (v if k == 'base' else (v[0] * hour_factor, v[1] * hour_factor)) for k, v in HOURS0.items()}
    d = M.draw(n, p, rng)
    r = {name: M.summarise(M.run(d, p, *M.POLICIES[name])) for name in M.POLICIES}
    M.HOURS = HOURS0
    return r


def global_sa(draws=10000, n=2000, seed=7):
    rng = np.random.default_rng(seed)
    names = list(RANGES)
    X, Y = [], []
    for _ in range(draws):
        p = dict(M.BASE)
        for k, (lo, hi) in RANGES.items():
            p[k] = rng.uniform(lo, hi)
        hf = rng.uniform(0.5, 2.0)
        r = evaluate(p, hf, n, rng)
        L0 = r['No loop']['loss']; Lt = r['Tiered loop (adopted)']['loss']
        Lf = r['Full loop on every decision']['loss']; Ll = r['Light loop on every decision']['loss']
        H0 = r['No loop']['hours']; Ht = r['Tiered loop (adopted)']['hours']; Hf = r['Full loop on every decision']['hours']
        Hl = r['Light loop on every decision']['hours']
        X.append([p[k] for k in names] + [hf])
        Y.append(dict(
            red_tiered=1 - Lt / L0, red_full=1 - Lf / L0, red_light=1 - Ll / L0,
            share_of_full=(L0 - Lt) / (L0 - Lf) if L0 > Lf else np.nan,
            per_hour_tiered=(L0 - Lt) / (Ht - H0),
            per_hour_review_gc=(Ll - Lt) / (Ht - Hl),          # adding review on GC decisions only
            per_hour_review_rt=(Lt - Lf) / (Hf - Ht),          # adding review on routine decisions too
            severe_none=r['No loop']['severe_gc'], severe_tiered=r['Tiered loop (adopted)']['severe_gc']))
    X = np.array(X); names = names + ['hour_factor']
    keys = list(Y[0])
    Yc = {k: np.array([y[k] for y in Y]) for k in keys}
    q = lambda v: [float(np.nanpercentile(v, x)) for x in (5, 25, 50, 75, 95)]
    summary = {k: q(v) for k, v in Yc.items()}
    summary['P(tiered reduces loss)'] = float(np.mean(Yc['red_tiered'] > 0))
    summary['P(tiered keeps >=80% of full benefit)'] = float(np.nanmean(Yc['share_of_full'] >= 0.8))
    summary['P(review worth more per hour on GC than routine)'] = float(np.mean(Yc['per_hour_review_gc'] > Yc['per_hour_review_rt']))
    summary['P(full loop beats tiered per hour on routine review)'] = float(np.mean(Yc['per_hour_review_rt'] > Yc['per_hour_tiered']))
    summary['P(severe GC failures fall)'] = float(np.mean(Yc['severe_tiered'] < Yc['severe_none']))
    srcc = {}
    for target in ('red_tiered', 'per_hour_review_rt', 'share_of_full'):
        y = Yc[target]; ok = ~np.isnan(y)
        srcc[target] = sorted(((names[j], float(spearmanr(X[ok, j], y[ok]).statistic)) for j in range(X.shape[1])),
                              key=lambda t: -abs(t[1]))[:6]
    return summary, srcc


def oat(n=20000, seed=11):
    """One-at-a-time: tiered loss reduction at each parameter's low and high end, others at base."""
    out = []
    for k, (lo, hi) in RANGES.items():
        vals = []
        for v in (lo, hi):
            p = dict(M.BASE); p[k] = v
            r = evaluate(p, 1.0, n, np.random.default_rng(seed))
            vals.append(1 - r['Tiered loop (adopted)']['loss'] / r['No loop']['loss'])
        out.append((k, lo, hi, vals[0], vals[1]))
    p = dict(M.BASE)
    r = evaluate(p, 1.0, n, np.random.default_rng(seed))
    base = 1 - r['Tiered loop (adopted)']['loss'] / r['No loop']['loss']
    return base, sorted(out, key=lambda t: -abs(t[4] - t[3]))


if __name__ == '__main__':
    summary, srcc = global_sa()
    base, tornado = oat()
    json.dump(dict(summary=summary, srcc=srcc, oat_base=base, tornado=tornado), open('sensitivity.json', 'w'), indent=1)
    for k, v in summary.items():
        print(k, [round(x, 3) for x in v] if isinstance(v, list) else round(v, 3))
    print('SRCC', json.dumps(srcc, indent=0))
    print('OAT base', round(base, 3))
    for t in tornado[:10]:
        print(f'{t[0]:14s} {t[1]:>5} -> {t[3]:.3f} | {t[2]:>5} -> {t[4]:.3f}')
