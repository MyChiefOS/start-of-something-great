"""Section 8: how often adding review makes results worse, across 3,000 random parameter settings."""
import numpy as np
import loop_sim as M, sensitivity as S
rng = np.random.default_rng(7)
rt, gc = [], []
for _ in range(3000):
    p = dict(M.BASE)
    for k, (lo, hi) in S.RANGES.items():
        p[k] = rng.uniform(lo, hi)
    r = S.evaluate(p, rng.uniform(0.5, 2.0), 2000, rng)
    rt.append(r['Tiered loop (adopted)']['loss'] - r['Full loop on every decision']['loss'])
    gc.append(r['Light loop on every decision']['loss'] - r['Tiered loop (adopted)']['loss'])
print('P(routine review hurts)', round(float(np.mean(np.array(rt) < 0)), 3), ' P(game-changing review hurts)', round(float(np.mean(np.array(gc) < 0)), 3))
