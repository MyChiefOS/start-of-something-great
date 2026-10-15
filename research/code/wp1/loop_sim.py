"""Day One Great Working Paper No. 1: Monte Carlo model of the five-step decision loop.

Each decision picks one of K options. The agent sees noisy, possibly stale, possibly biased value
estimates; it may misread the objective; the chosen plan may hide a material defect. Each loop step
is a remedy for one named error source (see the paper, section 4). Common random numbers are used
across policies so differences between policies are not sampling noise.
"""
import json, sys
import numpy as np

K = 4
BASE = dict(
    g=0.20,          # share of decisions that are game-changing (GC)
    stakes_gc=8.0,   # mean stakes of a GC decision relative to a routine one (=1)
    sigma=0.60,      # noise in the agent's value estimates (option spread = 1)
    phi=0.30,        # share of noise variance removed by simulation (step 2)
    sigma_b=0.50,    # shared-perspective blind spot, not removable by self-checks
    rho=0.77,        # error correlation between the agent and a same-family reviewer (Mueller et al. 2026)
    p_stale_gc=0.35, p_stale_rt=0.15,  # chance a key fact changed since training
    delta=1.50,      # how much a stale belief overrates one option
    d_research=0.60, # chance research catches the stale fact (step 1)
    p_mis=0.12,      # chance the objective is misread
    q_intent=0.50,   # chance the intent check catches a misread (step 4)
    q_intent_rev=0.30,  # chance the reviewer catches a misread the author missed (step 3)
    p_def_gc=0.50, p_def_rt=0.20,  # chance the chosen plan hides a material defect
    defect_cost=0.80,  # defect cost as a share of stakes
    q_self=0.20,     # chance a self-check catches the defect (step 4)
    q_rev=0.55,      # chance an independent reviewer catches it (step 3), before correlation
    h_base=0.15,     # chance the person catches a remaining defect from a bare answer
    h_loop=0.25,     # ... from a report with sources and assumptions (step 5)
    hm_base=0.30, hm_loop=0.45,  # chance the person catches a misread objective
    # Harms: each step can also make a decision worse.
    p_badsrc=0.05,   # research imports a misleading source that overrates one option
    p_misspec=0.10,  # the simulation's model is wrong: it overrates one option and still feels precise
    delta_m=1.00,    # size of that misspecification bias
    p_fa=0.10,       # the reviewer's false alarm talks the agent into its second-best option
    p_oc=0.05,       # the intent check 'corrects' a correct reading into a wrong one (harm of step 4)
    kappa=0.25,      # share of defects subtle enough that no AI check (self or reviewer) can catch them
)
# hours per decision: routine / game-changing
HOURS = dict(base=(0.5, 0.5), research=(0.25, 1.0), simulate=(0.25, 1.5), review=(0.5, 1.0),
             intent=(0.10, 0.25), share=(0.10, 0.25))
STEPS = ('research', 'simulate', 'review', 'intent', 'share')
LIGHT = {'research', 'simulate', 'intent', 'share'}
FULL = set(STEPS)
POLICIES = {
    'No loop': (set(), set()),
    'Light loop on every decision': (LIGHT, LIGHT),
    'Full loop on every decision': (FULL, FULL),
    'Tiered loop (adopted)': (LIGHT, FULL),
}
ABLATIONS = {f'Tiered without {s}': (LIGHT - {s}, FULL - {s}) for s in STEPS}


def draw(n, p, rng):
    """All random inputs for n decisions, shared by every policy (common random numbers)."""
    gc = rng.random(n) < p['g']
    s = np.where(gc, rng.lognormal(np.log(p['stakes_gc']) - 0.28, 0.75, n), 1.0)  # mean ~ stakes_gc
    V = rng.standard_normal((n, K)) * s[:, None]
    return dict(
        gc=gc, s=s, V=V,
        noise=rng.standard_normal((n, K)), noise_rev=rng.standard_normal((n, K)),
        b=rng.standard_normal((n, K)), b_ind=rng.standard_normal((n, K)),
        stale=rng.random(n) < np.where(gc, p['p_stale_gc'], p['p_stale_rt']),
        stale_opt=rng.integers(0, K, n), u_research=rng.random(n),
        mis=rng.random(n) < p['p_mis'], Z=rng.standard_normal((n, K)),
        u_int=rng.random(n), u_int_rev=rng.random(n), u_hm=rng.random(n),
        defect=rng.random(n) < np.where(gc, p['p_def_gc'], p['p_def_rt']),
        dcost=p['defect_cost'] * s * rng.uniform(0.5, 1.5, n),
        u_self=rng.random(n), u_rev=rng.random(n), u_h=rng.random(n),
        u_bad=rng.random(n), bad_opt=rng.integers(0, K, n), u_ms=rng.random(n), ms_opt=rng.integers(0, K, n),
        u_fa=rng.random(n), u_oc=rng.random(n), u_oc_h=rng.random(n), subtle=rng.random(n),
    )


def run(d, p, steps_rt, steps_gc):
    gc, s, V = d['gc'], d['s'], d['V']
    n = len(s)
    on = {k: np.where(gc, k in steps_gc, k in steps_rt) for k in STEPS}
    # Step 2: simulation removes a share of estimation noise.
    sig = p['sigma'] * np.where(on['simulate'], np.sqrt(1 - p['phi']), 1.0)
    # Step 3: averaging with an independent reviewer halves independent noise and shrinks the blind spot.
    rho = p['rho']
    b_rev = rho * d['b'] + np.sqrt(1 - rho ** 2) * d['b_ind']
    rev = on['review'][:, None]
    noise = np.where(rev, (d['noise'] + d['noise_rev']) / 2, d['noise']) * sig[:, None]
    blind = np.where(rev, (d['b'] + b_rev) / 2, d['b']) * p['sigma_b']
    err = (noise + blind) * s[:, None]
    # Step 1: a stale fact overrates one option unless research catches it.
    stale_left = d['stale'] & ~(on['research'] & (d['u_research'] < p['d_research']))
    bump = np.zeros((n, K))
    bump[np.arange(n), d['stale_opt']] = p['delta']
    err = err + np.where(stale_left[:, None], bump * s[:, None], 0.0)
    # Harms of steps 1 and 2: a misleading source, or a wrong simulation model, overrates one option.
    for flag, opt, size in ((on['research'] & (d['u_bad'] < p['p_badsrc']), d['bad_opt'], p['delta']),
                            (on['simulate'] & (d['u_ms'] < p['p_misspec']), d['ms_opt'], p['delta_m'])):
        harm = np.zeros((n, K)); harm[np.arange(n), opt] = size
        err = err + np.where(flag[:, None], harm * s[:, None], 0.0)
    # Misread objective: the agent optimises a different value vector unless someone catches it.
    caught_mis = (on['intent'] & (d['u_int'] < p['q_intent'])) | \
                 (on['review'] & (d['u_int_rev'] < p['q_intent_rev'] * (1 - 0.5 * rho))) | \
                 (d['u_hm'] < np.where(on['share'], p['hm_loop'], p['hm_base']))
    V_mis = 0.3 * V + np.sqrt(1 - 0.09) * d['Z'] * s[:, None]
    # Harm of step 4: over-correction turns a correct reading into a wrong one, unless the person notices.
    overcorrect = on['intent'] & ~d['mis'] & (d['u_oc'] < p['p_oc']) & \
                  ~(d['u_oc_h'] < np.where(on['share'], p['hm_loop'], p['hm_base']))
    target = np.where(((d['mis'] & ~caught_mis) | overcorrect)[:, None], V_mis, V)
    est = target + err
    order = np.argsort(-est, axis=1)
    # Harm of step 3: a false alarm moves the choice to the agent's second-best option.
    fa = on['review'] & (d['u_fa'] < p['p_fa'])
    choice = np.where(fa, order[:, 1], order[:, 0])
    regret = V.max(axis=1) - V[np.arange(n), choice]
    # Hidden defect in the chosen plan: caught by a self-check, a reviewer, or the person; rework if caught.
    # Subtle defects (share kappa) defeat every AI check at once: detection is correlated, not independent.
    ai_ok = d['subtle'] >= p['kappa']
    caught = (ai_ok & on['intent'] & (d['u_self'] < p['q_self'])) | \
             (ai_ok & on['review'] & (d['u_rev'] < p['q_rev'] * (1 - 0.5 * rho))) | \
             (d['u_h'] < np.where(on['share'], p['h_loop'], p['h_base']))
    defect_loss = np.where(d['defect'], np.where(caught, 0.1, 1.0) * d['dcost'], 0.0)
    loss = regret + defect_loss
    hours = np.where(gc, HOURS['base'][1], HOURS['base'][0]).astype(float)
    for k in STEPS:
        hours += np.where(on[k], np.where(gc, HOURS[k][1], HOURS[k][0]), 0.0)
    severe = gc & (loss > 1.0 * s)
    return dict(loss=loss, hours=hours, gc=gc, severe=severe, defect_missed=d['defect'] & ~caught)


def summarise(res):
    gc = res['gc']
    return dict(loss=res['loss'].mean(), loss_gc=res['loss'][gc].mean(), loss_rt=res['loss'][~gc].mean(),
                hours=res['hours'].mean(), severe_gc=res['severe'][gc].mean(),
                missed_defects=res['defect_missed'].mean())


def main(reps=40, n=5000, seed=20261015):
    rng = np.random.default_rng(seed)
    allp = {**POLICIES, **ABLATIONS}
    out = {k: [] for k in allp}
    for _ in range(reps):
        d = draw(n, BASE, rng)
        for name, (rt, gcs) in allp.items():
            out[name].append(summarise(run(d, BASE, rt, gcs)))
    table = {}
    base = np.array([r['loss'] for r in out['No loop']])
    for name, rows in out.items():
        cols = {k: np.array([r[k] for r in rows]) for k in rows[0]}
        red = 1 - cols['loss'] / base
        table[name] = {k: (float(v.mean()), float(1.96 * v.std(ddof=1) / np.sqrt(reps))) for k, v in cols.items()}
        table[name]['loss_reduction'] = (float(red.mean()), float(1.96 * red.std(ddof=1) / np.sqrt(reps)))
    json.dump(table, open(sys.argv[1] if len(sys.argv) > 1 else 'results.json', 'w'), indent=1)
    for name, t in table.items():
        print(f"{name:34s} loss {t['loss'][0]:.3f}±{t['loss'][1]:.3f}  reduction {100*t['loss_reduction'][0]:5.1f}%±{100*t['loss_reduction'][1]:.1f}"
              f"  GC severe {100*t['severe_gc'][0]:5.1f}%  missed defects {100*t['missed_defects'][0]:5.1f}%  hours {t['hours'][0]:.2f}")


if __name__ == '__main__':
    main()
