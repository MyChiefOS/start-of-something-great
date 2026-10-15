"""Draws the five figures of Working Paper No. 1 as inline SVG, from the stored results.

Run from the repository root: python3 research/code/wp1/figures.py
It prints nothing; build_figures() returns {name: svg} for the page builder.
Colours come from CSS classes in styles.css (.fig-*), so every figure follows the site's light and dark themes.
"""
import json, os
from html import escape

HERE = os.path.dirname(os.path.abspath(__file__))
R = lambda name: json.load(open(os.path.join(HERE, 'results', name)))


def svg(name, title, desc, w, h, body):
    return (f'<svg class="fig" viewBox="0 0 {w} {h}" role="img" aria-labelledby="{name}-t {name}-d">'
            f'<title id="{name}-t">{escape(title)}</title><desc id="{name}-d">{escape(desc)}</desc>{body}</svg>')


def t(x, y, s, cls='fig-text', anchor='start', size=12.5, weight=None):
    wt = f' font-weight="{weight}"' if weight else ''
    return f'<text x="{x:.1f}" y="{y:.1f}" class="{cls}" text-anchor="{anchor}" font-size="{size}"{wt}>{escape(s)}</text>'


def loop_diagram():
    W, H = 86, 56
    ya, yb = 110, 240
    xs = dict(x1=248, x2=348, x3=448, x4=548, x5=648)
    c = lambda x: x + W / 2
    out = ['<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
           '<path d="M0 0L10 5L0 10z" class="fig-axis-fill"/></marker></defs>']
    out.append(t(24, 30, 'Every decision gets four steps; game-changing ones add an independent review', size=15, weight=600))
    out.append(t(248, 70, 'Game-changing: all five steps', 'fig-quiet', size=11.5))
    out.append(t(248, 294, 'Everything else: steps 1, 2, 4 and 5', 'fig-quiet', size=11.5))
    paths = ['M104 175H114', f'M172 135V{ya}H248', f'M172 215V{yb}H248']
    for a, b in (('x1', 'x2'), ('x2', 'x3'), ('x3', 'x4'), ('x4', 'x5')):
        paths.append(f'M{xs[a] + W} {ya}H{xs[b]}')
    for a, b in (('x1', 'x2'), ('x2', 'x4'), ('x4', 'x5')):
        paths.append(f'M{xs[a] + W} {yb}H{xs[b]}')
    out.append('<g class="fig-line">' + ''.join(f'<path d="{p}" marker-end="url(#arr)"/>' for p in paths) + '</g>')
    out.append('<rect x="24" y="147" width="80" height="56" rx="8" class="fig-box"/>' + t(64, 179, 'Request', anchor='middle', weight=600))
    out.append('<polygon points="116,175 172,135 228,175 172,215" class="fig-box"/>' + t(172, 172, 'Game-', anchor='middle', size=12) + t(172, 187, 'changing?', anchor='middle', size=12))
    out.append(t(196, 102, 'yes', 'fig-quiet', size=11.5) + t(196, 256, 'no', 'fig-quiet', size=11.5))

    def step(x, y, n, lines, accent=False):
        g = [f'<rect x="{x}" y="{y - H / 2}" width="{W}" height="{H}" rx="8" class="{"fig-box-accent" if accent else "fig-box"}"/>']
        top = y - 6 if len(lines) == 1 else y - 12
        g.append(t(c(x), top, f'Step {n}', 'fig-quiet', 'middle', 11))
        for i, s in enumerate(lines):
            g.append(t(c(x), (y + 12) if len(lines) == 1 else (y + 4 + 15 * i), s, anchor='middle', weight=600))
        return ''.join(g)
    out += [step(xs['x1'], ya, 1, ['Research']), step(xs['x2'], ya, 2, ['Simulate']), step(xs['x3'], ya, 3, ['Fresh-agent', 'review'], True),
            step(xs['x4'], ya, 4, ['Intent', 'check']), step(xs['x5'], ya, 5, ['Report'])]
    out += [step(xs['x1'], yb, 1, ['Research']), step(xs['x2'], yb, 2, ['Simulate']), t(c(xs['x3']), yb - 8, 'review skipped', 'fig-quiet', 'middle', 11.5),
            step(xs['x4'], yb, 4, ['Intent', 'check']), step(xs['x5'], yb, 5, ['Report'])]
    out.append('<rect x="24" y="310" width="712" height="50" rx="8" class="fig-band"/>')
    out.append(t(40, 331, 'The gate: a decision is game-changing if it is hard or expensive to reverse; touches strategy, money,', size=11.5))
    out.append(t(40, 349, 'legal matters, security or people’s data; or is something we would announce publicly.', size=11.5))
    return svg('fig-loop', 'The Day One Great decision loop',
               'Every request passes a gate. Game-changing decisions go through research, simulation, a fresh-agent review, an intent check and a report. '
               'Everything else skips the review.', 760, 372, ''.join(out))


def forest():
    res, sens = R('results.json'), R('sensitivity.json')['summary']
    rows = [('Full loop on every decision', 'Full loop on every decision', 'red_full', False),
            ('Tiered loop (adopted)', 'Tiered loop (adopted)', 'red_tiered', True),
            ('Light loop on every decision', 'Light loop on every decision', 'red_light', False)]
    X = lambda v: 340 + (v + 15) / 55 * 360
    out = [t(24, 30, 'At base, the tiered loop keeps 98% of the full loop’s benefit for 77% of its added time', size=15, weight=600),
           t(24, 50, 'Dot: loss reduction at base parameters. Bar: middle 90% of 10,000 random parameter settings.', 'fig-quiet', size=11.5)]
    for v in range(-10, 41, 10):
        out.append(f'<line x1="{X(v):.1f}" x2="{X(v):.1f}" y1="84" y2="272" class="{"fig-zero" if v == 0 else "fig-grid"}"/>')
        out.append(t(X(v), 292, f'{v}%', 'fig-quiet', 'middle', 11.5))
    out.append(t(X(0) - 6, 80, 'worse than no loop', 'fig-quiet', 'end', 11))
    out.append(t(520, 316, 'Loss reduction against no loop', 'fig-quiet', 'middle', 11.5))
    desc = []
    for i, (name, key, sk, acc) in enumerate(rows):
        y = 120 + i * 56
        base = 100 * res[key]['loss_reduction'][0]
        hours = res[key]['hours'][0]
        lo, hi = 100 * sens[sk][0], 100 * sens[sk][4]
        cls = 'fig-accent' if acc else 'fig-mute'
        out.append(t(324, y - 2, name, anchor='end', weight=600 if acc else None))
        out.append(t(324, y + 15, f'{hours:.2f} hours per decision', 'fig-quiet', 'end', 11.5))
        out.append(f'<line x1="{X(lo):.1f}" x2="{X(hi):.1f}" y1="{y}" y2="{y}" class="{cls}-range"/>')
        out.append(f'<circle cx="{X(base):.1f}" cy="{y}" r="7" class="{cls}"/>')
        out.append(t(X(hi) + 10, y + 4, f'{base:.1f}%', size=12, weight=600 if acc else None))
        desc.append(f'{name}: {base:.1f}% at base, middle 90% of settings {lo:.1f}% to {hi:.1f}%, {hours:.2f} hours per decision.')
    return svg('fig-forest', 'Loss reduction by policy', ' '.join(desc), 760, 340, ''.join(out))


def ablation():
    a = R('final_numbers.json')['ablation']
    names = {'share': 'Report with sources', 'intent': 'Intent check', 'review': 'Independent review (game-changing only)',
             'research': 'Research', 'simulate': 'Simulation'}
    rows = sorted(a.items(), key=lambda kv: -kv[1][0])
    X = lambda v: 300 + v / 6 * 380
    out = [t(24, 30, 'No single step carries the loop: four steps add 4 to 5 points each', size=15, weight=600),
           t(24, 50, 'Points of loss reduction lost when one step is removed from the tiered loop, base parameters, 95% simulation intervals', 'fig-quiet', size=11.5)]
    for v in (0, 2, 4, 6):
        out.append(f'<line x1="{X(v):.1f}" x2="{X(v):.1f}" y1="76" y2="300" class="fig-grid"/>' + t(X(v), 320, str(v), 'fig-quiet', 'middle', 11.5))
    out.append(t(490, 342, 'Percentage points of loss reduction', 'fig-quiet', 'middle', 11.5))
    desc = []
    for i, (k, (pts, ci)) in enumerate(rows):
        y = 100 + i * 44
        cls = 'fig-mute' if k == 'simulate' else 'fig-accent'
        out.append(t(284, y + 4, names[k], anchor='end'))
        out.append(f'<rect x="300" y="{y - 12}" width="{X(pts) - 300:.1f}" height="24" rx="3" class="{cls}"/>')
        out.append(f'<line x1="{X(pts - ci):.1f}" x2="{X(pts + ci):.1f}" y1="{y}" y2="{y}" class="fig-whisker"/>')
        out.append(t(X(pts + ci) + 8, y + 4, f'{pts:.1f}', size=12))
        desc.append(f'{names[k]}: {pts:.1f} points, plus or minus {ci:.1f}.')
    return svg('fig-steps', 'What each step adds', ' '.join(desc), 760, 360, ''.join(out))


def breakeven():
    curve = R('final_numbers.json')['curve']
    X = lambda f: 96 + f / 0.4 * 580
    Y = lambda v: 330 - (v + 0.22) / 0.39 * 234

    def cross(k):
        for a, b in zip(curve, curve[1:]):
            if a[k] > 0 >= b[k]:
                return a['fa'] + a[k] / (a[k] - b[k]) * (b['fa'] - a['fa'])
    cg, cr = cross('gc'), cross('rt')
    out = [t(24, 30, f'Review stops reducing loss once false alarms pass {round(100 * cg)}% on big calls, {round(100 * cr)}% on routine ones', size=15, weight=600),
           t(24, 50, 'Loss avoided per decision by adding review, before counting its time; same-family reviewer (ρ = 0.77)', 'fig-quiet', size=11.5),
           t(24, 80, 'Loss avoided per decision', 'fig-quiet', size=11.5)]
    for i in range(8):
        v = -0.2 + i * 0.05
        out.append(f'<line x1="96" x2="676" y1="{Y(v):.1f}" y2="{Y(v):.1f}" class="fig-grid"/>' + t(86, Y(v) + 4, f'{v:.2f}', 'fig-quiet', 'end', 11.5))
    out.append(f'<line x1="96" x2="676" y1="{Y(0):.1f}" y2="{Y(0):.1f}" class="fig-zero"/>')
    for i in range(5):
        out.append(t(X(i * 0.1), 352, f'{i * 10}%', 'fig-quiet', 'middle', 11.5))
    out.append(t(386, 378, 'Reviewer false-alarm rate', 'fig-quiet', 'middle', 11.5))
    out.append(f'<line x1="{X(0.1):.1f}" x2="{X(0.1):.1f}" y1="96" y2="330" class="fig-ref"/>' + t(X(0.1) + 6, 110, 'Base assumption: 10%', 'fig-quiet', size=11.5))
    for k, cls in (('gc', 'fig-accent'), ('rt', 'fig-mute')):
        d = ''.join(f'{"M" if i == 0 else "L"}{X(r["fa"]):.1f} {Y(r[k]):.1f}' for i, r in enumerate(curve))
        out.append(f'<path d="{d}" class="{cls}-line"/>')
        out.append(''.join(f'<circle cx="{X(r["fa"]):.1f}" cy="{Y(r[k]):.1f}" r="2.5" class="{cls}"/>' for r in curve))
    out.append(f'<path d="M{X(cg):.1f} {Y(0) - 6:.1f}l6 6l-6 6l-6 -6z" class="fig-accent"/>' + t(X(cg) + 10, Y(0) - 10, f'breaks even at {round(100 * cg)}%', size=12, weight=600))
    out.append(f'<path d="M{X(cr):.1f} {Y(0) - 6:.1f}l6 6l-6 6l-6 -6z" class="fig-mute"/>'
               f'<line x1="{X(cr):.1f}" x2="{X(cr) + 8:.1f}" y1="{Y(0) + 7:.1f}" y2="{Y(0) + 36:.1f}" class="fig-whisker-quiet"/>'
               + t(X(cr) + 10, Y(0) + 48, f'breaks even at {round(100 * cr)}%', size=12))
    out.append('<line x1="450" x2="474" y1="106" y2="106" class="fig-accent-line"/>' + t(482, 110, 'Review on game-changing decisions', size=12))
    out.append('<line x1="450" x2="474" y1="126" y2="126" class="fig-mute-line"/>' + t(482, 130, 'Review on routine decisions', size=12))
    desc = (f'Loss avoided by review falls as the reviewer false-alarm rate rises. On game-changing decisions it reaches zero at about {100 * cg:.0f}%; '
            f'on routine decisions at about {100 * cr:.0f}%. At 0% false alarms review avoids {curve[0]["gc"]:.3f} units per game-changing decision '
            f'and {curve[0]["rt"]:.3f} per routine one.')
    return svg('fig-breakeven', 'Review break-even by false-alarm rate', desc, 760, 400, ''.join(out))


def tornado():
    d = R('final_numbers.json')
    names = {'p_fa': ('Reviewer false-alarm rate', '0–40%'), 'h_loop': ('Person’s catch rate with a report', '10–40%'),
             'kappa': ('Defects no AI check can catch', '0–50%'), 'h_base': ('Person’s catch rate, bare answer', '10–30%'),
             'sigma_b': ('Shared blind spot', '0.2–0.8'), 'defect_cost': ('Defect cost', '0.4–1.5× stakes'),
             'p_oc': ('Intent-check over-correction', '0–15%'), 'q_rev': ('Reviewer catch rate', '30–80%')}
    rows = d['tornado'][:8]
    base = 100 * d['oat_base']
    X = lambda v: 340 + v / 35 * 340
    top = rows[0]
    out = [t(24, 30, f'The reviewer’s false-alarm rate moves the benefit most, from {100 * top[3]:.1f}% to {100 * top[4]:.1f}%', size=15, weight=600),
           t(24, 50, 'Tiered loop’s loss reduction as one parameter moves across its range, all others at base', 'fig-quiet', size=11.5),
           '<rect x="24" y="66" width="14" height="12" class="fig-mute-soft"/>' + t(44, 76, 'parameter at the low end', 'fig-quiet', size=11.5),
           '<rect x="206" y="66" width="14" height="12" class="fig-mute"/>' + t(226, 76, 'at the high end', 'fig-quiet', size=11.5)]
    for v in range(0, 36, 5):
        out.append(f'<line x1="{X(v):.1f}" x2="{X(v):.1f}" y1="102" y2="382" class="fig-grid"/>' + t(X(v), 402, f'{v}%', 'fig-quiet', 'middle', 11.5))
    out.append(t(510, 426, 'Loss reduction from the tiered loop', 'fig-quiet', 'middle', 11.5))
    desc = []
    for i, (k, lo_v, hi_v, lo, hi) in enumerate(rows):
        y = 120 + i * 34
        lo, hi = 100 * lo, 100 * hi
        name, rng = names[k]
        acc = i == 0
        out.append(t(324, y + 4, f'{name} ({rng})', anchor='end', size=12))
        for v, soft in ((lo, True), (hi, False)):
            cls = ('fig-accent' if acc else 'fig-mute') + ('-soft' if soft else '')
            out.append(f'<rect x="{min(X(v), X(base)):.1f}" y="{y - 11}" width="{abs(X(v) - X(base)):.1f}" height="22" class="{cls}"/>')
        out.append(t(X(min(lo, hi)) - 6, y + 4, f'{min(lo, hi):.1f}', 'fig-quiet', 'end', 11.5))
        out.append(t(X(max(lo, hi)) + 6, y + 4, f'{max(lo, hi):.1f}', 'fig-quiet', size=11.5))
        desc.append(f'{name} ({rng}): {lo:.1f}% at the low end, {hi:.1f}% at the high end.')
    out.append(f'<line x1="{X(base):.1f}" x2="{X(base):.1f}" y1="100" y2="382" class="fig-zero"/>' + t(X(base), 94, f'base {base:.1f}%', anchor='middle', size=11.5))
    return svg('fig-tornado', 'Which assumptions move the result', f'Base {base:.1f}%. ' + ' '.join(desc), 760, 446, ''.join(out))


def build_figures():
    return {'loop': loop_diagram(), 'forest': forest(), 'steps': ablation(), 'breakeven': breakeven(), 'tornado': tornado()}


if __name__ == '__main__':
    for k, v in build_figures().items():
        print(k, len(v))
