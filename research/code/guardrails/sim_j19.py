"""J19 as built: one looping acting agent for a day. The daily cap (20) counts every post and draft it sends
(008, agent_actions_today). Scores: J04 (jevs.js bands), J02 10 (GitHub-only owner), J01 0/15 (owner older / newer
than a day), J13 0/10 (region known / unknown), J19 (24 h window: 1 earlier 20, 2-3 45, 4+ 60). J18 and J19 are
ask-only (032): left out of the total and the top score; on their own they can raise low to medium, never to high.
Default thresholds (010): medium any >= 40 or total >= 70; high any >= 80 or total >= 140."""
def j04(last_hour, usual=3):
    if last_hour >= 60: return 85
    r = last_hour / max(3, usual)
    return 0 if r <= 1 else 20 if r <= 2 else 45 if r <= 4 else 70
def j19(n): return 60 if n >= 4 else 45 if n >= 2 else 20 if n >= 1 else 0
def level(others, ask, ask_only=True):
    if not ask_only: others = others + [ask]; ask = 0
    top, total = max(others), sum(others)
    lv = 'high' if top >= 80 or total >= 140 else 'medium' if top >= 40 or total >= 70 else 'low'
    return 'medium' if lv == 'low' and ask >= 40 else lv
def day(iv, j01, j13, use, ask_only=True):
    t, times, c = 0, [], {'low': 0, 'medium': 0, 'high': 0}
    while t < 86400 and len(times) < 20:
        hour = sum(1 for x in times if x > t - 3600); earlier = sum(1 for x in times if x > t - 86400)
        c[level([j04(hour + 1), 10, j01, j13], j19(earlier) if use else 0, ask_only)] += 1
        times.append(t); t += iv
    return c
worst = {'with J19, ask-only': 0, 'with J19 in the total (rejected)': 0}
print(f"{'loop every':>10} | {'today: live/owner/Aaron':>24} | {'J19 ask-only':>14} | {'J19 in total':>14}   (worst case: owner < 1 day old, region unknown)")
for iv in (10, 60, 300, 900, 3600, 14400):
    a = day(iv, 15, 10, False); b = day(iv, 15, 10, True); c = day(iv, 15, 10, True, False)
    worst['with J19, ask-only'] = max(worst['with J19, ask-only'], b['high']); worst['with J19 in the total (rejected)'] = max(worst['with J19 in the total (rejected)'], c['high'])
    f = lambda x: f"{x['low']:2}/{x['medium']:2}/{x['high']:2}"
    print(f"{iv:>9}s | {f(a):>24} | {f(b):>14} | {f(c):>14}")
print('most held for Aaron in a day by one loop:', worst)
