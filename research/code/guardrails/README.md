# Guardrails round 1: simulations (Oct 30, 2026)

The evidence behind migration 032 and api/_secrets.js (Aaron, Oct 30: "Okay lets build out your approach and run the
loop on it"). Run from this folder: `node sim-j18.js > sim-j18-results.json` and `python3 sim_j19.py`.

- **sim-j18.js:** the key detector against 16 kinds of ordinary and technical text (2,000 each, generated) and 16 key
  formats written 8 ways; an entropy-only detector for comparison; contact masking run first; hostile-input timing.
  Result: no false alarms in any ordinary category; every format caught when written whole; none caught when split or
  reversed (a known miss, RK97); entropy-only flagged 96 to 100% of digests, base64, URL tokens and public keys;
  contact masking first broke Slack tokens and database passwords, so keys are hidden first. Limits: the generator
  encodes the same formats as the patterns, so the catch rate shows the patterns match their own specification, not
  that every real key format is covered (the fresh review).
- **sim_j19.py:** one looping agent for a day under the real daily cap (every post and draft counts, 008), with the
  worst-case other scores; J19 summed into the total against J19 ask-only. Result: today, loops every 15 minutes or
  slower get all 20 posts live; with J19 at most 2 go live at any speed tested (10 s to 4 h); summed, up to 14 a day
  would be held for Aaron; ask-only, none. The scores and thresholds are the defaults in 010 and db/jevs.js.
