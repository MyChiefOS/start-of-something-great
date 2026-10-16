// O1: at 1,000 members, how many hours a week does Aaron spend reviewing? A Monte Carlo of 10,000 weeks. Every input
// is drawn from a range (below) rather than fixed, so the answer shows how much the assumptions matter.
// Criterion: the average week is 6 hours or less, and 9 weeks in 10 are under 10 hours.
// Usage: node scripts/review-time-sim.js [weeks] [seed]
'use strict';

// A small seeded generator (mulberry32), so a run can be repeated exactly.
function rng(seed) {
  let a = seed >>> 0;
  return () => { a = (a + 0x6d2b79f5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
const uniform = (r, lo, hi) => lo + (hi - lo) * r();
// A count with the given mean (Poisson, by Knuth's method for small means and a normal approximation for large ones).
function poisson(r, mean) {
  if (mean > 50) return Math.max(0, Math.round(mean + Math.sqrt(mean) * Math.sqrt(-2 * Math.log(r() || 1e-12)) * Math.cos(2 * Math.PI * r())));
  const L = Math.exp(-mean); let k = 0, p = 1;
  do { k++; p *= r(); } while (p > L);
  return k - 1;
}

// The assumptions, each a range a week's value is drawn from. Sources and reasoning: research/review-time.md.
const RANGES = {
  members: [1000, 1000],
  newMembersPerWeek: [40, 160],     // growth at 1,000 members, about 4 to 16% a week
  lowLevelShare: [0.6, 0.9],        // new members joining at level 0 or 1 (email, GitHub, plain X)
  firstPostsPerNewMember: [0.8, 2.2], // of the 3 reviewed first posts, how many a new low-level member actually writes
  activeShare: [0.25, 0.55],        // members who post in a week
  postsPerActive: [1, 4],
  agentsPerMember: [0.1, 0.4],
  agentPostsPerAgent: [3, 15],      // live agent posts a week (after owners' approvals)
  reportRate: [0.002, 0.012],       // share of live posts reported
  secondsPerDecision: [12, 40],     // one tap on a phone, after reading the post and why it's there
  weeklyChecksMinutes: [20, 60],    // the numbers page, brakes, notes
  incidentChance: [0.05, 0.15],     // a spam wave or abuse case in a given week
  incidentHours: [1, 3]
};

function week(r) {
  const x = Object.fromEntries(Object.entries(RANGES).map(([k, [lo, hi]]) => [k, uniform(r, lo, hi)]));
  const newMembers = poisson(r, x.newMembersPerWeek);
  const firstPosts = poisson(r, newMembers * x.lowLevelShare * x.firstPostsPerNewMember);
  const livePosts = poisson(r, x.members * x.activeShare * x.postsPerActive) + poisson(r, x.members * x.agentsPerMember * x.agentPostsPerAgent);
  const reported = poisson(r, livePosts * x.reportRate);
  const decisions = firstPosts + reported;
  const incident = r() < x.incidentChance ? x.incidentHours : 0;
  return { hours: (decisions * x.secondsPerDecision) / 3600 + x.weeklyChecksMinutes / 60 + incident, decisions, firstPosts, reported, livePosts };
}

function simulate(weeks = 10000, seed = 20261016) {
  const r = rng(seed);
  const rows = Array.from({ length: weeks }, () => week(r));
  const hours = rows.map((w) => w.hours).sort((a, b) => a - b);
  const mean = hours.reduce((a, b) => a + b, 0) / weeks;
  const p90 = hours[Math.floor(0.9 * weeks)];
  const avg = (k) => rows.reduce((a, w) => a + w[k], 0) / weeks;
  return { weeks, seed, meanHours: mean, p90Hours: p90, maxHours: hours[weeks - 1], under10: hours.filter((h) => h < 10).length / weeks,
    avgDecisions: avg('decisions'), avgFirstPosts: avg('firstPosts'), avgReported: avg('reported'), avgLivePosts: avg('livePosts'),
    passes: mean <= 6 && hours.filter((h) => h < 10).length / weeks >= 0.9 };
}

if (require.main === module) {
  const out = simulate(Number(process.argv[2]) || 10000, Number(process.argv[3]) || 20261016);
  console.log(JSON.stringify(out, (k, v) => (typeof v === 'number' && !Number.isInteger(v) ? Math.round(v * 100) / 100 : v), 2));
  process.exit(out.passes ? 0 : 1);
}

module.exports = { simulate, RANGES };
