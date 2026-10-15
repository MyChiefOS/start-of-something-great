// Research section: Working Paper No. 1 is findable, readable without JavaScript, and says only what its code shows.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const wp1 = (f) => JSON.parse(read(path.join('research', 'code', 'wp1', 'results', f)));
const paper = () => read('research/decision-loop.html');
const text = (html) => html.replace(/<script[\s\S]*?<\/script>/g, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');

test('research pages are in the sitemap, the site search and llms.txt', () => {
  const sitemap = read('sitemap.xml');
  const { pages } = require(path.join(root, 'api', '_lib.js'));
  for (const p of ['/research', '/research/decision-loop']) {
    assert.ok(sitemap.includes('<loc>https://dayonegreat.com' + p + '</loc>'), p + ' missing from sitemap.xml');
    assert.ok(pages.some((x) => x.path === p), p + ' missing from the site search');
  }
  assert.ok(read('llms.txt').includes('https://dayonegreat.com/research/decision-loop'));
});

test('every page links to Research in its main navigation', () => {
  const files = fs.readdirSync(root).filter((f) => f.endsWith('.html') && f !== '404.html').concat(['research/decision-loop.html']);
  for (const f of files) {
    const nav = (read(f).match(/<nav class="site-nav"[\s\S]*?<\/nav>/) || [''])[0];
    assert.ok(nav.includes('href="/research"'), f + ' has no Research link in its navigation');
  }
});

test('the paper carries the tags Google Scholar needs, and its abstract is visible without JavaScript', () => {
  const html = paper();
  for (const tag of ['citation_title', 'citation_author', 'citation_publication_date', 'citation_technical_report_institution']) {
    assert.match(html, new RegExp('<meta name="' + tag + '" content="[^"]+">'), tag);
  }
  assert.match(html, /<meta name="citation_publication_date" content="\d{4}\/\d{2}\/\d{2}">/);
  assert.match(html, /<h2 id="abstract">Abstract<\/h2>\s*<p>At base settings/);
  assert.ok(!/<script(?![^>]*(application\/ld\+json|_vercel\/insights))/.test(html), 'the paper must not need JavaScript');
  const ld = JSON.parse(html.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/)[1]);
  assert.strictEqual(ld['@type'], 'ScholarlyArticle');
});

test('the paper states its review status and has no unfinished sections', () => {
  const t = text(paper());
  assert.ok(t.includes('not externally peer reviewed'));
  assert.ok(t.includes('Review and responses'));
  assert.ok(!/pending|TODO|TBD/i.test(t));
});

test('every figure has a text alternative, and every equation is native math, not an image', () => {
  const html = paper();
  const figs = html.match(/<svg class="fig"[\s\S]*?<\/svg>/g) || [];
  assert.strictEqual(figs.length, 5);
  for (const f of figs) {
    assert.match(f, /role="img" aria-labelledby="[\w-]+-t [\w-]+-d"/);
    assert.match(f, /<title id="[\w-]+-t">[^<]+<\/title><desc id="[\w-]+-d">[^<]{40,}<\/desc>/);
  }
  assert.strictEqual((html.match(/<math xmlns="http:\/\/www\.w3\.org\/1998\/Math\/MathML" display="block">/g) || []).length, 7);
});

test('the numbers in the abstract and results match the stored model results', () => {
  const t = text(paper());
  const res = wp1('results.json'), sens = wp1('sensitivity.json').summary, fin = wp1('final_numbers.json');
  const pct = (x) => (100 * x).toFixed(1) + '%';
  const r = (k) => res[k].loss_reduction[0];
  for (const v of [pct(r('Tiered loop (adopted)')), pct(r('Full loop on every decision')), pct(r('Light loop on every decision')),
    pct(sens['P(tiered reduces loss)']), pct(sens.red_tiered[2]), pct(sens.red_tiered[4]),
    pct(res['No loop'].severe_gc[0]), pct(res['Tiered loop (adopted)'].severe_gc[0])]) {
    assert.ok(t.includes(v), v + ' not found in the paper');
  }
  assert.ok(t.includes((100 * sens.red_tiered[0]).toFixed(1).replace('-', '−') + '%'), 'lower end of the 90% range');
  const share = r('Tiered loop (adopted)') / r('Full loop on every decision');
  assert.ok(t.includes(Math.round(100 * share) + '% of the full loop'), 'share of the full benefit');
  const curve = fin.curve, cross = (k) => { const i = curve.findIndex((c) => c[k] < 0), a = curve[i - 1], b = curve[i]; return a.fa + a[k] / (a[k] - b[k]) * (b.fa - a.fa); };
  assert.ok(t.includes('about ' + Math.round(100 * cross('gc')) + '%'), 'game-changing review break-even');
  assert.ok(t.includes('about ' + Math.round(100 * cross('rt')) + '%'), 'routine review break-even');
  for (const [step, [pts]] of Object.entries(fin.ablation)) assert.ok(t.includes(pts.toFixed(1)), step + ' step value ' + pts.toFixed(1));
});

test('every percentage in the abstract comes from the stored model results', () => {
  const html = paper();
  const abs = text(html.slice(html.indexOf('<h2 id="abstract">'), html.indexOf('<h2 id="introduction">')));
  const res = wp1('results.json'), sens = wp1('sensitivity.json').summary, fin = wp1('final_numbers.json');
  const r = (k) => res[k].loss_reduction[0];
  const curve = fin.curve, cross = (k) => { const i = curve.findIndex((c) => c[k] < 0), a = curve[i - 1], b = curve[i]; return a.fa + a[k] / (a[k] - b[k]) * (b.fa - a.fa); };
  const H = (k) => res[k].hours[0];
  const allowed = new Set([
    (100 * r('Tiered loop (adopted)')).toFixed(1), String(Math.round(100 * r('Tiered loop (adopted)') / r('Full loop on every decision'))),
    String(Math.round(100 * (H('Tiered loop (adopted)') - H('No loop')) / (H('Full loop on every decision') - H('No loop')))),
    (100 * sens.red_tiered[2]).toFixed(1), (100 * sens.red_tiered[0]).toFixed(1).replace('-', '−'), (100 * sens.red_tiered[4]).toFixed(1),
    (100 * sens['P(tiered reduces loss)']).toFixed(1), String(Math.round(100 * cross('gc'))),
    String(Math.round(100 * (1 - 0.424))), // share of settings where review on game-changing decisions helps (review_harm.py prints 0.424)
    '90' // names the interval ("the middle 90%"), not a result
  ]);
  const found = [...abs.matchAll(/(−?\d+(?:\.\d+)?)%/g)].map((m) => m[1]);
  assert.ok(found.length >= 8, 'expected the abstract to state its results');
  for (const v of found) assert.ok(allowed.has(v), v + '% in the abstract does not match the stored results');
});

test('the paper links only to https sources and to the code that reproduces it', () => {
  const html = paper();
  for (const m of html.matchAll(/<a href="([^"]+)"/g)) assert.ok(/^(https:\/\/|\/|#|mailto:)/.test(m[1]), 'bad link ' + m[1]);
  assert.ok(html.includes('https://github.com/MyChiefOS/start-of-something-great/tree/main/research/code/wp1'));
  for (const f of ['loop_sim.py', 'sensitivity.py', 'final_numbers.py', 'review_harm.py', 'figures.py']) {
    assert.ok(fs.existsSync(path.join(root, 'research', 'code', 'wp1', f)), f);
  }
});

test('the figures on the page are exactly what figures.py draws from the stored results', () => {
  const out = require('child_process').execFileSync('python3', ['-c',
    'import sys, json; sys.path.insert(0, "research/code/wp1"); from figures import build_figures; print(json.dumps(build_figures()))'], { cwd: root });
  const figs = JSON.parse(out.toString());
  const html = paper();
  for (const [name, svg] of Object.entries(figs)) assert.ok(html.includes(svg), 'figure ' + name + ' on the page differs from figures.py');
});
