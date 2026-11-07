// The team page (Aaron, Oct 30: "create a team page for the website… You will be in charge of those decisions").
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');

test('/team shows the four members, each with an avatar served from this site', () => {
  const html = read('team.html');
  for (const [name, img] of [['Aaron Chandler', 'aaron'], ['Claude', 'claude'], ['JEVs', 'jevs'], ['Second Look', 'second-look']]) {
    assert.match(html, new RegExp('<h2>' + name + '</h2>'), name);
    // The design handoff of Nov 5, 2026: each in the 72 px amber ring (design.css .av), with the live site's own emblem.
    assert.match(html, new RegExp('<img class="av" src="/images/team/' + img + '\\.svg" alt="" width="72" height="72">'), img);
    const svg = read('images/team/' + img + '.svg');
    assert.match(svg, /^<svg[^>]*xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);
    assert.ok(!/<script|href="http|xlink:href="http|<image|<foreignObject/i.test(svg), img + ': nothing loaded or run from an SVG');
  }
});

test('/team says plainly what is live and what is not, and keeps the Anthropic notice', () => {
  const html = read('team.html');
  assert.match(html, /Our automatic checks · live/);
  assert.match(html, /A narrow AI · live/); // Second Look, on since 047
  assert.match(html, /A narrow AI for audits · live/); // Third Look, on since 047
  assert.match(html, /Day One Great is not affiliated with or endorsed by Anthropic\./);
  assert.match(html, /no AI decides/);
  // Aaron, Oct 30: Second Look decides within limits, and the page says how the decision was made. The limits in the
  // design handoff's words (Nov 5); the market sentence below is Aaron's own (harness/FACTS.md), so it stays as he said it.
  assert.match(html, /It may clear an easy held post, and never hides, removes or bans anything/);
  assert.match(html, /We reviewed the market first: how other AI agent platforms \(Meta, OpenAI, xAI and Anthropic\) handle risky actions\. We compared their approaches with Day One Great&rsquo;s, learned from the risks we found, and made an informed decision\./);
});

test('/team is reachable: home links it, and the search list, sitemap and llms.txt name it', () => {
  assert.match(read('index.html'), /<a href="\/team">Meet the team<\/a>/);
  assert.match(read('api/_lib.js'), /path: '\/team', title: 'The team'/);
  assert.match(read('sitemap.xml'), /<loc>https:\/\/dayonegreat\.com\/team<\/loc>/);
  assert.match(read('llms.txt'), /\[The team\]\(https:\/\/dayonegreat\.com\/team\)/);
});
