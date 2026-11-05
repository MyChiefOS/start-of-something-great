// /citizens/<handle> (vercel.json rewrites it to /citizen): a citizen of the leaderboard, from the data
// scripts/build-data.js writes into /work-data.js (window.DOG_WORK) before each commit. The project has two citizens so
// far, Claude and Aaron. No request is made; everything is written with textContent.
(function () {
  var W = window.DOG_WORK;
  var name = document.getElementById('c-name');
  var dek = document.getElementById('c-dek');
  var body = document.getElementById('c-body');
  var crumb = document.getElementById('crumb-name');
  var MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }
  function link(href, text, cls) { var a = el('a', cls || '', text); a.href = href; return a; }
  function date(iso) { var d = new Date(iso); return MON[d.getUTCMonth()] + ' ' + d.getUTCDate() + ', ' + d.getUTCFullYear(); }
  function n(x) { return x.toLocaleString('en-US'); }
  function pct(x) { return String(Math.round(x * 1000) / 10).replace(/\.0$/, '') + '%'; }
  function none(heading, text) {
    name.textContent = heading;
    crumb.textContent = heading;
    dek.textContent = text + ' ';
    dek.appendChild(link('/leaderboard', 'See everyone on the Leaderboard.'));
  }
  if (!W) { none('Citizen profile', 'The profile data could not be loaded.'); return; }
  var m = location.pathname.match(/^\/citizens\/([a-z0-9-]{1,40})\/?$/);
  if (!m) { none('Choose a citizen', 'This address doesn’t name a citizen.'); return; }
  var c = Object.prototype.hasOwnProperty.call(W.citizens, m[1]) ? W.citizens[m[1]] : null;
  if (!c) { none('No such citizen', 'Nobody called ' + m[1] + ' has worked on the project yet.'); return; }
  var pr = function (num) { return W.prs.filter(function (p) { return p.number === num; })[0]; };
  var agent = c.type === 'Agent';

  document.title = c.name + ': Citizen profile: Day One Great';
  name.textContent = c.name;
  crumb.textContent = c.name;
  dek.textContent = (agent ? 'An AI agent. ' : 'A person. ') + c.role + ' No rank: no season has started.';

  // The design's four cards: rank (a band instead, spec 4.1), impact, merged, revert rate.
  var stats = document.getElementById('c-stats');
  function card(value, label, word) {
    var d = el('div', 'card');
    d.appendChild(el('span', 'num' + (word ? ' word' : ''), value));
    d.appendChild(el('p', 'fine', label));
    stats.appendChild(d);
  }
  card(c.band, 'band: under 10 audited items', true);
  card('Not measured', 'impact: needs audits', true);
  if (agent) card(n(c.merged), 'merged pull requests');
  else card(n(c.sign_offs), 'sign-offs: pull requests he merged');
  if (c.revert) card(pct(c.revert.rate), 'revert rate, public: ' + c.revert.k + ' of ' + c.revert.n + ' (95% interval ' + pct(c.revert.lo) + ' to ' + pct(c.revert.hi) + ')');
  else card('None', 'revert rate: no merged diffs of his own', true);

  var facts = document.getElementById('c-facts');
  function row(term, value) {
    facts.appendChild(el('dt', '', term));
    var dd = el('dd');
    (Array.isArray(value) ? value : [value]).forEach(function (v) { dd.appendChild(typeof v === 'string' ? document.createTextNode(v) : v); });
    facts.appendChild(dd);
  }
  row('Passport', 'Not issued yet: passports come with the log (phase 2)');
  if (agent) {
    row('Work', n(c.commits) + ' commits · +' + n(c.additions) + ' −' + n(c.deletions) + ' lines, across ' + n(c.merged) + ' merged pull requests');
    row('Strongest', 'Not measured: needs audits (phase 5)');
    row('Weakest', 'Not measured: needs audits (phase 5)');
    row('Acts for', ['Day One Great; its work is merged by ', link('/citizens/aaron', 'Aaron Chandler')]);
  } else {
    row('Sign-offs', n(c.sign_offs) + ' merged pull requests, every one so far');
    row('Merged diffs', 'None of his own: every commit carries Claude’s marks, and his part is the decision and the merge');
    row('Works with', link('/citizens/claude', 'Claude'));
  }
  row('Streak', c.streak + (c.streak === 1 ? ' day' : ' days') + ' in a row with a merge, up to #' + W.as_of.pr);
  row('Audits', '0: no auditor role yet (phase 5)');

  var chain = document.getElementById('c-chain');
  var first = pr(c.first), last = pr(c.last);
  if (first && last) {
    chain.appendChild(link(first.url, '#' + first.number, 'pill m tn'));
    chain.appendChild(el('span', '', '→')).setAttribute('aria-hidden', 'true');
    chain.appendChild(el('span', 'pill m', '…'));
    chain.appendChild(el('span', '', '→')).setAttribute('aria-hidden', 'true');
    chain.appendChild(link(last.url, '#' + last.number, 'pill a tn'));
  }

  var recent = document.getElementById('c-recent');
  document.getElementById('c-recent-caption').textContent = agent ? 'The latest merged pull requests holding its commits' : 'The latest pull requests he merged';
  c.recent.forEach(function (num) {
    var p = pr(num);
    if (!p) return;
    var tr = el('tr');
    var a = el('td'); a.appendChild(link(p.url, '#' + p.number)); tr.appendChild(a);
    tr.appendChild(el('td', '', p.title));
    tr.appendChild(el('td', 'fine', 'Not audited yet'));
    var s = el('td'); s.appendChild(el('span', 'pill f', agent ? 'Merged' : 'Merged by him, ' + date(p.merged_at))); tr.appendChild(s);
    recent.appendChild(tr);
  });
  body.hidden = false;
}());
