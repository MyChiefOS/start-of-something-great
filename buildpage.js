// /build (042, with project plans from 050): the design handoff's Build page, filled from the work module's public
// reads. The hero, the chart, its pills and the figures are the featured project's plan (/api/work/plan, carried in the
// summary); the packages, the receipt, the board and the live lines are the summary itself; the hero's checkpoint is
// the public log's latest. Every name and word anyone wrote is drawn with textContent, never as HTML; links go only to
// our own pages and this repository. Its own small script, so the Build page doesn't load the other work pages' code.
(function () {
  'use strict';
  var $ = function (x) { return document.getElementById(x); };
  var HEX = '0123456789abcdef';
  function isId(x) {
    if (typeof x !== 'string' || x.length !== 36) return false;
    for (var i = 0; i < 36; i++) { var ch = x.charAt(i); if ((i === 8 || i === 13 || i === 18 || i === 23) ? ch !== '-' : HEX.indexOf(ch) < 0) return false; }
    return true;
  }
  function isSha(x) { if (typeof x !== 'string' || x.length !== 40) return false; for (var i = 0; i < 40; i++) if (HEX.indexOf(x.charAt(i)) < 0) return false; return true; }
  function slot(node, name) { return node.querySelector('[data-slot="' + name + '"]'); }
  function clone(id) { return $(id).content.firstElementChild.cloneNode(true); }
  function txt(x) { return x === null || x === undefined ? '' : String(x); }
  function n(x) { var v = Number(x); return Number.isFinite(v) ? v : 0; }
  function plural(k, one, many) { return k === 1 ? '1 ' + one : k + ' ' + (many || one + 's'); }
  function width(el, pct) { var w = Math.max(0, Math.min(100, Math.round(n(pct) / 5) * 5)); el.className = 'w' + w; }
  function clock(s) { return typeof s === 'string' && s.length >= 19 ? s.slice(11, 19) : ''; }
  var STATE = { open: ['Open', ''], claimed: ['Claimed', 'a'], submitted: ['Submitted', 'a'], audited: ['Auditing', 'a'], approved: ['Done', 'f'], closed: ['Closed', 'm'] };
  function pill(el, state) { var s = STATE[state] || [txt(state), '']; el.textContent = s[0]; el.className = 'pill' + (s[1] ? ' ' + s[1] : ''); }
  function who(c) {
    if (!c || typeof c !== 'object') return '';
    if (c.kind === 'agent') return txt(c.name) + (c.owner ? ', for ' + txt(c.owner.name) : '');
    return txt(c.name);
  }
  function whoEl(c) {
    var span = document.createElement('span');
    if (!c) { var i = document.createElement('i'); i.textContent = 'Unclaimed'; span.className = 'fine'; span.appendChild(i); return span; }
    span.textContent = who(c) + ' ';
    var p = document.createElement('span');
    p.className = 'pill m';
    p.textContent = c.kind === 'agent' ? 'Agent' : c.kind === 'github' ? 'GitHub' : 'Person';
    span.appendChild(p);
    return span;
  }
  function link(el, href, text) { el.textContent = text; if (href) el.href = href; else el.removeAttribute('href'); }
  function taskHref(t) { return t && isId(t.id) ? '/tasks/' + t.id : null; }
  function projectHref(p) { return p && isId(p.id) ? '/projects/' + p.id : null; }
  function get(path) {
    return fetch(path, { headers: { Accept: 'application/json' }, credentials: 'same-origin' })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, status: r.status, d: d }; }, function () { return { ok: false, status: r.status, d: {} }; }); });
  }
  function ago(iso) {
    var s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
    if (!Number.isFinite(s)) return '';
    return s < 60 ? s + 's ago' : s < 3600 ? Math.floor(s / 60) + ' min ago' : s < 86400 ? Math.floor(s / 3600) + ' h ago' : Math.floor(s / 86400) + ' days ago';
  }

  var plan = null;
  function drawPlan() {
    var P = window.DOGPlan;
    if (!P || !plan) return;
    P.chart($('plan-chart'), plan);
    P.pills($('plan-pills'), plan);
    var f = P.figures({ scope: 'f-scope', verified: 'f-verified', share: 'f-share', done: 'f-done', text: 'plan-text' }, plan);
    var pr = plan.project || {};
    // "See the plan": the featured project's page, where its chart, schedule index and forecast are (the Nov 7 canvas).
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(String(pr.id || ''))) $('plan-link').href = '/projects/' + pr.id;
    $('plan-of').textContent = 'Sizes of the tasks in ' + txt(pr.title) + ', each under the first milestone due on or after the day it was posted.';
    var pg = window.DOGProgress(plan);
    $('pct').textContent = pg.pct + '%';
    width($('pct-bar'), pg.pct);
    $('pct-note').textContent = pg.note;
  }
  var resized;
  window.addEventListener('resize', function () { clearTimeout(resized); resized = setTimeout(function () { if (plan && window.DOGPlan) window.DOGPlan.chart($('plan-chart'), plan); }, 150); });

  function build(d) {
    plan = d.plan || null;
    if (plan) drawPlan(); else { $('pct-note').textContent = 'No project has a plan yet.'; $('plan-text').textContent = 'No project has a plan yet: a project’s poster adds its milestones.'; }
    // Third Look's public figures (044): counts from 1 to 4 come back as null, so no one is singled out.
    var tl = d.third_look || {};
    var few = function (v) { return v === null ? 'fewer than 5' : String(n(v)); };
    $('tl-figures').textContent = tl.mode === 'off' ? 'It is switched off.'
      : !tl.checked && tl.checked !== null ? 'It hasn’t checked any yet.'
      : 'So far it has checked ' + few(tl.checked) + (tl.mode === 'on' ? ' and passed ' + few(tl.passed) : ', and would have passed ' + few(tl.would_pass))
        + '; ' + few(tl.disagreed) + ' of those were reversed or not passed. No usable answer: ' + few(tl.no_answer) + '.';
    var pk = $('packages');
    pk.textContent = '';
    (d.packages || []).forEach(function (p) {
      if (!p || !isId(p.id)) return;
      var row = clone('pkg-tpl');
      slot(row, 'room').textContent = txt(p.room && p.room.code);
      link(slot(row, 'title'), projectHref(p), txt(p.title));
      slot(row, 'by').textContent = who(p.poster);
      width(slot(row, 'bar'), p.percent);
      slot(row, 'pct').textContent = n(p.percent) + '%';
      var st = slot(row, 'state');
      if (n(p.tasks) > 0 && n(p.approved) === n(p.tasks)) { st.textContent = 'Shipped'; st.className = 'pill f'; }
      else if (n(p.claimed) + n(p.submitted) > 0) { st.textContent = 'In progress'; st.className = 'pill a'; } else pill(st, 'open');
      pk.appendChild(row);
    });
    $('packages-empty').hidden = pk.children.length > 0;
    // The latest receipt, in the design's rows.
    var r = d.latest_receipt;
    $('receipt').hidden = !r;
    $('receipt-empty').hidden = !!r;
    if (r) {
      $('r-anchor').textContent = r.anchored ? 'Anchored' : 'Waiting for a checkpoint';
      $('r-anchor').className = r.anchored ? 'pill f' : 'pill a';
      $('r-ref').textContent = 'R-' + n(r.seq);
      $('r-task').textContent = txt(r.task && r.task.ref) + ' · ' + txt(r.task && r.task.title);
      $('r-worker').textContent = who(r.worker);
      var a = r.artifact || {}, ch = r.changes;
      $('r-changes').textContent = a.kind === 'pr' && ch ? '+' + n(ch.additions) + ' −' + n(ch.deletions) + (isSha(ch.merge_sha) ? ' · ' + ch.merge_sha.slice(0, 7) : '')
        : a.kind === 'pr' ? 'A pull request in this repository' : a.kind === 'link' ? 'A link' : 'A file, by its SHA-256';
      $('r-proof').textContent = a.kind === 'pr' && ch ? 'Merged into ' + (txt(ch.base) || 'its branch') + (ch.merged_by ? ' by @' + txt(ch.merged_by) : '') : 'The work as submitted, sealed in the public log';
      $('r-audit').textContent = ({ jevs: 'The JEVs auditor’s rules', poster: 'The task’s poster', person: 'Aaron, as the repository’s owner', third_look: 'Third Look' }[r.decided_by] || 'The audit') + ', ' + n(r.confidence) + '% confidence';
      $('r-points').textContent = r.points === null || r.points === undefined ? '–' : n(r.points) + ' (no money value)';
      $('r-approved').textContent = r.approved_seq === null || r.approved_seq === undefined ? 'Waiting for the poster' : 'Entry ' + n(r.approved_seq);
      $('r-anchored').textContent = r.anchored ? 'Entry ' + n(r.seq) + ', in checkpoint ' + n(d.checkpoint) : 'Not yet: the log signs a checkpoint within a minute';
      $('r-open').href = '/receipts/' + n(r.seq);
    }
    // The board.
    var b = $('board');
    b.textContent = '';
    (d.board || []).forEach(function (t) {
      if (!t || !isId(t.id)) return;
      var tr = clone('row-tpl');
      slot(tr, 'ref').textContent = txt(t.ref);
      link(slot(tr, 'title'), taskHref(t), txt(t.title));
      slot(tr, 'who').appendChild(whoEl(t.done_by || t.worker));
      pill(slot(tr, 'state'), t.status);
      var rc = slot(tr, 'receipt');
      if (t.receipt !== null && t.receipt !== undefined) { var ra = document.createElement('a'); ra.href = '/receipts/' + n(t.receipt); ra.textContent = 'R-' + n(t.receipt); rc.appendChild(ra); }
      else if (t.status === 'open') { var ca = document.createElement('a'); ca.className = 'btn s'; ca.href = taskHref(t); ca.textContent = 'Claim'; rc.appendChild(ca); }
      else { rc.className = 'fine'; rc.textContent = 'pending'; }
      b.appendChild(tr);
    });
    $('board-empty').hidden = b.children.length > 0;
    // Live: the work's latest log entries, at the time they were written (UTC).
    var LIVE = { 'task.claimed': 'claimed a task', 'task.submitted': 'submitted work', 'audit.verdict': 'checked a submission', 'task.approved': 'approved a task' };
    var lv = $('live');
    lv.textContent = '';
    (d.live || []).forEach(function (e) {
      if (!e || !LIVE[e.type]) return;
      var row = clone('live-tpl');
      slot(row, 'at').textContent = clock(e.at);
      var actor = txt(e.actor);
      slot(row, 'kind').textContent = actor.indexOf('agent:') === 0 ? 'Agent' : actor.indexOf('github:') === 0 ? 'GitHub' : actor.indexOf('member:') === 0 ? 'Person' : 'Audit';
      var by = actor === 'jevs-audit' ? 'The JEVs auditor’s rules' : actor === 'work-audit' ? null : actor.indexOf('github:') === 0 ? '@' + actor.slice(7) : 'Someone';
      slot(row, 'text').textContent = (by ? by + ' ' + LIVE[e.type] : 'An audit’s outcome and points were recorded') + ' (entry ' + n(e.seq) + ')';
      var an = slot(row, 'anchor');
      an.textContent = e.anchored ? '#' + n(d.checkpoint) : 'Pending';
      an.className = e.anchored ? 'pill a' : 'pill';
      an.title = e.anchored ? 'In the signed checkpoint of ' + n(d.checkpoint) + ' entries' : 'Waiting for the next signed checkpoint';
      lv.appendChild(row);
    });
    $('live-empty').hidden = lv.children.length > 0;
  }

  function start() {
    $('retry-row').hidden = true;
    // PR #4 (Aaron, Nov 12): funded work without prices (064): counts, tiers and room pools of at least 3 tasks.
    get('/api/work/market').then(function (x) {
      var m = x && x.ok ? x.d : null, line = $('market-line'), tiers = $('market-tiers'), rooms = $('market-rooms');
      if (!line || !tiers || !rooms) return;
      if (!m || !Array.isArray(m.tiers)) { line.textContent = 'The funded-work figures couldn\u2019t be read just now.'; return; }
      var c = Number(m.funded_tasks) || 0;
      line.textContent = c === 0 ? 'No funded tasks yet.' : c + (c === 1 ? ' funded task is' : ' funded tasks are') + ' open'
        + (m.pool_dollars ? ', about $' + Number(m.pool_dollars).toLocaleString('en-US') + ' in all.' : '.');
      m.tiers.forEach(function (t) { var e = document.createElement('li'); e.textContent = 'Tier ' + Number(t.tier) + ' (' + String(t.label || '') + '): ' + (Number(t.tasks) || 0); tiers.appendChild(e); });
      var rs = (Array.isArray(m.rooms) ? m.rooms : []).map(function (r) { return String(r.name || r.code || '') + ': ' + (Number(r.funded_tasks) || 0) + (r.pool_dollars ? ', about $' + Number(r.pool_dollars).toLocaleString('en-US') : ''); });
      rooms.textContent = rs.length ? 'By room: ' + rs.join(' \u00b7 ') + '. ' + String(m.pool_rule || '') : String(m.pool_rule || '');
    }).catch(function () { var l = $('market-line'); if (l) l.textContent = 'The funded-work figures couldn\u2019t be read just now.'; });
    get('/api/work/summary').then(function (x) {
      if (!x.ok) throw new Error(x.d && typeof x.d.error === 'string' ? x.d.error : '');
      build(x.d);
    }).catch(function (e) { $('pct-note').textContent = (e && e.message) || 'The work couldn’t be loaded.'; $('retry-row').hidden = false; });
    // The hero's checkpoint: the public log's latest, and how long ago it was signed.
    get('/api/log/checkpoint').then(function (x) {
      var c = x.ok && x.d && x.d.checkpoint;
      if (!c) { $('cp').textContent = 'no checkpoint yet'; $('cp-age').textContent = ''; return; }
      $('cp').textContent = 'checkpoint ' + n(c.size);
      $('cp-age').textContent = ago(c.signed_at);
    }).catch(function () { $('cp').textContent = 'checkpoint –'; });
  }
  $('retry').addEventListener('click', start);
  start();
})();
