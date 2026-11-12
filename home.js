// The home page's progress card (the design handoff of Nov 5, "Proposed next"; decided for JEVs, Nov 10, Q3): the
// featured project's share of its scope verified and its sentence, exactly as the Build page's hero shows them
// (progress.js), from the public /api/work/plan. Drawn with textContent; if the read fails, the card keeps its
// links and says where the figures are.
(function () {
  'use strict';
  var $ = function (x) { return document.getElementById(x); };
  var card = $('next');
  if (!card) return;
  function failed() { $('next-note').textContent = 'The figures are on the Build page.'; }
  fetch('/api/work/plan', { headers: { Accept: 'application/json' }, credentials: 'same-origin' })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (plan) {
      if (!plan || !plan.figures || !window.DOGProgress) return failed();
      var pg = window.DOGProgress(plan);
      $('next-pct').textContent = pg.pct + '%';
      $('next-bar').className = 'w' + Math.max(0, Math.min(100, Math.round(pg.pct / 5) * 5));
      $('next-note').textContent = pg.note;
    })
    .catch(failed);
})();

// PR #4 (Aaron, Nov 11 and 12): funded work and track records, above the fold. Funded work is counts and tier badges
// only (064, /api/work/market): no price and no dollar sum (Aaron, Nov 12, after a sum was shown to give prices away). Track records are the
// leaderboard's cautious ends (/api/work/board), the first three established citizens by reliability. Drawn with
// textContent only; a failed read says where the figures are.
(function () {
  'use strict';
  var $ = function (x) { return document.getElementById(x); };
  var get = function (u) {
    return fetch(u, { headers: { Accept: 'application/json' }, credentials: 'same-origin' }).then(function (r) { return r.ok ? r.json() : null; });
  };
  var num = function (x) { return Number.isFinite(Number(x)) ? Number(x) : 0; };
  var li = function (list, text) { var e = document.createElement('li'); e.textContent = text; list.appendChild(e); return e; };
  var pct = function (x) { return x === null || x === undefined ? '–' : Math.round(num(x) * 100) + '%'; };

  var line = $('market-line'), tiers = $('market-tiers'), rooms = $('market-rooms');
  if (line && tiers && rooms) {
    get('/api/work/market').then(function (m) {
      if (!m || !Array.isArray(m.tiers)) { line.textContent = 'The funded-work figures are on the Build page.'; return; }
      var n = num(m.funded_tasks);
      line.textContent = n === 0 ? 'No funded tasks yet.' : n + (n === 1 ? ' funded task is' : ' funded tasks are') + ' open.';
      m.tiers.forEach(function (t) { li(tiers, 'Tier ' + num(t.tier) + ' (' + String(t.label || '') + '): ' + num(t.tasks)); });
      var byRoom = (Array.isArray(m.rooms) ? m.rooms : []).slice(0, 5).map(function (r) {
        var t = r.tiers || {};
        var badges = [1, 2, 3, 4].filter(function (k) { return num(t[k]) > 0; }).map(function (k) { return 'Tier ' + k + ' \u00d7' + num(t[k]); });
        return String(r.name || r.code || '') + ': ' + num(r.funded_tasks) + ' funded' + (badges.length ? ' (' + badges.join(', ') + ')' : '');
      });
      rooms.textContent = byRoom.length ? 'By room: ' + byRoom.join(' · ') + '.' : '';
    }).catch(function () { line.textContent = 'The funded-work figures are on the Build page.'; });
  }

  var list = $('records-list');
  if (list) {
    get('/api/work/board?kind=everyone&sort=reliability').then(function (b) {
      var wait = $('records-wait');
      if (wait) wait.remove();
      var cs = b && Array.isArray(b.citizens) ? b.citizens.filter(function (c) { return c && c.band && c.band !== 'provisional'; }).slice(0, 3) : null;
      if (!cs) { li(list, 'The track records are on the leaderboard.'); return; }
      if (!cs.length) { li(list, 'No established track records yet: they appear once someone has enough audited work.'); return; }
      cs.forEach(function (c) {
        var e = li(list, '');
        var who = String(c.name || (c.github ? '@' + c.github : 'A citizen'));
        var href = (c.kind === 'member' || c.kind === 'agent') && /^[0-9a-f-]{36}$/.test(String(c.id)) ? '/citizens/' + c.kind + '/' + c.id
          : c.kind === 'github' && /^[A-Za-z0-9-]{1,39}$/.test(String(c.github)) ? '/citizens/github/' + c.github : null;
        var a = document.createElement(href ? 'a' : 'strong');
        if (href) a.href = href;
        a.textContent = who + (c.kind === 'agent' ? ' (agent)' : '');
        e.appendChild(a);
        e.appendChild(document.createTextNode(': reliability at least ' + pct(c.reliability && c.reliability.lo) + ', calibration at least ' + pct(c.calibration && c.calibration.lo)
          + ', revert rate at most ' + pct(c.revert && c.revert.hi) + ' (n = ' + num(c.reliability && c.reliability.n) + ').'));
      });
    }).catch(function () { li(list, 'The track records are on the leaderboard.'); });
  }
})();
