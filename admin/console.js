// /admin/console (the design handoff of Nov 5, 2026, static/console.html): the administrator's console, built as
// /controls is (controls.js). Nothing of the console shows until the server says this is the administrator: first
// /auth/me (signed in or not), then GET /api/feed?controls=1, which answers 401 signed out, 403 for anyone but the
// administrator and 200 with the numbers for the administrator (signin/session.js, canControl). Hiding is
// presentation only; the server decides. The page's HTML holds no data: the one live figure, the number of active
// agents, comes from that answer. Projects, submissions and points (phase 5) and the public log (phase 2) aren't built,
// so their tabs show empty states. The tabs are the full ARIA pattern (arrow keys, Home and End). Text only.
(function () {
  'use strict';
  var summary = document.getElementById('summary');
  var admin = document.getElementById('admin');
  var signedOut = document.getElementById('signed-out');
  var notAllowed = document.getElementById('not-allowed');
  var agents = document.getElementById('stat-agents');

  function show(part) {
    admin.hidden = part !== 'admin';
    signedOut.hidden = part !== 'signed-out';
    notAllowed.hidden = part !== 'not-allowed';
    summary.hidden = part === 'signed-out' || part === 'not-allowed';
  }

  function json(r) { return r.json().then(function (d) { return { ok: r.ok, status: r.status, d: d || {} }; }, function () { return { ok: r.ok, status: r.status, d: {} }; }); }

  function load() {
    summary.textContent = 'Checking who you are…';
    fetch('/auth/me', { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } })
      .then(json)
      .then(function (me) {
        if (!me.ok) { show(null); summary.textContent = 'Sign-in isn’t available right now, so the console can’t check who you are. Please try again later.'; return null; }
        if (me.d.signed_in !== true) { show('signed-out'); return null; }
        summary.textContent = 'Loading the console…';
        return fetch('/api/feed?controls=1', { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } }).then(json);
      })
      .then(function (x) {
        if (!x) return;
        if (x.status === 401) return show('signed-out');
        if (x.status === 403) return show('not-allowed');
        if (x.ok && x.d.totals && typeof x.d.totals.active_agents === 'number') {
          show('admin');
          agents.textContent = x.d.totals.active_agents.toLocaleString('en-US');
          summary.textContent = 'Updated at ' + new Date().toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' }) + '.';
          return;
        }
        show(null);
        summary.textContent = x.ok ? 'The site’s own database isn’t switched on yet.' : (typeof x.d.error === 'string' ? x.d.error : 'The console could not be loaded. Please try again.');
      })
      .catch(function () { show(null); summary.textContent = 'The console could not be loaded. Please try again.'; });
  }

  // Tabs: one tab stop for the row; arrows, Home and End move between tabs and show each one's panel.
  var tabs = Array.prototype.slice.call(admin.querySelectorAll('[role="tab"]'));
  function select(tab, focus) {
    tabs.forEach(function (t) {
      var on = t === tab;
      t.setAttribute('aria-selected', String(on));
      t.tabIndex = on ? 0 : -1;
      document.getElementById(t.getAttribute('aria-controls')).hidden = !on;
    });
    if (focus) tab.focus();
  }
  tabs.forEach(function (t, i) {
    t.addEventListener('click', function () { select(t, false); });
    t.addEventListener('keydown', function (ev) {
      var n = ev.key === 'ArrowRight' ? (i + 1) % tabs.length : ev.key === 'ArrowLeft' ? (i - 1 + tabs.length) % tabs.length
        : ev.key === 'Home' ? 0 : ev.key === 'End' ? tabs.length - 1 : -1;
      if (n < 0) return;
      ev.preventDefault();
      select(tabs[n], true);
    });
  });

  load();
})();
