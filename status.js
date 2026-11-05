// /status: the live values in the card, from the site's own public answers (/api/status for the go-live stage,
// /api/ready for sign-in and the timers' heartbeat). Text only (textContent), our own paths only. Without this script,
// or when an answer can't be had, the card keeps the repository's values and says so: never a guess.
(function () {
  'use strict';
  var status = document.getElementById('live-status');
  if (!status) return;

  function get(path) {
    return fetch(path, { headers: { Accept: 'application/json' }, cache: 'no-store' }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
  }
  // A pill's words and kind (a, f or m; '' for the plain pill).
  function pill(id, text, kind) {
    var el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
    el.className = 'pill' + (kind ? ' ' + kind : '') + (id === 'live-jevs' ? ' big' : '');
  }
  // A line under a pill, shown once it has something true to say.
  function line(id, text) {
    var el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
    el.hidden = false;
  }
  function ago(s) {
    if (s < 90) return Math.round(s) + ' seconds ago';
    if (s < 5400) return Math.round(s / 60) + ' minutes ago';
    return Math.round(s / 3600) + ' hours ago';
  }
  function reached(db) {
    if (!db || typeof db !== 'object') return false;
    return Object.keys(db).some(function (k) { return db[k] === 'reached'; });
  }
  function why(e) { return e && e.message ? e.message : 'no answer'; }

  var failed = [];
  var a = get('/api/status').then(function (s) {
    if (s.stage === 'public') pill('live-stage', 'Open', 'f');
    else if (s.stage === 'closed') pill('live-stage', 'Closed', '');
    else pill('live-stage', 'Unknown', 'm');
    line('live-stage-now', 'Live: /api/status answers “' + String(s.stage) + '”.');
  }).catch(function (e) { failed.push('/api/status (' + why(e) + ')'); });

  var b = get('/api/ready').then(function (d) {
    if (d.error) throw new Error(String(d.error));
    if (d.stage === 'closed') pill('live-signin', 'Off: the site is closed', '');
    else if (d.stage === 'public' && d.keys === true && reached(d.database)) pill('live-signin', 'On', 'f');
    else pill('live-signin', 'Not ready', 'm');
    line('live-signin-now', 'Live: the stage, the sign-in keys and the database, as /api/ready reports them.');
    var t = d.timers;
    line('live-uptime-now', t && typeof t.last_run_s_ago === 'number' ? 'Live: the site’s timers last finished ' + ago(t.last_run_s_ago) + ' (/api/ready).'
      : t === 'closed' ? 'Live: the timers don’t run while the site is closed.'
      : t === 'never' ? 'Live: the timers have never run (/api/ready).'
      : 'Live: the timers’ heartbeat couldn’t be read (/api/ready).');
  }).catch(function (e) { failed.push('/api/ready (' + why(e) + ')'); });

  Promise.all([a, b]).then(function () {
    var at = new Date().toISOString().slice(11, 16) + ' UTC';
    status.textContent = failed.length
      ? 'Couldn’t load ' + failed.join(' and ') + ' at ' + at + ', so those values are the repository’s. Reload the page to try again.'
      : 'Go-live and sign-in are live, as of ' + at + '. JEVs mode and the uptime schedule are the repository’s.';
  });
})();
