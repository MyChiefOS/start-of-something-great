// /status: the public log's health card (038; CODING_AGENT_SPEC.md 1.6), from /api/log/checkpoint. Text only.
(function () {
  var $ = function (id) { return document.getElementById(id); };
  if (!$('log-card')) return;
  function set(id, text, cls) { var e = $(id); e.textContent = text; e.className = 'pill' + (cls ? ' ' + cls : ''); }
  function ago(iso) {
    if (!iso) return 'never';
    var s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
    return s < 90 ? s + ' seconds ago' : s < 5400 ? Math.round(s / 60) + ' minutes ago' : s < 172800 ? Math.round(s / 3600) + ' hours ago' : Math.round(s / 86400) + ' days ago';
  }
  fetch('/api/log/checkpoint', { headers: { Accept: 'application/json' } })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (!d.available) { $('log-line').textContent = 'The log isn’t switched on here.'; return; }
      var w = (d.witnesses[0] && d.witnesses[0].site_reading) || {};
      set('log-size', d.tree_size.toLocaleString() + (d.tree_size === 1 ? ' entry' : ' entries'), 'a');
      set('log-age', d.checkpoint ? ago(d.checkpoint.signed_at) : 'None yet', d.checkpoint ? 'a' : 'm');
      set('log-witness', w.status === 'ok' ? '1 of 1 online' : w.status === 'stale' ? '0 of 1: stopped' : w.status === 'unverified' ? 'Alarm' : '0 of 1: no copy yet',
        w.status === 'ok' ? 'f' : w.status === 'unverified' ? '' : 'm');
      set('log-check', w.witnessed_at ? ago(w.witnessed_at) : 'Not yet', w.witnessed_at ? 'a' : 'm');
      set('log-monitor', w.status === 'unverified' ? 'Unverified' : w.tree_matches_checkpoints === false ? 'Tree mismatch' : w.status === 'ok' ? 'No problems found' : 'Waiting for the witness',
        w.status === 'unverified' || w.tree_matches_checkpoints === false ? '' : w.status === 'ok' ? 'f' : 'm');
      $('log-line').textContent = w.status === 'unverified' ? 'Unverified: ' + w.reason + ' The site keeps running.'
        : 'Live from /api/log/checkpoint' + (w.checked_at ? '; the site last read the witness ' + ago(w.checked_at) : '') + '. Check any receipt on /receipts.';
    })
    .catch(function () { $('log-line').textContent = 'The log’s health couldn’t be loaded just now.'; });
})();
