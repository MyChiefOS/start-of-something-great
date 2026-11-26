// /security: the public log's key and the witness's state, from /api/log/checkpoint (038). Text only, never HTML.
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var PILL = { ok: ['pill f', 'Witnessing'], stale: ['pill a', 'Stopped'], unverified: ['pill', 'Alarm'], unknown: ['pill m', 'No copy yet'] };
  fetch('/api/log/checkpoint', { headers: { Accept: 'application/json' } })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (!d.available || !d.log_key) {
        $('key-vkey').textContent = $('key-fp').textContent = $('key-made').textContent = 'The log isn’t switched on here.';
        $('w-state').textContent = 'Not running'; return;
      }
      $('key-vkey').textContent = d.log_key.vkey;
      $('key-fp').textContent = d.log_key.fingerprint;
      $('key-made').textContent = new Date(d.log_key.created_at).toLocaleString();
      var w = d.witnesses[0] && d.witnesses[0].site_reading;
      var p = PILL[(w && w.status) || 'unknown'];
      $('w-state').className = p[0];
      $('w-state').textContent = p[1];
      $('w-line').textContent = !w || w.status === 'unknown' ? 'No copy on the branch yet.'
        : w.status === 'unverified' ? w.reason
        : 'Holds a checkpoint of ' + Number(w.witness_size).toLocaleString() + ' entries' + (w.witnessed_at ? ', from its run at ' + new Date(w.witnessed_at).toLocaleString() : '') + '.';
    })
    .catch(function () { $('key-say').textContent = 'The key couldn’t be loaded just now. It is at /api/log/checkpoint.'; $('w-state').textContent = 'Not checked'; });
})();

// 089: the security wiki's newest advisories, with the zero-day filter and each weakness linked to its CWE entry at
// MITRE (from /api/work/wiki). Text only, never HTML; a link only to cwe.mitre.org.
(function () {
  var rows = document.getElementById('wiki-rows');
  if (!rows) return;
  var say = document.getElementById('wiki-say');
  var all = document.getElementById('wiki-all');
  var zero = document.getElementById('wiki-zero');
  var data = null;
  function cell(tr, text) { var td = document.createElement('td'); if (text !== undefined) td.textContent = text; tr.appendChild(td); return td; }
  function show(onlyZero) {
    all.setAttribute('aria-pressed', String(!onlyZero)); zero.setAttribute('aria-pressed', String(onlyZero));
    rows.textContent = '';
    var list = (onlyZero ? data.zero_days : data.newest) || [];
    say.textContent = list.length ? (onlyZero ? list.length + ' zero-days in the last 30 days.' : 'The newest ' + list.length + ' advisories.') : (onlyZero ? 'No zero-days in the last 30 days.' : 'No advisories yet.');
    list.forEach(function (e) {
      var tr = document.createElement('tr');
      cell(tr, String(e.ident || '') + (e.zero_day && !onlyZero ? ' (zero-day)' : '') + ': ' + String(e.title || ''));
      var w = cell(tr);
      if (e.cwe && /^https:\/\/cwe\.mitre\.org\/data\/definitions\/[0-9]{1,5}\.html$/.test(String(e.cwe_url || ''))) {
        var a = document.createElement('a'); a.href = e.cwe_url; a.rel = 'noopener'; a.textContent = e.cwe; w.appendChild(a);
      } else w.textContent = e.cwe || 'Not named';
      cell(tr, e.published ? String(e.published).slice(0, 10) : '');
      rows.appendChild(tr);
    });
  }
  all.addEventListener('click', function () { if (data) show(false); });
  zero.addEventListener('click', function () { if (data) show(true); });
  fetch('/api/work/wiki', { headers: { Accept: 'application/json' } })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (b) { data = b && (b.data || b); if (!data || !data.newest) { say.textContent = 'The wiki couldn’t be loaded just now.'; return; } show(false); })
    .catch(function () { say.textContent = 'The wiki couldn’t be loaded just now.'; });
})();
