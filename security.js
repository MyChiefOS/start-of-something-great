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
