// /risks: the filters. Each filter is a link with its own address (/risks?status=accepted&severity=medium), so a
// filtered view can be shared; this script reads the address and hides the rows that don't match. Without it, every
// row shows. Text only (textContent); it fetches nothing.
(function () {
  'use strict';
  var rows = document.getElementById('risk-rows');
  var shown = document.getElementById('shown');
  if (!rows || !shown) return;
  var q = new URLSearchParams(window.location.search);
  var want = { status: q.get('status') || '', severity: q.get('severity') || '' };

  // Each link keeps the other filter, so status and severity combine.
  Array.prototype.forEach.call(document.querySelectorAll('.filters a[data-filter]'), function (a) {
    var f = a.getAttribute('data-filter');
    var v = a.getAttribute('data-value');
    var next = { status: want.status, severity: want.severity };
    next[f] = v;
    var p = new URLSearchParams();
    if (next.status) p.set('status', next.status);
    if (next.severity) p.set('severity', next.severity);
    a.setAttribute('href', '/risks' + (p.toString() ? '?' + p.toString() : '') + '#shown');
    if (want[f] === v) a.setAttribute('aria-current', 'true');
    else a.removeAttribute('aria-current');
  });

  var all = rows.querySelectorAll('tr');
  var n = 0;
  Array.prototype.forEach.call(all, function (tr) {
    var ok = (!want.status || tr.getAttribute('data-status') === want.status) && (!want.severity || tr.getAttribute('data-severity') === want.severity);
    tr.hidden = !ok;
    if (ok) n++;
  });
  if (!want.status && !want.severity) shown.textContent = 'All ' + all.length + ' risks.';
  else shown.textContent = n + ' of ' + all.length + ' risks match' + (n ? '.' : '. Choose All to see every risk.');
})();
