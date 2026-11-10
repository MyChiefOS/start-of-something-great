// /engine: the trust engine's eight parts as tabs (the design handoff of Nov 5, static/engine.html; decided for JEVs,
// Nov 10, Q4: marked Proposed and not built, no sample figures, each tab saying what does that job today). Tabs move with
// a click and the arrow keys. The Signatures tab shows the public log's latest checkpoint, the one part that runs today.
(function () {
  'use strict';
  var tabs = Array.prototype.slice.call(document.querySelectorAll('[role="tab"][data-tab]'));
  function pick(name, focus) {
    tabs.forEach(function (t) {
      var on = t.getAttribute('data-tab') === name;
      t.className = on ? 'on' : '';
      t.setAttribute('aria-selected', on ? 'true' : 'false');
      t.tabIndex = on ? 0 : -1;
      var p = document.getElementById(t.getAttribute('aria-controls'));
      if (p) p.hidden = !on;
      if (on && focus) t.focus();
    });
  }
  tabs.forEach(function (t, i) {
    t.addEventListener('click', function () { pick(t.getAttribute('data-tab')); });
    t.addEventListener('keydown', function (e) {
      if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
      e.preventDefault();
      pick(tabs[(i + (e.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length].getAttribute('data-tab'), true);
    });
  });
  var line = document.getElementById('cp-line');
  fetch('/api/log/checkpoint', { headers: { Accept: 'application/json' } })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (d) {
      var c = d && d.available && d.checkpoint;
      if (!c || !Number.isSafeInteger(c.size)) return;
      var when = new Date(c.signed_at);
      line.textContent = 'The latest covers ' + c.size + (c.size === 1 ? ' entry' : ' entries') + ', signed '
        + (isNaN(when) ? '' : when.toUTCString().replace(' GMT', ' UTC')) + ' with ' + String((d.log_key && d.log_key.algorithm) || 'Ed25519') + '.';
    })
    .catch(function () { /* the link stays */ });
})();
