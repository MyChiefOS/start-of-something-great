// The home page's progress card (the design handoff of Nov 5, "Proposed next"; decided for JEVs, Nov 10, Q3): the
// featured project's share of its scope verified and its sentence, exactly as the Build page's hero shows them
// (plan.js, progress), from the public /api/work/plan. Drawn with textContent; if the read fails, the card keeps its
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
      if (!plan || !plan.figures || !window.DOGPlan) return failed();
      var pg = window.DOGPlan.progress(plan);
      $('next-pct').textContent = pg.pct + '%';
      $('next-bar').className = 'w' + Math.max(0, Math.min(100, Math.round(pg.pct / 5) * 5));
      $('next-note').textContent = pg.note;
    })
    .catch(failed);
})();
