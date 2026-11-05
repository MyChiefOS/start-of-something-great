// /projects (the design handoff of Nov 5, 2026, static/projects.html): search, the room filter and the status chips,
// all in the page (there is one project, so nothing is fetched). The design's default chip is "Open"; when nothing
// matches, the table folds away and the empty state under "When nothing matches" says what was looked for and what
// to try. Without this script every project shows and the chips stay hidden. Text only (textContent).
(function () {
  'use strict';
  var q = document.getElementById('project-q');
  var room = document.getElementById('project-room');
  var chips = document.getElementById('status-chips');
  var table = document.getElementById('project-table');
  var rows = Array.prototype.slice.call(document.querySelectorAll('#project-rows tr'));
  var text = document.getElementById('no-match-text');
  var status = 'open';
  var NAMES = { open: 'open', claimed: 'claimed', submitted: 'submitted', completed: 'completed' };

  // The age column: whole days since the project was posted, as the design shows it ("1d").
  rows.forEach(function (tr) {
    var since = Date.parse(tr.getAttribute('data-since') + 'T00:00:00Z');
    var cell = tr.querySelector('[data-age]');
    if (!isNaN(since) && cell) cell.textContent = Math.max(0, Math.floor((Date.now() - since) / 86400000)) + 'd';
  });

  function words(s) { return s.toLowerCase().split(/\s+/).filter(Boolean); }

  function apply() {
    var want = words(q.value);
    var shown = 0;
    rows.forEach(function (tr) {
      var hay = tr.getAttribute('data-search');
      var ok = (status === 'all' || tr.getAttribute('data-status') === status)
        && (!room.value || tr.getAttribute('data-room') === room.value)
        && want.every(function (w) { return hay.indexOf(w) >= 0; });
      tr.hidden = !ok;
      if (ok) shown++;
    });
    table.hidden = shown === 0;
    if (shown > 0) { text.textContent = 'When a search finds nothing, it says so here, with what to try next.'; return; }
    var parts = [];
    if (status !== 'all') parts.push(NAMES[status]);
    var what = (parts.length ? parts[0] + ' ' : '') + 'projects';
    if (q.value.trim()) text.textContent = 'No ' + what + ' match “' + q.value.trim() + '”' + (room.value ? ' in ' + room.value : '') + '.';
    else if (room.value) text.textContent = 'No ' + what + ' in ' + room.value + '.';
    else text.textContent = 'No ' + what + ' yet. The one project here, this site, is claimed: choose Claimed or All.';
  }

  q.addEventListener('input', apply);
  room.addEventListener('change', apply);
  chips.addEventListener('click', function (ev) {
    var b = ev.target.closest('button[data-status]');
    if (!b) return;
    status = b.getAttribute('data-status');
    Array.prototype.forEach.call(chips.querySelectorAll('button[data-status]'), function (c) {
      c.setAttribute('aria-pressed', String(c === b));
    });
    apply();
  });
  chips.hidden = false;
  apply();
})();
