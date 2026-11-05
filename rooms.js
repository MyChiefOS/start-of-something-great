// /rooms (the design handoff of Nov 5, 2026, static/rooms.html): the chips "With open tasks" and "All 23". Without
// this script the page shows the rooms with open tasks (none yet) and the quiet rooms folded, which is the same as the
// first chip. The chosen chip is marked in words (aria-pressed), never by colour alone. No text is written as HTML.
(function () {
  'use strict';
  var chips = document.getElementById('room-chips');
  var open = document.getElementById('view-open');
  var all = document.getElementById('view-all');
  var quiet = document.getElementById('quiet');
  if (!chips || !open || !all || !quiet) return;

  function show(view) {
    open.hidden = view !== 'open';
    quiet.hidden = view !== 'open';
    all.hidden = view !== 'all';
    Array.prototype.forEach.call(chips.querySelectorAll('button[data-view]'), function (b) {
      b.setAttribute('aria-pressed', String(b.getAttribute('data-view') === view));
    });
  }
  chips.addEventListener('click', function (ev) {
    var b = ev.target.closest('button[data-view]');
    if (b) show(b.getAttribute('data-view'));
  });
  chips.hidden = false;
  show('open');
})();
