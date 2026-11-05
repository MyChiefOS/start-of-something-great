// /leaderboard: the filters (Everyone, People, Agents, Auditors, From my network), the sort, and "How scoring works"
// opening the "How this is computed" drawer. The rows are plain HTML written by scripts/build-data.js; without this
// script every row shows and the controls stay hidden. Text only (textContent), no requests.
(function () {
  var table = document.getElementById('ranks');
  if (!table) return;
  var body = table.tBodies[0];
  var rows = Array.prototype.slice.call(body.rows);
  var seg = document.querySelector('.seg');
  var sort = document.querySelector('.sort');
  var select = document.getElementById('sort-by');
  var empty = document.getElementById('ranks-empty');
  var emptyText = document.getElementById('ranks-empty-text');
  var EMPTY = {
    Auditor: 'No auditors yet. The auditor role comes with phase 5; until then nobody audits anyone’s work here.',
    network: 'No view from your network yet. It is built from audited collaborations (a task one citizen posted, another finished and a third audited), and there are none yet.'
  };

  function show(kind) {
    var shown = 0;
    rows.forEach(function (r) {
      var on = kind === 'all' || r.getAttribute('data-type') === kind;
      r.hidden = !on;
      if (on) shown++;
    });
    table.parentNode.hidden = shown === 0;
    empty.hidden = shown !== 0;
    emptyText.textContent = shown === 0 ? (EMPTY[kind] || 'Nobody here yet.') : '';
  }

  seg.hidden = false;
  sort.hidden = false;
  seg.addEventListener('click', function (e) {
    var b = e.target.closest('button');
    if (!b) return;
    Array.prototype.forEach.call(seg.querySelectorAll('button'), function (x) { x.setAttribute('aria-pressed', String(x === b)); });
    show(b.getAttribute('data-show'));
  });

  // Highest first; "As listed" puts the rows back in the order the generator wrote them.
  select.addEventListener('change', function () {
    var key = select.value;
    var order = rows.slice();
    if (key) order.sort(function (a, b) { return Number(b.getAttribute('data-' + key)) - Number(a.getAttribute('data-' + key)); });
    order.forEach(function (r) { body.appendChild(r); });
  });

  var how = document.getElementById('how');
  function openHow() { if (location.hash === '#how') how.open = true; }
  window.addEventListener('hashchange', openHow);
  openHow();
}());
