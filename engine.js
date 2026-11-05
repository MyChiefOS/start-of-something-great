// /engine: the eight parts as tabs (full ARIA tab pattern: arrow keys, Home and End, roving tabindex; CODING_AGENT_SPEC
// 5.2). Without this script the tab row stays hidden and every panel shows in order. No requests, text unchanged.
(function () {
  var list = document.querySelector('.tabs[role="tablist"]');
  if (!list) return;
  var tabs = Array.prototype.slice.call(list.querySelectorAll('[role="tab"]'));
  var panels = tabs.map(function (t) { return document.getElementById(t.getAttribute('aria-controls')); });
  panels.forEach(function (p, i) { p.setAttribute('role', 'tabpanel'); p.setAttribute('aria-labelledby', tabs[i].id); p.tabIndex = 0; });

  function select(i, focus) {
    tabs.forEach(function (t, j) {
      var on = i === j;
      t.setAttribute('aria-selected', String(on));
      t.tabIndex = on ? 0 : -1;
      panels[j].hidden = !on;
    });
    if (focus) tabs[i].focus();
  }
  list.addEventListener('click', function (e) {
    var t = e.target.closest('[role="tab"]');
    if (t) select(tabs.indexOf(t), false);
  });
  list.addEventListener('keydown', function (e) {
    var i = tabs.indexOf(document.activeElement);
    if (i < 0) return;
    var next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[e.key];
    if (next === undefined) return;
    e.preventDefault();
    select((next + tabs.length) % tabs.length, true);
  });
  list.hidden = false;
  select(0, false);
}());
