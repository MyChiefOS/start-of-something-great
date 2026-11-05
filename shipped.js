// Renders /api/shipped. Public text is only ever inserted with textContent (check P5):
// this file must never use innerHTML, insertAdjacentHTML, outerHTML or document.write.
// Each shipped proposal is drawn as the design's card (the design handoff of Nov 5, 2026, static/shipped.html): the
// Shipped pill, title, who proposed it, the proposal's own words, then the decision on GitHub. Only real entries: when
// nothing has shipped, the empty state says so and where to start.
(function () {
  'use strict';
  var PROPOSE = 'https://github.com/MyChiefOS/start-of-something-great/issues/new?template=proposal.yml';
  var list = document.getElementById('shipped');
  var summary = document.getElementById('summary');

  // Each entry is the design's card, cloned from the page's <template> and filled with text.
  var tpl = document.getElementById('card-tpl');
  function slot(n, k) { return n.querySelector('[data-slot="' + k + '"]'); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }
  function day(iso) {
    var d = new Date(iso);
    return isNaN(d) ? '' : d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  }
  function safeGithubUrl(u) {
    return typeof u === 'string' && u.indexOf('https://github.com/MyChiefOS/start-of-something-great/issues/') === 0 ? u : null;
  }
  function credit(p) {
    var by = p.proposed_by || {};
    if (by.label && by.label !== 'Person') return by.label;
    return by.github_user ? '@' + by.github_user : 'a member of the public';
  }

  function card(p) {
    var a = tpl.content.firstElementChild.cloneNode(true);
    slot(a, 'title').textContent = p.title || 'Untitled proposal';
    slot(a, 'by').textContent = 'Proposed by ' + credit(p) + ' on ' + day(p.proposed_at) + ' · shipped ' + day(p.shipped_at) + ' · #' + p.number;
    var text = slot(a, 'text');
    if (p.change) text.textContent = p.change; else text.remove();
    var linkP = slot(a, 'link');
    if (p.edited_after_approval) { var f = el('p', linkP.className, 'Edited after approval: check the history on GitHub.'); a.insertBefore(f, linkP); }
    var url = safeGithubUrl(p.url);
    if (url) {
      var link = el('a', null, 'See the decision on GitHub');
      link.href = url;
      link.rel = 'noopener';
      linkP.appendChild(link);
    } else linkP.remove();
    return a;
  }

  fetch('/api/shipped', { headers: { Accept: 'application/json' } })
    .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then(function (data) {
      var ps = (data && data.shipped) || [];
      if (!ps.length) {
        summary.textContent = 'Nothing has shipped from a proposal yet.';
        var empty = el('div', 'empty');
        empty.appendChild(el('p', null, 'Nothing has shipped from a proposal yet. The first one could be yours.'));
        var p = el('p');
        var link = el('a', null, 'Propose a change');
        link.href = PROPOSE;
        p.appendChild(link);
        empty.appendChild(p);
        list.appendChild(empty);
        return;
      }
      summary.textContent = ps.length + (ps.length === 1 ? ' proposal' : ' proposals') + ' shipped, newest first.';
      ps.forEach(function (p) { list.appendChild(card(p)); });
    })
    .catch(function () {
      summary.textContent = 'This list could not load right now. ';
      var link = el('a', null, 'See shipped proposals on GitHub');
      link.href = 'https://github.com/MyChiefOS/start-of-something-great/issues?q=label%3A%22status%3A+shipped%22';
      summary.appendChild(link);
    });
})();
