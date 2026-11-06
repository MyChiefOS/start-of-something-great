// Renders /api/proposals. Public text is only ever inserted with textContent (check P5):
// this file must never use innerHTML, insertAdjacentHTML, outerHTML or document.write.
// Each proposal is drawn as the design's card (the design handoff of Nov 5, 2026, static/proposals.html): status pill,
// title, who filed it, the proposal's own words, then the link to its discussion on GitHub. Only real proposals: when
// there are none, the empty state says so and where to start.
(function () {
  'use strict';
  var STATUS_TEXT = {
    waiting: 'Waiting',
    'in review': 'In review',
    approved: 'Approved',
    declined: 'Declined',
    shipped: 'Shipped',
    closed: 'Closed'
  };
  // The pill's look, always with its words (never colour alone): a = amber edge, f = filled, m = muted.
  var PILL = { 'in review': 'a', approved: 'a', shipped: 'f', declined: 'm', closed: 'm' };
  var PROPOSE = 'https://github.com/MyChiefOS/start-of-something-great/issues/new?template=proposal.yml';
  var list = document.getElementById('proposals');
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
  function filedBy(p) {
    var by = p.filed_by || {};
    var who = by.github_user ? 'Filed by @' + by.github_user : 'Filed by a member of the public';
    return by.label && by.label !== 'Person' ? who + ' · ' + by.label : who;
  }

  function card(p) {
    var a = tpl.content.firstElementChild.cloneNode(true);
    var pill = slot(a, 'status');
    pill.className = 'pill' + (PILL[p.status] ? ' ' + PILL[p.status] : '');
    pill.textContent = STATUS_TEXT[p.status] || 'Unknown';
    slot(a, 'title').textContent = p.title || 'Untitled proposal';
    slot(a, 'by').textContent = filedBy(p) + ' · #' + p.number + ' · ' + day(p.created_at);
    var text = slot(a, 'text');
    if (p.change) text.textContent = p.change; else text.remove();
    var linkP = slot(a, 'link');
    if (p.why) {
      var why = text.cloneNode(false);
      why.appendChild(el('strong', null, 'Why: '));
      why.appendChild(document.createTextNode(p.why));
      a.insertBefore(why, linkP);
    }
    if (p.edited_after_approval) { var f = text.cloneNode(false); f.className = 'fine ' + text.className; f.textContent = 'Edited after approval: check the history on GitHub.'; a.insertBefore(f, linkP); }
    var url = safeGithubUrl(p.url);
    if (url) {
      var link = el('a', null, 'Discuss on GitHub (' + (p.comments || 0) + ')');
      link.href = url;
      link.rel = 'noopener';
      linkP.appendChild(link);
    } else linkP.remove();
    return a;
  }

  fetch('/api/proposals', { headers: { Accept: 'application/json' } })
    .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then(function (data) {
      var ps = (data && data.proposals) || [];
      if (!ps.length) {
        summary.textContent = 'No proposals yet.';
        var empty = el('div', 'empty');
        empty.appendChild(el('p', null, 'No proposals yet. Be the first.'));
        var p = el('p');
        var link = el('a', null, 'Propose a change');
        link.href = PROPOSE;
        p.appendChild(link);
        empty.appendChild(p);
        list.appendChild(empty);
        return;
      }
      summary.textContent = ps.length + (ps.length === 1 ? ' proposal' : ' proposals') + ', newest first.';
      ps.forEach(function (p) { list.appendChild(card(p)); });
    })
    .catch(function () {
      summary.textContent = 'Proposals could not load right now. ';
      var link = el('a', null, 'See them on GitHub');
      link.href = 'https://github.com/MyChiefOS/start-of-something-great/issues?q=label%3Aproposal';
      summary.appendChild(link);
    });
})();
