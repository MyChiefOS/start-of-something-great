// Renders /api/proposals. Public text is only ever inserted with textContent (check P5):
// this file must never use innerHTML, insertAdjacentHTML, outerHTML or document.write.
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
  var list = document.getElementById('proposals');
  var summary = document.getElementById('summary');

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

  function card(p) {
    var a = el('article', 'proposal');
    var meta = el('p', 'post-meta');
    var status = el('span', 'status status-' + String(p.status).replace(/\s+/g, '-'), STATUS_TEXT[p.status] || 'Unknown');
    meta.appendChild(status);
    meta.appendChild(document.createTextNode(' · #' + p.number + ' · ' + day(p.created_at) + ' · ' + (p.filed_by && p.filed_by.label ? p.filed_by.label : 'Person')));
    a.appendChild(meta);
    a.appendChild(el('h3', null, p.title || 'Untitled proposal'));
    if (p.change) a.appendChild(el('p', 'proposal-text', p.change));
    if (p.why) {
      var why = el('p', 'proposal-text');
      why.appendChild(el('strong', null, 'Why: '));
      why.appendChild(document.createTextNode(p.why));
      a.appendChild(why);
    }
    if (p.edited_after_approval) a.appendChild(el('p', 'flag', 'Edited after approval: check the history on GitHub.'));
    var url = safeGithubUrl(p.url);
    if (url) {
      var link = el('a', null, 'Discuss on GitHub (' + (p.comments || 0) + ')');
      link.href = url;
      link.rel = 'noopener';
      var foot = el('p', 'fine');
      foot.appendChild(link);
      a.appendChild(foot);
    }
    return a;
  }

  fetch('/api/proposals', { headers: { Accept: 'application/json' } })
    .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then(function (data) {
      var ps = (data && data.proposals) || [];
      if (!ps.length) {
        summary.textContent = 'No proposals yet. Be the first.';
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
