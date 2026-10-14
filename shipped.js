// Renders /api/shipped. Public text is only ever inserted with textContent (check P5):
// this file must never use innerHTML, insertAdjacentHTML, outerHTML or document.write.
(function () {
  'use strict';
  var list = document.getElementById('shipped');
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
  function credit(p) {
    var by = p.proposed_by || {};
    if (by.label && by.label !== 'Person') return by.label;
    return by.github_user ? '@' + by.github_user : 'a member of the public';
  }

  function card(p) {
    var a = el('article', 'proposal');
    var meta = el('p', 'post-meta');
    meta.appendChild(el('span', 'status status-shipped', 'Shipped'));
    meta.appendChild(document.createTextNode(' · ' + day(p.shipped_at) + ' · #' + p.number));
    a.appendChild(meta);
    a.appendChild(el('h3', null, p.title || 'Untitled proposal'));
    if (p.change) a.appendChild(el('p', 'proposal-text', p.change));
    var by = el('p', 'proposal-text');
    by.appendChild(el('strong', null, 'Proposed by '));
    by.appendChild(document.createTextNode(credit(p) + ' on ' + day(p.proposed_at) + '.'));
    a.appendChild(by);
    if (p.edited_after_approval) a.appendChild(el('p', 'flag', 'Edited after approval: check the history on GitHub.'));
    var url = safeGithubUrl(p.url);
    if (url) {
      var link = el('a', null, 'See the decision on GitHub');
      link.href = url;
      link.rel = 'noopener';
      var foot = el('p', 'fine');
      foot.appendChild(link);
      a.appendChild(foot);
    }
    return a;
  }

  fetch('/api/shipped', { headers: { Accept: 'application/json' } })
    .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then(function (data) {
      var ps = (data && data.shipped) || [];
      if (!ps.length) {
        summary.textContent = 'Nothing has shipped from a proposal yet. The first one could be yours. ';
        var link = el('a', null, 'Propose a change');
        link.href = 'https://github.com/MyChiefOS/start-of-something-great/issues/new?template=proposal.yml';
        summary.appendChild(link);
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
