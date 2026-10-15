// /review: Aaron's review queue, built for a phone (SF5): each post shows why it is here and one button per
// decision. Everything members wrote is shown with textContent, never as HTML.
(function () {
  var queue = document.getElementById('queue');
  var summary = document.getElementById('summary');
  var LABEL = { approve: 'Approve', keep: 'Keep', remove: 'Remove', restore: 'Undo' };
  var DONE = { approve: 'Approved: it’s live.', keep: 'Kept: the reports are closed.', remove: 'Removed.', restore: 'Restored: it’s live again.' };
  var REASON = { spam: 'spam', abuse: 'abuse', private_info: 'private information', illegal: 'illegal', other: 'other' };
  var open = 0;

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function count() {
    summary.textContent = open === 0 ? 'Nothing waiting. The queue is clear.' : open + (open === 1 ? ' post needs' : ' posts need') + ' a decision, oldest first.';
  }

  function why(i) {
    var parts = [];
    if (i.first_posts) parts.push('one of a new member’s first 3 posts');
    if (i.reports) {
      parts.push(i.reports + (i.reports === 1 ? ' report' : ' reports') + (i.reasons.length ? ' (' + i.reasons.map(function (r) { return REASON[r] || r; }).join(', ') + ')' : ''));
    }
    if (i.classifiers && i.classifiers.length) parts.push('flagged by ' + i.classifiers.join(', '));
    return 'Why: ' + parts.join('; ') + '.';
  }

  function decide(card, i, decision, buttons, result) {
    buttons.forEach(function (b) { b.disabled = true; });
    result.textContent = 'Saving…';
    fetch('/api/feed', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ review: i.id, decision: decision }) })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, status: r.status, d: d }; }); })
      .then(function (x) {
        if (!x.ok) {
          result.textContent = x.d.error || 'That didn’t go through.';
          if (x.status !== 409) buttons.forEach(function (b) { b.disabled = false; });
          return;
        }
        result.textContent = DONE[decision];
        card.classList.add('decided');
        if (decision !== 'restore') { open = Math.max(0, open - 1); count(); }
        buttons.forEach(function (b) { b.hidden = true; });
        // A mistaken removal can be undone right here.
        if (decision === 'remove') {
          var undo = el('button', 'button', LABEL.restore);
          undo.type = 'button';
          undo.addEventListener('click', function () { undo.remove(); decide(card, i, 'restore', [undo], result); });
          result.after(undo);
        }
      })
      .catch(function () { result.textContent = 'That didn’t go through. Please try again.'; buttons.forEach(function (b) { b.disabled = false; }); });
  }

  function render(d) {
    queue.textContent = '';
    open = d.open;
    count();
    d.items.forEach(function (i) {
      var card = el('article', 'post review-item');
      var meta = el('p', 'post-meta');
      meta.appendChild(el('strong', '', i.author.name));
      meta.appendChild(document.createTextNode(' · level ' + i.author.level + ' · ' + i.author.live_posts + ' live ' + (i.author.live_posts === 1 ? 'post' : 'posts')
        + (i.author.status === 'banned' ? ' · banned' : '') + ' · ' + (i.status === 'waiting' ? 'waiting' : i.status)));
      card.appendChild(meta);
      i.body.split(/\n{2,}/).forEach(function (para) { card.appendChild(el('p', '', para)); });
      card.appendChild(el('p', 'fine', why(i)));
      i.notes.forEach(function (n) { card.appendChild(el('p', 'fine note', 'Reporter: ' + n)); });
      var row = el('div', 'review-actions');
      var result = el('p', 'fine', '');
      result.setAttribute('role', 'status');
      var buttons = i.actions.map(function (a) {
        var b = el('button', 'button' + (a === 'remove' ? ' danger' : ' primary'), LABEL[a]);
        b.type = 'button';
        b.addEventListener('click', function () { decide(card, i, a, buttons, result); });
        row.appendChild(b);
        return b;
      });
      card.appendChild(row);
      card.appendChild(result);
      queue.appendChild(card);
    });
  }

  function load() {
    summary.textContent = 'Loading the queue…';
    fetch('/api/feed?queue=1', { headers: { Accept: 'application/json' } })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, status: r.status, d: d }; }); })
      .then(function (x) {
        if (x.ok) return render(x.d);
        queue.textContent = '';
        summary.textContent = x.status === 401 ? 'Sign in to review.' : (x.d.error || 'The queue could not be loaded.');
        if (x.status === 401) { var a = el('a', '', 'Sign in'); a.href = '/join'; queue.appendChild(a); }
      })
      .catch(function () { summary.textContent = 'The queue could not be loaded. Please try again.'; });
  }

  document.getElementById('refresh').addEventListener('click', load);
  load();
})();
