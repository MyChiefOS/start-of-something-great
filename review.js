// /review: Aaron's review queue, built for a phone (SF5): each post shows why it is here and one button per
// decision. Everything members wrote is shown with textContent, never as HTML.
(function () {
  var queue = document.getElementById('queue');
  var summary = document.getElementById('summary');
  var LABEL = { approve: 'Approve', keep: 'Keep', remove: 'Remove', restore: 'Undo' };
  var DONE = { approve: 'Approved: it’s live.', keep: 'Kept: the reports are closed.', remove: 'Removed.', live: 'Restored: it’s live again.', waiting: 'Restored: it’s waiting for review again.' };
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
    if (i.classifiers && i.classifiers.length) parts.push('flagged by ' + i.classifiers.map(function (c) { return c === 'jevs' ? 'JEVs (automatic checks)' : c; }).join(', '));
    if (i.appealed) parts.push('the author appealed');
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
        result.textContent = decision === 'restore' ? DONE[x.d.status] : DONE[decision];
        card.classList.add('decided');
        if (decision !== 'restore') { open = Math.max(0, open - 1); count(); }
        else if (x.d.status === 'waiting') { open += 1; count(); }
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
        if (x.status === 401) { var a = el('a', '', 'Sign in'); a.href = '/join?return_to=%2Freview'; queue.appendChild(a); }
      })
      .catch(function () { summary.textContent = 'The queue could not be loaded. Please try again.'; });
  }

  // PR 13: paused owners and their appeals. Lift ends a pause now; Keep lets it end on time. Nothing here needs Aaron
  // for the system to keep working: every pause lifts by itself.
  var appealBox = document.getElementById('appeals');
  var appealList = document.getElementById('appeal-list');
  function loadAppeals() {
    fetch('/api/notify/appeals', { headers: { Accept: 'application/json' } })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
      .then(function (x) {
        appealList.textContent = '';
        appealBox.hidden = !(x.ok && x.d.containments.length);
        if (!x.ok) return;
        x.d.containments.forEach(function (cn) {
          var card = el('article', 'post review-item');
          var meta = el('p', 'post-meta');
          meta.appendChild(el('strong', '', cn.member.name));
          meta.appendChild(document.createTextNode(' · ' + (cn.reason === 'copies' ? cn.measured + ' copies of earlier text in an hour' : cn.measured + ' agent actions in an hour')
            + ' (usual ' + cn.usual + ') · ends ' + new Date(cn.ends_at).toLocaleString()));
          card.appendChild(meta);
          card.appendChild(el('p', 'fine', cn.appeal ? 'Appealed' + (cn.appeal.note ? ': ' + cn.appeal.note : ' (no note).') : 'No appeal.'));
          var row = el('div', 'review-actions');
          var result = el('p', 'fine', '');
          result.setAttribute('role', 'status');
          var choices = cn.appeal && !cn.decision ? ['lift', 'keep'] : ['lift'];
          var buttons = choices.map(function (d) {
            var b = el('button', 'button' + (d === 'lift' ? ' primary' : ''), d === 'lift' ? 'Lift now' : 'Keep');
            b.type = 'button';
            b.addEventListener('click', function () {
              buttons.forEach(function (y) { y.disabled = true; });
              fetch('/api/notify/appeals', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ containment: cn.id, decision: d }) })
                .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, d: j }; }); })
                .then(function (y) { result.textContent = y.ok ? (d === 'lift' ? 'Lifted: their agents are back on their rules.' : 'Kept: it ends on time.') : y.d.error; buttons.forEach(function (z) { z.hidden = y.ok; z.disabled = false; }); });
            });
            row.appendChild(b);
            return b;
          });
          card.appendChild(row);
          card.appendChild(result);
          appealList.appendChild(card);
        });
      })
      .catch(function () { appealBox.hidden = true; });
  }

  document.getElementById('refresh').addEventListener('click', function () { load(); loadAppeals(); });
  load();
  loadAppeals();
})();
