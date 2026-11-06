// The approval screen (the design handoff of Nov 5, 2026, CODING_AGENT_SPEC.md 2.2): one component for every place a
// person approves or rejects something an automated system or an agent put in front of them. /admin/review uses it;
// /account (notices), /account/agents (drafts) and the claim page can adopt it the same way (see DogApproval.card).
// What it shows, for one item:
//   * the exact words or action, never a preview; for text with an earlier approved version, a word-by-word diff;
//   * the SHA-256 of the exact bytes the decision binds, in short form, with "Copy full hash", and whether this browser
//     got the same hash from the words on screen;
//   * the base rates from the item's history, always with the sample size, and "Not enough history yet" under 20;
//   * why it is here (question IDs and their families, never a score) in a "Why this is here" disclosure, which is also
//     the only place any model confidence may go;
//   * one button per decision and reason, all drawn alike and at least 44 px tall: no generic "OK", no colour for the
//     choice to pick, and reject is never red only. "Other reason" asks for the reason in words;
//   * for a sensitive item (tier 3), a 10-second read with the words scrolled to the end before the buttons work;
//   * after a decision, Undo for 30 seconds, in the card and in a toast (role="status"). Decisions the caller marks
//     "deferred" (publishing, keeping) are sent only when the 30 seconds end, so Undo sends nothing; others (removing)
//     are sent at once and Undo asks the caller to reverse them. Leaving the page sends what is waiting.
//   * how long the item was on screen (visible, with the tab in front), sent with the decision for the oversight counts.
// Text only: everything is set with textContent. No inline style; the look is /approval.css on the site's tokens.
(function () {
  'use strict';
  var UNDO_SECONDS = 30;
  var READ_SECONDS = 10;
  var pending = []; // deferred decisions waiting for their 30 seconds: { send, cancel }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }
  function addClass(e, c) { if ((' ' + e.className + ' ').indexOf(' ' + c + ' ') < 0) e.className = (e.className + ' ' + c).trim(); }
  function now() { return Date.now(); }
  var later = function (f, ms) { return setTimeout(f, ms); };

  // SHA-256 of text as UTF-8, in hex, in this browser (WebCrypto). Resolves null where WebCrypto isn't available.
  function sha256(text) {
    try {
      if (!window.crypto || !window.crypto.subtle || typeof TextEncoder === 'undefined') return Promise.resolve(null);
      return window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)).then(function (buf) {
        return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
      }).catch(function () { return null; });
    } catch (e) { return Promise.resolve(null); }
  }

  // Word-by-word diff of two texts (longest common subsequence), as [{ kind: 'same' | 'del' | 'ins', text }]. Long texts
  // (over 600 words either side) aren't compared word by word: null, and the caller shows both versions.
  function diff(a, b) {
    var x = String(a).split(/(\s+)/), y = String(b).split(/(\s+)/);
    if (x.length > 1200 || y.length > 1200) return null;
    var n = x.length, m = y.length, i, j, L = [];
    for (i = 0; i <= n; i++) { L.push(new Array(m + 1).fill(0)); }
    for (i = n - 1; i >= 0; i--) for (j = m - 1; j >= 0; j--) L[i][j] = x[i] === y[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
    var out = [];
    var push = function (kind, t) { var last = out[out.length - 1]; if (last && last.kind === kind) last.text += t; else out.push({ kind: kind, text: t }); };
    i = 0; j = 0;
    while (i < n && j < m) {
      if (x[i] === y[j]) { push('same', x[i]); i++; j++; } else if (L[i + 1][j] >= L[i][j + 1]) { push('del', x[i]); i++; } else { push('ins', y[j]); j++; }
    }
    while (i < n) push('del', x[i++]);
    while (j < m) push('ins', y[j++]);
    return out;
  }

  // "Published as written 91% of 120 recent decisions; edited 7%; removed 2%." Rates only from 20 (2.2).
  function baseRates(h) {
    if (!h) return null;
    var n = h.decided || 0;
    var noun = h.noun || 'earlier decisions';
    if (n < 20) return 'Not enough history yet: ' + n + ' ' + noun + ' (a rate needs 20).';
    var pct = function (k) { return Math.round(100 * (k || 0) / n) + '%'; };
    var parts = [(h.approvedLabel || 'Approved as written') + ' ' + pct(h.approved) + ' of ' + n + ' ' + noun];
    if (h.edited !== undefined && h.edited !== null) parts.push('edited ' + pct(h.edited));
    parts.push((h.rejectedLabel || 'rejected') + ' ' + pct(h.removed));
    return parts.join('; ') + '.';
  }

  // The toast: one shared region the page provides (role="status"), or one made here at the end of <main>.
  function toastRegion(opts) {
    if (opts.toast) return opts.toast;
    var t = document.getElementById('ap-toast');
    if (!t) {
      t = el('div', 'ap-toast');
      t.id = 'ap-toast';
      t.setAttribute('role', 'status');
      t.hidden = true;
      var main = document.getElementById('main');
      if (main) main.appendChild(t);
    }
    return t;
  }

  // Makes one item's card. Returns { el, focusSide(side), undo(), decided() }.
  //   item: { id, pill, words, previous, sha256, bindsShownWords (optional: false when the words on screen are masked),
  //           mismatchNote, meta: [strings], why, whyDetails: [strings], since (ISO time), history: { decided,
  //           approved, edited, removed, noun, approvedLabel, rejectedLabel }, tier (0 to 3), readSeconds,
  //           choices: [{ decision, label, side: 'approve' | 'reject', reasons: [{ code, label }], deferred, done }],
  //           edit: { label, approveLabel } (optional: "Edit, then approve", for drafts) }
  //   opts: { onDecide(choice, { reason, note, sha256, seenMs, text, keepalive }) -> Promise<{ ok, message, undo }>,
  //           onSettled(outcome), toast }
  function card(item, opts) {
    opts = opts || {};
    var card = el('article', 'card ap');
    card.setAttribute('data-item', item.id);
    card.tabIndex = -1;
    if (item.pill) card.appendChild(el('span', 'pill a', item.pill));

    // The words, every paragraph. Long ones sit in their own scroll box (a sensitive item must be read to the end).
    var words = el('blockquote', 'ap-words');
    String(item.words || '').split(/\n{2,}/).forEach(function (para) { words.appendChild(el('p', '', para)); });
    var long = String(item.words || '').length > 1200;
    if (long) { addClass(words, 'ap-long'); words.tabIndex = 0; words.setAttribute('aria-label', 'The full text'); }
    card.appendChild(words);

    if (item.previous !== undefined && item.previous !== null && item.previous !== item.words) {
      var d = diff(item.previous, item.words);
      var box = el('div', 'ap-diff');
      box.appendChild(el('p', 'fine', 'Changes from the last approved version (removed words struck through, new words underlined):'));
      var p = el('p', 'ap-diff-text');
      if (d) d.forEach(function (part) { p.appendChild(el(part.kind === 'del' ? 'del' : part.kind === 'ins' ? 'ins' : 'span', '', part.text)); });
      else { p.appendChild(el('span', 'fine', 'Too long to compare word by word. The last approved version: ')); p.appendChild(el('span', '', item.previous)); }
      box.appendChild(p);
      card.appendChild(box);
    }

    (item.meta || []).forEach(function (m) { card.appendChild(el('p', 'fine ap-meta', m)); });
    if (item.why) card.appendChild(el('p', 'fine why', item.why));
    if (item.since) {
      var since = el('p', 'fine', 'In the queue since ');
      var t = el('time', '', new Date(item.since).toLocaleString());
      t.setAttribute('datetime', new Date(item.since).toISOString());
      since.appendChild(t);
      since.appendChild(document.createTextNode('.'));
      card.appendChild(since);
    }
    if (item.whyDetails && item.whyDetails.length) {
      var det = el('details', 'ap-why');
      det.appendChild(el('summary', '', 'Why this is here'));
      item.whyDetails.forEach(function (w) { det.appendChild(el('p', 'fine', w)); });
      card.appendChild(det);
    }
    var rates = baseRates(item.history);
    if (rates) card.appendChild(el('p', 'fine ap-rates', rates));

    // The hash of the bytes the decision binds.
    var bound = item.sha256 || null;
    var hashLine = el('p', 'fine ap-hash');
    var hashText = el('span', '', '');
    var copy = el('button', 'linkbtn ap-copy', 'Copy full hash');
    copy.type = 'button';
    var hashNote = el('span', 'ap-hash-note', '');
    function showHash(h, note) {
      bound = h;
      hashText.textContent = h ? 'SHA-256 of the exact words this decision binds: ' : 'The words’ hash isn’t available, so this can’t be decided here.';
      if (h) { var code = el('code', '', h.slice(0, 8) + '…' + h.slice(-8)); code.setAttribute('title', h); hashText.appendChild(code); hashText.appendChild(document.createTextNode('. ')); }
      copy.hidden = !h;
      hashNote.textContent = note || '';
    }
    copy.addEventListener('click', function () {
      var ok = function () { status.textContent = 'Copied the full hash: ' + bound + '.'; };
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(bound).then(ok, function () { status.textContent = 'Full hash: ' + bound; });
        else status.textContent = 'Full hash: ' + bound;
      } catch (e) { status.textContent = 'Full hash: ' + bound; }
    });
    hashLine.appendChild(hashText);
    hashLine.appendChild(copy);
    hashLine.appendChild(document.createTextNode(' '));
    hashLine.appendChild(hashNote);
    card.appendChild(hashLine);
    showHash(bound, '');
    // Before the server sends a hash (a page from before 041), this browser's hash of the words is the one bound.
    if (!bound && item.hashFromWords) sha256(String(item.words || '')).then(function (h) { if (h) showHash(h, 'Worked out in this browser from the words above.'); });
    if (bound) {
      sha256(String(item.words || '')).then(function (mine) {
        if (mine === null) return;
        if (mine === bound) hashNote.textContent = 'This browser got the same hash from the words above.';
        else hashNote.textContent = item.mismatchNote || 'The words above aren’t byte for byte the stored words this hash is of.';
      });
    }

    // Time on screen: counted while the card is visible and the tab is in front.
    var seen = 0, since0 = null, visible = true;
    var tick = function () { if (since0 !== null) { seen += now() - since0; since0 = now(); } };
    var front = function () { return !document.visibilityState || document.visibilityState === 'visible'; };
    var start = function () { if (since0 === null && visible && front()) since0 = now(); };
    var stop = function () { tick(); since0 = null; };
    if (typeof IntersectionObserver === 'function') {
      visible = false;
      new IntersectionObserver(function (es) { es.forEach(function (e) { visible = e.isIntersecting; if (visible) start(); else stop(); }); }, { threshold: 0.4 }).observe(card);
    }
    if (document.addEventListener) document.addEventListener('visibilitychange', function () { if (front()) start(); else stop(); });
    start();
    var seenMs = function () { tick(); return Math.round(seen); };

    // The read gate, for a sensitive item.
    var tier = item.tier || 0;
    var gateSeconds = tier >= 3 ? (item.readSeconds || READ_SECONDS) : 0;
    var gate = gateSeconds ? el('p', 'fine ap-gate', '') : null;
    var scrolled = !long;
    if (long) words.addEventListener('scroll', function () { if (words.scrollTop + words.clientHeight >= words.scrollHeight - 4) { scrolled = true; check(); } });
    if (gate) card.appendChild(gate);

    // The decisions: one button for each decision and reason, approve side first, then reject side.
    var row = el('div', 'ap-decide');
    var sides = { approve: el('div', 'ap-side ap-approve'), reject: el('div', 'ap-side ap-reject') };
    var buttons = [];
    var status = el('p', 'fine ap-status', '');
    status.setAttribute('role', 'status');
    var other = el('div', 'ap-other');
    other.hidden = true;
    var done = false, undoFn = null, undoTimer = null;

    (item.choices || []).forEach(function (c) {
      (c.reasons || []).forEach(function (r) {
        var b = el('button', 'btn ap-choice', '');
        b.type = 'button';
        b.setAttribute('data-decision', c.decision);
        b.setAttribute('data-reason', r.code);
        b.appendChild(el('span', 'ap-verb', c.label));
        b.appendChild(el('span', 'ap-reason', r.code === 'other' ? 'other reason…' : r.label));
        b.addEventListener('click', function () {
          if (r.code === 'other') return askOther(c);
          decide(c, r.code, null);
        });
        (sides[c.side] || sides.reject).appendChild(b);
        buttons.push(b);
      });
    });
    if (item.edit) {
      var eb = el('button', 'btn ap-choice ap-edit', '');
      eb.type = 'button';
      eb.setAttribute('data-decision', 'edit');
      eb.appendChild(el('span', 'ap-verb', item.edit.label || 'Edit'));
      eb.appendChild(el('span', 'ap-reason', 'then approve'));
      eb.addEventListener('click', openEdit);
      sides.approve.appendChild(eb);
      buttons.push(eb);
    }
    row.appendChild(sides.approve);
    row.appendChild(sides.reject);
    card.appendChild(row);
    card.appendChild(other);
    card.appendChild(status);

    function enabled(on) { buttons.forEach(function (b) { b.disabled = !on; }); }
    var opened = gateSeconds === 0;
    function check() {
      if (opened || !gate) return;
      var left = Math.max(0, gateSeconds - Math.floor(seenMs() / 1000));
      if (left === 0 && scrolled) { opened = true; gate.textContent = 'Read. You can decide now.'; enabled(true); return; }
      gate.textContent = 'Sensitive: read it through first' + (long && !scrolled ? ', to the end of the text' : '') + '. The buttons work after '
        + (left ? left + ' more seconds on screen' : 'that') + '.';
      later(check, 1000);
    }
    if (gate) { enabled(false); check(); }

    // "Other reason": the reason in words, then the same decision.
    function askOther(c) {
      other.textContent = '';
      other.hidden = false;
      var id = 'ap-other-' + item.id + '-' + c.decision;
      var label = el('label', '', 'Your reason to ' + c.label.toLowerCase() + ' (1 to 300 characters)');
      label.setAttribute('for', id);
      var input = el('input', '');
      input.id = id;
      input.type = 'text';
      input.setAttribute('maxlength', '300');
      var go = el('button', 'btn ap-choice', c.label + ' with this reason');
      go.type = 'button';
      go.addEventListener('click', function () {
        var v = String(input.value || '').trim();
        if (!v) { status.textContent = 'Write the reason first.'; input.focus(); return; }
        decide(c, 'other', v);
      });
      other.appendChild(label);
      other.appendChild(input);
      other.appendChild(go);
      buttons.push(go);
      input.focus();
    }

    // "Edit, then approve" (drafts): the words in a box; approving sends the edited words and their own hash.
    function openEdit() {
      other.textContent = '';
      other.hidden = false;
      var id = 'ap-edit-' + item.id;
      var label = el('label', '', 'Edit the words, then approve them');
      label.setAttribute('for', id);
      var area = el('textarea', '');
      area.id = id;
      area.value = String(item.words || '');
      var go = el('button', 'btn ap-choice', item.edit.approveLabel || 'Approve the edited words');
      go.type = 'button';
      go.addEventListener('click', function () {
        var text = String(area.value || '');
        sha256(text).then(function (h) {
          var c = { decision: 'approve', label: item.edit.approveLabel || 'Approve', edited: true, deferred: true, done: 'Approved with your edits.' };
          decide(c, 'edited', null, { text: text, sha256: h });
        });
      });
      other.appendChild(label);
      other.appendChild(area);
      other.appendChild(go);
      buttons.push(go);
      area.focus();
    }

    function settle(outcome) {
      done = true;
      addClass(card, 'decided');
      buttons.forEach(function (b) { b.hidden = true; });
      other.hidden = true;
      if (opts.onSettled) opts.onSettled(outcome);
    }
    function showUndo(message, act) {
      var toast = toastRegion(opts);
      undoFn = act;
      status.textContent = message + ' ';
      var u = el('button', 'linkbtn ap-undo', 'Undo');
      u.type = 'button';
      u.addEventListener('click', function () { if (undoFn) undoFn(); });
      status.appendChild(u);
      toast.textContent = message + ' ';
      var tu = el('button', 'linkbtn ap-undo', 'Undo');
      tu.type = 'button';
      tu.addEventListener('click', function () { if (undoFn) undoFn(); });
      toast.appendChild(tu);
      toast.hidden = false;
      clearTimeout(undoTimer);
      undoTimer = later(function () { undoFn = null; u.remove(); if (toast.firstChild && tu.parentNode === toast) toast.hidden = true; }, UNDO_SECONDS * 1000);
    }

    function decide(c, reason, note, edited) {
      if (done) return;
      var args = { reason: reason, note: note, sha256: edited ? edited.sha256 : bound, seenMs: seenMs(), text: edited ? edited.text : undefined };
      if (!args.sha256) { status.textContent = 'This can’t be decided here: the words’ hash isn’t available.'; return; }
      enabled(false);
      if (c.deferred) {
        // Sent when the 30 seconds end (or when the page is left); Undo sends nothing.
        var timer;
        var entry = { send: function (keepalive) { clearTimeout(timer); remove(); return send(c, args, keepalive); }, cancel: function () { clearTimeout(timer); remove(); } };
        var remove = function () { var k = pending.indexOf(entry); if (k >= 0) pending.splice(k, 1); };
        pending.push(entry);
        timer = later(function () { entry.send(false); }, UNDO_SECONDS * 1000);
        settle({ decision: c.decision, reason: reason, pending: true, seenMs: args.seenMs });
        showUndo((c.waiting || (c.label + ': in ' + UNDO_SECONDS + ' seconds.')), function () {
          entry.cancel();
          undoFn = null;
          done = false;
          card.className = card.className.replace(/\s*\bdecided\b/, '');
          buttons.forEach(function (b) { b.hidden = false; });
          enabled(opened);
          status.textContent = 'Undone: nothing was sent.';
          var toast = toastRegion(opts); toast.textContent = 'Undone: nothing was sent.';
          if (opts.onSettled) opts.onSettled({ decision: c.decision, undone: true });
        });
        return;
      }
      status.textContent = 'Saving…';
      send(c, args, false);
    }
    function send(c, args, keepalive) {
      args.keepalive = keepalive;
      return Promise.resolve(opts.onDecide(c, args)).then(function (r) {
        if (!r || !r.ok) {
          status.textContent = (r && r.message) || 'That didn’t go through.';
          if (!(r && r.final)) { done = false; card.className = card.className.replace(/\s*\bdecided\b/, ''); buttons.forEach(function (b) { b.hidden = false; }); enabled(opened); }
          if (opts.onSettled) opts.onSettled({ decision: c.decision, failed: true });
          return;
        }
        if (c.deferred) { status.textContent = r.message || c.done || 'Done.'; return; }
        settle({ decision: c.decision, reason: args.reason, seenMs: args.seenMs });
        if (r.undo) {
          showUndo(r.message || c.done || 'Done.', function () {
            undoFn = null;
            status.textContent = 'Undoing…';
            Promise.resolve(r.undo()).then(function (u) {
              status.textContent = (u && u.message) || 'Undone.';
              var toast = toastRegion(opts); toast.textContent = status.textContent;
              if (u && u.ok && opts.onSettled) opts.onSettled({ decision: c.decision, undone: true });
            });
          });
        } else status.textContent = r.message || c.done || 'Done.';
      }).catch(function () {
        status.textContent = 'That didn’t go through. Please try again.';
        done = false; buttons.forEach(function (b) { b.hidden = false; }); enabled(opened);
      });
    }

    return {
      el: card,
      // Moves focus to the first button of a side (the page's A and R keys); never decides by itself.
      focusSide: function (side) { var b = sides[side] && sides[side].querySelector('button'); if (b && !b.hidden && !b.disabled) { b.focus(); return true; } return false; },
      undo: function () { if (undoFn) { undoFn(); return true; } return false; },
      decided: function () { return done; }
    };
  }

  // Leaving the page sends what is waiting (fetch with keepalive, through each caller's onDecide).
  function flush() { pending.slice().forEach(function (p) { p.send(true); }); }
  if (window.addEventListener) window.addEventListener('pagehide', flush);

  window.DogApproval = { card: card, diff: diff, baseRates: baseRates, sha256: sha256, flush: flush, UNDO_SECONDS: UNDO_SECONDS, READ_SECONDS: READ_SECONDS };
})();
