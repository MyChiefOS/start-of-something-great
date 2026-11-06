// /admin/review (at /review until Nov 5, 2026): Aaron's review queue, built for a phone (SF5). Everything members wrote
// is shown with textContent, never as HTML.
// Phase 4 of the design handoff of Nov 5, 2026 (CODING_AGENT_SPEC.md section 2, as Aaron decided it: review is
// automated by JEVs and the narrow AI after it, items reach him by risk, no two-person review, so no "Ask another reviewer"):
// each item is the shared approval screen (/approval.js): the pill, the exact words, who wrote it, why it is here by
// question ID and family (never a score), the SHA-256 of the words a decision binds, the author's record here with its
// sample size, and one button per decision and reason, all drawn alike, so one tap decides with a reason and there is
// no generic "OK". Sensitive items (tier 3) need 10 seconds on screen first. Publish and Keep wait 30 seconds for Undo;
// Remove happens at once and Undo restores. The queue comes highest tier first, then oldest; past today's budget the
// rest wait with their age shown and nothing is approved to clear them. Keys: J and K move, A and R go to a side's
// reasons (they never decide by themselves), U undoes; a switch turns them off. A summary of this visit, for Aaron only.
// UX PR D (the UI/UX review of Oct 31, findings 6 and 12's front-end part): signed out, only the sign-in panel; an
// empty queue says what happens when nothing is waiting; each item says when it joined the queue and lists its reasons
// in the order they can arise (see why()).
// UX PR G (finding 12's backend part): a post JEVs held or hid names the questions that flagged it (asked()).
(function () {
  var queue = document.getElementById('queue');
  var summary = document.getElementById('summary');
  var LABEL = { approve: 'Publish', keep: 'Keep', remove: 'Remove', restore: 'Restore' };
  var DONE = { approve: 'Published: it’s live.', keep: 'Kept: the reports are closed.', remove: 'Removed.', live: 'Restored: it’s live again.', waiting: 'Restored: it’s waiting for review again.' };
  var WAITING = { approve: 'Publishing in 30 seconds.', keep: 'Keeping in 30 seconds.', restore: 'Restoring in 30 seconds.' };
  var REASON = { spam: 'spam', abuse: 'abuse', private_info: 'private information', illegal: 'illegal', other: 'other' };
  // Why a decision is made, in words, for each reason code the database accepts (041, app.review_decisions).
  var BECAUSE = { ordinary: 'an ordinary post', checked: 'I checked what it flags', not_upheld: 'the report isn’t upheld', spam: 'spam', abuse: 'abuse',
    private_info: 'private information', illegal: 'illegal', mistake: 'removed by mistake', other: 'other reason' };
  // UX PR G (finding 12): the public titles of JEVs's questions, as db/jevs.js names them (test/ux-g.test.js keeps the
  // two the same). The queue sends only the IDs that flagged a post, highest first, never a number.
  var TITLES = {
    J01: 'Account age', J02: 'Sign-in strength', J03: 'Disposable email', J04: 'Activity against its own usual rate',
    J05: 'Clusters', J06: 'New agents in a day', J07: 'Links and new domains', J08: 'Contact details',
    J09: 'Copies of other members’ words', J10: 'Track record', J11: 'Sensitive action',
    J12: 'Reply-chain depth', J13: 'Region', J14: 'Credible reports', J15: 'Sub-agent spawning',
    J18: 'Keys and passwords', J19: 'Repeats of its own post'
  };
  // The question families, as /checks lists them.
  var FAMILY = { J01: 'the account', J02: 'the account', J03: 'the account', J04: 'the account', J05: 'the account', J06: 'the account',
    J10: 'the account', J13: 'the account', J07: 'the post', J08: 'the post', J09: 'the post', J12: 'the post', J14: 'a report',
    J11: 'agent actions', J15: 'agent actions', J18: 'an agent posting on its own', J19: 'an agent posting on its own' };
  var open = 0;
  var LEVEL = { 0: 'Email only', 1: 'GitHub member', 2: 'Verified' };
  // The pill: what the post is now (held, hidden, reported or sampled), then its first reason in a few words.
  var STATE = { waiting: 'Held', removed: 'Hidden', live: 'Reported' };
  function pill(i) {
    var word = i.item_type === 'sampled' ? 'Sampled' : STATE[i.status] || i.status;
    var first = (i.questions || [])[0];
    var reason = i.appealed ? 'appealed' : first ? (TITLES[first] ? TITLES[first].charAt(0).toLowerCase() + TITLES[first].slice(1) : first)
      : i.first_posts ? 'first posts' : i.reports && i.status !== 'live' ? 'reported' : i.item_type === 'sampled' ? 'flagged after it went live' : '';
    return (i.tier === 3 ? 'Sensitive · ' : '') + word + (reason ? ' · ' + reason : '');
  }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function count() {
    summary.textContent = open === 0 ? 'Nothing is waiting.' : open + (open === 1 ? ' post needs' : ' posts need') + ' a decision, the most sensitive first, then the oldest.';
  }

  // The reasons, oldest first. The queue sends one time per item (flagged_at, its oldest open flag), not one per reason,
  // so the order comes from the database's rules (inferred from the code, not measured): a first-post flag is made with
  // the post (004); a report needs a live post (app.reportable), and JEVs's hold at posting takes the post off live in
  // the same step (032), so an open JEVs flag beside open reports came from a report (post.reported); an appeal needs
  // that hold first (app.jevs_appealable). A sample's flag needs a live post too (041).
  function why(i) {
    var parts = [];
    if (i.first_posts) parts.push('one of a new member’s first 3 posts');
    if (i.reports) {
      parts.push(i.reports + (i.reports === 1 ? ' report' : ' reports') + (i.reasons.length ? ' (' + i.reasons.map(function (r) { return REASON[r] || r; }).join(', ') + ')' : ''));
    }
    if (i.classifiers && i.classifiers.length) {
      parts.push('flagged by ' + i.classifiers.map(function (c) {
        return c === 'jevs' ? 'JEVs (automatic checks)' : (i.classifier_labels && i.classifier_labels[c]) || c;
      }).join(', '));
    }
    if (i.appealed) parts.push('the author appealed');
    return 'Why: ' + parts.join('; ') + '.';
  }
  // "Our checks asked about: Sign-in strength (J02), Clusters (J05)." An ID the page doesn't know is shown as it is.
  function asked(i) {
    var ids = i.questions || [];
    if (!ids.length) return null;
    return 'Our checks asked about: ' + ids.map(function (id) { return TITLES[id] ? TITLES[id] + ' (' + id + ')' : id; }).join(', ') + '.';
  }
  function families(i) {
    var ids = i.questions || [], by = {}, order = [];
    ids.forEach(function (id) { var f = FAMILY[id] || 'other'; if (!by[f]) { by[f] = []; order.push(f); } by[f].push(id); });
    if (!order.length) return null;
    return 'Question families: ' + order.map(function (f) { return f + ' (' + by[f].join(', ') + ')'; }).join('; ') + '. Each question is on The checks page.';
  }
  function tierLine(i) {
    if (i.tier === 3) return 'Tier 3, sensitive: ' + (i.reasons && (i.reasons.indexOf('private_info') >= 0 || i.reasons.indexOf('illegal') >= 0)
      ? 'a report of private information or something illegal' : 'our checks found contact details or keys') + '. It needs 10 seconds on screen before you decide.';
    if (i.tier === 2) return 'Tier 2: held for a person after the automated checks. Every decision names its reason.';
    return null;
  }

  // ---- Deciding ----
  function send(i, decision, args) {
    var body = { review: i.id, decision: decision, reason: args.reason, sha256: args.sha256, seen_ms: args.seenMs };
    if (args.note) body.note = args.note;
    return fetch('/api/feed', { method: 'POST', keepalive: Boolean(args.keepalive), headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, status: r.status, d: d }; }); });
  }
  var session = { decided: 0, seen: [], by: {} };
  function sessionLine() {
    var box = document.getElementById('session');
    if (!session.decided) { box.hidden = true; return; }
    var s = session.seen.slice().sort(function (a, b) { return a - b; });
    var med = s.length ? s[Math.floor((s.length - 1) / 2)] / 1000 : null;
    var parts = Object.keys(session.by).map(function (k) { return session.by[k] + ' ' + { approve: 'published', keep: 'kept', remove: 'removed', restore: 'restored' }[k]; });
    document.getElementById('session-text').textContent = session.decided + (session.decided === 1 ? ' decision' : ' decisions') + ' (' + parts.join(', ') + ')'
      + (med === null ? '' : ', a median of ' + (Math.round(med * 10) / 10) + ' seconds on each item') + (open === 0 ? '. Nothing is left in the queue.' : '. ' + open + ' still waiting.');
    box.hidden = false;
  }
  function settled(o) {
    var decision = o.decision;
    if (o.failed) return;
    if (o.undone) {
      session.decided = Math.max(0, session.decided - 1);
      session.by[decision] = Math.max(0, (session.by[decision] || 1) - 1);
      if (!session.by[decision]) delete session.by[decision];
      session.seen.pop();
      open += 1;
    } else {
      session.decided += 1;
      session.by[decision] = (session.by[decision] || 0) + 1;
      session.seen.push(o.seenMs || 0);
      open = Math.max(0, open - 1);
    }
    count();
    sessionLine();
  }

  function choicesFor(i) {
    var reasons = i.decision_reasons || { approve: ['ordinary', 'checked', 'other'], keep: ['not_upheld', 'ordinary', 'checked', 'other'],
      remove: ['spam', 'abuse', 'private_info', 'illegal', 'other'], restore: ['mistake', 'other'] };
    return i.actions.map(function (a) {
      return { decision: a, label: LABEL[a], side: a === 'remove' ? 'reject' : 'approve', deferred: a !== 'remove', waiting: WAITING[a], done: DONE[a],
        reasons: (reasons[a] || ['other']).map(function (r) { return { code: r, label: BECAUSE[r] || r }; }) };
    });
  }

  var cards = [];
  function render(d) {
    queue.textContent = '';
    cards = [];
    open = d.open;
    count();
    var b = d.budget;
    var budget = document.getElementById('budget');
    var left = b ? Math.max(0, b.daily - b.used) : null;
    if (b) {
      budget.textContent = b.used >= b.daily
        ? 'You have decided ' + b.used + ' held items today, your daily budget of ' + b.daily + '. The rest wait here with their age shown; nothing is approved to clear them, and you can still decide them.'
        : 'Today: ' + b.used + ' of your ' + b.daily + ' held items decided.';
      budget.hidden = false;
    } else budget.hidden = true;
    document.getElementById('empty').hidden = d.items.length > 0;
    document.getElementById('keys').hidden = !d.items.length || !document.addEventListener;
    d.items.forEach(function (i, n) {
      if (left !== null && n === left && n > 0) queue.appendChild(el('p', 'fine', 'Past today’s budget: these wait, with their age shown. Nothing is approved to clear them; you can still decide them.'));
      var meta = [];
      meta.push(i.author.name + ' · ' + (LEVEL[i.author.level] || 'level ' + i.author.level) + ' (level ' + i.author.level + ') · ' + i.author.live_posts + ' live '
        + (i.author.live_posts === 1 ? 'post' : 'posts') + (i.author.status === 'banned' ? ' · banned' : ''));
      i.notes.forEach(function (x) { meta.push('Reporter: ' + x); });
      var details = [tierLine(i), asked(i), families(i)].filter(Boolean);
      var item = {
        id: i.id, pill: pill(i), words: i.body, sha256: i.sha256, hashFromWords: !i.sha256, tier: i.tier || 2, meta: meta, why: why(i), since: i.flagged_at,
        whyDetails: details,
        mismatchNote: 'The words above have contact details hidden, as everywhere on the site, so they aren’t byte for byte the stored words this hash is of.',
        history: i.history ? { decided: i.history.decided, approved: i.history.approved, removed: i.history.removed, noun: 'earlier decisions on this member’s posts',
          approvedLabel: 'Published or kept as written', rejectedLabel: 'removed' } : null,
        choices: choicesFor(i)
      };
      var c = window.DogApproval.card(item, {
        onDecide: function (choice, args) {
          return send(i, choice.decision, args).then(function (x) {
            if (!x.ok) return { ok: false, final: x.status === 409 || x.status === 404, message: x.d.error || 'That didn’t go through.' };
            var msg = choice.decision === 'restore' ? DONE[x.d.status] : DONE[choice.decision];
            if (choice.decision !== 'remove') return { ok: true, message: msg };
            return { ok: true, message: msg, undo: function () {
              return send(i, 'restore', { reason: 'undo', sha256: args.sha256, seenMs: 0 }).then(function (y) {
                return y.ok ? { ok: true, message: DONE[y.d.status] } : { ok: false, message: y.d.error || 'That didn’t go through.' };
              });
            } };
          }).catch(function () { return { ok: false, message: 'That didn’t go through. Please try again.' }; });
        },
        onSettled: settled
      });
      queue.appendChild(c.el);
      cards.push(c);
    });
    sessionLine();
  }

  // ---- Keys: J and K move between items, A and R go to a side's reasons, U undoes. Never in a text field. ----
  var keysOn = true;
  try { keysOn = window.localStorage.getItem('dog.review.keys') !== 'off'; } catch (e) { keysOn = true; }
  var toggle = document.getElementById('keys-toggle');
  function showKeys() {
    toggle.setAttribute('aria-pressed', String(keysOn));
    toggle.textContent = keysOn ? 'Turn shortcuts off' : 'Turn shortcuts on';
    document.getElementById('keys-text').textContent = keysOn
      ? 'Keys: J next, K previous, A publish or keep (then choose the reason), R remove (then choose the reason), U undo.'
      : 'Keyboard shortcuts are off.';
  }
  toggle.addEventListener('click', function () {
    keysOn = !keysOn;
    try { window.localStorage.setItem('dog.review.keys', keysOn ? 'on' : 'off'); } catch (e) { /* kept for this visit only */ }
    showKeys();
  });
  showKeys();
  var at = -1;
  function move(by) {
    var live = cards.filter(function (c) { return !c.decided(); });
    if (!live.length) return;
    var cur = live.indexOf(cards[at]);
    var next = live[Math.max(0, Math.min(live.length - 1, cur < 0 ? 0 : cur + by))];
    at = cards.indexOf(next);
    next.el.focus();
    if (next.el.scrollIntoView) next.el.scrollIntoView({ block: 'start' });
  }
  if (document.addEventListener) {
    document.addEventListener('keydown', function (ev) {
      if (!keysOn || ev.ctrlKey || ev.metaKey || ev.altKey) return;
      var t = ev.target && ev.target.tagName;
      if (t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT') return;
      var k = String(ev.key || '').toLowerCase();
      if (k === 'j') move(1);
      else if (k === 'k') move(-1);
      else if ((k === 'a' || k === 'r') && cards[at]) cards[at].focusSide(k === 'a' ? 'approve' : 'reject');
      else if (k === 'u') { for (var n = cards.length - 1; n >= 0; n--) if (cards[n].undo()) break; }
      else return;
      if (ev.preventDefault) ev.preventDefault();
    });
  }

  function load() {
    summary.textContent = 'Loading the queue…';
    fetch('/api/feed?queue=1', { headers: { Accept: 'application/json' } })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, status: r.status, d: d }; }); })
      .then(function (x) {
        var out = x.status === 401;
        // Everything under the summary appears with the answer, so nothing on screen moves when it arrives.
        document.getElementById('signed-out').hidden = !out;
        summary.hidden = out;
        document.getElementById('refresh-row').hidden = out;
        document.getElementById('review-note').hidden = false;
        if (x.ok) return render(x.d);
        queue.textContent = '';
        summary.textContent = x.d.error || 'The queue could not be loaded.';
      })
      .catch(function () {
        summary.textContent = 'The queue could not be loaded. Please try again.';
        document.getElementById('refresh-row').hidden = false;
        document.getElementById('review-note').hidden = false;
      });
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
          var card = el('article', 'card queue-item');
          // "<name> · paused until <time>. "<their appeal>"", as the design draws it, then what set it off.
          var line = el('p', 'paused-line');
          line.appendChild(el('strong', '', cn.member.name));
          line.appendChild(document.createTextNode(' · paused until ' + new Date(cn.ends_at).toLocaleString() + '.'
            + (cn.appeal && cn.appeal.note ? ' “' + cn.appeal.note + '”' : '')));
          card.appendChild(line);
          card.appendChild(el('p', 'fine', (cn.reason === 'copies' ? cn.measured + ' copies of earlier text in an hour' : cn.measured + ' agent actions in an hour')
            + ' (usual ' + cn.usual + ') · ' + (cn.appeal ? 'appealed' + (cn.appeal.note ? '' : ', with no note') : 'no appeal') + '.'));
          var row = el('div', 'acts');
          var result = el('p', 'fine', '');
          result.setAttribute('role', 'status');
          var choices = cn.appeal && !cn.decision ? ['lift', 'keep'] : ['lift'];
          var buttons = choices.map(function (d) {
            var b = el('button', 'btn s', d === 'lift' ? 'End pause' : 'Keep');
            b.type = 'button';
            b.addEventListener('click', function () {
              buttons.forEach(function (y) { y.disabled = true; });
              fetch('/api/notify/appeals', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ containment: cn.id, decision: d }) })
                .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, d: j }; }); })
                .then(function (y) { result.textContent = y.ok ? (d === 'lift' ? 'Ended: their agents are back on their rules.' : 'Kept: it ends on time.') : y.d.error; buttons.forEach(function (z) { z.hidden = y.ok; z.disabled = false; }); });
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
