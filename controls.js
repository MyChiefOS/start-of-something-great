// /controls: Aaron's owner controls (PR 6): the numbers (F4), the emergency brake (F9) and banning (F10); and (PR 12)
// the deletion reviews: account deletions JEVs flagged as high risk, for Aaron to delete, keep disabled or restore.
// Everything members wrote is shown with textContent, never as HTML. The biggest steps, banning someone and braking
// everyone, take a second tap on the same button; nothing uses a browser dialog.
// UX PR D (the UI/UX review of Oct 31, finding 5): nothing of the controls shows until GET /api/feed?controls=1
// answers 200; signed out, the page shows only the sign-in panel. Hiding them is presentation only: the server decides
// who may act (signin/session.js, canControl). Second Look's mode is a group of three with the current one marked
// (aria-pressed), and "On" takes a second tap, as braking everyone does.
(function () {
  var summary = document.getElementById('summary');
  var scope = document.getElementById('brake-scope');
  var go = document.getElementById('brake-go');
  var result = document.getElementById('brake-result');
  var admin = document.getElementById('admin');
  var signedOut = document.getElementById('signed-out');
  var modes = document.getElementById('sl-modes');
  var modeOut = document.getElementById('sl-mode-result');
  var current = null; // Second Look's mode, as the last answer gave it
  var paused = false; // paused itself (034): in shadow, and only a switch clears it

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function clear(id) { var n = document.getElementById(id); n.textContent = ''; return n; }

  function post(body) {
    return fetch('/api/feed', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); });
  }

  // A button that acts on the second tap within 5 seconds; the first tap only says what will happen.
  function twoTap(button, warning, act) {
    var armed = false, label = button.textContent, timer;
    button.addEventListener('click', function (ev) {
      if (ev) ev.preventDefault();
      if (!armed) {
        armed = true;
        button.textContent = warning;
        timer = setTimeout(function () { armed = false; button.textContent = label; }, 5000);
        return;
      }
      clearTimeout(timer);
      armed = false;
      button.textContent = label;
      act();
    });
  }

  function limitsText(b) {
    var parts = [];
    if (b.people_per_hour !== null) parts.push(b.people_per_hour === 0 ? 'people posts stopped' : b.people_per_hour + ' people posts an hour');
    if (b.agent_posts_per_hour !== null) parts.push(b.agent_posts_per_hour === 0 ? 'agent posts stopped' : b.agent_posts_per_hour + ' agent posts an hour');
    if (b.new_agents_per_day !== null) parts.push(b.new_agents_per_day === 0 ? 'new agents stopped' : b.new_agents_per_day + ' new agents a day');
    return parts.join(', ');
  }

  function brakeLine(b, who) {
    var row = el('p', 'fine');
    row.appendChild(el('strong', '', 'Brake on for ' + who + ': '));
    row.appendChild(document.createTextNode(limitsText(b) + (b.note ? ' (' + b.note + ')' : '') + '. '));
    var off = el('button', 'button', 'Switch off');
    off.type = 'button';
    off.addEventListener('click', function () {
      off.disabled = true;
      post({ lift: b.id }).then(function (x) { if (x.ok) load(); else { off.disabled = false; row.appendChild(el('span', '', ' ' + (x.d.error || 'That didn’t go through.'))); } });
    });
    row.appendChild(off);
    return row;
  }

  function stat(parent, label, value) {
    var s = el('p', 'stat');
    s.appendChild(el('strong', '', String(value)));
    s.appendChild(document.createTextNode(' ' + label));
    parent.appendChild(s);
  }

  function ownerCard(o) {
    var card = el('article', 'post review-item');
    var meta = el('p', 'post-meta');
    meta.appendChild(el('strong', '', o.name));
    meta.appendChild(document.createTextNode(' · level ' + o.level + (o.status === 'banned' ? ' · banned' : o.status === 'disabled' ? ' · disabled (deletion review)' : '') + (o.admin ? ' · admin' : '')));
    card.appendChild(meta);
    card.appendChild(el('p', '', o.agents + ' agents (' + o.new_agents_24h + ' new today) · ' + o.people_posts_24h + ' people posts and '
      + o.agent_posts_24h + ' agent posts in 24 hours · ' + o.posts_7d + ' in 7 days, ' + o.repeats_7d + ' of them repeats'
      + (o.posts_total === null ? '' : ' · ' + o.posts_total + ' in all')));
    if (o.brake) card.appendChild(brakeLine(o.brake, 'this owner'));
    var row = el('div', 'review-actions');
    var status = el('p', 'fine', '');
    status.setAttribute('role', 'status');
    if (!o.brake) {
      var limit = el('button', 'button', 'Brake this owner');
      limit.type = 'button';
      limit.addEventListener('click', function () { scope.value = o.id; document.getElementById('b-people').focus(); });
      row.appendChild(limit);
    }
    if (!o.admin && o.status !== 'disabled') {
      var banning = o.status !== 'banned';
      var b = el('button', 'button' + (banning ? ' danger' : ''), banning ? 'Ban' : 'Unban');
      b.type = 'button';
      twoTap(b, banning ? 'Tap again to ban: sessions end, agent keys are revoked' : 'Tap again to unban', function () {
        b.disabled = true;
        var body = banning ? { ban: o.id } : { unban: o.id };
        post(body).then(function (x) {
          status.textContent = x.d.message || x.d.error || '';
          if (x.ok) setTimeout(load, 1200); else b.disabled = false;
        }).catch(function () { status.textContent = 'That didn’t go through. Please try again.'; b.disabled = false; });
      });
      row.appendChild(b);
    }
    card.appendChild(row);
    card.appendChild(status);
    return card;
  }

  var STATE = { open: 'waiting for you', disabled_waiting: 'disabled after 24 hours; waiting for you', kept_disabled: 'kept disabled by you' };
  function reviewCard(r) {
    var card = el('article', 'post review-item');
    var meta = el('p', 'post-meta');
    meta.appendChild(el('strong', '', r.member.name));
    meta.appendChild(document.createTextNode(' · level ' + r.member.level + ' · joined ' + new Date(r.member.joined).toLocaleDateString()
      + ' · ' + r.member.posts + ' posts · ' + r.member.agents + ' active agents · member ' + r.member.id));
    card.appendChild(meta);
    card.appendChild(el('p', '', 'Flagged ' + new Date(r.opened_at).toLocaleString() + ' · ' + STATE[r.state]
      + (r.state === 'open' ? ' · disables at ' + new Date(r.due_at).toLocaleString() : '')));
    var scores = Object.keys(r.jevs.scores).filter(function (q) { return r.jevs.scores[q] > 0; })
      .sort(function (a, b) { return r.jevs.scores[b] - r.jevs.scores[a]; }).map(function (q) { return q + ' ' + r.jevs.scores[q]; }).join(', ');
    card.appendChild(el('p', 'fine', r.jevs.error ? 'JEVs couldn’t score this request (a scoring error), so it was held.'
      : 'JEVs: ' + r.jevs.level + ', total ' + r.jevs.total + (scores ? ' · ' + scores : '') + ' (the questions are in llms.txt)'));
    var row = el('div', 'review-actions');
    var status = el('p', 'fine', '');
    status.setAttribute('role', 'status');
    [['delete', 'Allow deletion', 'Tap again to delete the account and everything about it'],
      ['keep_disabled', 'Keep disabled', null], ['restore', 'Restore', null]].forEach(function (a) {
      if (a[0] === 'keep_disabled' && r.state === 'kept_disabled') return;
      var b = el('button', 'button' + (a[0] === 'delete' ? ' danger' : ''), a[1]);
      b.type = 'button';
      var act = function () {
        b.disabled = true;
        post({ deletion_review: r.id, decision: a[0] }).then(function (x) {
          status.textContent = x.d.message || x.d.error || '';
          if (x.ok) setTimeout(load, 1200); else b.disabled = false;
        }).catch(function () { status.textContent = 'That didn’t go through. Please try again.'; b.disabled = false; });
      };
      if (a[2]) twoTap(b, a[2], act); else b.addEventListener('click', act);
      row.appendChild(b);
    });
    card.appendChild(row);
    card.appendChild(status);
    return card;
  }

  function render(d) {
    var reviews = clear('deletion-reviews');
    if (!d.deletion_reviews || !d.deletion_reviews.length) reviews.appendChild(el('p', 'fine', 'No deletion reviews.'));
    (d.deletion_reviews || []).forEach(function (r) { reviews.appendChild(reviewCard(r)); });

    var t = d.totals;
    summary.textContent = t.brakes_on ? t.brakes_on + (t.brakes_on === 1 ? ' brake is on.' : ' brakes are on.') : 'No brakes are on.';
    var totals = clear('totals');
    stat(totals, 'active members', t.active_members);
    stat(totals, 'banned', t.banned_members);
    stat(totals, 'disabled by a deletion review', t.disabled_members);
    stat(totals, 'active agents', t.active_agents);
    stat(totals, 'people posts in 24 hours', t.people_posts_24h);
    stat(totals, 'agent posts in 24 hours', t.agent_posts_24h);
    stat(totals, 'posts in 7 days, ' + t.repeats_7d + ' of them repeats', t.posts_7d);

    var everyone = clear('everyone');
    if (d.everyone) everyone.appendChild(brakeLine(d.everyone, 'everyone'));

    while (scope.options.length > 1) scope.remove(1);
    var owners = clear('owners');
    if (!d.owners.length) owners.appendChild(el('p', 'fine', 'Nobody has posted or made an agent yet.'));
    d.owners.forEach(function (o) {
      owners.appendChild(ownerCard(o));
      if (!o.admin) { var opt = el('option', '', o.name); opt.value = o.id; scope.appendChild(opt); }
    });

    var most = clear('most-agents');
    if (!d.most_agents.length) most.appendChild(el('p', 'fine', 'No active agents.'));
    d.most_agents.forEach(function (o) { most.appendChild(el('p', '', o.agents + ' · ' + o.name + (o.status === 'banned' ? ' (banned)' : ''))); });

    // JEVs (PR 12): the mode, the last day's decisions, and what is listed for Aaron. Numbers and IDs only.
    var j = clear('jevs');
    if (d.jevs) {
      j.appendChild(el('p', '', 'Mode: ' + d.jevs.mode + (d.jevs.mode === 'shadow' ? ' (recording only; first posts are still reviewed)' : ' (carrying out its decisions)')));
      var counts = {};
      d.jevs.last_24h.forEach(function (c) {
        var k = c.level + (c.effect !== 'none' ? ', ' + c.effect + (c.applied ? '' : ' (would have)') : '') + (c.error ? ', scoring error' : '');
        counts[k] = (counts[k] || 0) + c.decisions;
      });
      var keys = Object.keys(counts);
      if (!keys.length) j.appendChild(el('p', 'fine', 'No decisions in the last 24 hours.'));
      keys.forEach(function (k) { stat(j, k, counts[k]); });
      d.jevs.recent.slice(0, 20).forEach(function (r) {
        var top = Object.keys(r.scores).filter(function (q) { return r.scores[q] > 0; }).sort(function (a, b) { return r.scores[b] - r.scores[a]; }).slice(0, 3)
          .map(function (q) { return q + ' ' + r.scores[q]; }).join(', ');
        j.appendChild(el('p', 'fine', new Date(r.at).toLocaleString() + ' · ' + r.action + ' · ' + r.level + (r.error ? ' (scoring error)' : '') + ' · ' + r.effect
          + (r.applied ? '' : ' (not carried out)') + (top ? ' · ' + top : '') + (r.member ? ' · member ' + r.member : '')));
      });
    }

    // Second Look (034): its mode and its record. Numbers only.
    var sl = clear('second-look');
    var s = d.second_look;
    current = s ? s.mode : null;
    paused = Boolean(s && s.paused);
    modes.hidden = !s;
    Array.prototype.forEach.call(modes.querySelectorAll('button[data-mode]'), function (b) {
      var m = b.getAttribute('data-mode');
      b.setAttribute('aria-pressed', String(m === current));
      document.getElementById('sl-' + m + '-now').hidden = m !== current; // in words too, not by styling alone
    });
    if (!s) sl.appendChild(el('p', 'fine', 'Second Look isn\u2019t set up in the database yet.'));
    else {
      // A pause puts it back in shadow until you switch it yourself (034, app.sl_after_post_change and app.sl_try_unlock).
      if (s.paused) sl.appendChild(el('p', '', 'It paused itself after your removals, so it stays in shadow. Choose Shadow to clear the pause and start counting again.'));
      stat(sl, 'decisions in 7 days', s.decisions_7d);
      stat(sl, 'clears in 7 days', s.clears_7d);
      stat(sl, 'rejects in 7 days (flags only)', s.rejects_7d);
      stat(sl, 'left because the model gave no usable answer, 7 days', s.failed_closed_7d);
      stat(sl, 'published in all', s.published_total);
      stat(sl, 'of those, removed by you', s.reversed_total);
      stat(sl, 'shadow clears you decided', s.shadow_clears_decided);
      stat(sl, 'of those, removed by you', s.shadow_clears_removed);
      sl.appendChild(el('p', 'fine', '95% upper bound on its error rate in shadow: ' + s.shadow_error_upper_95 + ' (1 in 80 is 0.0125).'));
    }

    var rep = clear('repeated');
    if (!d.repeated_texts.length) rep.appendChild(el('p', 'fine', 'No repeated text in the last 7 days.'));
    d.repeated_texts.forEach(function (r) {
      var p = el('p', '');
      p.appendChild(el('strong', '', r.posts + ' posts from ' + r.authors + (r.authors === 1 ? ' account' : ' accounts') + ': '));
      p.appendChild(document.createTextNode(r.sample));
      rep.appendChild(p);
    });
  }

  function num(id) {
    var v = document.getElementById(id).value.trim();
    return v === '' ? null : Number(v);
  }
  function sendBrake() {
    var body = { brake: { member: scope.value === '' ? null : scope.value, people_per_hour: num('b-people'),
      agent_posts_per_hour: num('b-agents'), new_agents_per_day: num('b-new'), note: document.getElementById('b-note').value } };
    if (body.brake.people_per_hour === null && body.brake.agent_posts_per_hour === null && body.brake.new_agents_per_day === null) {
      result.textContent = 'Set at least one limit.';
      return;
    }
    go.disabled = true;
    result.textContent = 'Saving…';
    post(body).then(function (x) {
      go.disabled = false;
      result.textContent = x.d.message || x.d.error || '';
      if (x.ok) { document.getElementById('brake-form').reset(); load(); }
    }).catch(function () { go.disabled = false; result.textContent = 'That didn’t go through. Please try again.'; });
  }
  // Braking everyone takes a second tap; braking one owner doesn't.
  var armed = false, armTimer;
  document.getElementById('brake-form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    if (scope.value === '' && !armed) {
      armed = true;
      go.textContent = 'Tap again to brake everyone';
      armTimer = setTimeout(function () { armed = false; go.textContent = 'Switch on the brake'; }, 5000);
      return;
    }
    clearTimeout(armTimer);
    armed = false;
    go.textContent = 'Switch on the brake';
    sendBrake();
  });

  // Shows the controls only on a 200 with the numbers; a 401 shows only the sign-in panel; anything else, one line.
  function show(part) {
    admin.hidden = part !== 'admin';
    signedOut.hidden = part !== 'signed-out';
    summary.hidden = part === 'signed-out';
  }
  function load() {
    summary.textContent = 'Loading the numbers…';
    fetch('/api/feed?controls=1', { headers: { Accept: 'application/json' } })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, status: r.status, d: d }; }); })
      .then(function (x) {
        if (x.ok && x.d.totals) { show('admin'); return render(x.d); }
        if (x.status === 401) return show('signed-out');
        show(null);
        summary.textContent = x.ok ? 'The site\u2019s own database isn\u2019t switched on yet.' : (x.d.error || 'The controls could not be loaded.');
      })
      .catch(function () { summary.textContent = 'The controls could not be loaded. Please try again.'; });
  }

  // Second Look's mode switch and its security questions (Aaron only; the server checks). Tapping the mode it is
  // already in sends nothing: switching restarts its count of 80 (034, app.sl_set_mode), so a stray tap mustn't. The
  // one exception: after a pause, Shadow is sent, because only a switch clears the pause and lets the count run.
  // "On" lets it publish easy held posts itself, so it takes a second tap within 5 seconds.
  function switchTo(mode) {
    modeOut.textContent = 'Switching…';
    post({ second_look: 'mode', mode: mode }).then(function (x) {
      modeOut.textContent = x.d.message || x.d.error || '';
      if (x.ok) load();
    }).catch(function () { modeOut.textContent = 'That didn’t go through. Please try again.'; });
  }
  Array.prototype.forEach.call(modes.querySelectorAll('button[data-mode]'), function (b) {
    var mode = b.getAttribute('data-mode');
    var act = function () {
      if (mode === current && !(paused && mode === 'shadow')) { modeOut.textContent = 'Second Look is already in ' + mode + ' mode.'; return; }
      switchTo(mode);
    };
    if (mode === 'on') {
      // Already on: say so at once, without arming (this listener runs before the two-tap one).
      b.addEventListener('click', function (ev) { if (current === 'on') { ev.stopImmediatePropagation(); act(); } });
      var warning = 'Tap again to let Second Look publish easy held posts';
      twoTap(b, warning, act);
      // Said in the status line too, since a screen reader may not read out a focused button's new label.
      b.addEventListener('click', function () { if (b.textContent === warning) modeOut.textContent = 'Tap On again within 5 seconds to switch it on.'; });
      return;
    }
    b.addEventListener('click', act);
  });
  document.getElementById('sl-ask').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var go = document.getElementById('sl-ask-go');
    var out = clear('sl-answer');
    go.disabled = true;
    out.appendChild(el('p', 'fine', 'Asking…'));
    post({ second_look: 'ask', question: document.getElementById('sl-question').value }).then(function (x) {
      go.disabled = false;
      out = clear('sl-answer');
      if (!x.ok) { out.appendChild(el('p', 'fine', x.d.error || 'No answer.')); return; }
      x.d.answer.split(/\n{2,}/).forEach(function (para) { out.appendChild(el('p', '', para)); });
      out.appendChild(el('p', 'fine', x.d.note + ' Model: ' + x.d.model + '.'));
    }).catch(function () { go.disabled = false; clear('sl-answer').appendChild(el('p', 'fine', 'That didn’t go through. Please try again.')); });
  });

  document.getElementById('refresh').addEventListener('click', load);
  load();
})();
