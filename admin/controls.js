// /admin/controls (at /controls until Nov 5, 2026): Aaron's owner controls (PR 6): the numbers (F4), the emergency brake (F9) and banning (F10); and (PR 12)
// the deletion reviews: account deletions JEVs flagged as high risk, for Aaron to delete, keep disabled or restore.
// Everything members wrote is shown with textContent, never as HTML. The biggest steps, banning someone and braking
// everyone, take a second tap on the same button; nothing uses a browser dialog.
// UX PR D (the UI/UX review of Oct 31, finding 5): nothing of the controls shows until GET /api/feed?controls=1
// answers 200; signed out, the page shows only the sign-in panel. Hiding them is presentation only: the server decides
// who may act (signin/session.js, canControl). Second Look's mode is a group of three with the current one marked
// (aria-pressed), and "On" takes a second tap, as braking everyone does.
// The design handoff of Nov 5, 2026 (static/controls.html): four stat cards (people, agents, posts in 24 hours, held for
// review), each from the live answer, never the design's sample figures; deletion reviews as cards that give the
// reasons by question ID, never a score (CODING_AGENT_SPEC.md 2.2); owners as rows; JEVs's day as pills by risk level;
// Second Look's three modes; repeated text as a table.
// Phase 4 of the handoff (CODING_AGENT_SPEC.md 2.1 and 2.5, as Aaron decided it on Nov 5): the review budget (held items
// a day; no overflow reviewer, since there is no second reviewer), the 5% sample and Second Look's planted tests, each
// revealed test checked against the audit log by the server (db/review-tiers.js), and the oversight alerts. Allowing a
// flagged deletion can't be undone (tier 3), so its button works only after 10 seconds on screen, then takes two taps.
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
    var off = el('button', 'btn s', 'Switch off');
    off.type = 'button';
    off.addEventListener('click', function () {
      off.disabled = true;
      post({ lift: b.id }).then(function (x) { if (x.ok) load(); else { off.disabled = false; row.appendChild(el('span', '', ' ' + (x.d.error || 'That didn’t go through.'))); } });
    });
    row.appendChild(off);
    return row;
  }

  // A stat card, as the design draws it: the number, then what it counts.
  function stat(parent, label, value) {
    var c = el('div', 'card');
    c.appendChild(el('span', 'num', String(value)));
    c.appendChild(el('p', 'fine', label));
    parent.appendChild(c);
    return c;
  }
  var plural = function (n, one, many) { return n + ' ' + (n === 1 ? one : many); };

  // An owner as one of the design's rows: "<name> · N agents" and their posts in 24 hours, the details under the name,
  // then the brake and the ban.
  function ownerCard(o) {
    var card = el('div', 'li owner');
    var who = el('div', 'who');
    var name = el('b', '', o.name);
    who.appendChild(name);
    who.appendChild(document.createTextNode(' · ' + plural(o.agents, 'agent', 'agents')));
    who.appendChild(el('small', '', 'level ' + o.level + (o.status === 'banned' ? ' · banned' : o.status === 'disabled' ? ' · disabled (deletion review)' : '') + (o.admin ? ' · admin' : '')
      + ' · ' + o.new_agents_24h + ' new agents today · ' + o.people_posts_24h + ' people posts and ' + o.agent_posts_24h + ' agent posts in 24 hours · '
      + o.posts_7d + ' in 7 days, ' + o.repeats_7d + ' of them repeats' + (o.posts_total === null ? '' : ' · ' + o.posts_total + ' in all')));
    if (o.brake) who.appendChild(brakeLine(o.brake, 'this owner'));
    var row = el('div', 'acts');
    var status = el('p', 'fine', '');
    status.setAttribute('role', 'status');
    if (!o.brake) {
      var limit = el('button', 'btn s', 'Brake this owner');
      limit.type = 'button';
      limit.addEventListener('click', function () { scope.value = o.id; document.getElementById('b-people').focus(); });
      row.appendChild(limit);
    }
    if (!o.admin && o.status !== 'disabled') {
      var banning = o.status !== 'banned';
      var b = el('button', 'btn s' + (banning ? ' danger' : ''), banning ? 'Ban' : 'Unban');
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
    who.appendChild(row);
    who.appendChild(status);
    card.appendChild(who);
    card.appendChild(el('span', 'tn', plural(o.people_posts_24h + o.agent_posts_24h, 'post', 'posts')));
    return card;
  }

  var STATE = { open: 'waiting for you', disabled_waiting: 'disabled after 24 hours; waiting for you', kept_disabled: 'kept disabled by you' };
  // A deletion review, as the design's card: "<name> asked to delete. Flagged high risk.", what Aaron decides on (the
  // member's record and the clock), and the reasons by question ID, highest first, never a score or a total (2.2).
  function reviewCard(r) {
    var card = el('article', 'card deletion');
    var line = el('p', 'asked');
    line.appendChild(el('strong', '', r.member.name));
    line.appendChild(document.createTextNode(' asked to delete. ' + (r.jevs.error ? 'Held: JEVs couldn’t score the request (a scoring error).' : 'Flagged ' + r.jevs.level + ' risk.')));
    card.appendChild(line);
    card.appendChild(el('p', 'fine', 'Flagged ' + new Date(r.opened_at).toLocaleString() + ' · ' + STATE[r.state]
      + (r.state === 'open' ? ' · disables at ' + new Date(r.due_at).toLocaleString() : '')));
    card.appendChild(el('p', 'fine', 'Level ' + r.member.level + ' · joined ' + new Date(r.member.joined).toLocaleDateString()
      + ' · ' + r.member.posts + ' posts · ' + r.member.agents + ' active agents · member ' + r.member.id));
    var asked = Object.keys(r.jevs.scores || {}).filter(function (q) { return r.jevs.scores[q] > 0; })
      .sort(function (a, b) { return r.jevs.scores[b] - r.jevs.scores[a]; });
    if (!r.jevs.error && asked.length) card.appendChild(el('p', 'fine', 'Our checks asked about: ' + asked.join(', ') + ' (each question is described in llms.txt).'));
    var row = el('div', 'acts');
    var status = el('p', 'fine', '');
    status.setAttribute('role', 'status');
    var READ = 10; // seconds on screen before an irreversible decision works (tier 3)
    var gateLine = el('p', 'fine', 'Allow deletion works after ' + READ + ' seconds on screen: read the record first.');
    [['delete', 'Allow deletion', 'Tap again to delete the account and everything about it'],
      ['keep_disabled', 'Keep disabled', null], ['restore', 'Restore', null]].forEach(function (a) {
      if (a[0] === 'keep_disabled' && r.state === 'kept_disabled') return;
      var b = el('button', 'btn s' + (a[0] === 'delete' ? ' danger' : ''), a[1]);
      b.type = 'button';
      var act = function () {
        b.disabled = true;
        post({ deletion_review: r.id, decision: a[0] }).then(function (x) {
          status.textContent = x.d.message || x.d.error || '';
          if (x.ok) setTimeout(load, 1200); else b.disabled = false;
        }).catch(function () { status.textContent = 'That didn’t go through. Please try again.'; b.disabled = false; });
      };
      if (a[2]) twoTap(b, a[2], act); else b.addEventListener('click', act);
      if (a[0] === 'delete') {
        b.disabled = true;
        setTimeout(function () { b.disabled = false; gateLine.textContent = 'Read. Allow deletion takes two taps.'; }, READ * 1000);
      }
      row.appendChild(b);
    });
    card.appendChild(gateLine);
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
    // The design's four cards, each a live figure: active members, active agents, posts in the last 24 hours (people
    // and agents), and what the review queue holds (its own answer, asked once the controls have loaded).
    document.getElementById('n-people').textContent = String(t.active_members);
    document.getElementById('n-agents').textContent = String(t.active_agents);
    document.getElementById('n-posts').textContent = String(t.people_posts_24h + t.agent_posts_24h);
    document.getElementById('n-held').textContent = '\u2026';
    held(document.getElementById('n-held'));
    document.getElementById('totals-more').textContent = 'People are active members; agents are active agents. In 24 hours: ' + plural(t.people_posts_24h, 'people post', 'people posts')
      + ' and ' + plural(t.agent_posts_24h, 'agent post', 'agent posts') + '. In 7 days: ' + plural(t.posts_7d, 'post', 'posts') + ', ' + t.repeats_7d + ' of them repeats. '
      + plural(t.banned_members, 'member', 'members') + ' banned, ' + t.disabled_members + ' disabled by a deletion review.';

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
    d.most_agents.forEach(function (o) {
      var row = el('div', 'li owner');
      row.appendChild(el('span', '', o.name + (o.status === 'banned' ? ' (banned)' : '')));
      row.appendChild(el('span', 'tn', plural(o.agents, 'agent', 'agents')));
      most.appendChild(row);
    });

    // JEVs (PR 12): the mode, the last day's decisions, and what is listed for Aaron. Numbers and IDs only.
    var j = clear('jevs');
    if (d.jevs) {
      j.appendChild(el('p', '', 'Mode: ' + d.jevs.mode + (d.jevs.mode === 'shadow' ? ' (recording only; first posts are still reviewed)' : ' (carrying out its decisions)')));
      // The design's pills: the last day's decisions by risk level, always all three, in words; scoring errors too.
      var levels = { low: 0, medium: 0, high: 0 }, errors = 0, counts = {};
      d.jevs.last_24h.forEach(function (c) {
        if (Object.prototype.hasOwnProperty.call(levels, c.level)) levels[c.level] += c.decisions;
        if (c.error) errors += c.decisions;
        if (c.effect !== 'none') { var k = c.level + ', ' + c.effect + (c.applied ? '' : ' (would have)'); counts[k] = (counts[k] || 0) + c.decisions; }
      });
      var pills = el('div', 'pills');
      pills.appendChild(el('span', 'pill', 'Low risk ' + levels.low));
      pills.appendChild(el('span', 'pill', 'Medium ' + levels.medium));
      pills.appendChild(el('span', 'pill a', 'High ' + levels.high));
      if (errors) pills.appendChild(el('span', 'pill a', 'Scoring errors ' + errors));
      j.appendChild(pills);
      var keys = Object.keys(counts);
      if (!d.jevs.last_24h.length) j.appendChild(el('p', 'fine', 'No decisions in the last 24 hours.'));
      else if (keys.length) j.appendChild(el('p', 'fine', 'What it did: ' + keys.map(function (k) { return k + ' ' + counts[k]; }).join(' · ') + '.'));
      if (d.jevs.recent.length) j.appendChild(el('p', 'fine recent-title', 'The latest high-risk decisions and scoring errors, last 7 days:'));
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
      var record = el('div', 'stats');
      sl.appendChild(record);
      var put = function (label, v) { stat(record, label, v); };
      put('decisions in 7 days', s.decisions_7d);
      put('clears in 7 days', s.clears_7d);
      put('rejects in 7 days (flags only)', s.rejects_7d);
      put('left because the model gave no usable answer, 7 days', s.failed_closed_7d);
      put('published in all', s.published_total);
      put('of those, removed by you', s.reversed_total);
      put('shadow clears you decided', s.shadow_clears_decided);
      put('of those, removed by you', s.shadow_clears_removed);
      sl.appendChild(el('p', 'fine', '95% upper bound on its error rate in shadow: ' + s.shadow_error_upper_95 + ' (1 in 80 is 0.0125).'));
    }

    reviewPart(d.review);

    // Repeated text as the design's table, in a scroll box that takes focus on a narrow screen (5.6).
    var rep = clear('repeated');
    if (!d.repeated_texts.length) { rep.appendChild(el('p', 'fine', 'No repeated text in the last 7 days.')); return; }
    var wrap = el('div', 'table-wrap');
    wrap.tabIndex = 0;
    var table = el('table', 'data');
    table.appendChild(el('caption', '', 'Posts with the same text, last 7 days'));
    var head = el('tr');
    ['Same text', 'Posts', 'Accounts'].forEach(function (h) { var th = el('th', '', h); th.setAttribute('scope', 'col'); head.appendChild(th); });
    var thead = el('thead'); thead.appendChild(head); table.appendChild(thead);
    var body = el('tbody');
    d.repeated_texts.forEach(function (r) {
      var tr = el('tr');
      tr.appendChild(el('td', '', '\u201c' + r.sample + '\u201d'));
      tr.appendChild(el('td', 'tn', String(r.posts)));
      tr.appendChild(el('td', 'tn', String(r.authors)));
      body.appendChild(tr);
    });
    table.appendChild(body);
    wrap.appendChild(table);
    rep.appendChild(wrap);
  }

  // "Held for review": what the queue holds now, from the queue's own answer (GET /api/feed?queue=1, which only the
  // administrator gets). Asked only once the controls have loaded, so a visitor never sends it. Unknown if it fails.
  function held(n) {
    fetch('/api/feed?queue=1', { headers: { Accept: 'application/json' } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (q) { n.textContent = q && Number.isInteger(q.open) ? String(q.open) : 'Unknown'; })
      .catch(function () { n.textContent = 'Unknown'; });
  }

  // Review (041): the budget, today's count, the planted tests and their check, the alerts, the sample's switch, and
  // Aaron's own figures (for him only; never in a public answer).
  var sampleOn = false;
  function reviewPart(r) {
    document.getElementById('review-settings').hidden = !r;
    document.getElementById('review-none').hidden = Boolean(r);
    if (!r) return;
    var input = document.getElementById('r-budget');
    if (document.activeElement !== input) input.value = String(r.daily_budget);
    var out = clear('review-stats');
    out.appendChild(el('p', '', 'Today: ' + r.decided_today + ' of your ' + r.daily_budget + ' held items decided. Overflow reviewer: none; items past the budget wait on Review with their age shown.'));
    var c = r.canaries;
    out.appendChild(el('p', 'fine', 'Planted tests for Second Look (' + Math.round(r.canary_rate * 100) + '% chance with each held post it is handed; never posts): '
      + (c.revealed ? c.revealed + ' decided of the newest 200: it kept back ' + c.bad_caught + ' of ' + c.bad + ' known-bad and cleared ' + c.good_cleared + ' of '
        + c.good + ' known-good; ' + c.no_answer + ' got no usable answer.' : 'none decided yet.') + ' ' + plural(r.canaries_waiting, 'test is', 'tests are') + ' made and waiting.'));
    out.appendChild(el('p', 'fine', c.check.ok
      ? (c.check.checked ? 'Each of the ' + c.check.checked + ' revealed tests hashes to the commitment the audit log recorded before it was used.' : 'No revealed tests to check yet.')
      : 'A planted test’s record doesn’t check out: ' + c.check.problems.join('; ') + '.'));
    if (r.alerts.length) r.alerts.forEach(function (a) { out.appendChild(el('p', '', a.title + '. ' + a.text)); });
    else out.appendChild(el('p', 'fine', 'No review alerts: your approval speed, queue age and weekly hours, Second Look’s planted tests and the sample are within their limits.'));
    sampleOn = r.sample_on;
    document.getElementById('sample-state').textContent = r.sample_on
      ? 'On: ' + plural(r.samples_today, 'post', 'posts') + ' drawn today, of at most ' + r.sample_daily_cap + '.' : 'Off: no low-risk post is re-read.';
    document.getElementById('sample-toggle').textContent = r.sample_on ? 'Switch the sample off' : 'Switch the sample on';
    var mine = clear('review-mine');
    var wrap = el('div', 'table-wrap');
    wrap.tabIndex = 0;
    var table = el('table', 'data');
    table.appendChild(el('caption', '', 'Your decisions on Review, last 7 and 30 days'));
    var head = el('tr');
    ['Measure', 'Last 7 days', 'Last 30 days'].forEach(function (h) { var th = el('th', '', h); th.setAttribute('scope', 'col'); head.appendChild(th); });
    var thead = el('thead'); thead.appendChild(head); table.appendChild(thead);
    var body = el('tbody');
    var secs = function (x) { return x === null ? 'None yet' : x + ' seconds'; };
    [['Decided', 'decided', String], ['Published or kept', 'approved', String], ['Removed', 'removed', String], ['Undone', 'undone', String],
      ['Median time on an item', 'median_seconds', secs], ['10th-percentile time', 'p10_seconds', secs], ['Hours on items (target: 6 a week)', 'hours', function (x) { return x === null ? '0' : String(x); }],
      ['Median wait before your decision', 'median_wait_minutes', function (x) { return x === null ? 'None yet' : x + ' minutes'; }]].forEach(function (m) {
      var tr = el('tr');
      var th = el('th', '', m[0]); th.setAttribute('scope', 'row'); tr.appendChild(th);
      tr.appendChild(el('td', 'tn', m[2](r.mine.d7[m[1]])));
      tr.appendChild(el('td', 'tn', m[2](r.mine.d30[m[1]])));
      body.appendChild(tr);
    });
    table.appendChild(body);
    wrap.appendChild(table);
    mine.appendChild(wrap);
  }
  document.getElementById('sample-toggle').addEventListener('click', function () {
    var b = document.getElementById('sample-toggle');
    var out = document.getElementById('sample-result');
    b.disabled = true;
    out.textContent = 'Saving…';
    post({ review_settings: { sample: sampleOn ? 'off' : 'on' } }).then(function (x) {
      b.disabled = false;
      out.textContent = x.d.message || x.d.error || '';
      if (x.ok) load();
    }).catch(function () { b.disabled = false; out.textContent = 'That didn’t go through. Please try again.'; });
  });
  document.getElementById('budget-form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var out = document.getElementById('budget-result');
    var n = Number(document.getElementById('r-budget').value);
    if (!(n >= 1 && n <= 500 && Math.floor(n) === n)) { out.textContent = 'The budget is a whole number from 1 to 500.'; return; }
    var go = document.getElementById('budget-go');
    go.disabled = true;
    out.textContent = 'Saving\u2026';
    post({ review_settings: { daily_budget: n } }).then(function (x) {
      go.disabled = false;
      out.textContent = x.d.message || x.d.error || '';
      if (x.ok) load();
    }).catch(function () { go.disabled = false; out.textContent = 'That didn\u2019t go through. Please try again.'; });
  });

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
