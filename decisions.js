// /decisions: what JEVs decided, from /api/decisions (036). Counts and question IDs only. Everything is written with
// textContent, never as HTML. A rate is shown only from the API's min_sample decisions (20): under it, "Not enough
// history yet" (CODING_AGENT_SPEC.md 2.2).
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var status = $('status');
  var WHERE = { site_post: 'Site post', agent_post: 'Agent post', agent_draft: 'Agent draft', account: 'Account', agent: 'Agent', github_post: 'GitHub post', github_account: 'GitHub account', github_agent: 'GitHub agent', signup: 'Sign-up' };
  // The design's words where it has them ("Held for Aaron", "Hidden, reason sent", "Declined politely").
  var OUTCOME = { held: 'Held for Aaron', hidden: 'Hidden until Aaron looks', queued: 'Sent to Aaron’s queue', challenged: 'Waiting for the owner',
    recorded_only: 'Recorded only, not carried out', scoring_error: 'Couldn’t be scored, so held', alerted: 'Aaron alerted', went_ahead: 'Went ahead',
    declined: 'Declined politely' };
  var day = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' });

  function text(id, value) { $(id).textContent = value; }
  var K = 5;
  // A count of 1 to 4 comes back null (036): say "fewer than 5", so no number on the page describes one person.
  function count(n) { return n === null ? 'Fewer than ' + K : new Intl.NumberFormat().format(n); }
  function render(d) {
    if (!d.available) {
      status.textContent = d.message || 'There are no decisions to count here.';
      return;
    }
    K = d.min_count || 5;
    var ago = Math.max(0, Math.round((Date.now() - new Date(d.generated_at).getTime()) / 60000));
    text('counted', 'Counted to the start of the hour. Counts from 1 to 4 show as “fewer than 5”, and smaller groups aren’t listed, so no number points to one person.');
    status.textContent = '';

    var h = d.last_24h;
    text('n-low', count(h.low));
    text('n-medium', count(h.medium_waiting));
    text('n-high', count(h.high_held));
    text('n-appeals', count(h.appeals_open));
    var note = 'Site and GitHub together: ' + count(h.decisions) + ' decisions in all.';
    if (h.high !== null && h.high_held !== null && h.high > h.high_held) note += ' ' + count(h.high - h.high_held) + ' more scored high risk without a hold or a hide: '
      + (d.jevs_mode === 'shadow' ? 'JEVs is in shadow mode on the site, so it records and changes nothing there.' : 'some actions are only recorded, or alerted to Aaron.');
    note += ' Appeals are counted for site posts; an /appeal on GitHub alerts Aaron directly.';
    text('day-note', note);
    $('day-note').hidden = false;

    var body = $('high');
    body.textContent = '';
    d.high_7d.forEach(function (r) {
      var tr = document.createElement('tr');
      var qs = r.questions.map(function (q) {
        if (q === 'region') return 'Region';
        return d.questions && d.questions[q] ? q + ' ' + d.questions[q].charAt(0).toLowerCase() + d.questions[q].slice(1) : q;
      }).join(', ') || 'None scored 25 or more';
      var outcome = r.outcome === 'hidden' && r.place.indexOf('github') === 0 ? 'Hidden, reason sent' : (OUTCOME[r.outcome] || r.outcome);
      [day.format(new Date(r.day + 'T00:00:00Z')), WHERE[r.place] || r.place, qs, outcome, count(r.decisions)].forEach(function (v) {
        var td = document.createElement('td'); td.textContent = v; tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    $('high-empty').hidden = d.high_7d.length > 0;

    var s = d.second_look;
    if (!s) $('sl-none').hidden = false;
    else {
      var mode = s.mode === 'on' ? 'On' : s.mode === 'off' ? 'Off' : s.paused ? 'Shadow mode, paused' : 'Shadow mode';
      text('sl-mode', mode);
      text('sl-text', s.mode === 'on' ? 'It publishes easy held posts itself, and Aaron gets a notice for each one.'
        : s.mode === 'off' ? 'It looks at no posts.'
        : s.paused ? 'It paused itself back to shadow after Aaron removed more than 1 in 80 of the posts it published. It logs what it would publish and changes nothing until he switches it again.'
        : 'It logs what it would publish and changes nothing. It switches itself on after Aaron agrees with its last ' + count(s.needed) + ' decisions.');
      var shadow = s.mode === 'shadow';
      $('sl-row').hidden = !shadow;
      if (shadow) {
        text('sl-agree', count(s.agreed_in_a_row) + ' of ' + count(s.needed));
        // The design's track (static/decisions.html): its fill is one of its stylesheet's widths, in steps of 5%, set as a
        // class (no style from the script); the exact figure is in the words beside it and in aria-valuenow.
        var track = $('sl-track'), max = s.needed || 80, now = Math.min(s.agreed_in_a_row || 0, max);
        track.setAttribute('aria-valuemax', String(max));
        track.setAttribute('aria-valuenow', String(now));
        $('sl-bar').className = 'w' + Math.round((20 * now) / max) * 5;
      }
      text('sl-fine', (shadow ? 'Agreement so far. At most ' + count(s.daily_clear_cap) + ' easy posts a day once on.' : 'At most ' + count(s.daily_clear_cap) + ' easy posts a day.')
        + ' It pauses itself if Aaron removes more than 1 in 80.');
      $('sl').hidden = false;
    }

    review(d.review, d.min_sample);
  }

  // Human oversight (041; Aaron, Nov 5: "I gave guidance to use JEVs, and Second Look"): what the automated reviewers
  // passed on to a person, what Second Look decided, its sample and its planted tests. Never the person's own figures.
  // Before 041 is applied the API sends null and the page says the counts aren't switched on yet.
  var IDS = ['r-held', 'r-github', 'r-flagged', 'r-sl', 'r-clears', 'r-published', 's-reread', 's-none', 's-missed', 's-drawn', 'c-used', 'c-bad', 'c-good', 'c-none'];
  function total(sm) { return sm.other === null ? count(sm.shown) + ' and fewer than 5 more' : count(sm.shown); }
  function part(sm, i) { return count(sm.parts[i] === undefined ? 0 : sm.parts[i]); }
  function review(r, min) {
    if (!r) {
      IDS.forEach(function (id) { text(id + '-7', 'Not counted yet'); text(id + '-30', 'Not counted yet'); });
      text('means-text', 'these counts are being switched on.');
      text('alerts', 'not counted yet.');
      return;
    }
    text('counted-through', r.counted_through ? ' (through ' + day.format(new Date(r.counted_through + 'T00:00:00Z')) + ', UTC)' : '');
    [['7', r.d7], ['30', r.d30]].forEach(function (w) {
      var x = w[1], n = w[0], c = x.canaries, sm = x.sample;
      text('r-held-' + n, count(x.jevs_held));
      text('r-github-' + n, count(x.github_hidden));
      text('r-flagged-' + n, count(x.sample_flagged));
      text('r-sl-' + n, count(x.sl_decisions));
      text('r-clears-' + n, count(x.sl_clears));
      text('r-published-' + n, count(x.sl_published));
      text('s-reread-' + n, part(sm, 0));
      text('s-none-' + n, part(sm, 1));
      text('s-missed-' + n, part(sm, 2));
      text('s-drawn-' + n, total(sm));
      text('c-used-' + n, String(c.used));
      text('c-bad-' + n, c.bad < min ? 'Not enough history yet: ' + c.bad_caught + ' of ' + c.bad : Math.round((100 * c.bad_caught) / c.bad) + '% of ' + c.bad);
      text('c-good-' + n, c.good_cleared + ' of ' + c.good);
      text('c-none-' + n, String(c.no_answer));
    });
    var w = r.d30;
    var passed = [w.jevs_held, w.github_hidden, w.sample_flagged];
    text('means-text', 'in the last ' + w.days + ' counted days, JEVs and Second Look passed on ' + (passed.some(function (v) { return v === null; })
      ? 'a few posts (some counts are under 5)' : (passed[0] + passed[1] + passed[2]) + ' posts') + ' to a person, and Second Look published '
      + count(w.sl_published) + ' held posts with no person. Planted tests: it kept back ' + w.canaries.bad_caught + ' of ' + w.canaries.bad + ' known-bad ones.');
    text('sample-state', r.limits.sample_on ? 'The sample is on: 5% of low-risk posts, at most ' + r.limits.sample_daily_cap + ' a day.' : 'The sample is off: no low-risk post is re-read.');
    text('alerts', r.alerts.length ? r.alerts.map(function (a) { return a.title + '. ' + a.text; }).join(' ') : 'none now.');
  }

  function load() {
    status.textContent = 'Loading the counts…';
    $('retry-row').hidden = true;
    var ref = null;
    fetch('/api/decisions', { headers: { Accept: 'application/json' } })
      .then(function (r) {
        ref = r.headers && r.headers.get ? r.headers.get('x-vercel-id') : null;
        return r.json().then(function (d) { return { ok: r.ok, code: r.status, d: d }; });
      })
      .then(function (x) {
        if (!x.ok) throw Object.assign(new Error(x.d && x.d.error ? x.d.error : 'The counts couldn’t be loaded.'), { code: x.code });
        render(x.d);
      })
      .catch(function (e) {
        var why = e && e.code === 429 ? 'Too many requests just now. Please wait a minute, then try again.'
          : e && e.code ? e.message : 'The counts couldn’t be loaded: the network didn’t answer.';
        status.textContent = why + (ref ? ' Reference: ' + ref + '.' : '');
        $('retry-row').hidden = false;
      });
  }
  $('retry').addEventListener('click', load);
  load();
})();
