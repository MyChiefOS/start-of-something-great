// /controls: Aaron's owner controls (PR 6): the numbers (F4), the emergency brake (F9) and banning (F10).
// Everything members wrote is shown with textContent, never as HTML. The biggest steps, banning someone and braking
// everyone, take a second tap on the same button; nothing uses a browser dialog.
(function () {
  var summary = document.getElementById('summary');
  var scope = document.getElementById('brake-scope');
  var go = document.getElementById('brake-go');
  var result = document.getElementById('brake-result');

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
    meta.appendChild(document.createTextNode(' · level ' + o.level + (o.status === 'banned' ? ' · banned' : '') + (o.admin ? ' · admin' : '')));
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
    if (!o.admin) {
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

  function render(d) {
    var t = d.totals;
    summary.textContent = t.brakes_on ? t.brakes_on + (t.brakes_on === 1 ? ' brake is on.' : ' brakes are on.') : 'No brakes are on.';
    var totals = clear('totals');
    stat(totals, 'active members', t.active_members);
    stat(totals, 'banned', t.banned_members);
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

  function load() {
    summary.textContent = 'Loading the numbers…';
    fetch('/api/feed?controls=1', { headers: { Accept: 'application/json' } })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, status: r.status, d: d }; }); })
      .then(function (x) {
        if (x.ok && x.d.totals) return render(x.d);
        if (x.ok) { summary.textContent = 'The database opens with the private preview.'; return; }
        summary.textContent = x.status === 401 ? 'Sign in to see the owner controls.' : (x.d.error || 'The controls could not be loaded.');
        if (x.status === 401) { var a = el('a', '', 'Sign in'); a.href = '/join?return_to=%2Fcontrols'; clear('totals').appendChild(a); }
      })
      .catch(function () { summary.textContent = 'The controls could not be loaded. Please try again.'; });
  }

  document.getElementById('refresh').addEventListener('click', load);
  load();
})();
