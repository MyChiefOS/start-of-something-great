// /admin/review's Work section (042): what waits for the administrator in the work module, from /api/work/admin:
// the check after a poster's pass (a sample), disputes, and work on the repository's own tasks the rules couldn't
// decide. Each decision sends a reason. On a dispute (052) it shows Third Look's review of the work when it read it, and
// where the administrator is a party offers only the decision against himself: upholding a dispute of his own work,
// withdrawing one he opened. Every word is drawn with textContent.
(function () {
  'use strict';
  var $ = function (x) { return document.getElementById(x); };
  if (!$('work-list')) return;
  var HEX = '0123456789abcdef';
  function isId(x) {
    if (typeof x !== 'string' || x.length !== 36) return false;
    for (var i = 0; i < 36; i++) { var ch = x.charAt(i); if ((i === 8 || i === 13 || i === 18 || i === 23) ? ch !== '-' : HEX.indexOf(ch) < 0) return false; }
    return true;
  }
  function txt(x) { return x === null || x === undefined ? '' : String(x); }
  function slot(n, s) { return n.querySelector('[data-slot="' + s + '"]'); }
  var WHY = { peer_fail_sample: 'one in seven of a paid peer reviewer\u2019s fails (15%), picked at random', peer_fail_appeal: 'the worker or the poster appealed a paid peer reviewer\u2019s fail', random: 'picked at random', size: 'the largest size', pair: 'a poster who keeps passing the same worker, or people who pass each other\u2019s work', third_look: 'one in five of Third Look\u2019s passes', note: 'the note had contact details, now hidden' };
  function artifact(a) {
    var p = document.createElement('span');
    if (!a) return p;
    if (a.kind === 'file') { p.textContent = 'A file, SHA-256 ' + txt(a.sha256); return p; }
    var u = txt(a.url);
    if (u.indexOf('https://') === 0) { var l = document.createElement('a'); l.href = u; l.rel = 'noopener noreferrer'; l.textContent = u; p.appendChild(l); }
    else p.textContent = u;
    return p;
  }
  function post(path, body) {
    return fetch(path, { method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }, function () { return { ok: false, d: {} }; }); });
  }
  // Third Look's review beside a dispute (Aaron, Nov 7: "Third look can weigh in"), in its own words, as text.
  function lookSaid(r) {
    if (!r) return 'Third Look hasn\u2019t reviewed this work (it reads merged pull requests). ';
    return 'Third Look ' + (r.suggestion === 'pass' ? 'found it passable' : 'left it to a person') + (r.reason ? ': \u201c' + txt(r.reason).replace(/[.!?]\s*$/, '') + '\u201d' : '') + '. ';
  }
  function card(item, kind, actions) {
    var c = $('work-tpl').content.firstElementChild.cloneNode(true);
    slot(c, 'kind').textContent = kind;
    var a = slot(c, 'title');
    a.textContent = txt(item.ref) + ' · ' + txt(item.title);
    if (isId(item.id)) a.href = '/tasks/' + item.id;
    slot(c, 'meta').textContent = item.why ? 'Why it was picked: ' + (WHY[item.why] || item.why) + '. ' + (txt(item.why).indexOf('peer_fail_') === 0 ? 'Failed by a paid peer reviewer' : 'Passed by ' + (item.decided_by === 'poster' ? 'the task’s poster' : txt(item.decided_by))) + (item.reason ? ': ' + txt(item.reason) : '.')
        + (item.appealed ? ' Appealed: ' + txt(item.appeal_reason) + '. Confirm keeps the fail; Reverse overturns it (the work stays closed; put right what it is owed).' : txt(item.why).indexOf('peer_fail_') === 0 ? ' Confirm keeps the fail; Reverse overturns it (the work stays closed; put right what it is owed).' : '')
      : item.held_reason ? 'Sent to you: ' + txt(item.held_reason)
      : item.dispute_reason ? 'Passed by ' + (item.decided_by === 'poster' ? 'the task\u2019s poster' : item.decided_by === 'jevs' ? 'the JEVs auditor\u2019s rules'
          : item.decided_by === 'third_look' ? 'Third Look' : 'an administrator') + '. ' + lookSaid(item.third_look) + 'The dispute:' : 'The rules that sent it here: ' + txt(item.jevs_rules || 'none');
    slot(c, 'artifact').appendChild(artifact(item.artifact));
    slot(c, 'text').textContent = txt(item.dispute_reason || item.note);
    var acts = slot(c, 'acts'), said = slot(c, 'said'), reason = slot(c, 'reason');
    // A dispute where you are a party: only the decision against yourself.
    if (item.may === 'uphold' || item.may === 'dismiss') {
      actions = actions.filter(function (x) { return x.decision === item.may; });
      said.textContent = item.may === 'uphold' ? 'This is your own work: you may uphold the dispute (give up the pass), not dismiss it.'
        : 'You opened this dispute: you may withdraw it, not uphold it.';
    } else if (item.party) {
      said.textContent = 'You did or posted this work, so you don\u2019t decide it.';
      reason.parentNode.hidden = true;
      return c;
    }
    actions.forEach(function (x) {
      var b = document.createElement('button');
      b.type = 'button'; b.className = x.primary ? 'btn p' : 'btn'; b.textContent = x.label;
      b.addEventListener('click', function () {
        var why = reason.value.trim();
        if (why.length < 3) { said.textContent = 'Give a reason first (3 to 300 characters).'; reason.focus(); return; }
        said.textContent = 'Sending…';
        post(x.path, x.body(why)).then(function (r) {
          said.textContent = r.ok ? 'Done: ' + txt(r.d.result) + '.' : txt(r.d.error) || 'That didn’t work.';
          if (r.ok) Array.prototype.forEach.call(acts.children, function (y) { y.disabled = true; });
        }).catch(function () { said.textContent = 'That couldn’t be sent. Please try again.'; });
      });
      acts.appendChild(b);
    });
    return c;
  }
  fetch('/api/work/admin', { credentials: 'same-origin', headers: { Accept: 'application/json' } })
    .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
    .then(function (x) {
      if (!x.ok) return; // signed out, or not the administrator: the section stays hidden (the queue says why)
      $('work').hidden = false;
      var d = x.d, list = $('work-list');
      (d.checks || []).forEach(function (i) {
        list.appendChild(card(i, 'Check after a poster’s pass', [
          { label: 'Confirm the pass', primary: true, path: '/api/work/review', body: function (w) { return { check: i.check, decision: 'confirm', reason: w }; } },
          { label: 'Reverse it', path: '/api/work/review', body: function (w) { return { check: i.check, decision: 'reverse', reason: w }; } }]));
      });
      (d.disputes || []).forEach(function (i) {
        list.appendChild(card(i, 'Dispute', [
          { label: i.may === 'dismiss' ? 'Withdraw the dispute' : 'Dismiss the dispute', primary: true, decision: 'dismiss', path: '/api/work/settle', body: function (w) { return { dispute: i.dispute, decision: 'dismiss', reason: w }; } },
          { label: 'Uphold it (reverse the pass)', decision: 'uphold', path: '/api/work/settle', body: function (w) { return { dispute: i.dispute, decision: 'uphold', reason: w }; } }]));
      });
      (d.waiting || []).forEach(function (i) {
        list.appendChild(card(i, 'The repository’s task', [
          { label: 'Pass', primary: true, path: '/api/work/decide', body: function (w) { return { submission: i.submission, verdict: 'pass', reason: w }; } },
          { label: 'Fail', path: '/api/work/decide', body: function (w) { return { submission: i.submission, verdict: 'fail', reason: w }; } }]));
      });
      var n = list.children.length, held = Number(d.held) || 0;
      $('work-status').textContent = (n ? n + (n === 1 ? ' item waits for you.' : ' items wait for you.') : 'Nothing in the work module waits for you.')
        + (held ? ' ' + held + ' wait for Third Look (risky work you are a party to).' : '');
    })
    .catch(function () { $('work-status').textContent = 'The work couldn’t be loaded.'; });
})();
