// /peer (065; unpaid since 067, Aaron, Nov 21, 2026): the peer reviewer queue. Take the oldest held work you may review,
// decide it pass or fail with a reason, or give it back. Since 068 (Aaron, Nov 22): the cases queue (checks and disputes,
// decided by peers first, the administrator the last appeal) and the appeal of a peer's decision. The database
// decides who may review what (app.peer_block); this page only asks. Our own scripts only; drawn with textContent.
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var take = $('peer-take'), item = $('peer-item'), status = $('peer-status');
  if (!take || !item || !status || !window.fetch) return;
  var review = null;
  var say = function (t) { status.textContent = t; };
  var post = function (path, body) {
    return fetch('/api/work/' + path, { method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) })
      .then(function (r) { return r.json().then(function (d) { return { status: r.status, d: d }; }, function () { return { status: r.status, d: {} }; }); });
  };
  var WHY = { empty: 'Nothing is waiting that you may review just now.', level: 'Reviewers are at JEVs level 2.', buyer: 'A buyer account can’t review work.',
    party: 'You are part of the only work waiting.', collaborated: 'You worked with the people on the only work waiting.', rotation: 'You have reviewed enough of these people’s work this month.',
    decided_it: 'You helped decide the only work waiting.', admin: 'An administrator decides as the administrator.' };
  take.addEventListener('click', function () {
    say('Looking for work you may review…');
    post('peer/take').then(function (x) {
      if (x.status === 401) { say('Sign in first.'); return; }
      if (x.status >= 400) { say((x.d && x.d.error) || 'Something went wrong. Please try again.'); return; }
      if (!x.d || !x.d.review) { say(WHY[x.d && x.d.reason] || WHY.empty); return; }
      review = x.d.review;
      $('peer-task').href = '/tasks/' + encodeURIComponent(String(x.d.task));
      $('peer-until').textContent = new Date(x.d.expires_at).toLocaleString();
      item.hidden = false; take.disabled = true; say('');
    }).catch(function () { say('Something went wrong. Please try again.'); });
  });
  var decide = function (verdict) {
    var reason = $('peer-reason').value.trim();
    if (reason.length < 3) { say('Give a reason of at least 3 characters.'); return; }
    post('peer/decide', { review: review, verdict: verdict, reason: reason }).then(function (x) {
      if (x.status >= 400) { say((x.d && x.d.error) || 'Something went wrong. Please try again.'); return; }
      var r = x.d && x.d.result;
      say(r === 'pass' || r === 'fail' ? 'Decided: ' + r + '. Thank you.' : r === 'lapsed' ? 'Your 24 hours ran out; the work went back to the queue.' : 'Someone decided it first; nothing was recorded for you.');
      item.hidden = true; take.disabled = false; review = null; $('peer-reason').value = '';
    }).catch(function () { say('Something went wrong. Please try again.'); });
  };
  $('peer-pass').addEventListener('click', function () { decide('pass'); });
  $('peer-fail').addEventListener('click', function () { decide('fail'); });
  $('peer-back').addEventListener('click', function () {
    post('peer/release', { review: review }).then(function () { item.hidden = true; take.disabled = false; review = null; say('Given back.'); });
  });

  // 068: cases (checks and disputes).
  var ctake = $('case-take'), citem = $('case-item'), cstatus = $('case-status'), kase = null, ckind = null;
  var csay = function (t) { if (cstatus) cstatus.textContent = t; };
  if (ctake && citem) {
    ctake.addEventListener('click', function () {
      csay('Looking for a case you may decide…');
      post('peer/case/take').then(function (x) {
        if (x.status === 401) { csay('Sign in first.'); return; }
        if (x.status >= 400) { csay((x.d && x.d.error) || 'Something went wrong. Please try again.'); return; }
        if (!x.d || !x.d.case) { csay(WHY[x.d && x.d.reason] || 'No case is waiting that you may decide just now.'); return; }
        kase = x.d.case; ckind = x.d.kind;
        $('case-task').href = '/tasks/' + encodeURIComponent(String(x.d.task));
        $('case-kind').textContent = ckind === 'dispute' ? 'A dispute of a pass' : 'A check of a fail';
        var dec = x.d.decision || {};
        var said = ckind === 'dispute' ? ('Why it was disputed: ' + (x.d.dispute_reason || 'no reason given'))
          : ('The fail’s reason: ' + (dec.reason || 'none given') + (x.d.appeal_reason ? '. The appeal: ' + x.d.appeal_reason : ''));
        $('case-evidence').textContent = said;
        $('case-yes').textContent = ckind === 'dispute' ? 'Uphold (reverse the pass)' : 'Confirm the decision';
        $('case-no').textContent = ckind === 'dispute' ? 'Dismiss' : 'Overturn it';
        citem.hidden = false; ctake.disabled = true; csay('');
      }).catch(function () { csay('Something went wrong. Please try again.'); });
    });
    var cdecide = function (yes) {
      var reason = $('case-reason').value.trim();
      if (reason.length < 3) { csay('Give a reason of at least 3 characters.'); return; }
      var d = ckind === 'dispute' ? (yes ? 'uphold' : 'dismiss') : (yes ? 'confirm' : 'reverse');
      post('peer/case/decide', { case: kase, decision: d, reason: reason }).then(function (x) {
        if (x.status >= 400) { csay((x.d && x.d.error) || 'Something went wrong. Please try again.'); return; }
        var r = x.d && x.d.result;
        csay(r === 'proposed' ? 'Recorded. It takes effect on ' + new Date(x.d.due_at).toLocaleString() + ' unless a party appeals it.'
          : r === 'lapsed' ? 'Your 24 hours ran out; the case went back to the queue.' : r === 'blocked' ? 'You can’t decide this case any more; it went back to the queue.' : 'Someone decided it first.');
        citem.hidden = true; ctake.disabled = false; kase = null; $('case-reason').value = '';
      }).catch(function () { csay('Something went wrong. Please try again.'); });
    };
    $('case-yes').addEventListener('click', function () { cdecide(true); });
    $('case-no').addEventListener('click', function () { cdecide(false); });
    $('case-back').addEventListener('click', function () {
      post('peer/case/release', { case: kase }).then(function () { citem.hidden = true; ctake.disabled = false; kase = null; csay('Given back.'); });
    });
  }
  // Appeal a peer's decision: the notice links here with ?case=.
  var aform = $('appeal-form'), astatus = $('appeal-status');
  if (aform) {
    var given = new URLSearchParams(location.search).get('case');
    if (given && /^[0-9a-f-]{36}$/i.test(given)) { $('appeal-case').value = given; }
    aform.addEventListener('submit', function (e) {
      e.preventDefault();
      post('peer/case/appeal', { case: $('appeal-case').value.trim(), reason: $('appeal-reason').value.trim() }).then(function (x) {
        astatus.textContent = x.status < 400 ? 'Appealed. An administrator decides it.' : ((x.d && x.d.error) || 'Something went wrong. Please try again.');
      }).catch(function () { astatus.textContent = 'Something went wrong. Please try again.'; });
    });
  }
})();
