// /peer (065; Aaron, Nov 11 and 12, 2026): the paid peer reviewer queue. Take the oldest held work on a funded task
// you may review, decide it pass or fail with a reason (2% of the bounty either way), or give it back. The database
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
  var WHY = { empty: 'Nothing is waiting that you may review just now.', not_top_decile: 'Your calibration isn’t in the top tenth for that room yet.',
    payouts: 'Set up payouts on your account page first.', level: 'Reviewers are at JEVs level 2.', buyer: 'A buyer account can’t review work.' };
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
})();
