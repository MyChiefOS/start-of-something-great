// /errors/rate-limited (the design handoff of Nov 5, 2026: the Error template, CODING_AGENT_SPEC.md 5.5): the wait, the
// reference and where Try again goes, from the address that sent the visitor here:
//   ?retry=<seconds, 1 to 86400>   how long to wait (the 429 answer's Retry-After); without it, "a minute"
//   &ref=<reference>               the request's reference (for example Vercel's x-vercel-id); without it, "none"
//   &from=</path on this site>     the page to try again; without it, back one page (or home)
// Text only (textContent); only a path on this site is ever used as a link.
(function () {
  var q = new URLSearchParams(location.search);
  var wait = document.getElementById('wait');
  var retry = document.getElementById('retry');

  var ref = q.get('ref');
  if (ref && /^[A-Za-z0-9:_.-]{1,100}$/.test(ref)) document.getElementById('ref').textContent = ref;

  var from = q.get('from');
  if (from && /^\/(?![/\\])[^\s\\]*$/.test(from)) retry.href = from;
  else if (history.length > 1) retry.addEventListener('click', function (e) { e.preventDefault(); history.back(); });

  var left = /^[0-9]{1,5}$/.test(q.get('retry') || '') ? Math.min(86400, Math.max(1, Number(q.get('retry')))) : null;
  function say(s) {
    if (s <= 0) { document.getElementById('wait-line').textContent = 'You can try again now. Nothing was lost, and your account is not locked.'; return; }
    wait.textContent = s < 120 ? s + (s === 1 ? ' second' : ' seconds') : Math.ceil(s / 60) + ' minutes';
  }
  if (left !== null) {
    var end = Date.now() + left * 1000;
    say(left);
    var timer = setInterval(function () {
      var s = Math.ceil((end - Date.now()) / 1000);
      say(s);
      if (s <= 0) clearInterval(timer);
    }, 1000);
  }
})();
