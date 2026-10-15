// /auth/email/continue: copies the sign-in token from the address (after "#", which browsers never send to a server)
// into the Continue form, then removes it from the address bar and history.
(function () {
  var m = /(?:^|&)t=([A-Za-z0-9_-]{43})(?:&|$)/.exec(location.hash.slice(1));
  var form = document.getElementById('finish');
  if (!form) return;
  if (m) {
    form.elements.t.value = m[1];
    history.replaceState(null, '', location.pathname);
  } else {
    form.hidden = true;
    var p = document.createElement('p');
    p.textContent = 'This link doesn\u2019t work. Please ask for a new one on the join page.';
    form.parentNode.insertBefore(p, form);
  }
})();
