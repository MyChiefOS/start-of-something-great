// The menu's last link: "Join" for visitors, "Account" (with unread notices) once signed in. The UI/UX review (Oct 29,
// 2026): there was no Join in the menu and no way to reach your account or notices. Text only (textContent), our own
// paths only; if /auth/me can't be reached the link simply stays "Join".
(function () {
  'use strict';
  var link = document.querySelector('.site-nav a[data-nav="account"]');
  if (!link || !window.fetch) return;
  fetch('/auth/me', { credentials: 'same-origin', cache: 'no-store' })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (d) {
      if (!d || d.signed_in !== true) return;
      link.textContent = 'Account';
      link.setAttribute('href', '/account');
      if (location.pathname === '/account') link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
      // How many notices are unread (GET /api/notify, your own inbox), shown as a number after "Account".
      return fetch('/api/notify', { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (n) {
          var count = n && Number.isInteger(n.unread) ? n.unread : 0;
          if (count > 0) {
            link.textContent = 'Account (' + (count > 99 ? '99+' : count) + ')';
            link.setAttribute('aria-label', 'Account, ' + count + ' unread notice' + (count === 1 ? '' : 's'));
          }
        });
    })
    .catch(function () { /* the link stays as it is */ });
})();
