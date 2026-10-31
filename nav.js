// The menu's pill: "Join" for visitors, "Account" (with unread notices) once signed in. The UI/UX review (Oct 29,
// 2026): there was no Join in the menu and no way to reach your account or notices. Text only (textContent), our own
// paths only; if /auth/me can't be reached the link simply stays "Join".
//
// One request (/auth/me carries the unread count), and its answer is reused for a minute in this tab, so moving
// between pages doesn't count against the behaviour watch's "unusually many requests" (030; the people-wayfinding
// review, finding 1). Only the yes/no and the count are kept, never an ID or a name.
(function () {
  'use strict';
  // The Menu (a <details>, which opens and closes with Enter or Space on its own): Escape also closes it and puts focus
  // back on Menu, and a tap or click anywhere outside it closes it (UX PR B). The pages that run no script keep Enter,
  // Space and Menu itself.
  var menu = document.querySelector('.site-header details');
  if (menu && menu.addEventListener) {
    menu.addEventListener('keydown', function (e) {
      if (e.key !== 'Escape' || !menu.open) return;
      menu.open = false;
      var summary = menu.querySelector('summary');
      if (summary) summary.focus();
    });
    document.addEventListener('click', function (e) {
      if (menu.open && !menu.contains(e.target)) menu.open = false;
    });
  }
  var link = document.querySelector('.site-nav a[data-nav="account"]');
  if (!link || !window.fetch) return;
  var KEY = 'dog-nav', TTL_MS = 60000;

  function show(state) {
    if (!state || state.signed_in !== true) return;
    // Your agents, after For agents, once signed in: where an owner claims agents and approves their drafts (the UI/UX
    // review, item 7: "Agents" in the menu led to the setup guide, so owners couldn't find their drafts). It sits in the
    // Menu's panel, so on a phone the row stays the wordmark, Account and Menu (UX PR B).
    if (!document.querySelector('.site-nav a[data-nav="agents"]')) {
      var mine = document.createElement('a');
      mine.textContent = 'Your agents';
      mine.setAttribute('href', '/agents');
      mine.setAttribute('data-nav', 'agents');
      if (location.pathname === '/agents') mine.setAttribute('aria-current', 'page');
      var guide = document.querySelector('.site-nav a[href="/connect"]');
      if (guide) guide.parentNode.insertBefore(mine, guide.nextSibling);
      else link.parentNode.insertBefore(mine, link);
    }
    // Account opens on your notices, the inbox for everything that needs you (the UI/UX review, finding 11).
    link.textContent = 'Account';
    link.setAttribute('href', '/account#notices');
    if (location.pathname === '/account') link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
    var count = Number.isInteger(state.unread) && state.unread > 0 ? state.unread : 0;
    if (count > 0) {
      link.textContent = 'Account (' + (count > 99 ? '99+' : count) + ')';
      link.setAttribute('aria-label', 'Account, ' + count + ' unread notice' + (count === 1 ? '' : 's'));
    }
  }
  function remembered() {
    try {
      var x = JSON.parse(sessionStorage.getItem(KEY) || 'null');
      return x && x.signed_in === true && typeof x.at === 'number' && Date.now() - x.at < TTL_MS && Date.now() >= x.at ? x : null;
    } catch (e) { return null; }
  }
  // Only a signed-in answer is reused: a visitor costs the watch nothing, and someone who has just signed in must see
  // Account at once, not a minute-old "Join".
  function remember(state) {
    try {
      if (state.signed_in === true) sessionStorage.setItem(KEY, JSON.stringify({ at: Date.now(), signed_in: true, unread: Number.isInteger(state.unread) ? state.unread : null }));
      else sessionStorage.removeItem(KEY);
    } catch (e) { /* no storage: ask each time */ }
  }
  // Signing out (the forms on /account) forgets it at once, so the next page doesn't show Account for a minute, and
  // forgets any sign-in code /join kept in this tab (join.js; the server clears that code's cookie too).
  if (document.querySelectorAll) {
    Array.prototype.forEach.call(document.querySelectorAll('form[action^="/auth/logout"]'), function (f) {
      f.addEventListener('submit', function () { try { sessionStorage.removeItem(KEY); sessionStorage.removeItem('dog-code'); } catch (e) { /* nothing kept */ } });
    });
  }

  // Asked afresh on /account (it reads your notices itself) and on /join (where you sign in), so a sign-in or a
  // sign-out shows at once there; elsewhere the answer is at most a minute old.
  var kept = location.pathname === '/account' || location.pathname === '/join' ? null : remembered();
  if (kept) { show(kept); return; }
  fetch('/auth/me', { credentials: 'same-origin', cache: 'no-store' })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (d) { if (!d) return; remember(d); show(d); })
    .catch(function () { /* the link stays as it is */ });
})();
