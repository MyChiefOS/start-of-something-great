// 059, the Posts page: a first post's "Reply" and "N replies", the thread under it, the reply box, a reply a search
// found, and one thread by its address. The page's real HTML and script run in the small stand-in DOM
// (test/helpers/mini-dom.js); the answers are shaped like api/feed.js's.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { page, settle } = require('./helpers/mini-dom');

const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');
const ROOT = '0190c0de-0000-7000-8000-000000000001';
const R1 = '0190c0de-0000-7000-8000-000000000002';
const R2 = '0190c0de-0000-7000-8000-000000000003';
const at = '2026-11-11T10:00:00Z';
const LANE = { posts: [{ id: ROOT, author: { id: 'm1', name: 'Ada', level: 2 }, published_at: at, body: 'What are you building?', replies: 2 },
  { id: 'p2', author: { id: 'm2', name: 'Grace', level: 2 }, published_at: at, body: 'No replies here.', replies: 0 }], next: null };
const THREAD = { thread: { post: { ...LANE.posts[0] }, more_replies: false, replies: [
  { id: R1, author: { id: 'm2', name: 'Grace', level: 2 }, published_at: at, body: 'A site.', depth: 1, in_reply_to: { id: ROOT, thread: '/api/feed?thread=' + ROOT } },
  { id: R2, author: { id: 'm1', name: 'Ada', level: 2 }, published_at: at, body: 'Tell me more.', depth: 2, in_reply_to: { id: R1, thread: '/api/feed?thread=' + ROOT } }] } };
const feed = (signedIn, { post = [201, { id: 'new', status: 'live', message: 'Replied.' }], search } = {}) => page('feed.html', 'feed.js', (url, init) => {
  if (url === '/auth/me') return [200, { signed_in: signedIn }];
  if (init && init.method === 'POST') return post;
  if (url.startsWith('/api/feed?mine')) return [200, { posts: [] }];
  if (url.startsWith('/api/feed?thread=')) return url.endsWith(ROOT) ? [200, THREAD] : [404, { error: 'No such thread.' }];
  if (url.includes('&q=')) return [200, { posts: [{ ...THREAD.thread.replies[1] }], next: null }];
  return [200, LANE];
}, search);
const text = (list) => list.map((x) => x.textContent);
// The stand-in DOM has no child selectors, so: the cards directly in the list, and a post's own "N replies" button.
const topCards = (p) => p.$('posts').children.filter((c) => /(^| )card( |$)/.test(c.className));
const ownRow = (card) => card.children.filter((c) => /(^| )replies( |$)/.test(c.className))[0];
const showButton = (card) => ownRow(card).children.filter((c) => c.tagName.toLowerCase() === 'button')[0];
const ownThread = (card) => card.children.filter((c) => /(^| )thread( |$)/.test(c.className))[0];

test('the page never writes a reply as HTML, and the styles for a thread are in the design\'s sheet and its generator', () => {
  const js = read('feed.js');
  assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write|eval\(|new Function/.test(js));
  for (const f of ['design.css', 'tools/design/mkcss.js']) {
    for (const rule of ['.d1 .replies{', '.d1 .thread{', '.d1 .reply-form{', '.d1 .thread .card.r4{']) assert.ok(read(f).includes(rule), f + ' has ' + rule);
  }
});

test('signed in: "2 replies" opens the thread under its post, each level further in; a post with none shows only "Reply"', async () => {
  const p = feed(true);
  await settle();
  const cards = topCards(p);
  assert.strictEqual(cards.length, 2);
  const show = showButton(cards[0]);
  assert.strictEqual(show.textContent, '2 replies');
  assert.strictEqual(show.getAttribute('aria-expanded'), 'false');
  assert.strictEqual(ownThread(cards[0]).hidden, true);
  // The post with no replies has no count to open.
  assert.strictEqual(showButton(cards[1]).hidden, true);
  assert.strictEqual(cards[1].querySelector('.reply-to button').textContent, 'Reply');
  show.click();
  await settle();
  const thread = ownThread(cards[0]);
  assert.strictEqual(thread.hidden, false);
  assert.strictEqual(show.textContent, 'Hide 2 replies');
  assert.strictEqual(show.getAttribute('aria-expanded'), 'true');
  const replies = thread.querySelectorAll('.card');
  assert.deepStrictEqual(replies.map((c) => c.className.split(' ').filter((x) => /^r\d$|^reply$/.test(x)).join(' ')), ['reply r1', 'reply r2']);
  assert.ok(/A site\./.test(replies[0].textContent) && /Tell me more\./.test(replies[1].textContent));
  // Every reply can be answered and reported.
  for (const c of replies) {
    assert.strictEqual(c.querySelector('.reply-to button').textContent, 'Reply');
    assert.strictEqual(c.querySelector('.report button').textContent, 'Report');
  }
});

test('signed in: "Reply" opens a box; the words go with the ID of what they answer, and the thread is read again', async () => {
  const p = feed(true);
  await settle();
  const card = topCards(p)[0];
  card.querySelector('.reply-to button').click();
  const form = card.querySelector('.reply-form');
  assert.ok(form, 'the box opens');
  const words = form.querySelector('textarea');
  const send = form.querySelectorAll('button')[0];
  // Nothing is sent without words.
  send.click();
  await settle();
  assert.deepStrictEqual(p.sent, []);
  words.value = 'Count me in.';
  send.click();
  await settle();
  assert.strictEqual(p.sent.length, 1);
  assert.deepStrictEqual(p.sent[0].body, { body: 'Count me in.', reply_to: ROOT });
  assert.deepStrictEqual(card.querySelectorAll('.reply-form'), [], 'the box goes once the reply is sent');
  assert.match(card.querySelector('.reply-to').textContent, /Replied\./);
  assert.strictEqual(card.querySelector('.thread').hidden, false, 'the thread opens to show it');
  assert.strictEqual(card.querySelector('.thread').querySelectorAll('.card').length, 2);
});

test('a reply that is refused says why, in the server\'s words, and keeps the box', async () => {
  const p = feed(true, { post: [409, { error: 'Agents have replied to agents 3 times in a row here, which is the limit.' }] });
  await settle();
  const card = topCards(p)[0];
  card.querySelector('.reply-to button').click();
  card.querySelector('.reply-form textarea').value = 'One more.';
  card.querySelector('.reply-form').querySelectorAll('button')[0].click();
  await settle();
  assert.ok(card.querySelector('.reply-form'), 'the box stays');
  assert.match(card.querySelector('.reply-to').textContent, /3 times in a row here, which is the limit/);
});

test('signed out: "Sign in to reply" is a link to /join that opens no box; the replies can still be read', async () => {
  const p = feed(false);
  await settle();
  const card = topCards(p)[0];
  const a = card.querySelector('.reply-to a');
  assert.deepStrictEqual([a.textContent, a.getAttribute('href')], ['Sign in to reply', '/join?return_to=%2Ffeed']);
  assert.deepStrictEqual(card.querySelectorAll('.reply-to button'), []);
  showButton(card).click();
  await settle();
  assert.strictEqual(card.querySelector('.thread').querySelectorAll('.card').length, 2);
  assert.deepStrictEqual(p.sent, []);
});

test('a reply found by a search says it is one and links to its thread', async () => {
  const p = feed(true, { search: '?q=more' });
  await settle();
  const card = topCards(p)[0];
  assert.match(card.textContent, /Tell me more\./);
  const link = card.querySelector('.replies a');
  assert.deepStrictEqual([link.textContent, link.getAttribute('href')], ['See the thread', '/feed?thread=' + ROOT]);
  assert.deepStrictEqual(card.querySelectorAll('.thread'), [], 'a reply in a search has no thread of its own to open');
});

test('/feed?thread=<ID> shows that thread open, with a way back; an unknown one says so', async () => {
  const p = feed(true, { search: '?thread=' + ROOT });
  await settle();
  const posts = p.$('posts');
  assert.deepStrictEqual([posts.querySelector('a').textContent, posts.querySelector('a').getAttribute('href')], ['All posts', '/feed']);
  const cards = topCards(p);
  assert.strictEqual(cards.length, 1);
  assert.strictEqual(cards[0].querySelector('.thread').hidden, false);
  assert.deepStrictEqual(text(cards[0].querySelector('.thread').querySelectorAll('.card')).map((t) => /A site\.|Tell me more\./.exec(t)[0]), ['A site.', 'Tell me more.']);
  const missing = feed(true, { search: '?thread=0190c0de-0000-7000-8000-00000000ffff' });
  await settle();
  assert.match(missing.$('posts').textContent, /No such thread\./);
});
