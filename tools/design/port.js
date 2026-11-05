// Port one of Aaron's static design pages into the site, exactly: its <main> markup and copy as written, links mapped
// to the site's real paths, and every inline style turned into a class with the same declarations (style-src 'self').
// node port.js <static dir> <page.html>  -> prints JSON {main, notice, styles:{cls:decl}} ; used by build.js
'use strict';
const fs = require('fs');
const crypto = require('crypto');
const ROUTES = { 'index.html': '/', 'feed.html': '/feed', 'talk.html': '/talk', 'proposals.html': '/proposals', 'shipped.html': '/shipped',
  'connect.html': '/connect', 'join.html': '/join', 'team.html': '/team', 'handshake.html': '/handshake', 'name.html': '/name',
  'research.html': '/research', 'paper.html': '/research/decision-loop', 'terms.html': '/terms', 'privacy.html': '/privacy', 'api.html': '/api',
  'llms.html': '/llms.txt', 'receipt.html': '/receipts', 'receipts.html': '/receipts', 'build.html': '/build', 'task.html': '/build',
  'leaderboard.html': '/leaderboard', 'citizen.html': '/leaderboard', 'loops.html': '/loops', 'account.html': '/account',
  'agents.html': '/account/agents', 'claim.html': '/account/agents', 'member.html': '/feed', 'directory.html': '/agents',
  'agentprofile.html': '/agents', 'autonomy.html': '/autonomy', 'security.html': '/security', 'status.html': '/status',
  'roadmap.html': '/roadmap', 'decisions.html': '/decisions', 'checks.html': '/checks', 'moderation.html': '/moderation',
  'disputes.html': '/disputes', 'dispute.html': '/disputes', 'rooms.html': '/rooms', 'room.html': '/rooms', 'projects.html': '/projects',
  'project.html': '/projects', 'agentjoin.html': '/agents/join', 'console.html': '/admin/console', 'engine.html': '/engine',
  'controls.html': '/admin/controls', 'review.html': '/admin/review', 'search.html': '/search', 'sitemap.html': '/sitemap',
  'error.html': '/errors/rate-limited', '404.html': '/404' };
const cls = (decl) => 'x' + crypto.createHash('sha256').update(decl).digest('hex').slice(0, 8);
function port(html) {
  // Everything between the end of the shell (header and the rows under it) and the footer.
  let body = html.slice(html.indexOf('</header>') + 9, html.indexOf('<footer'));
  body = body.replace(/^\s*(<div class="sub2[^"]*"[^>]*>.*?<\/div>\s*)+/s, '');
  return convert(body);
}
// The design's markup, with its links mapped to the site's paths and its inline styles as classes.
function convert(body) {
  const styles = {};
  body = body.replace(/href="([a-z0-9-]+\.html)(#[^"]*)?"/g, (m, f, h) => 'href="' + (ROUTES[f] || '/' + f.replace(/\.html$/, '')) + (h || '') + '"');
  body = body.replace(/ style="([^"]*)"/g, (m, d) => { const decl = d.trim().replace(/;$/, ''); const c = cls(decl); styles[c] = decl; return ' data-x="' + c + '"'; });
  // Merge each data-x into the element's class attribute.
  body = body.replace(/<([a-z0-9]+)([^>]*?) data-x="(x[0-9a-f]{8})"([^>]*)>/g, (m, tag, a, c, b) => {
    const attrs = a + b;
    if (/ class="/.test(attrs)) return '<' + tag + attrs.replace(/ class="([^"]*)"/, (q, v) => ' class="' + (v ? v + ' ' : '') + c + '"') + '>';
    return '<' + tag + attrs + ' class="' + c + '">';
  });
  // Prototype-only hooks: the skip link's script action and data-act stay only where a production script replaces them.
  body = body.replace(/ data-act="skipTo"/g, '');
  return { body: body.trim(), styles };
}
module.exports = { port, convert, ROUTES, cls };
if (require.main === module) {
  const [dir, page] = process.argv.slice(2);
  process.stdout.write(JSON.stringify(port(fs.readFileSync(dir + '/' + page, 'utf8')), null, 1));
}
