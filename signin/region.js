// The regional gate (Aaron's decision, Oct 16, 2026): sign-up from the EU, the EEA, the UK and Switzerland is declined
// politely, in code, before any personal data is collected. The visitor is told we kept nothing about them; the only
// record is how many visitors from each country were declined that day (app.region_declines).
// The country comes from Vercel's x-vercel-ip-country header, which Vercel sets itself from the visitor's address.
// It is a best guess: a VPN can move someone in or out, which is why the firewall block planned for release (ROADMAP)
// sits in front of this, and why the privacy policy still has to say what happens if someone slips through.
'use strict';

// The 27 EU member states (ISO 3166-1 alpha-2, as Vercel reports them; Greece is GR).
const EU = ['AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL',
  'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE'];
// Parts of EU member states that have country codes of their own and are inside the EU: Åland (Finland), and French
// Guiana, Guadeloupe, Martinique, Mayotte, Réunion and Saint Martin (France). The Azores, Madeira and the Canary Islands
// are reported under PT and ES.
const EU_REGIONS = ['AX', 'GF', 'GP', 'MQ', 'YT', 'RE', 'MF'];
// The rest of the European Economic Area.
const EEA = ['IS', 'LI', 'NO'];
// The United Kingdom (GB). "UK" is the code's reserved spelling and "EU" a code some address databases give European
// addresses they can't place; both are declined in case a provider ever reports them.
const UK = ['GB', 'UK'];
const SWITZERLAND = ['CH'];
const OTHER_SPELLINGS = ['EU'];

const DECLINED = Object.freeze([...EU, ...EU_REGIONS, ...EEA, ...UK, ...SWITZERLAND, ...OTHER_SPELLINGS]);
const SET = new Set(DECLINED);

// The visitor's country as two capital letters, or null when the header is missing or malformed.
function country(req) {
  const raw = req && req.headers ? req.headers['x-vercel-ip-country'] : undefined;
  const c = String(raw || '').trim().toUpperCase();
  return /^[A-Z]{2}$/.test(c) ? c : null;
}

// The country if sign-up is declined there, otherwise null.
function declined(req) {
  const c = country(req);
  return c !== null && SET.has(c) ? c : null;
}

const MESSAGE = 'Day One Great isn’t open to people in the European Union, the European Economic Area, the United Kingdom or '
  + 'Switzerland yet, so we can’t sign you up. We haven’t kept anything about you: no account, no email address, no '
  + 'network address. The only thing we note is that one visitor from your country was turned away today, as a number.';

// The page a declined person sees. Plain text in a fixed page; nothing from the request is echoed. No cookie is set.
function page() {
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
    + '<meta name="robots" content="noindex"><title>Not open in your region yet · Day One Great</title><link rel="stylesheet" href="/styles.css"></head>'
    + '<body><main class="wrap signin"><h1>Not open in your region yet</h1><p>' + MESSAGE + '</p>'
    + '<p>You’re welcome to read everything on the site. <a href="/">Back to the home page</a></p></main></body></html>';
}

module.exports = { EU, EU_REGIONS, EEA, UK, SWITZERLAND, DECLINED, country, declined, MESSAGE, page };
