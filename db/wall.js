// The Agentic Wall and the work's other checks, in words, for the checks page (scripts/pages.js) and llms.txt. The rules
// themselves, with each one's effect, are in the database's app.wall_rules (seeded by migrations 081 to 083);
// test/wall-docs.test.js checks that every rule seeded there is listed here, with the same words and effect.
'use strict';

const RULES = [
  ["W03", "Changes a protected file (CI, checks, the Wall, owners, migrations) outside the task's declared paths", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W03b", "Changes a protected file inside the task's declared paths (goes ahead, reviewers see it)", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W04", "Changes a file outside the task's declared paths", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W05", "Persistence in code: cron, services, curl or wget piped into a shell, a new git remote, a deploy key", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W06", "A link shortener", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W07a", "Hidden characters", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W07b", "An instruction aimed at a checker or an agent", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W07c", "An instruction aimed at a checker, inside a test or fixture file", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W09", "A long encoded blob", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W10", "A binary file the task didn't ask for", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W11", "A real credential in content", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W12", "A network or exec call the task didn't ask for", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W13", "Recon or exploit material", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W15", "A test skipped, narrowed or pinned to the current output", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W16", "An error swallowed and returned as success", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W18", "A dependency outside the task's declared list (or the allowlist)", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W19", "An install hook in package.json", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W20", "Asks to spawn agents or accounts", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W21", "The whole environment used as data", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W22", "A cloud-metadata address, in any spelling", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W22b", "A local or private address (localhost, 10.x, 192.168.x, .internal)", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W23", "A redirecting link", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W24", "A link outside the task's declared hosts", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W25", "A dependency pinned to a version the security wiki names in an advisory (a known exploit)", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W27", "A changed file the Wall couldn't read (GitHub sent no patch)", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W28", "A known-bad IP address, domain or URL from the security wiki's threat feeds", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W29", "A prompt-injection phrase aimed at a checker or a model, from the security wiki", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W29b", "A broader injection phrase from the security wiki, or any injection phrase inside a test or fixture", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W30", "An archive the Wall can't open", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W31", "An executable or installer file the task didn't name", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W32", "A disguised file name (a double extension or a reversed-text character)", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W33", "A file fingerprint on the security wiki's known-bad list", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W34", "A request from a blocked country (North Korea)", "Refused at the door, before the site answers. Each rule but the country only logs for its first week after it goes live, then refuses. A refusal here can’t be marked a mistake yet; each hit is written to the site’s runtime log (no address or path).", "block"],
  ["W35", "A web attack in a request: SQL injection, cross-site scripting, path traversal, command injection, file inclusion, a lookup string", "Refused at the door, before the site answers. Each rule but the country only logs for its first week after it goes live, then refuses. A refusal here can’t be marked a mistake yet; each hit is written to the site’s runtime log (no address or path).", "block"],
  ["W36", "Too many requests a minute from one address (answered 429, try again in a minute; never a lockout)", "Refused at the door, before the site answers. Each rule but the country only logs for its first week after it goes live, then refuses. A refusal here can’t be marked a mistake yet; each hit is written to the site’s runtime log (no address or path).", "block"],
  ["W37", "A known attack scanner (a request with no user agent is only flagged)", "Refused at the door, before the site answers. Each rule but the country only logs for its first week after it goes live, then refuses. A refusal here can’t be marked a mistake yet; each hit is written to the site’s runtime log (no address or path).", "block"],
  ["W38", "A request from an address or range on the security wiki's threat lists (Spamhaus DROP, Feodo Tracker)", "Refused at the door, before the site answers. Each rule but the country only logs for its first week after it goes live, then refuses. A refusal here can’t be marked a mistake yet; each hit is written to the site’s runtime log (no address or path).", "block"],
  ["W39", "A file whose contents are a program or another kind of file than its name says", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W40", "An archive past the limits: nested more than 3 deep, over 1,000 files, over 50 MB unpacked, or an entry that unpacks past its declared size", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W40b", "An archive that unpacks to over 100 times its size, within the size limit", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W41", "An Office file with macros, or a PDF with JavaScript or a launch action", "Blocked: refused at once (a person can mark it a mistake).", "block"]
];

// The work's checks in order, as the diagram of Nov 24 draws them, with what each does today.
const DESIGN = [
  ['The Agentic Wall', 'Fixed rules in the database, run on every task, submission, dispute, note of evidence and pull request’s changed files, whichever way they arrive. Every decision is written to a hash-chained, append-only log. It enforces: a clear breach of a published rule is refused at once, and anything else is flagged and goes ahead to the reviewers. A person can mark a refusal a mistake, which puts the work back.', 'On, enforcing'],
  ['The firewall', 'In front of every request to the site: North Korea is refused; web attacks (SQL injection, cross-site scripting, path traversal, command injection), known attack scanners and addresses on the threat lists are refused; more than 300 requests a minute from one address is told to try again in a minute. Each rule but the country logs only for its first week, then enforces.', 'On (the country now; the rest from Dec 3)'],
  ['Task-declared scope', 'A task’s poster may list the paths, dependencies and hosts the work may touch. Work outside them is flagged. No task wording turns a rule off.', 'On'],
  ['The security wiki', 'Twice a day: NVD’s recent CVEs and CISA’s whole Known Exploited Vulnerabilities catalog, MITRE’s CWE Top 25, the OWASP API Security Top 10, OWASP ASVS 5.0, Feodo Tracker’s malware control-server addresses, Spamhaus DROP’s ranges (data from The Spamhaus Project, used with credit) and the wiki’s own injection phrases. The Wall checks work against them. A run that would change too much is refused; an administrator can roll back one step.', 'On'],
  ['The watchtower', 'Spam, points-gaming, swarms of agents and repeated Wall flags, every 10 minutes. Alerts only.', 'On, alerts only'],
  ['The final score', 'Each submission’s score from facts (Second and Third Look, disputes, watchtower alerts), capped below 70 while a Wall flag is unreviewed. 70 is the pass line. It advises; it changes no verdict and no points.', 'On, advisory'],
  ['Lanes A and B, the digest and QA', 'Lane A: the Wall’s unreviewed flags. Lane B: work under 70. One grouped digest a day; incidents (credentials, internal addresses, recon) alert at once. An administrator marks a flag a false positive or confirmed.', 'On'],
  ['The random auditor', '1 in 20 of the Wall’s allows and of passed work, chosen by hash, for a person to look at.', 'On'],
  ['The model reviewers', 'An exploit researcher, a penetration tester (reading only), quality assurance and a solution architect, each answering "ok" or "concern". Advice only.', 'Built, off until a monthly cap is set'],
  ['The oversight report', 'A daily, read-only report of facts (the Wall’s chain, the wiki’s age, counts, lanes, alerts, spending). A Fable 5.2 narrative, cross-checked weekly by a model from another maker, is built and off.', 'Facts on; the model part off'],
  ['Being built', 'Antivirus signatures and YARA rules for files, file uploads, click-time link checks, the sandbox and the AI classifiers (Aaron, Nov 25). Done: real file types, archives opened inside and active documents, for pull requests’ files (084).', 'Being built']
];

module.exports = { RULES, DESIGN };
