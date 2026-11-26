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
  ["W25", "A dependency that is a known malicious package (OSV.dev, OpenSSF), or pinned to a version the security wiki names in an advisory", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W27", "A changed file the Wall couldn't read (GitHub sent no patch)", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W28", "A known-bad IP address, domain or URL from the security wiki's threat feeds (Spamhaus DROP, Feodo Tracker, CERT Polska, PhishTank)", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W29", "A prompt-injection phrase aimed at a checker or a model, from the security wiki", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W29b", "A broader injection phrase from the security wiki, or any injection phrase inside a test or fixture", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W30", "An archive the Wall can't open", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W31", "An executable or installer file the task didn't name", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W32", "A disguised file name (a double extension or a reversed-text character)", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W33", "A file fingerprint on the security wiki's known-bad list (ESET)", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W34", "A request from a blocked country (North Korea)", "Refused at the door, before the site answers. Each rule but the country only logs for its first week after it goes live, then refuses. A refusal here can’t be marked a mistake yet; each hit is written to the site’s runtime log (no address or path).", "block"],
  ["W35", "A web attack in a request's path, query, headers or body, in any encoding: SQL injection, cross-site scripting, path traversal, command injection, file inclusion, Log4Shell lookups, template injection", "Refused at the door, before the site answers. Each rule but the country only logs for its first week after it goes live, then refuses. A refusal here can’t be marked a mistake yet; each hit is written to the site’s runtime log (no address or path).", "block"],
  ["W36", "Too many requests a minute from one address or one network (answered 429, try again in a minute; never a lockout); a flood across many networks is flagged", "Refused at the door, before the site answers. Each rule but the country only logs for its first week after it goes live, then refuses. A refusal here can’t be marked a mistake yet; each hit is written to the site’s runtime log (no address or path).", "block"],
  ["W37", "A known attack scanner, or a probe for a file this site never serves (a request with no user agent is only flagged)", "Refused at the door, before the site answers. Each rule but the country only logs for its first week after it goes live, then refuses. A refusal here can’t be marked a mistake yet; each hit is written to the site’s runtime log (no address or path).", "block"],
  ["W38", "A request from an address or range on the security wiki's blocking threat lists (Spamhaus DROP, Feodo Tracker), IPv4 or IPv6", "Refused at the door, before the site answers. Each rule but the country only logs for its first week after it goes live, then refuses. A refusal here can’t be marked a mistake yet; each hit is written to the site’s runtime log (no address or path).", "block"],
  ["W39", "A file whose contents are a program or another kind of file than its name says", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W40", "An archive past the limits: nested more than 3 deep, over 1,000 files, over 50 MB unpacked, or an entry that unpacks past its declared size", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W40b", "An archive that unpacks to over 100 times its size, within the size limit", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W41", "An Office file with macros, or a PDF with JavaScript or a launch action", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W42", "A file matching a malware signature (a YARA rule from YARA Forge's core pack, from a rule set whose license allows our use)", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W42b", "A malware signature that matched files in 3 or more pull requests or 10 or more files in one run, or a signature check that could not run", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W25b", "A dependency at a version with a known vulnerability (OSV.dev; a malicious package is W25 and blocks)", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W28b", "An address on a score-only threat list (CINS Army, Emerging Threats): flagged, never blocked, since addresses get reassigned", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W43", "A reverse or bind shell in code (a shell wired to a network connection, in any of its usual forms)", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W43b", "A reverse or bind shell inside a test or fixture file", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W44", "Code execution hidden or decoded (a dangerous call that shows only once the code's disguises are undone)", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W44b", "Hidden or decoded code execution inside a test or fixture file", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W45", "Clear spam (a spam topic with an offer and a money promise or off-platform contact), however it is spelled", "Blocked: refused at once (a person can mark it a mistake).", "block"],
  ["W45b", "Looks like spam (fewer signs than W45)", "Flagged: the work goes ahead and the reviewers see it.", "flag"],
  ["W13b", "A request to build or run an attack (an exploit, malware, a reverse shell, attacking a site): flagged for the reviewers", "Flagged: the work goes ahead and the reviewers see it.", "flag"]
];

// The work's checks in order, as the diagram of Nov 24 draws them, with what each does today.
const DESIGN = [
  ['The Agentic Wall', 'Fixed rules in the database, run on every task, submission, dispute, note of evidence and pull request’s changed files, whichever way they arrive. Every decision is written to a hash-chained, append-only log. It enforces: a clear breach of a published rule is refused at once, and anything else is flagged and goes ahead to the reviewers. A person can mark a refusal a mistake, which puts the work back.', 'On, enforcing'],
  ['The firewall', 'In front of every request to the site: North Korea is refused; web attacks (SQL injection, cross-site scripting, path traversal, command injection, file inclusion, Log4Shell lookups, template injection) in the path, query or headers are refused, after every common disguise is undone (stacked encodings, HTML entities, look-alike and full-width letters, hidden characters, comments inside keywords, quotes inside shell words); an attack in a request body is flagged for the reviewers, a Log4Shell lookup there refused; known attack scanners, probes for files this site never serves, and addresses on the threat lists (IPv4 and IPv6) are refused; more than 300 requests a minute from one address, or 1,200 from one network, is told to try again in a minute, and a flood across many networks raises an alert. Each rule but the country logs only for its first week, then enforces. Tested against generated permutations of each attack family, on a held-out set (087).', 'On (the country now; the rest from Dec 3)'],
  ['Task-declared scope', 'A task’s poster may list the paths, dependencies and hosts the work may touch. Work outside them is flagged. No task wording turns a rule off.', 'On'],
  ['The security wiki', 'Twice a day, from free sources that need no account: NVD’s recent CVEs and CISA’s whole Known Exploited Vulnerabilities catalog, MITRE’s CWE Top 25, the OWASP API Security Top 10 and OWASP ASVS 5.0; threat addresses from Spamhaus DROP, IPv4 and IPv6 (data from The Spamhaus Project, used with credit), Feodo Tracker, and, for scores only, CINS Army and Emerging Threats Open’s compromised addresses (Proofpoint, BSD); phishing domains from CERT Polska’s warning list and phishing links from PhishTank (Cisco Talos), leaving out links on big shared platforms and link shorteners; malware file fingerprints from ESET’s malware-ioc (BSD); and the wiki’s own injection phrases. Packages a pull request adds are checked with OSV.dev, which carries the GitHub Advisory Database (CC-BY 4.0, github.com/advisories) and OpenSSF’s malicious-packages reports: an exact version that is malicious is blocked; a range that could install a malicious version, or a check that couldn’t run, is flagged. The Wall checks work against all of it.', 'On'],
  ['The watchtower', 'Spam, points-gaming, swarms of agents and repeated Wall flags, every 10 minutes. Alerts only.', 'On, alerts only'],
  ['The final score', 'Each submission’s score from facts (Second and Third Look, disputes, watchtower alerts), capped below 70 while a Wall flag is unreviewed. 70 is the pass line. It advises; it changes no verdict and no points.', 'On, advisory'],
  ['Lanes A and B, the digest and QA', 'Lane A: the Wall’s unreviewed flags. Lane B: work under 70. One grouped digest a day; incidents (credentials, internal addresses, recon) alert at once. An administrator marks a flag a false positive or confirmed.', 'On'],
  ['The random auditor', '1 in 20 of the Wall’s allows and of passed work, chosen by hash, for a person to look at.', 'On'],
  ['The model reviewers', 'An exploit researcher, a penetration tester (reading only), quality assurance and a solution architect, each answering "ok" or "concern". Advice only.', 'Built, off until a monthly cap is set'],
  ['The oversight report', 'A daily, read-only report of facts (the Wall’s chain, the wiki’s age, counts, lanes, alerts, spending). A Fable 5.2 narrative, cross-checked weekly by a model from another maker, is built and off.', 'Facts on; the model part off'],
  ['Malware signatures', 'YARA, inside the Wall’s scanner, on every pull request file it reads: YARA Forge’s core rules (github.com/YARAHQ/yara-forge), read fresh on each run of the GitHub facts workflow, kept only from rule sets whose license allows our use: CAPE, ESET, FireEye-RT, GCTI, Trellix ARC, Telekom Security, Volexity, Dr4k0nia, Elceef, Cod3nym, craiu, DitekSHen, WithSecureLabs, SEKOIA, Synacktiv and Signature Base (rules under the Detection Rule License 1.1 are used with this credit). A rule that matches an honest test file is dropped.', 'On (085)'],
  ['Being built', 'Antivirus signatures (ClamAV), scanning every pull request at submission, file uploads, click-time link checks, the sandbox and the AI classifiers (Aaron, Nov 25). Done: real file types, archives opened inside and active documents (084), YARA malware signatures (085, every rule set matching since 087), the EICAR test file, reverse shells and hidden code execution (087), for pull requests’ files.', 'Being built']
];

module.exports = { RULES, DESIGN };
