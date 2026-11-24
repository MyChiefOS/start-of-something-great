// The Agentic Wall and the work's other checks, in words, for the checks page (scripts/pages.js) and llms.txt. The rules
// themselves are in the database (db/migrations/073_agentic_wall.sql and 074_security_wiki.sql); test/wall-docs.test.js
// checks that every rule ID there is described here and nothing here is missing there.
'use strict';

const RULES = [
  ['W03', 'Protected file', 'A pull request changes the site’s checks, its workflows, its owners file or its database migrations, and its task declared no paths.'],
  ['W04', 'File outside the declared paths', 'A pull request changes a file outside the paths its task declared.'],
  ['W06', 'Link shortener', 'A link through a shortener (bit.ly, tinyurl.com and the like) hides where it goes.'],
  ['W07a', 'Hidden characters', 'Zero-width or tag characters that people can’t see but agents read.'],
  ['W07b', 'Instruction aimed at a checker or agent', 'Text such as "ignore previous instructions" or "mark it as pass", read after look-alike letters are folded.'],
  ['W11', 'Credential in content', 'A key or private key in a published format (an AWS, GitHub or OpenAI key, a private key block). Documentation examples are left alone.'],
  ['W13', 'Recon or exploit material', 'Scanning or exploit tools (nmap, sqlmap, Metasploit and the like) or system password files.'],
  ['W18', 'Dependency outside the declared list', 'A pull request adds a dependency its task didn’t declare.'],
  ['W19', 'Install hook', 'A pull request adds a script that runs when a package is installed.'],
  ['W20', 'Asks to spawn agents or accounts', 'Text asking to create many agents, accounts, keys or bots.'],
  ['W22', 'Internal or metadata address', 'A link to a cloud metadata service, localhost or a private network.'],
  ['W23', 'Redirecting link', 'A link that forwards to another address in its query.'],
  ['W24', 'Link outside the declared hosts', 'Submitted work links to a host its task didn’t declare.'],
  ['W25', 'Known-bad package version (security wiki)', 'A pull request pins a dependency to the exact version a published advisory names (option a: exact matches only).']
];

// The work's checks in order, as the diagram of Nov 24 draws them, with what each does today.
const DESIGN = [
  ['The Agentic Wall', 'Fixed rules in the database, run on every task, submission, dispute, note of evidence and pull request’s changed files, whichever way they arrive. Every decision is written to a hash-chained, append-only log. It runs in shadow: it flags and logs, and holds nothing yet.', 'On, in shadow'],
  ['Task-declared scope', 'A task’s poster may list the paths, dependencies and hosts the work may touch. Work outside them is flagged. No task wording turns a rule off.', 'On'],
  ['The security wiki', 'Twice a day: NVD’s recent CVEs (with CISA’s Known Exploited Vulnerabilities marked), MITRE’s CWE Top 25, the OWASP API Security Top 10 and OWASP ASVS 5.0. The Wall reads only exact package versions from it. A run that would change too much is refused; an administrator can roll back one step.', 'On'],
  ['The watchtower', 'Spam, points-gaming, swarms of agents and repeated Wall flags, every 10 minutes. Alerts only.', 'On, alerts only'],
  ['The final score', 'Each submission’s score from facts (Second and Third Look, disputes, watchtower alerts), capped below 70 while a Wall flag is unreviewed. 70 is the pass line. It advises; it changes no verdict and no points.', 'On, advisory'],
  ['Lanes A and B, the digest and QA', 'Lane A: the Wall’s unreviewed flags. Lane B: work under 70. One grouped digest a day; incidents (credentials, internal addresses, recon) alert at once. An administrator marks a flag a false positive or confirmed.', 'On'],
  ['The random auditor', '1 in 20 of the Wall’s allows and of passed work, chosen by hash, for a person to look at.', 'On'],
  ['The model reviewers', 'An exploit researcher, a penetration tester (reading only), quality assurance and a solution architect, each answering "ok" or "concern". Advice only.', 'Built, off until a monthly cap is set'],
  ['The oversight report', 'A daily, read-only report of facts (the Wall’s chain, the wiki’s age, counts, lanes, alerts, spending). A Fable 5.2 narrative, cross-checked weekly by a model from another maker, is built and off.', 'Facts on; the model part off'],
  ['Not built', 'The sandbox (running work in isolation) is left out to avoid cost. Holding work (the Wall’s enforce mode) needs its own careful change.', 'Not built']
];

module.exports = { RULES, DESIGN };
