# Audit logging requirements

What Day One Great logs, and why, traced to NIST SP 800-53 Rev 5 and the DISA Application Security and Development STIG (V6), as Aaron directed on Nov 8, 2026: "Go review NIST 800-53 audit logging requirements and go review DISA STIG Application Logging requirements make sure that level of logging in intergarated into the system." and "Put in the requirements based on NIST 800-53 and DISA STIG application logging requirements." The pass-or-fail criteria are AL1 to AL16 in [ACCEPTANCE.md](ACCEPTANCE.md).

## Aaron's choices where the STIG conflicted with earlier decisions

He chose the STIG each time (harness/FACTS.md, Nov 8):

- **The network address and request headers** are recorded beside each audit record and kept a year (V-222447, V-222448). This replaces, for audit records, the privacy page's "Never the network address itself".
- **Audit records are kept at least a year**, also after an account is deleted, with Aaron's security alerts about it (V-222621).
- **A private weekly copy on Vercel**, as well as a hash chain and a signed digest (V-222481, V-222482, V-222506, V-222507).
- **3 failed sign-ins in 15 minutes lock the account**, every way in, GitHub's included, for 15 minutes; and processing halts on audit failure (V-222432, V-222486; the halt is the second part). This replaces "checks alert, never lock out" for these two (INTEGRITY.md records the exception). Aaron confirmed on Nov 9, after the review showed a failed try needs no PIN, key file or enrolled browser: "you need to follow NIST and DISA STIG guidelines". The cost: anyone who knows a member's GitHub username can lock that member's sign-in for 15 minutes at a time, Aaron's included, and with many networks many members at once (RISKS.md RK138, Medium). Narrowed by: nothing is tested or counted during a lock; 10 key-file tries an hour per IPv6 /48 or IPv4 /24 (NIST SP 800-63B 3.2.2); browsers already signed in stay signed in; Aaron releases a lock from the Console's Admins tab, with a reason.
- **Members travelling in the EU, EEA, UK or Switzerland**: their confirmation record keeps its request details like every other (Aaron, Nov 9: "Record them too"; CHARTER.md section 2).

## NIST SP 800-53 Rev 5

| Control | Title | How it is met | Status |
|---|---|---|---|
| AU-1 | Policy and procedures | This file, ACCEPTANCE.md AL1 to AL16, and Aaron's decisions in harness/FACTS.md. | Built (053) |
| AU-2 | Event logging | The events in AL3 to AL7, chosen because each supports an after-the-fact investigation; reviewed with each release. | Built (053) |
| AU-3, AU-3(1) | Content of audit records | AL1, AL2. | Built (053) |
| AU-4 | Audit log storage capacity | AL10; the plan's capacity is a setting changed by migration. | Built (053) |
| AU-5, AU-5(1) | Response to audit logging failures | AL10 (storage), AL11, AL15. | Partly built; the rest in the second part |
| AU-6, AU-6(1), AU-6(3) | Review, analysis and reporting | AL14, AL15; the behaviour watch already alerts. | Second part |
| AU-7, AU-7(1) | Reduction and report generation | AL14. | Second part |
| AU-8 | Time stamps | AL1: the database clock, UTC, microseconds. | Met before 053 |
| AU-9, AU-9(4) | Protection of audit information | AL8; only the administrator reads; only migrations change the audit functions. | Built (053) |
| AU-9(2), AU-9(3) | Stored elsewhere; cryptographic protection | AL12, AL13. | Second part |
| AU-10 | Non-repudiation | The actor is proven by the database (019); the chain and signed digest (AL12). | Partly; the rest in the second part |
| AU-11 | Retention | AL9: at least a year. | Built (053) |
| AU-12 | Audit record generation | Triggers in the database, always on, for every event in AL3 to AL7. | Built (053) |
| AC-7 | Unsuccessful logon attempts | AL3. | Built (053) |

## DISA Application Security and Development STIG (V6)

Every requirement whose title mentions audit, logs, logons, sessions or time stamps (95), from STIG Manager's published list of the STIG.

| V-ID | Requirement | Status | Criterion | How |
|---|---|---|---|---|
| V-222387 | The application must provide a capability to limit the number of logon sessions per user. | Not a logging requirement (listed by keyword only) |  | Session limits: not part of this work. |
| V-222389 | The application must automatically terminate the non-privileged user session and log off non-privileged users after a 15 minute idle time period has elapsed. | Not a logging requirement (listed by keyword only) |  | Idle timeout (15 minutes): sessions here last 30 days by Aaron's sign-in design; a separate decision. |
| V-222390 | The application must automatically terminate the admin user session and log off admin users after a 10 minute idle time period is exceeded. | Not a logging requirement (listed by keyword only) |  | Admin idle timeout (10 minutes): as above; a separate decision. |
| V-222398 | Applications with SOAP messages requiring integrity must include the following message elements:-Message ID-Service Request-Timestamp-SAML Assertion (optionally included in messages) and all elements of the message must be digitally signed. | Not applicable |  | No SOAP messages. |
| V-222399 | Messages protected with WS_Security must use time stamps with creation and expiration times. | Not applicable |  | No WS-Security. |
| V-222413 | The application must automatically audit account creation. | Met before 053 | AL5 | member.joined; agent.create, agent.register, agent.subagent. |
| V-222414 | The application must automatically audit account modification. | Built (053) | AL5 | Renames, PINs, browser keys and key files added in 053; levels, identities and regions before. |
| V-222415 | The application must automatically audit account disabling actions. | Met before 053 | AL5 | member.ban, member.disable, containment.start, agent.revoke, agent.expire. |
| V-222416 | The application must automatically audit account removal actions. | Met before 053 | AL5 | member.deleted (counts only), agent.revoke. |
| V-222421 | The application must automatically audit account enabling actions. | Met before 053 | AL5 | member.unban, member.restore, containment.lift, agent.claim. |
| V-222425 | The application must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies. | Not a logging requirement (listed by keyword only) |  | Access control: covered by S2 and S3. |
| V-222431 | The application must audit the execution of privileged functions. | Built (053) | AL6 | Work decisions, Third Look's mode and settings added in 053; admin.set, bans, level changes, moderation and brakes before. |
| V-222432 | The application must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minute time period. | Built (053) | AL3 | 3 failed sign-ins in 15 minutes lock the account, every way in, for 15 minutes (Aaron, Nov 8: "Follow the STIG guidelines"). While it is locked no key file or PIN is tested or counted and every try gets the same answer, "locked". Two failures at once are counted one at a time. |
| V-222435 | The application must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access. | Not applicable |  | No DoD notice and consent banner: a public site. |
| V-222437 | The application must display the time and date of the users last successful logon. | Met before 053 |  | The account page shows when each browser last signed in. |
| V-222439 | For applications providing audit record aggregation, the application must compile audit records from organization-defined information system components into a system-wide audit trail that is time-correlated with an organization-defined level of tolerance for the relationship between time stamps of individual records in the audit trail. | Not applicable |  | No audit aggregation across components: one database holds the audit log; time is the database clock. |
| V-222441 | The application must provide audit record generation capability for the creation of session IDs. | Built (053) | AL4 | session.created, with a reference to the session. |
| V-222442 | The application must provide audit record generation capability for the destruction of session IDs. | Built (053) | AL4 | session.ended. |
| V-222443 | The application must provide audit record generation capability for the renewal of session IDs. | Not applicable | AL4 | Session IDs are never renewed: a session keeps its ID for its life (no renewal to record). |
| V-222444 | The application must not write sensitive data into the application logs. | Built (053) | AL16 | No secret in audit records; request paths are kept without their query strings. |
| V-222445 | The application must provide audit record generation capability for session timeouts. | Built (053) | AL4 | session.expired, recorded by the timer's sweep. |
| V-222446 | The application must record a time stamp indicating when the event occurred. | Met before 053 | AL1 | Every record has its time from the database clock. |
| V-222447 | The application must provide audit record generation capability for HTTP headers including User-Agent, Referer, GET, and POST. | Built (053) | AL2 | User agent, referrer, method and path (no query string) beside each record made in a request. |
| V-222448 | The application must provide audit record generation capability for connecting system IP addresses. | Built (053) | AL2 | The connecting IP address, as Vercel sets it. |
| V-222450 | The application must generate audit records when successful/unsuccessful attempts to grant privileges occur. | Built (053) | AL5, AL6 | Grants (administrator, levels, agent rules) recorded; refused tries recorded as JEVs holds and admin.founder_refused. |
| V-222451 | The application must generate audit records when successful/unsuccessful attempts to access security objects occur. | Built (053) | AL7 | Aaron's reads of the Console, the work queue, the post review queue and the owner controls (console.read, admin.read); a non-administrator's attempt is refused and alerted (the behaviour watch). |
| V-222452 | The application must generate audit records when successful/unsuccessful attempts to access security levels occur. | Built (053) | AL5 | Trust levels: changes recorded. |
| V-222453 | The application must generate audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur. | Not applicable |  | No classification levels. |
| V-222454 | The application must generate audit records when successful/unsuccessful attempts to modify privileges occur. | Built (053) | AL5, AL6 | As V-222450. |
| V-222455 | The application must generate audit records when successful/unsuccessful attempts to modify security objects occur. | Built (053) | AL6 | Settings and configuration changes recorded with what changed. |
| V-222456 | The application must generate audit records when successful/unsuccessful attempts to modify security levels occur. | Built (053) | AL5 | As V-222452. |
| V-222457 | The application must generate audit records when successful/unsuccessful attempts to modify categories of information (e.g., classification levels) occur. | Not applicable |  | No classification levels. |
| V-222458 | The application must generate audit records when successful/unsuccessful attempts to delete privileges occur. | Built (053) | AL5 | Key revocations, administrator removal (migrations, recorded in change_log). |
| V-222459 | The application must generate audit records when successful/unsuccessful attempts to delete security levels occur. | Built (053) | AL5 | As V-222452. |
| V-222460 | The application must generate audit records when successful/unsuccessful attempts to delete application database security objects occur. | Built (053) | AL6 | Database objects change only by migration, recorded in change_log with its SHA-256. |
| V-222461 | The application must generate audit records when successful/unsuccessful attempts to delete categories of information (e.g., classification levels) occur. | Not applicable |  | No classification levels. |
| V-222462 | The application must generate audit records when successful/unsuccessful logon attempts occur. | Built (053) | AL1, AL3 | Each successful sign-in (member.signed_in, session.created) and each failed one (signin.failed) is its own record: wrong key files and PINs against the member, and, with no account to count against, a key file for a username nobody has, a failed browser or code proof, and an expired code; each refusal during a lock (signin.refused). |
| V-222463 | The application must generate audit records for privileged activities or other system-level access. | Built (053) | AL6 | As V-222431. |
| V-222464 | The application must generate audit records showing starting and ending time for user access to the system. | Built (053) | AL4 | Session made and ended (or expired): the start and end of access. |
| V-222465 | The application must generate audit records when successful/unsuccessful accesses to objects occur. | Built (053) | AL7 | Aaron's reads of audit, review and control data recorded (as V-222451); changes to objects recorded per AL5 and AL6. |
| V-222466 | The application must generate audit records for all direct access to the information system. | Met before 053 | AL6 | Direct database changes happen only through the migration workflow, recorded in change_log; Supabase's own logs record dashboard access. |
| V-222467 | The application must generate audit records for all account creations, modifications, disabling, and termination events. | Built (053) | AL5 | As V-222413 to V-222421. |
| V-222468 | The application must initiate session auditing upon startup. | Met before 053 | AL8 | Auditing is part of the database: triggers that are always on, with no switch. |
| V-222469 | The application must log application shutdown events. | Met before 053 |  | Closing the site is a reviewed migration or LAUNCH_STAGE change, recorded in change_log and git. |
| V-222470 | The application must log destination IP addresses. | Built (053) | AL2 | The host each request was made to. |
| V-222471 | The application must log user actions involving access to data. | Built (053) | AL7 | As V-222465. |
| V-222472 | The application must log user actions involving changes to data. | Built (053) | AL6 | Changes to posts, agents, drafts, reports, work, settings. |
| V-222473 | The application must produce audit records containing information to establish when (date and time) the events occurred. | Met before 053 | AL1 | As V-222446. |
| V-222474 | The application must produce audit records containing enough information to establish which component, feature or function of the application triggered the audit event. | Built (053) | AL1 | The component, from the action. |
| V-222475 | When using centralized logging; the application must include a unique identifier in order to distinguish itself from other application logs. | Second part (AL13) | AL13 | The private copy will name this application. |
| V-222476 | The application must produce audit records that contain information to establish the outcome of the events. | Built (053) | AL1 | Outcome: success or failure. |
| V-222477 | The application must generate audit records containing information that establishes the identity of any individual or process associated with the event. | Met before 053 | AL1 | The actor, proven by the database. |
| V-222478 | The application must generate audit records containing the full-text recording of privileged commands or the individual identities of group account users. | Met before 053 | AL6 | Privileged actions record their action, subject and from-to values; there are no group accounts. |
| V-222479 | The application must implement transaction recovery logs when transaction based. | Not applicable |  | Transaction recovery: the database's own write-ahead log and backups. |
| V-222480 | The application must provide centralized management and configuration of the content to be captured in audit records generated by all application components. | Met before 053 | AL1 | What each record holds is defined in one place, the database (migrations). |
| V-222481 | The application must off-load audit records onto a different system or media than the system being audited. | Second part (AL11 to AL15) | AL13 | A private weekly copy on Vercel Blob storage (Aaron, Nov 8: "Also a private copy on Vercel"). |
| V-222482 | The application must be configured to write application logs to a centralized log repository. | Second part (AL11 to AL15) | AL13 | As V-222481. |
| V-222483 | The application must provide an immediate warning to the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity. | Built (053) | AL10 | A warning at 75% of the plan's storage. |
| V-222484 | Applications categorized as having a moderate or high impact must provide an immediate real-time alert to the SA and ISSO (at a minimum) for all audit failure events. | Second part (AL11 to AL15) | AL15 | Immediate alerts on audit failures. |
| V-222485 | The application must alert the ISSO and SA (at a minimum) in the event of an audit processing failure. | Second part (AL11 to AL15) | AL15 | As V-222484. |
| V-222486 | The application must shut down by default upon audit failure (unless availability is an overriding concern). | Second part (AL11 to AL15) | AL11, AL12 | Writes in the same transaction (an action without its record doesn't happen); writes stop on a broken chain. |
| V-222487 | The application must provide the capability to centrally review and analyze audit records from multiple components within the system. | Second part (AL11 to AL15) | AL14 | The Console's audit view. |
| V-222488 | The application must provide the capability to filter audit records for events of interest based upon organization-defined criteria. | Second part (AL11 to AL15) | AL14 | Filters. |
| V-222489 | The application must provide an audit reduction capability that supports on-demand reporting requirements. | Second part (AL11 to AL15) | AL14 | Reports. |
| V-222490 | The application must provide an audit reduction capability that supports on-demand audit review and analysis. | Second part (AL11 to AL15) | AL14 | As above. |
| V-222491 | The application must provide an audit reduction capability that supports after-the-fact investigations of security incidents. | Second part (AL11 to AL15) | AL14 | As above. |
| V-222492 | The application must provide a report generation capability that supports on-demand audit review and analysis. | Second part (AL11 to AL15) | AL14 | As above. |
| V-222495 | The application must provide an audit reduction capability that does not alter original content or time ordering of audit records. | Second part (AL11 to AL15) | AL14 | Read-only views, ordered by time and ID. |
| V-222496 | The application must provide a report generation capability that does not alter original content or time ordering of audit records. | Second part (AL11 to AL15) | AL14 | As above. |
| V-222497 | The applications must use internal system clocks to generate time stamps for audit records. | Met before 053 | AL1 | The database clock. |
| V-222498 | The application must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT). | Met before 053 | AL1 | UTC. |
| V-222499 | The application must record time stamps for audit records that meet a granularity of one second for a minimum degree of precision. | Met before 053 | AL1 | Microseconds. |
| V-222500 | The application must protect audit information from any type of unauthorized read access. | Met before 053 | AL8 | Only an administrator reads the audit log; request records the same. |
| V-222501 | The application must protect audit information from unauthorized modification. | Built (053) | AL8 | No role can change a record or its request record. |
| V-222502 | The application must protect audit information from unauthorized deletion. | Built (053) | AL8, AL9 | No role can delete one; request records go only after a year. |
| V-222503 | The application must protect audit tools from unauthorized access. | Met before 053 | AL8 | The audit functions belong to the database owner; only reviewed migrations change them. |
| V-222504 | The application must protect audit tools from unauthorized modification. | Met before 053 | AL8 | As above. |
| V-222505 | The application must protect audit tools from unauthorized deletion. | Met before 053 | AL8 | As above. |
| V-222506 | The application must back up audit records at least every seven days onto a different system or system component than the system or component being audited. | Second part (AL11 to AL15) | AL13 | At least every 7 days. |
| V-222507 | The application must use cryptographic mechanisms to protect the integrity of audit information. | Second part (AL11 to AL15) | AL12 | A SHA-256 chain and a signed daily digest. |
| V-222508 | Application audit tools must be cryptographically hashed. | Met before 053 |  | Migrations carry SHA-256 fingerprints (db/manifest.json, schema_migrations); function digests are checked daily. |
| V-222509 | The integrity of the audit tools must be validated by checking the files for changes in the cryptographic hash value. | Met before 053 |  | As above: the daily drift check compares them. |
| V-222512 | The application must audit who makes configuration changes to the application. | Built (053) | AL6 | As V-222455; migrations in change_log name who merged them. |
| V-222547 | The application must allow the use of a temporary password for system logons with an immediate change to a permanent password. | Not applicable |  | No temporary passwords. |
| V-222561 | Applications used for non-local maintenance sessions must audit non-local maintenance and diagnostic sessions for organization-defined auditable events. | Not applicable |  | No non-local maintenance sessions in the application. |
| V-222574 | The application user interface must be either physically or logically separated from data storage and management interfaces. | Not a logging requirement (listed by keyword only) |  | Separation of interfaces: not part of this work. |
| V-222577 | The application must not expose session IDs. | Met before 053 | AL1 | Session IDs are never exposed: the audit log holds a reference, the database only a hash. |
| V-222578 | The application must destroy the session ID value and/or cookie on logoff or browser close. | Met before 053 | AL4 | Sign-out destroys the session; recorded since 053. |
| V-222579 | Applications must use system-generated session identifiers that protect against session fixation. | Met before 053 |  | Sessions are 32 random bytes made by the system. |
| V-222580 | Applications must validate session identifiers. | Met before 053 |  | Sessions are validated against their hash. |
| V-222581 | Applications must not use URL embedded session IDs. | Met before 053 |  | Never in URLs: a secure cookie. |
| V-222582 | The application must not re-use or recycle session IDs. | Met before 053 |  | Never reused. |
| V-222621 | The ISSO must ensure application audit trails are retained for at least 1 year for applications without SAMI data, and 5 years for applications including SAMI data. | Built (053) | AL9 | Kept at least a year; never deleted, also after an account is deleted. |
| V-222622 | The ISSO must review audit trails periodically based on system documentation recommendations or immediately upon system security events. | Second part (AL11 to AL15) | AL15 | A weekly review summary to Aaron, and immediate alerts on security events. |
| V-222672 | The application must generate audit records when concurrent logons from different workstations occur. | Met before 053 |  | The behaviour watch alerts Aaron to many sessions at once; each session is recorded (AL4). |

Sources: NIST SP 800-53 Rev 5 (FedRAMP's control reference, fedramp.gov); DISA Application Security and Development STIG V6 (STIG Manager's list, github.com/NUWCDIVNPT/stig-manager; the rule text at stigviewer.com).
