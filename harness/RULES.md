# Harness rules

Seven rules that keep the work on the North Star. They don't replace the charter; they say how to apply it so the work ships. `npm run harness` checks the ones a script can check, at the start of every session.

1. **Ship to main.** Every pull request targets `main`. Never stack one on another branch. Work that isn't on main isn't done, and work older than 2 days that isn't on main is flagged.
   *Why: on Oct 19 and Oct 22, stacked PRs (#33, #34, #35) were merged into side branches and nothing reached the site.*
2. **Requirement gate (Musk, steps 1 and 2).** Before building anything, name its owner: Aaron's words with a date, or a standing decision in CHARTER section 2. No owner means it goes on the parking list in FACTS.md, not into the code. Delete before you simplify, simplify before you speed up, speed up before you automate.
   *Why: "in case" work (extra checks, extra reviews, extra fixes) kept pushing the launch away.*
3. **Know or say you don't.** Every claim about a live system (GitHub, Vercel, Supabase, the site) is either checked in this session, with the check shown, or labelled "not checked". Never fill a gap with a guess.
   *Why: on Oct 22 Claude said terms didn't exist (they did, in Aaron's doc) and that Vercel access was never granted (unknown).*
4. **Facts survive sessions.** When Aaron decides something or a fact is confirmed, write it in harness/FACTS.md in the same turn, with the date and the source. Summaries lose things; the repository doesn't.
   *Why: summaries dropped that the GitHub sign-in keys were already in Vercel and that the terms were approved.*
5. **Ask once, sharply.** At most one decision question per reply, asked once, recorded in FACTS.md. Don't re-ask a question Aaron answered; check FACTS.md first.
6. **Review in proportion.** A fresh-agent review is for changes that are hard to undo, touch security, money or people's data, or will be announced. Launch steps of already-reviewed work get the tests and one look, not three reviews.
7. **The stop list doesn't move.** Claude never handles secrets, creates accounts, spends money, accepts terms, merges, or makes the go-live decision. Those are Aaron's, and asking for them is never an excuse to stall the rest.
