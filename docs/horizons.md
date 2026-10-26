# Horizons: what a desk may decide, and what it hands on

*Informative. How the family's horizon principle applies to a desk. Nothing here changes the
normative specification; the proposal at the end would need a decision row and a spec change.*

## The principle

A horizon is a responsibility of interpretation, not a schedule. A daily view asks what changed and
what needs attention; a monthly view looks for patterns no single day shows; a yearly view asks
whether those patterns change the assumptions the work rests on. A participant with a slow horizon may
react today when something questions an important assumption: its horizon decides which consequences
it weighs, not how long it must wait. The Monitor Protocol states the authority rule: "A faster
horizon never writes what a slower one owns" (its P8), and "urgency does not confer that authority on
the observing worker".

## Where a desk sits

A desk passes work. Its records live at the event and day horizons:

| Horizon | What it owns on or around a desk | Written by |
|---|---|---|
| event | a record: an ask, a claim, a report, a verify, a checkpoint | any participant, for its own work |
| day | a working session's plan and its dispositions: a checkpoint's `next` and `blocked_on`, the close of a work ask | the participants doing the work |
| week or release | the rules of the desk: the specification, the schemas, the registry words, `desk.json` policy and roles, a frozen conformance claim | the maintainers, through decision rows; after a freeze, the owner |
| month and beyond | beliefs and claims about the world: conjectures, verdicts, the family charter | the slower process that owns them (a pre-registered analysis, the charter's owner) |

Three rules follow.

1. **A desk record never writes what a slower horizon owns.** A `verify` is an observation about one
   report against one settle condition. It is not a belief update, and an `accepted` close is a
   disposition of work, not a claim's graduation. A desk record can be evidence for a slower horizon;
   it enters that horizon only through that horizon's own procedure (a citation in a decision row, an
   instrument note, a pre-registered analysis).
2. **A fast participant may raise, not decide.** When something on the desk questions a rule, the
   participant writes an ask addressed to whoever owns the rule, now, with what would settle it. It
   does not change the rule because the matter is urgent. After a freeze (a released specification, a
   handed-off packet), findings become proposed decision rows that wait for the owner's review.
3. **Evidence rises, policy descends.** Records and their citations flow up as evidence; decisions
   flow down as `desk.json` policy and roles, which tools then enforce. Neither direction skips a
   level.

## What a desk already has for this

- **Bounds on silence** (R9, R10): leases and heartbeats make a fast participant's absence visible
  within its own bound, so a slower one never has to guess.
- **Waiting written on the desk** (§8, row 61): a participant that waits on a slower horizon says so
  in a checkpoint's `blocked_on`, where everyone can see what is pending on whom.
- **Roles** (R21): a desk can reserve operations for some identities, for example `close` for people.
- **Levels** (R20): an agent's record never carries a person's level, whatever it claims.

## A proposal for a later version (not normative)

An ask could carry an optional `horizon` (the Monitor Protocol's words: `event`, `minute`, `hour`,
`day`, `week`, `month`), and a role could carry the slowest horizon it may decide. A reader would then
flag a close of an ask by a writer whose role does not reach the ask's horizon, the way it flags
`unpermitted` today. This would let a desk mark "this decision belongs to the owner" mechanically,
instead of by convention. It needs a decision row, a registry change for the word, and a conformance
check; it is additive.
