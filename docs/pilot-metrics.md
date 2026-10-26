# Pilot metrics

*How `desk stats` supports a two-week pilot, and which count answers which question.*

A pilot answers questions about a desk in use: did it lose requests, did two agents take the same
work, did verification catch false "done" reports, did anyone notice silence. `desk stats` computes
counts from the records, always as of a stated time and always with their denominators
(spec §7.4). What the records cannot show is said out loud: `stats` carries an `unknown` list, and
this page names the instrument for each gap.

The file-desk pilot's frozen pre-registration (`paper/file-desk/PREREGISTRATION-2026-09-24.md`,
outcomes O1–O7) is the model; the column "file-desk outcome" maps each question onto it.

## Questions and counts

Run `desk stats --json --as-of <cut-off> --as <reader>` at the pilot's cut-off. Every count below is
a field of that output.

| Question | Count (`stats` field) | Denominator | File-desk outcome |
|---|---|---|---|
| Were requests lost across watcher restarts? | `unacknowledged_by_reader.count`: records by others written at least `older_than_seconds` (default 3600) before the cut-off that this reader never acknowledged | `unacknowledged_by_reader.of_records_by_others` | O1 |
| … and were they handled? | not in the desk; see "What the desk cannot count" | | O1 |
| Did two agents claim the same work? | `duplicate_claims.count`: claims written while another holder's lease on that ask was live; `contested.count`: asks contested at the cut-off | `duplicate_claims.of_claims`; `contested.of_asks` | O2 |
| Did verification catch false "done" reports? | `refuted_reports.count`, and `verifies.by_result.refuted` | `refuted_reports.of_reports`; `verifies.count` | O3a |
| Did asks expire with nobody attending? | `expired.unattended`: asks past their deadline, unclosed, with no live lease at the deadline | `expired.of_asks` (and `expired.count`) | O4 |
| Did writers go quiet? | `silent_intervals.count`: checkpoint gaps longer than the declared heartbeat, plus writers silent at the cut-off | `silent_intervals.writers` | (new in v0.2) |
| Were rewrites detected? | `rewrites_detected.count`: `rewritten` findings (read memory, citations, `seen` heads) | none: any is a finding | O7, with `desk validate` |
| How often did a person have to step in? | `human_steps.count`: records on asks written by a `human:` writer or `on_behalf_of` a person | `human_steps.of_records_on_asks` | O5 (desk part) |
| How long did work take? | `median_seconds_from_ask.{claim,report,verify,close}.median` | `…of_asks_reaching` for each step | (descriptive) |
| Was the record intact? | `desk validate --profile strict` verdict and counts | lines, records, links checked | O7 |

Levels matter when reading verifies: `verifies.by_level` separates agent verifies (`unverified`) from
signed system checks (`machine_verified`) and a person's signed verifies (`human_verified`).

## The caveat that makes one count useless as an outcome

Verify-before-close (R8) makes the share of accepted closes that have a qualifying verify 100% by
construction: a close without one is `unverified_close` and does not count. `accepted_closes` is
therefore a description, not an outcome. The outcome that says whether closures were right is an
**independent reading** of each closed ask: does the cited evidence support the report, judged by
someone who took no part (O3b in the file-desk pre-registration). Run it from `desk show <ask-ref>`
and the files each report cites.

## What the desk cannot count

- **Whether a delivered record was handled.** A desk records what was written, not what a watcher
  did. `unacknowledged_by_reader` is the proxy (a record acknowledged is one its reader says it
  handled); the direct measure is each handler's log of handled references, as conformance check D03
  keeps. `stats` lists this under `unknown`.
- **Owner messages that relayed content between sessions** (O5's chat half) and **re-entry without
  relay** (O6): count them from the harness transcripts.
- **Readers on other machines.** Reader positions live outside the desk (R7), so
  `unacknowledged_by_reader` covers the reader named in `--as`, on the machine that holds its state.

## Pre-register before running

Freeze the questions, the cut-off, the predictions and the falsifiers before the pilot starts, as
the file-desk pre-registration does. A pilot run through this build's own dogfooding desk would have
one builder and one owner, so O2 is near zero by construction and cannot be an outcome there.
