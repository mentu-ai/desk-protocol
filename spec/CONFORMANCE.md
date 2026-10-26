# Conformance, spec 0.2

This document is normative. A tool is conformant when the suite in `conformance/` reports every
check below as PASS, or as SKIP with the reason the check allows. The suite is black-box: it drives
a tool only through the command interface in §2, and it also writes raw lines itself to test the
echo-and-tail path.

## 1. Report format

Family format (registry `conformance_report`): a table with one row per check (id, rule, result),
where the result is PASS, FAIL, or SKIP with a reason, plus the date, the suite version, the
implementation command and the commit tested.

```
python3 conformance/run.py --impl "python3 desk.py" [--only D01,D05] [--json report.json]
                           [--monitor .siblings/monitor-protocol] [--commitment .siblings/commitment-protocol]
```

`DESK_IMPL` may replace `--impl`. The suite creates every desk, state directory and file it uses in
a temporary directory, and removes nothing else.

## 2. Command interface

The suite runs `<impl> <command> [arguments]`. The interface below is what a tool must offer to be
tested; a tool may offer more.

**Options every command accepts.** `--desk <path>` (else `DESK_PATH`), `--as <identity>` (else
`DESK_ID`; read commands accept it quietly, D35), `--state-dir <dir>` (the base of reader state,
else `DESK_STATE_DIR`), and `--json` (one JSON document on stdout). Times are RFC 3339 UTC.
Durations are seconds, optionally with a suffix `s`, `m` or `h`.

**Exit codes.**

| Code | Meaning |
|---|---|
| 0 | ok, or `verified` |
| 1 | `failed` (also: the named record does not exist) |
| 2 | `incomplete` |
| 3 | refused by policy: the record would be invalid, or breaks the desk's policy (R8, R12, R16, R18, R21, §9) |
| 4 | identity locked (R2) |
| 5 | invalid desk (no or malformed `desk.json`, or an unsafe layout such as a symlinked log directory) |
| 64 | usage error (unknown command or option, missing argument, malformed identity or reference) |

**Write commands.** Each appends one record as `--as`, fills `v`, `seq`, `ts`, `from` and `prev`,
and with `--json` prints `{"ref": "<from>#<seq>", "digest": "sha256:…", "record": {…}}`. Without
`--json` it prints the reference.

| Command | Arguments |
|---|---|
| `init <path>` | `[--name <text>]`; creates `desk.json` and `log/`; prints `{"desk": {"id", "path"}}` with `--json` |
| `ask` | `--text <t> --settle <s> [--by <time>] [--to <identity or role:name or *>]` |
| `claim <ask-ref>` | `[--lease <seconds>]` |
| `release <claim-ref>` | `--reason <r>` |
| `report <ask-ref>` | `--text <t> [--evidence <kind>:<ref>]...` |
| `verify <report-ref>` | `--result established\|refuted\|unknown [--reason <r>] [--evidence <kind>:<ref>]...`; the tool cites the report with its digest |
| `close <ask-ref>` | `--outcome accepted\|withdrawn\|superseded [--reason <r>] [--verify <ref>]`; for `accepted` the tool cites the qualifying verify with its digest |
| `checkpoint` | `[--next <t>] [--heartbeat <seconds>] [--no-seen]`; by default lists `seen` heads |
| `append` | one JSON object on stdin; the tool fills the missing envelope fields and refuses a `from` other than `--as` |
| any write | `[--supersedes <ref> --reason <r>] [--on-behalf-of <human identity>] [--to <addressee>]` |

`--evidence` splits at the first colon: `file:/tmp/x.log`, `record:agent:b@t#2`, `url:https://…`.

**Read commands.**

| Command | `--json` output (the fields the suite reads) |
|---|---|
| `status [--as-of <time>]` | `{"as_of", "asks": [ask], "writers": [writer], "findings": [finding], "gaps": [word], "ignored": [ref]}` |
| `show <ref>` | `{"ref", "record", "line", "digest", "level", "flags": [word], "thread", "on_behalf_of", "evidence": [{"kind", "ref", "flag"}], "superseded_by"}` |
| `inbox [--all]` | `{"items": [{"ref", "op", "from", "why": [word]}], "other_unacknowledged": n}` |
| `validate [--profile default\|strict]` | `{"verdict", "profile", "counts": {…}, "findings": [finding]}`; the exit code follows the verdict |
| `stats [--as-of <time>]` | counts, each with its denominator |
| `export --cloudevents [--profile monitor-protocol]` | a JSON array of CloudEvents (always JSON) |
| `instructions --for agents-md\|claude-md\|gemini-md\|generic` | text |

- `ask` = `{"ref" (root), "current", "state", "to", "deadline", "holder", "live_claims": [ref],
  "verify": {"ref", "result", "level", "independent"} or null, "close": {"ref", "outcome"} or null,
  "flags": [word]}`.
- `writer` = `{"identity", "records", "last_seq", "last_checkpoint", "heartbeat_seconds", "silent",
  "chain", "gaps": [[first, last]], "duplicates": [seq], "rewritten"}`.
- `finding` = `{"flag", "subject", "detail"}`, where `flag` is a registry flag and `subject` is a
  reference, an identity, or `<path relative to the desk>:<line number>` for a line with no usable
  reference. A witness finding names the witness in `detail`.
- `why` words: `to_me`, `to_role`, `cites_mine`, `thread`, `open_ask`, `waiting`.

**Position commands.** `watch [--catch-up] [--exit-after <duration>] [--poll <duration>]
[--format line|json] [--to-me] [--ops <op,op>] [--max-width <n>]`. In `json` format each line is one
object: `{"type": "record", "ref", "op", "from", "ts", "record"}`, `{"type": "flag", "flag",
"subject", "detail", "time"}`, or `{"type": "watch", "event": "start"|"end", "time"}`.
`ack <ref>`, `ack --upto <ref>` and `seek <identity> <seq> --reason <r>` print
`{"writer", "position"}` with `--json`. `ack <ref>` exits 3 when an earlier record of that writer is
unacknowledged (§8 of the spec).

## 3. Checks

Each check names the rule it tests. "Raw" means the suite writes the line itself, chaining `prev`
where the check needs it. Times in checks that test a boundary use `--as-of` and raw lines with
chosen `ts`, so no check depends on the machine's speed.

| Check | Rule | What the suite does, and what passes |
|---|---|---|
| D01 | §5, R8, §7.2 | A asks, B claims, B reports, C verifies `established`, A closes `accepted`. Status: state `closed`, outcome `accepted`, verify `established` and independent, every level `unverified` (agents), no finding. |
| D02 | P9, R16 | A shell writer appends an ask and a checkpoint with `printf`, computing `prev` with `tail -n 1 \| tr -d '\n' \| shasum -a 256` (or `sha256sum`). `validate` returns `verified`, and status shows the ask. SKIP without a POSIX shell. |
| D03 | R7 | A writer appends 1,000 records while a watcher (`watch --catch-up --format json`) is killed at random points, at least 20 times, and restarted. The handler records each reference idempotently, then acknowledges it. Passes when all 1,000 are handled, each exactly once, with no acknowledgment before handling. |
| D04 | R4 | A record without its `\n` is not shown by status or watch; once completed it is. |
| D05 | R4, P14 | A malformed line is reported as `invalid` with its raw bytes quoted in `detail`; the record after it is read and delivered. |
| D06 | R5 | Raw `seq` 1, 3, 3: a `gap` (2) and a `duplicate` (3) are reported for that writer. |
| D07 | R2 | While the suite holds the writer's lock, a write exits 4 and appends nothing. `append` with another `from` exits 3. A raw line in one writer's log naming another writer is `invalid`. |
| D08 | R9 | Two holders' live claims make the ask `contested`; the holder is the earlier claim, deterministically. |
| D09 | R9 | A claim with a 60 s lease at `T` is live `--as-of T+60s` and expired at `T+60.001s`; a renewal by the holder at `T+30s` moves the expiry to `T+90s`. |
| D10 | R8 | The tool refuses an accepted close with no qualifying verify (exit 3, nothing written); a raw one raises `unverified_close` and the ask is not closed. |
| D11 | R8, P7 | A verify by the report's own writer is not independent; the tool refuses an accepted close citing it. |
| D12 | P8, §5 | A verify `unknown` without a reason is refused (exit 3); with one, the ask is `verified` with result `unknown`, is not closed, and cannot be closed as accepted. |
| D13 | R10 | An ask is `expired` one second after its deadline and not one second before. |
| D14 | R10 | A writer with `heartbeat_seconds` 60 is `silent` 61 s after its checkpoint and not 59 s after. |
| D15 | R18, R1 | A superseding ask replaces the original in status (one thread, new text); the original line is still in the log and `show` names its successor. |
| D16 | R11 | A raw record with an unknown field and one with an unknown operation: `validate` is `verified` and counts one ignored record; the unknown field survives in `show`. |
| D17 | R6, P4 | Records whose text, settle, evidence and reason carry shell commands that would create a canary file, plus ANSI escapes: after every read command runs, no canary exists and no raw escape byte appears in line output. |
| D18 | R12 | An oversized record is refused (exit 3, nothing written). A likely secret is written with a warning under `secrets: warn` and refused under `secrets: refuse`. |
| D19 | §9 | Under `signing: required`, a raw unsigned record and a raw record with a bad signature are `invalid`; a record the suite signs correctly is accepted and, from a `human` member's verify, reaches `human_verified`. SKIP without `ssh-keygen -Y`. |
| D20 | §11, P2 | Two clones of one desk exchange records through git for 100 rounds; no merge conflicts, and the merged desk validates. SKIP without git. |
| D21 | R17, R14 | A report citing a missing file, a verify citing a missing record and a close citing a missing verify: each citation is `unresolved`, and the ask is not closed. |
| D22 | R14 | A symlinked writer directory and a symlinked segment are `invalid` and not read; a write through a symlinked log directory exits 5. SKIP where the suite cannot create symlinks. |
| D23 | R15 | After a read as a participant, editing an already-read line in place, or truncating it, is reported as `rewritten` on the next read and on every read after, until `seek`. |
| D24 | R16 | A broken `prev` is `chain_broken`. A missing `prev` is `unchained` under `warn`; under `required` the tool refuses to write it and readers exclude a raw one. |
| D25 | R17 | After C's verify cites B's report with its digest, rewriting that report and re-forging B's chain so every link checks is still reported as `rewritten`, witnessed by C's verify. |
| D26 | R17 | After C's checkpoint lists B's head in `seen`, rewriting that uncited record is reported as `rewritten`, witnessed by the checkpoint. |
| D27 | R7 | After `ack --upto` of B's `#3`, the next delivery from B is `#4`, never `#3` and never `#5`. `ack` of `#5` while `#4` is unacknowledged exits 3. Re-acknowledging `#3` changes nothing. |
| D28 | §12 | Every event of `export --cloudevents --profile monitor-protocol` over a sample desk (all seven operations, a signed and an unsigned writer of each kind, a rejected line) validates against the Monitor Protocol's `schemas/observation.json` at a pinned commit with that repository's validator; no value exceeds its ceilings; `source` is a URI reference and `time` a timestamp. SKIP when that repository or Node.js is unavailable. |
| D29 | §3 | Malformed identities are refused (exit 64); aliases are normalized; logs live at `log/<kind>/<name>@<scope>/`; no path under the desk contains a colon. |
| D30 | R18 | A supersede without a reason is refused (exit 3); a raw one is `invalid` and changes nothing. |
| D31 | R19, R20 | An agent's record `on_behalf_of` a person stays `unverified`, with both identities shown, even when the agent's record is signed. |
| D32 | R21 | With roles that do not let agents close, an agent's raw close is `unpermitted` and the ask's state is unchanged; the tool refuses it (exit 3). |
| D33 | §7.5 | A clean desk is `verified` (exit 0); an `unchained` record makes it `incomplete` (exit 2) under `default` and `failed` (exit 1) under `strict`; a `chain_broken` record fails both. Counts are present. |
| D34 | §12 | The fixture in `docs/crosswalk-commitment-protocol.md` bridges a full cycle, exported by the tool, into a Commitment ledger; that protocol's reference verifier at a pinned commit returns `verified`; every `source_key` is unique; a second bridge adds no rows. SKIP when that repository is unavailable. |
| D35 | CONTEXT §3 lesson 1 | `show`, `status`, `validate`, `stats` and `export` accept `--as` without error. |
| D36 | §8, Monitor P12 | `inbox` lists records addressed to the reader, to its role, citing its records, in its threads, and open asks to `*`; it leaves out and counts the rest; `ack --upto` clears them. |
| D37 | §13 | Every flag, level, outcome and gap word the tool printed during the run is in `spec/registry-draft.json`. |
| D38 | §8 | A reader that waits on someone else writes a checkpoint naming the ask in `blocked_on`, then acknowledges it: `watch --catch-up` no longer re-delivers it, `inbox` keeps listing it as `waiting`, a new record on its thread is listed as `thread`, and once the ask is closed it is no longer waiting. |

## 4. Rigor

Every negative check has a positive control in the same check (the unmodified desk passes before the
defect is introduced). `conformance/mutants.py` reintroduces named defects into a copy of the
reference tool and confirms that the check named after each one fails; a suite that cannot fail a
wrong implementation is decorative (Monitor Protocol, 05-conformance).
