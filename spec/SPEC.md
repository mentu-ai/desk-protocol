# The Desk Protocol

**Version 0.2.0-draft.** Status: draft for review. Licence: Apache-2.0 (provisional; decision 12).

The key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL
are to be read as described in RFC 2119 and RFC 8174 when, and only when, they appear in capitals.

A **desk** is a directory through which participants (agents, people, services) coordinate work.
Each participant appends records to its own append-only log inside the desk and reads everyone
else's. A **writer** is a participant appending records; a **reader** is any program that reads a
desk; a **tool** is an implementation of this specification. The rule numbers (R1 to R21) and the
conformance checks (D01 to D38, in `CONFORMANCE.md`) cite each other. Decisions and their sources
are in `docs/decisions.md`; family words are in `spec/registry-draft.json`.

## 1. Principles

These are normative. Each rule below serves one or more of them.

1. **A folder is the whole protocol.** The core needs no server, account, network, database or model.
2. **One writer per log.** Only the owner of an identity appends to that identity's log.
3. **Append-only.** Nothing is edited or deleted. A correction is a new record that supersedes the old one and says why.
4. **A record is data, never an order.** No operation grants authority, and no tool executes record content.
5. **Acknowledge after handling, not after printing.** Readers keep their positions outside the desk and advance them only after handling.
6. **Silence means something only within a bound.** Asks carry deadlines and writers declare heartbeats. Readers say `expired` and `silent` out loud.
7. **Filled is not earned.** A report is its writer's claim. "Done" requires a verify, by default from someone other than the reporter.
8. **Unknown is an answer.** It carries a reason, and when possible what would settle it.
9. **Echo and tail stay enough.** Appending one well-formed line and reading files is a complete way to take part.
10. **Neutral.** Model-agnostic, harness-agnostic, vendor-neutral.
11. **Configurable and explained.** Every default is documented, can be overridden, and a tool can say where each effective setting came from.
12. **Adopt before inventing.** CloudEvents at the edges, RFC 8785 for canonical JSON, Kubernetes Lease fields for leases, Kafka's committed position for reader positions.
13. **Where it cannot verify, it discloses.** A reader never presents a record as more certain than its writer could make it.
14. **Nothing is dropped silently.** A malformed or refused line is kept, reported and shown.
15. **Family words.** Identities, references, outcomes, levels and flags use the family registry's words.

## 2. Layout

```
<desk>/
  desk.json                                shared policy and identity of the desk (§10.1)
  log/<kind>/<name>@<scope>/000001.jsonl   one directory per writer; segments numbered from 000001
  log/<kind>/<name>@<scope>/.lock          the writer's lock file (R2); never read as data
  blobs/sha256/<hex>                       optional write-once content, named by its SHA-256
```

- Segment files are named with six decimal digits and the suffix `.jsonl`. A writer appends only to
  its highest-numbered segment and MAY start the next one at any time. `seq` and `prev` continue
  across segments. Readers read a writer's segments in numeric order as one sequence of lines.
- Readers MUST ignore entries whose names begin with `.` anywhere under `log/`. Readers MUST report
  every other unexpected entry (a kind directory other than `human`, `agent` or `system`, a writer
  directory whose name is not a valid `name@scope`, a file that is not a segment, a file-sync
  conflict copy) as `invalid`, and MUST NOT read it as records.
- A tool that creates a desk SHOULD also write a `.gitignore` containing `.lock`, for the git carrier.
- **Reader state** (positions, read memory, caches) never lives inside the desk. Its default base
  is `$XDG_STATE_HOME/desk/` on Linux (`~/.local/state/desk/` when unset),
  `~/Library/Application Support/desk/` on macOS and `%LOCALAPPDATA%\desk\` on Windows, followed by
  `<desk-id>/`. `DESK_STATE_DIR` replaces the base.

## 3. Identity

```
identity = kind ":" name "@" scope
kind     = "human" / "agent" / "system"
name     = scope = [a-z0-9] *[a-z0-9._+-]        ; "name@scope" is at most 64 characters
```

- `system` covers services, CI jobs, webhooks and probes. Examples: `agent:codex@repo-a`,
  `human:alex@laptop`, `system:ci@repo-a`.
- On disk the colon becomes a directory level: `log/agent/codex@repo-a/`. No path contains a colon.
- Tools SHOULD accept the family aliases on input and MUST write only canonical identities: `user:`
  reads as `human:`; `hook:`, `webhook:` and `probe:` read as `system:`; a bare `a@b.c` reads as
  `human:a@b.c`. Uppercase input is lowercased. A tool MUST refuse any other malformed identity.
- A participant's `harness` label is informational and MUST NOT decide what anyone may do.
- Only one live process may write under an identity (R2).

## 4. Records and references

A record is one JSON object on one line, UTF-8, ending with `\n`:

```
{"v":"0.2","seq":41,"ts":"2026-09-24T18:12:04.120Z","from":"agent:codex@repo-a","op":"ask","to":"*","text":"Which base URL should staging tests use?","settle":"a base URL whose /health answers 200 from the staging runner","by":"2026-09-24T19:00:00Z","prev":"sha256:9f2c…"}
```

**References.** Inside a desk a record is referenced as `<from>#<seq>`, for example
`agent:codex@repo-a#41`. Outside a desk the same record is `{source, id}` with
`source` = `desk:<desk-id>/<kind>/<name>@<scope>` and `id` = the decimal `seq`; its string form is
`<source>#<id>`. Digests are written `sha256:<64 lowercase hex>`. The digest of a record is the
SHA-256 of the exact bytes of its line without the `\n`.

| Field | Required | Meaning |
|---|---|---|
| `v` | yes | spec version, `"0.2"` (readers accept `0.<n>`) |
| `seq` | yes | integer; 1 for a writer's first record, then +1 per record |
| `ts` | yes | the writer's clock, UTC, exactly `YYYY-MM-DDTHH:MM:SS.mmmZ` |
| `from` | yes | the writer's identity; MUST equal the log directory's identity |
| `op` | yes | an operation (§5) |
| `to` | no | an identity, `role:<name>`, or `*` (the default) |
| `re` | by operation | the reference of the record this one is about |
| `text` | by operation | human-readable content |
| `settle` | `ask` | the observation that would settle the ask |
| `by` | no | deadline, RFC 3339 UTC (`Z`), fractional seconds optional |
| `lease_duration_seconds` | no | integer ≥ 1, on `claim`; the policy default applies when absent |
| `evidence` | no | list of evidence items (below) |
| `result` | `verify` | `established`, `refuted` or `unknown` |
| `reason` | see §5 | why; a non-empty string |
| `outcome` | `close` | `accepted`, `withdrawn` or `superseded` |
| `state` | `checkpoint` | resume summary (below) |
| `supersedes` | no | reference of an earlier record by the same writer and operation that this one corrects; requires `reason` |
| `on_behalf_of` | no | a `human:` identity this writer acts for (R19) |
| `prev` | by policy (R16) | `sha256:<hex>` of the writer's previous line |
| `ext` | no | object; extension keys in reverse-DNS form (`org.example.field`) |
| `sig` | no | signature (§9) |

**Evidence item:** `{kind, ref, digest?, observed_at?}`. Kinds: `file`, `url`, `command`,
`commit`, `record`, `event`, `blob`, `note`. A `record` ref is an in-desk reference; a `blob` ref is
a digest; an `event` ref is a foreign `<source>#<id>` string; a `file` ref is an absolute path or a
path relative to the desk directory.

**Checkpoint state:** `{established?: [string], unknown?: [{what, reason, settle?}], next?: string,
blocked_on?: [string], heartbeat_seconds?: integer ≥ 1, seen?: {<identity>: {seq, digest}}}`.

`spec/schemas/record.schema.json` is normative for the shape of a record. A line that fails it is
`invalid` (R4). Unknown top-level fields are allowed and preserved (R11). Timestamps MUST denote a
real instant; a reader treats one that does not (month 13, second 61) as a schema failure.

## 5. Operations

| Operation | Requires | Meaning |
|---|---|---|
| `ask` | `text`, `settle` | A need or a question. `by` gives its deadline. |
| `claim` | `re` → an ask | "I am working on it" until the lease ends (R9). A new claim by the current holder renews it. |
| `release` | `re` → the writer's own claim; `reason` | Gives the claim up, with a reason or handoff note. |
| `report` | `re` → an ask; `text` | Progress or an answer, with evidence where possible. Always a claim by its writer. |
| `verify` | `re` → a report; `result`; `reason` unless `established` | Checks the report against the ask's `settle`. |
| `close` | `re` → an ask; `outcome`; `reason` unless `accepted` | Ends the ask. `accepted` requires a qualifying verify (R8), cited in `evidence`. |
| `checkpoint` | `state` | A heartbeat plus a resume summary of the writer's own work. |

The vocabulary is closed. A tool MUST refuse to write an operation, field value or evidence kind
this version does not define. Readers preserve and ignore unknown operations (R11). A new
operation or value is a spec change with a decision row.

## 6. Rules

- **R1. Append-only.** Writers never modify or remove bytes already written.
- **R2. One writer.** A writer appends only under its own log directory. While it writes, it holds an
  exclusive advisory lock on `log/<kind>/<name>@<scope>/.lock`: `flock(LOCK_EX)` on POSIX systems,
  a lock on the file's first byte (`LockFileEx` or `_locking`) on Windows. A tool that cannot take
  the lock within a bounded wait MUST fail with exit code 4 and write nothing. A tool MUST refuse to
  append a record whose `from` is not its own identity.
- **R3. Atomic lines.** Each record is written with a single write that ends in `\n`, then flushed;
  `fsync` is on by default. Before appending, a writer that finds its log ending without `\n`
  (a torn write) MUST first append a single `\n`, which turns the fragment into a visible `invalid`
  line; it MUST NOT truncate it.
- **R4. Complete lines only.** Readers consume only complete lines; a trailing partial line waits
  for the next read. A complete line that is not a well-formed record (not UTF-8 JSON, not an
  object, fails the schema, `from` differs from its directory, longer than `max_record_bytes`) is
  reported as `invalid` with its raw bytes shown quoted and truncated. It never stops the reader and
  is never dropped from view. A partial line already longer than `max_record_bytes` is reported as
  `invalid` too, because it can never become a record.
- **R5. Sequence.** Per writer, in line order: a record whose `seq` is above the next expected value
  is preceded by a `gap`; a record whose `seq` is not above every `seq` already seen from that writer
  is a `duplicate`. A duplicate is reported and excluded from derived state, so every reference
  names at most one record. Readers never renumber.
- **R6. Data, not authority.** No tool executes or evaluates record content or passes it to a shell
  or interpreter. Displayed content is quoted, attributed to its writer, and escapes control and
  format characters (Unicode categories Cc, Cf, Cs, Co, Cn, Zl, Zp).
- **R7. Committed position.** For each other writer's log, a reader keeps a committed position: the
  next `seq` to deliver (Kafka's committed position). An acknowledgment is cumulative within one
  writer's log, is written only after handling, and never moves backwards. Going backwards is an
  explicit `seek` with a reason recorded in the reader's state. A watcher resumes from its committed
  positions after any restart. Delivery is at least once; handling is idempotent by reference. A
  reader's own records are never delivered to it.
- **R8. Verify before close.** By default an `accepted` close qualifies only if its `evidence` cites
  (kind `record`) a verify that is effective (§7.1), has result `established`, refers to an effective
  report on the same ask, and was written by an identity other than that report's writer
  (`independent_verify`). A cited digest, when present, MUST match. A tool refuses a close that does
  not qualify; readers flag one appended by hand as `unverified_close` and do not treat the ask as
  closed. `close_requires_verify: false` lifts the verify requirement; `independent_verify: false`
  lifts only the independence requirement.
- **R9. Leases.** A holder's claim holds its ask until now is past `renew_time + duration`, where
  `renew_time` is the `ts` of the holder's latest claim on that ask and `duration` is that claim's
  `lease_duration_seconds` or the policy default. At exactly `renew_time + duration` the lease is
  still held. A `release` by the holder, later in its log than its latest claim, ends the hold. A
  holder SHOULD renew at no more than half the duration. If two or more holders' leases are live,
  the ask is `contested` and the holder is the one whose current hold began earliest, ordered by the
  `ts` of the claim that began it, then `from`, then `seq`. Claims are advisory and never prove
  exclusive control of the work. Expiry compares the holder's `ts` with the reader's clock, so readers
  whose clocks disagree can disagree near the boundary; writers SHOULD keep their clocks synchronized.
- **R10. Silence.** An ask whose deadline has passed and that is not closed is `expired`. The
  deadline is the current version's `by`, or its `ts` plus `default_deadline_seconds`. A writer is
  `silent` when now is past `T + H`, where `T` is the `ts` of its latest effective checkpoint (or of
  its first record, if it has none) and `H` is that checkpoint's `heartbeat_seconds` (or the policy
  default). Readers show `expired`, `silent` and `unknown` explicitly, never as "nothing happened".
- **R11. Forward compatibility.** Unknown fields and unknown operations are preserved and otherwise
  ignored. A record with an unknown operation is valid, takes part in sequence and chain checks, has
  no effect on derived state, and is counted as ignored.
- **R12. Size and secrets.** A tool refuses a record whose line (without `\n`) exceeds
  `max_record_bytes`; large content goes to `blobs/sha256/<hex>`, cited as evidence of kind `blob`.
  Tools scan text they write for likely secrets and warn (`secrets: warn`) or refuse
  (`secrets: refuse`). Removing a leaked secret means rewriting history everywhere the desk was
  carried; say so to users.
- **R13. Order.** Timestamps order records only within one writer. Across writers, causality is
  carried by `re` and by citations. Where this specification orders records across writers (R9, §7)
  it does so only to be deterministic.
- **R14. No following.** Readers never follow symbolic links inside `log/` (a link is `invalid`) and
  never open evidence paths automatically. They MAY test whether a `file` evidence path exists
  without following links.
- **R15. Read memory.** A reader remembers, per segment, how many bytes of complete lines it has read
  and the SHA-256 of those bytes. If a segment later shrinks, disappears, or its remembered prefix
  hashes differently, the reader reports the writer as `rewritten`, keeps the old memory, and keeps
  reporting it until the participant re-baselines with an explicit `seek` (§8).
- **R16. Chain.** Every record except the first line of its writer's log carries `prev`: the digest
  of the exact bytes of the writer's previous line (whether or not that line is a valid record). A
  shell can compute it: `tail -n 1 <segment> | tr -d '\n' | shasum -a 256`. Readers verify every
  link and report `chain_broken` on a mismatch, and on a first line that carries `prev`. The `chain`
  policy decides what a missing `prev` means: `off`, ignored; `warn` (default), reported as
  `unchained`; `required`, the tool refuses to write it and readers refuse the record (it is reported
  as `unchained` and excluded from derived state).
- **R17. Citations are witnesses.** Evidence of kind `record` SHOULD carry the `digest` of the cited
  line. Readers verify it: a mismatch is `rewritten` (naming the witness), and a missing target is
  `unresolved`. Each `seen` entry in a checkpoint is a witness in the same way. Because each line
  commits to its predecessor, one matching citation pins the cited writer's history up to it. A
  writer's newest records stay unwitnessed until someone cites them or lists them in `seen`.
- **R18. Corrections.** `supersedes` names an earlier record (lower `seq`) by the same writer with the
  same operation, and requires `reason`. The superseding record takes the place of the original in
  derived state (§7.1); the original stays in the log. A tool refuses a supersede without a reason;
  readers report one appended by hand as `invalid`, and one naming another writer, another operation
  or a later record as `invalid`. A supersede whose target is absent is `unresolved`.
- **R19. Acting for someone.** `on_behalf_of` names a person the writer acts for. Readers show both
  identities. The record keeps its writer's level (R20); only the person's own signed record carries
  the person's level. When roles are configured, the person named MUST match an actor entry;
  otherwise the record is `unpermitted`.
- **R20. Levels.** Readers derive a level for every record from the family ladder `unverified` <
  `reported` < `machine_verified` < `human_verified`:

  | Writer kind | Unsigned, or signing `off` | Signed with a valid member key (§9) |
  |---|---|---|
  | `agent` | `unverified` | `unverified` |
  | `system` | `reported` | `machine_verified` |
  | `human` | `reported` | `human_verified` for its own `verify` and `close`; `reported` otherwise |

  No field raises a level. `on_behalf_of` never does. A `refuted` result is an outcome and never
  lowers a level.
- **R21. Roles (optional profile).** When `desk.json` defines `roles`, a writer's role is that of the
  first entry in `roles.actors` whose `id` matches its identity (`*` matches any run of characters);
  a writer matching no entry has no role. A record whose operation is not in its role's
  `permissions` (where `"*"` means all), or not in `policy.ops`, is `unpermitted`: it is reported
  and excluded from derived state. Without roles, anyone may perform any operation in `policy.ops`.

## 7. Derived state

Readers compute this state from the records and never store it as truth. Two conformant readers
given the same desk, policy and time compute the same state.

### 7.1 Effective records and threads

- A record is **eligible** if it is valid, not a duplicate, not refused (R16 `required`, §9
  `required`) and not `unpermitted`. It is **superseded** when an eligible record of the same writer
  and operation, with a higher `seq`, names it in `supersedes`. It is **effective** if it is
  eligible and not superseded. Within one writer the current version of a correction chain is its
  highest `seq`.
- The **root** of a record is found by following `supersedes` back to a record that names none.
  References to any version resolve to the root's thread. A **thread** is keyed by the root reference
  of an ask; its content (`to`, `text`, `settle`, `by`) is its current version.
- `re` MUST resolve to an effective record of the kind §5 requires (ask, own claim, report). A `re`
  that does not is `unresolved`, and the record has no effect on the thread.

### 7.2 Per ask, as of time `T`

Evaluate in this order; the first that applies is the state.

1. **`closed`** with its outcome, if a qualifying close exists: `withdrawn` and `superseded` closes
   always qualify; `accepted` closes qualify under R8. With several, the earliest by (`ts`, `from`,
   `seq`) wins. Each accepted close that does not qualify raises `unverified_close`.
2. **`verified`**, if an effective verify refers to an effective report of the thread. The summary
   verify is the first non-empty class of: `established` verifies that meet R8's independence rule;
   `refuted`; `unknown`; other `established` verifies (earliest by `ts`, `from`, `seq` within the
   class). The
   state carries its result, its level (R20) and whether it is independent.
3. **`reported`**, if an effective report refers to the thread.
4. **`claimed`**, if at least one lease is live at `T` (R9).
5. **`open`** otherwise.

Flags on the ask: `expired` (R10), `contested` (R9), `unverified_close` (R8), `unresolved` (a record
on the thread cites evidence or a `seen` head that is absent), `unpermitted` (a record on the thread
was excluded by R21). The holder (R9) and every live claim are reported whatever the state.

### 7.3 Per writer

Last `seq`; record count; last checkpoint; declared `heartbeat_seconds`; whether it is `silent`;
gaps and duplicates; chain status: `chain_broken` if any link fails, else `unchained` if any record
lacks a required `prev` (and `chain` is not `off`), else `chained`; `rewritten` if R15 or a witness
says so.

### 7.4 Statistics

Always stated as of a time and always with denominators: asks; claims; contested asks; reports;
verifies by result and by level; accepted closes, with and without a qualifying verify; expired
asks; silent intervals (a checkpoint arriving more than its predecessor's `heartbeat_seconds` after
it, or a writer silent at `T`); median seconds from ask to first claim, first report, first verify
and close, each over the asks that reached that step. `docs/pilot-metrics.md` maps pilot questions
to these counts.

### 7.5 Validation verdict

`validate` reads the whole desk and returns one verdict under a named profile, with counts, never a
bare "valid". The names follow the Commitment Protocol's verifier.

| Verdict | When | Exit |
|---|---|---|
| `verified` | Every line parses, every chain link checks, every cited digest matches, and nothing below applies. | 0 |
| `incomplete` | Nothing failed, but some records are `unchained` (under `warn`), some citations or `seen` heads are `unresolved`, or a writer has a `gap`. | 2 |
| `failed` | Any `invalid`, `duplicate`, `chain_broken`, `rewritten` or refused record. Under the `strict` profile, also anything that would otherwise be `incomplete`. | 1 |

The counts include at least: lines, records, writers, `invalid`, `duplicate`, gaps, links checked,
`chain_broken`, `unchained`, refused, citations checked, `rewritten`, `unresolved`, and ignored
(unknown operations). State flags (`expired`, `contested`, `silent`, `unverified_close`,
`unpermitted`) are counted but do not change the verdict: they describe the work, not the record.

### 7.6 Gaps

Status output lists what the reader does not know, with registry words: `unattested_origin` when
signing is off or some records are unsigned; `single_actor` when one identity wrote every record;
`independence_unknown` when a verify's writer and its report's writer differ only in scope (R8
counts them as independent; the reader discloses the doubt); `stale_source` when a writer is
`silent`.

## 8. Reader operations

- **Watch.** A watcher prints one line per new record from other writers, in each writer's `seq`
  order from its committed position, and one line per status change (a flag appearing). It never
  acknowledges. With catch-up it first prints the backlog (records at or after the committed
  position); without it, it starts at the current end of each log.
- **Acknowledge.** `ack <ref>` commits the position of the ref's writer to `seq + 1` only when every
  earlier record of that writer is already acknowledged; otherwise it refuses (exit 3), naming the
  unacknowledged records. `ack --upto <ref>` commits cumulatively through `ref`. Acknowledging an
  already acknowledged record succeeds and changes nothing. Acknowledging says the reader has done
  its part for now: it acted, it decided the record needs nothing from it, or it wrote on the desk
  what it is waiting for, with a claim or with a checkpoint whose `blocked_on` names the record. A
  reader SHOULD NOT leave a record unacknowledged only because it waits on someone else: waiting
  belongs on the desk, where a lease or a heartbeat bounds it and others can see it, not in the
  reader's private state. A reader that filters (`--to-me`, `--ops`) acknowledges with `--upto`.
- **Seek.** `seek <identity> <seq> --reason <text>` sets that writer's committed position to `seq`,
  in either direction, re-baselines the read memory (R15) for that writer, and records the reason
  and time in the reader's state.
- **Inbox.** What needs the reader: unacknowledged records whose `to` names the reader or one of its
  roles, that cite one of its records (`re`, `supersedes` or evidence), that belong to one of its
  threads, and unclosed asks addressed to `*`; and, whether acknowledged or not, every unclosed ask
  whose thread the reader's latest checkpoint names in `blocked_on`, marked as waiting. The reader's
  threads are those it wrote in and those it waits on. A `blocked_on` entry names a record when it
  starts with that record's reference, followed by the end of the entry, a space, or a colon. The
  inbox filters by addressing, not by ownership, and counts the other unacknowledged records.

## 9. Signing profile (optional)

- A signature covers the record's RFC 8785 canonical JSON without the `sig` field. It is made with
  `ssh-keygen -Y sign -n desk` and checked with `ssh-keygen -Y verify -n desk -I <from>`, against an
  allowed-signers list built from `desk.json` `members` (`<identity> namespaces="desk" <key>`).
- `sig` holds the base64 body of the armored SSH signature, without the armor lines or line breaks.
- The `signing` policy: `off`, signatures are ignored; `warn`, valid signatures raise levels (R20),
  and an unsigned record or one whose signature does not verify keeps the unsigned level and is
  counted under `unattested_origin`; `required`, readers refuse an unsigned or mis-signed record,
  reporting it as `invalid`, and tools refuse to write one.

## 10. Configuration

### 10.1 `desk.json` (shared)

`spec/schemas/desk.schema.json` is normative. Fields: `id` (a random UUID set at creation, never
changed), `name`, `spec` (`"0.2"`), `members` (`[{identity, keys?: [ssh public key], note?}]`),
`policy`, `roles` (R21), `namespace` (default `desk`; the CloudEvents type prefix), `ext`. An
unknown key or policy key makes the desk invalid (exit 5), because a misspelt policy would
otherwise weaken it silently.

| Policy | Default | Meaning |
|---|---|---|
| `close_requires_verify` | `true` | R8 |
| `independent_verify` | `true` | R8 |
| `default_lease_seconds` | `900` | R9 |
| `default_deadline_seconds` | `14400` | R10 |
| `heartbeat_seconds` | `600` | R10 |
| `max_record_bytes` | `16384` | R4, R12 |
| `chain` | `warn` | R16: `off`, `warn`, `required` |
| `signing` | `off` | §9: `off`, `warn`, `required` |
| `secrets` | `warn` | R12: `off`, `warn`, `refuse` |
| `ops` | all seven | R21: the operations this desk accepts |

### 10.2 Participant settings and precedence

Participant settings are never shared: identity, harness label, desks (paths with aliases), state
directory, watch format and filters, `fsync`, output width. Environment variables: `DESK_PATH` (a
desk path or alias), `DESK_ID` (the participant identity), `DESK_STATE_DIR`, `DESK_CONFIG` (the
participant settings file) and `DESK_FORMAT`. Precedence, highest first: command-line flag,
environment, participant file, `desk.json` policy, built-in default. A tool explains every
effective value and its source on request (`config --explain`).

## 11. Carriers

The record format is fixed; how records travel is not.

- **Folder (core).** One machine, any number of repositories; every participant uses the same
  absolute path.
- **Git.** The desk is a repository. Participants commit and push only their own log directories, so
  merges never conflict. Lock files stay out of the repository.
- **File sync.** The same rule. Conflict copies are reported (§2).
- **Hub.** A bridge publishes records to a Monitor Protocol hub (§12). Documented, not run, in 0.2.
- **Ledger.** A bridge writes the accountable part of a desk into a Commitment Protocol ledger (§12).
  Documented and tested as a mapping, not run as a service, in 0.2.
- **Web mirror.** Any view. Answers written there come back through a participant that appends
  them to its own log with `on_behalf_of` naming the person.

## 12. Crosswalks and the CloudEvents export

**Export.** Each record becomes one CloudEvents 1.0 event in structured JSON:

| Attribute | Value |
|---|---|
| `specversion` | `"1.0"` |
| `id` | `seq`, as a string |
| `source` | `desk:<desk-id>/<kind>/<name>@<scope>` |
| `type` | `<namespace>.<op>` |
| `subject` | the full string reference of the thread's root ask; absent for a checkpoint |
| `time` | `ts` |
| `datacontenttype` | `application/json` |
| `data` | `{record, provenance}`, with `provenance` = `{origin, tier, verification, actor, on_behalf_of?, wasDerivedFrom: [{source, id}], supersedes?: {source, id}}` |

`origin` is the writer's kind; `verification` is the record's level (R20); `actor` is `from`;
`wasDerivedFrom` lists the `re` target and every `record` citation; `tier` follows the next table.
Every other line (`invalid`, `duplicate`, refused or `unpermitted`) becomes an event of type
`<namespace>.rejected`, with `source` = the writer's source plus `/rejected`, `id` = its line number
in the writer's log, and `data` = `{raw, reason, provenance}`, as the Monitor Protocol does for
rejected input (its P2). Nothing is left out of an export silently.

**Profile `monitor-protocol`** adds the Monitor Protocol's extension attributes: `sequence` (`seq`
zero-padded to 20 digits), `origin`, `tier`, `verified` (the level), `horizon` (`event`) and `actor`.
No value may exceed that protocol's origin ceilings, and every event MUST validate against its
`schemas/observation.json` at a pinned commit, checked with its own validator (D28).

| Record | `tier` |
|---|---|
| unsigned, or signing off | `unverified` |
| signed, `system` writer | `measured` |
| signed, `human` writer, its own `verify` or `close` | `src` |
| anything else | `unverified` |

`docs/crosswalk-monitor-protocol.md` and `docs/crosswalk-commitment-protocol.md` give the
operation, identity, level and position mappings. Bridged Commitment signals carry the desk
reference in full string form as `source_key` (a second signal from one record appends `+<op>`), so
bridging twice writes nothing new. A desk record read inside a Commitment-governed run is an input
under that protocol's Invariant 6: the run records its reference, digest and text before using it.

## 13. The family registry

Until the family registry is published (owner decision 3), `spec/registry-draft.json` holds exactly
the words of the family appendix and is marked draft. Every identity kind, outcome, level, flag
and gap word this specification uses MUST appear there; the conformance suite checks it. Once a
registry exists, the draft is replaced by a pinned version.

## 14. Security considerations

Records are data (principle 4, R6), so a desk cannot widen anyone's permissions; adapters present
records as quoted data from other participants. On one machine, file permissions separate writers
only as far as operating-system users do; beyond that, use signing. Levels never rise above the
writer's own (R19, R20). The chain (R16), witnesses (R17), `seen` heads and read memory (R15)
make rewrites visible, with one limit that no construction here removes: **a writer can rewrite its
own newest, uncited records before anyone has read them.** A rewrite becomes visible only after
someone has cited, listed in `seen`, or read what came before it. `SECURITY.md` has the threat
model and its tests.

## 15. Conformance

A conformant tool passes every check in `CONFORMANCE.md` through the command interface defined
there, or reports SKIP with a stated reason where a check allows it. The echo-and-tail path needs no
tool: `CONFORMANCE.md` D02 shows a complete `printf` participation, including `prev`.
