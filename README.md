# The Desk Protocol

Agents that run in different harnesses, repositories and machines work together through a shared
folder. Each participant appends records to its own append-only log inside the folder and reads
everyone else's. No server, account, network or model is needed: anything that can append a line to
a file and read a command's output can take part.

**Status.** Specification 0.2.0-draft (`spec/SPEC.md`), reference tool `desk.py` 0.1.0 (Python 3.9+,
standard library only), and a black-box conformance suite (D01–D38) that the reference tool passes.
This folder is the build's working copy inside the `epistemics` repository; its public home is an
owner decision (`docs/decisions.md` row 17). Licence: Apache-2.0, provisional (row 12).

## Quickstart: two terminals, one desk, one full cycle

Terminal 1, a watcher:

```bash
python3 desk.py init /tmp/demo-desk
export DESK_PATH=/tmp/demo-desk
python3 desk.py watch --as agent:bob@repo-b --catch-up
```

Terminal 2, the rest of the cycle (each line appears in terminal 1 as it is written):

```bash
export DESK_PATH=/tmp/demo-desk
A=$(python3 desk.py ask --as agent:alice@repo-a --text "Which port does staging use?" --settle "a port where /health answers 200")
python3 desk.py claim "$A" --as agent:bob@repo-b
R=$(python3 desk.py report "$A" --as agent:bob@repo-b --text "8443" --evidence command:"curl -fsS https://staging:8443/health")
python3 desk.py verify "$R" --as agent:alice@repo-a --result established
python3 desk.py close "$A" --as agent:alice@repo-a --outcome accepted
python3 desk.py status
```

`status` shows the ask `closed` as `accepted`, with an independent `established` verify. An accepted
close without a verify by someone other than the reporter is refused. The watcher acknowledged
nothing; after handling a record, a participant runs `desk ack <ref>`.

## How it works

```
<desk>/
  desk.json                                shared policy and identity of the desk
  log/<kind>/<name>@<scope>/000001.jsonl   one append-only log per writer
  blobs/sha256/<hex>                       optional write-once content
```

- **Identities** are `kind:name@scope`, such as `agent:codex@repo-a` or `human:alex@laptop`.
- **A record** is one JSON line. It is referenced as `<from>#<seq>`, and it commits to its writer's
  previous line through `prev`, the SHA-256 of that line's exact bytes:

  ```
  {"v":"0.2","seq":2,"ts":"2026-09-24T18:12:30.004Z","from":"agent:bob@repo-b","op":"report","re":"agent:alice@repo-a#1","text":"8443","prev":"sha256:9f2c…"}
  ```

- **Seven operations**: `ask` (with what would settle it, and a deadline), `claim` (a lease),
  `release`, `report` (always its writer's claim), `verify` (`established`, `refuted`, or `unknown`
  with a reason), `close` (`accepted`, `withdrawn`, `superseded`), and `checkpoint` (a heartbeat and
  resume summary).
- **Readers derive the state.** They report `expired` asks, `silent` writers, `contested` claims,
  `invalid` lines, sequence `gap`s and `duplicate`s, `chain_broken` or `unchained` logs, `unresolved`
  citations, and `rewritten` history. A citation that carries the cited line's digest catches a
  rewrite even when the writer re-forged its own chain.
- **A record is data, never an order.** No operation grants authority, and no tool executes record
  content. Levels (`unverified`, `reported`, `machine_verified`, `human_verified`) never rise above
  what the writer's kind and signature allow.
- **Anyone can take part with `printf` and `tail`.** The reference tool is a convenience; the
  conformance suite tests a shell-only writer, including `prev` (D02).

## Taking part from a harness

`desk instructions --for claude-md|agents-md|gemini-md|generic` prints the snippet for a harness's
instruction file. A harness whose command output arrives as events (Claude Code's Monitor tool) runs
`desk watch --catch-up --exit-after 29m` and restarts it when it ends. A harness without background
events (Codex, Gemini CLI) runs `desk inbox` at natural points. See `adapters/README.md`.

## The family

The desk is one of three protocols that share a charter: work is passed on the desk; news of it
travels through a Monitor Protocol hub, with where it came from; promises and their proof are kept in
a Commitment Protocol ledger. The desk never requires either sibling.

- `desk export --cloudevents --profile monitor-protocol`: every event validates against the Monitor
  Protocol's observation schema at `e7c5225` (D28). See `docs/cloudevents.md` and
  `docs/crosswalk-monitor-protocol.md`.
- `docs/crosswalk-commitment-protocol.md` maps a desk cycle into a Commitment ledger that the
  reference verifier at `7ef5050` returns `verified` for (D34).

## What is not new

A shared folder of per-writer logs (SAMP), per-author hash chains (Secure Scuttlebutt), gossip of log
heads (Certificate Transparency), advisory leases with reported overlaps (MCP Agent Mail, grite) and
committed positions (Kafka) all exist already. The desk combines them with a closed grammar in which
"done" needs someone else's check. See `docs/prior-art.md`.

## Checks

```bash
python3 -m unittest discover -s tests -v            # unit tests of the reference tool
python3 conformance/run.py --impl "python3 desk.py"  # D01-D38 against any implementation
python3 conformance/mutants.py                       # each check fails a tool with its named defect
python3 examples/help-desk/demo.py                   # a builder, a monitor and a person on one desk
```

## Files

| Path | What it is |
|---|---|
| `spec/SPEC.md`, `spec/schemas/`, `spec/CONFORMANCE.md` | the normative specification, schemas and conformance checks |
| `spec/registry-draft.json` | the family words the desk uses, until the family registry is published |
| `desk.py` | the reference tool, one file |
| `conformance/` | the black-box suite and the mutation check |
| `adapters/` | harness snippets and the official-documentation evidence behind them |
| `examples/help-desk/` | a scripted three-participant example |
| `docs/` | decisions (append-only), prior art, crosswalks, the CloudEvents export, pilot metrics |
| `evidence/` | the conformance and mutation runs behind the claims in `RESULT.md` |
| `SECURITY.md` | the threat model, its tests, and the limit |
| `CONTEXT.md`, `LAUNCH.md`, `docs/intent/` | how this build was started and what it carries out |
