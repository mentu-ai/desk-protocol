# The CloudEvents export

`desk export --cloudevents [--profile monitor-protocol] [--jsonl]` writes every line of a desk as a
CloudEvents 1.0 event in structured JSON: a JSON array by default (the
`application/cloudevents-batch+json` shape), or one event per line with `--jsonl`. The mapping is
normative in `spec/SPEC.md` §12; this page explains it and shows an example.

## Why an export and not native CloudEvents

A desk must stay writable with one `printf` line, and the Monitor Protocol's observation schema
requires eleven attributes plus `data`. CloudEvents at the edges gives interoperability without
making the shell path heavier (family intent §4.5).

## The mapping

| Attribute | Value |
|---|---|
| `specversion` | `"1.0"` |
| `id` | `seq`, as a string |
| `source` | `desk:<desk-id>/<kind>/<name>@<scope>`: one source per writer, so `id` is unique within it |
| `type` | `<namespace>.<op>`, with `namespace` from `desk.json` (default `desk`; owner decision 1) |
| `subject` | the full string reference of the thread's root ask, `desk:<desk-id>/<kind>/<name>@<scope>#<seq>`; absent for a checkpoint |
| `time` | the record's `ts` |
| `datacontenttype` | `application/json` |
| `data.record` | the record exactly as parsed |
| `data.provenance` | `{origin, tier, verification, actor, on_behalf_of?, wasDerivedFrom, supersedes?}` |

- `origin` is the writer's kind; `actor` is `from`; `verification` is the record's level (R20).
- `wasDerivedFrom` lists `{source, id}` for the `re` target and every `record` citation.
- `supersedes` is `{source, id}` of the corrected record; the reason stays in `data.record`.
- `tier` is `unverified` unless the record is signed: `measured` for a signed `system` record, and
  `src` for a person's own signed `verify` or `close`.

**Lines the reader does not accept** (`invalid`, `duplicate`, refused by the chain or signing policy,
or `unpermitted`) become events too, so nothing leaves an export silently: `type`
`<namespace>.rejected`, `source` = the writer's source plus `/rejected`, `id` = the line number in the
writer's log, and `data` = `{raw, reason, location, provenance}`. The separate source keeps each
source's `sequence` strictly increasing, which the Monitor Protocol requires.

## The `monitor-protocol` profile

Adds the Monitor Protocol's extension attributes, so each event is a valid observation:

| Attribute | Value |
|---|---|
| `sequence` | `seq` (or the line number, for a rejected line) zero-padded to 20 digits |
| `origin` | the writer's kind |
| `tier` | as above |
| `verified` | the record's level (`unverified` for a rejected line) |
| `horizon` | `event` |
| `actor` | the writer's identity |

No value exceeds the Monitor Protocol's origin ceilings (`ORIGIN_VERIFICATION_CEILING`,
`ORIGIN_TIER_CEILING`), no human-only value appears on a non-human origin, and the desk never emits
`certified`.

## Example

A verify written by an agent, exported with the profile:

```json
{
 "specversion": "1.0",
 "id": "2",
 "source": "desk:6f5b2084-4435-4181-a968-0875675dde70/agent/codex@repo-a",
 "type": "desk.verify",
 "time": "2026-09-24T20:09:19.130Z",
 "datacontenttype": "application/json",
 "data": {
  "record": {"v": "0.2", "seq": 2, "ts": "2026-09-24T20:09:19.130Z", "from": "agent:codex@repo-a", "op": "verify",
             "re": "agent:claude@monitor#2", "result": "established",
             "evidence": [{"kind": "record", "ref": "agent:claude@monitor#2", "digest": "sha256:beea434c…"}],
             "prev": "sha256:95ffd76b…"},
  "provenance": {"origin": "agent", "tier": "unverified", "verification": "unverified", "actor": "agent:codex@repo-a",
                 "wasDerivedFrom": [{"source": "desk:6f5b2084-4435-4181-a968-0875675dde70/agent/claude@monitor", "id": "2"}]}
 },
 "subject": "desk:6f5b2084-4435-4181-a968-0875675dde70/agent/codex@repo-a#1",
 "sequence": "00000000000000000002",
 "origin": "agent", "tier": "unverified", "verified": "unverified", "horizon": "event", "actor": "agent:codex@repo-a"
}
```

## How D28 checks it

Conformance check D28 builds a sample desk with all seven operations, signed and unsigned writers of
each kind, and a malformed line, exports it with the profile, and validates every event with the
Monitor Protocol's own validator at its pinned commit (`dist/schema.js` when built, otherwise the
dependency-free `src/schema.ts` run through Node's type stripping) and its own ceiling tables. That
validator treats `format` as an annotation, so D28 also checks `source` (a URI reference) and `time`
(a timestamp) itself. The run of 2026-09-24 found 11 of 11 events valid at `e7c5225`.

The family intent's probe (Appendix B) reported 5 of 5 records valid; D28 reproduces that result on a
larger sample, and adds signed records, a release, a checkpoint and a rejected line.
