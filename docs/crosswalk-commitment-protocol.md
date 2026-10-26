# Crosswalk: the Desk Protocol and the Commitment Protocol

*Desk spec 0.2 against the Commitment Protocol v2.3, commit `7ef5050f5dd7821adb3c6509ba3f223fd28db7e7`
(read 2026-09-24). Informative, except the fixture at the end, which conformance check D34 runs.*

The desk passes work between agents; the Commitment Protocol keeps promises and their proof in a
ledger. A bridge writes the accountable part of a desk into a ledger. Neither protocol requires the
other; this document is the mapping a bridge follows, following the family intent (§4.6).

## Operations

| Desk | Commitment | Notes |
|---|---|---|
| `ask` | `capture` (kind `observation`), then `commit` (kind `commitment`) citing it | Rule 1: every commitment traces to an observation. |
| `claim` | `claim` | Only when no other actor holds the commitment; a contested desk claim becomes an `annotate` of kind `note`. |
| `release` | `release` | Only the owner may release (PROTOCOL.md, State invariants). |
| `report` | `capture` of evidence, then `submit` when the reporter holds the claim | v2.3: only the owner may submit. Otherwise the evidence capture alone. |
| `verify`, established or unknown | `annotate`, kind `verdict`, on the submission (or on the evidence capture) | The desk result goes in `payload.meta.desk_result`. |
| `verify`, refuted | `reopen` while the commitment is in review; otherwise `annotate` `verdict` | Returns the commitment to `claimed`. |
| `close`, accepted | `approve` when a `submit` was bridged; otherwise a direct `close` with evidence | v2.3 still permits the direct close. |
| `close`, withdrawn or superseded | `annotate`, kind `dismiss`, on the commitment | `dismiss` became an annotation kind in v2.0. |
| `checkpoint` | not bridged | Liveness is not accountability. |
| `supersedes` with a reason | a new signal with a `refines` relation | Commitment has no `supersedes` relation yet (intent C6). |

## States

| Desk | Commitment |
|---|---|
| `open` | `open` |
| `claimed` | `claimed` |
| `reported` | `in_review` (when a submit was bridged) |
| `verified` | no state; recorded as an annotation |
| `closed` | `closed` |

## Identities, references, levels

- **Actors.** A desk identity `kind:name@scope` is written unchanged as the Commitment `actor`; the
  family grammar makes the scope optional there, and the Commitment Protocol accepts any actor string.
- **References.** Each bridged signal carries the desk reference in full string form,
  `desk:<desk-id>/<kind>/<name>@<scope>#<seq>`, as its `source_key`. When one desk record becomes two
  signals, the second key appends `+<op>` (`…#1+commit`, `…#2+submit`). The Commitment Protocol rejects
  a duplicate `source_key`, and the bridge skips keys it finds, so bridging twice writes nothing new.
  The reference verifier does not check `source_key`; D34 checks uniqueness itself.
- **IDs.** `{prefix}_{8hex}` with the eight hex characters taken from the SHA-256 of the `source_key`,
  so the IDs match the format LEDGER.md defines (the spec's own examples do not; intent C4).
- **Levels.** Desk levels (R20) are not written into `trust.verification`: trust there is computed by
  the ledger's own mechanical model and is never self-reported (TRUST.md). The desk result travels as
  data in the annotation.
- **Hashes.** Rows are hashed with the Commitment content hash (LEDGER.md §Hash Computation: `hash`
  and `prevHash` zeroed with keys kept, sorted keys, compact separators, `/` escaped as `\/`). A desk
  digest is over raw line bytes; the two are never compared.

## Inputs are events

A desk record that an agent reads inside a Commitment-governed run is an input under the Commitment
Protocol's Invariant 6. The run records a signal citing the desk reference, the record's digest
(`desk show <ref> --json` gives `digest`) and its text before folding it into a step. Recording it
gives it no authority: a record is data, never an order (desk principle 4).

## The fixture (conformance check D34)

The function below is the mapping as code. It reads the tool's `export --cloudevents` output, so the
check exercises the implementation under test, and appends to a ledger file. It is self-contained
(standard library only) and implements the Commitment content hash from LEDGER.md rather than
importing the reference verifier, so the verifier checks an independent implementation of the
documented algorithm.

<!-- fixture:start -->
```python
import hashlib
import json

GENESIS = "0" * 64


def content_hash(row):
    """Commitment Protocol v2.3 content hash (spec/LEDGER.md, Hash Computation)."""
    obj = dict(row)
    obj["hash"] = ""
    obj["prevHash"] = ""
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).replace("/", "\\/")
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def bridge(events, ledger_path, workspace="desk"):
    """Append the accountable part of a desk (CloudEvents from `desk export`) to a Commitment ledger.

    Returns the number of rows added. Idempotent: every row carries its desk reference as source_key.
    """
    rows = []
    try:
        with open(ledger_path, encoding="utf-8") as fh:
            rows = [json.loads(line) for line in fh if line.strip()]
    except FileNotFoundError:
        pass
    by_key = {row["source_key"]: row for row in rows if row.get("source_key")}
    added = []

    def emit(prefix, op, key, record, payload):
        if key in by_key:
            return by_key[key]["id"]
        prev = (added or rows)[-1]["hash"] if (added or rows) else GENESIS
        row = {"id": prefix + "_" + hashlib.sha256(key.encode()).hexdigest()[:8], "op": op, "ts": record["ts"],
               "actor": record["from"], "workspace": workspace, "hash": "", "prevHash": prev,
               "source_key": key, "payload": payload}
        row["hash"] = content_hash(row)
        added.append(row)
        by_key[key] = row
        return row["id"]

    records = [(e["source"], e["data"]["record"]) for e in events
               if e.get("type", "").rsplit(".", 1)[-1] != "rejected" and "record" in e.get("data", {})]
    records.sort(key=lambda sr: (sr[1]["ts"], sr[1]["from"], sr[1]["seq"]))
    source_of = {}                 # desk ref -> desk source
    for source, record in records:
        source_of["%s#%d" % (record["from"], record["seq"])] = source

    def key_of(ref):
        return "%s#%s" % (source_of[ref], ref.rsplit("#", 1)[1]) if ref in source_of else None

    commitment, owner, submitted, in_review, evidence_of = {}, {}, {}, {}, {}
    ask_of = {}                    # desk ref of a claim or report -> desk ref of its ask
    for source, record in records:
        ref = "%s#%d" % (record["from"], record["seq"])
        key = key_of(ref)
        op = record["op"]
        if op == "ask":
            memory = emit("mem", "capture", key, record, {"body": record["text"], "kind": "observation"})
            commitment[ref] = emit("cmt", "commit", key + "+commit", record,
                                   {"body": record["text"], "kind": "commitment", "source": memory})
            continue
        target = record.get("re")
        if op in ("claim", "report", "close"):
            ask = target
        elif op in ("release", "verify"):
            ask = ask_of.get(target)
        else:
            continue                                   # checkpoints are not bridged
        if ask not in commitment:
            continue                                   # the ask is not on this desk
        cmt = commitment[ask]
        if op == "claim":
            ask_of[ref] = ask
            if owner.get(cmt) in (None, record["from"]):
                owner[cmt] = record["from"]
                emit("op", "claim", key, record, {"body": record.get("text", "claimed on the desk"), "kind": "claim", "commitment": cmt})
            else:
                emit("ann", "annotate", key, record, {"body": "contested claim on the desk", "kind": "note", "target": cmt})
        elif op == "release":
            if owner.get(cmt) == record["from"]:
                owner[cmt] = None
                emit("op", "release", key, record, {"body": record["reason"], "kind": "release", "commitment": cmt, "reason": record["reason"]})
        elif op == "report":
            ask_of[ref] = ask
            evidence = emit("mem", "capture", key, record, {"body": record["text"], "kind": "evidence", "refs": [key]})
            evidence_of[ref] = evidence
            if owner.get(cmt) == record["from"]:
                submitted[ref] = emit("op", "submit", key + "+submit", record,
                                      {"body": record["text"], "kind": "submission", "commitment": cmt, "evidence": evidence,
                                       "summary": record["text"][:120]})
                in_review[cmt] = True
        elif op == "verify":
            result = record["result"]
            if result == "refuted" and in_review.get(cmt):
                in_review[cmt] = False
                emit("op", "reopen", key, record, {"body": record["reason"], "kind": "reopen", "commitment": cmt, "reason": record["reason"]})
            else:
                target_id = submitted.get(target) or evidence_of.get(target) or cmt
                emit("ann", "annotate", key, record, {"body": "desk verify: %s" % result, "kind": "verdict", "target": target_id,
                                                      "meta": {"desk_result": result, "desk_ref": key}})
        elif op == "close":
            if record["outcome"] == "accepted":
                if in_review.get(cmt):
                    in_review[cmt] = False
                    emit("op", "approve", key, record, {"body": "accepted on the desk", "kind": "approval", "commitment": cmt,
                                                        "comment": "accepted on the desk"})
                else:
                    proof = next((evidence_of[r] for r, a in ask_of.items() if a == ask and r in evidence_of), None)
                    if proof:
                        emit("op", "close", key, record, {"body": "accepted on the desk", "kind": "verdict", "commitment": cmt, "evidence": proof})
            else:
                emit("ann", "annotate", key, record, {"body": record["reason"], "kind": "dismiss", "target": cmt})
    if added:
        with open(ledger_path, "a", encoding="utf-8") as fh:
            for row in added:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return len(added)
```
<!-- fixture:end -->

## What the fixture shows, and what it does not

- A full desk cycle (ask, claim, report, independent verify, accepted close) becomes seven rows:
  `capture`, `commit`, `claim`, `capture`, `submit`, `annotate`, `approve`. The reference verifier
  at `7ef5050` returns `verified` (exit 0), every `source_key` is unique, and a second run adds no
  rows (D34).
- The reference verifier checks content hashes and the chain's placement of rows. It does not check
  the Commitment state machine or `source_key` uniqueness, and the Commitment Protocol has no
  black-box suite yet, so D34 shows that the bridged ledger is well formed, not that every state
  transition is legal (intent §9).
- A rewrite that keeps every row placed passes the reference verifier under both profiles (intent
  Appendix B probe 5, and LEDGER.md §Verdict and coverage). The desk side catches the analogous
  rewrite through its chain and witnesses (D25); the ledger side waits on the ancestry binding the
  intent proposes for Commitment 2.4.
