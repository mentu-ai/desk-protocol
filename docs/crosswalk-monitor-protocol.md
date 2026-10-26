# Crosswalk: the Desk Protocol and the Monitor Protocol

*Desk spec 0.2 against the Monitor Protocol 0.1.3, commit `e7c52250cd57ca6877096c6acf068b4b94629414`
(read 2026-09-24). Informative. The CloudEvents export it relies on is normative in `spec/SPEC.md`
§12 and described in `docs/cloudevents.md`; conformance check D28 validates it.*

The desk passes work between agents through a folder; the Monitor Protocol delivers news of work
through a hub, with its provenance. A hub bridge publishes desk records to a monitor so that
subscribers get them in real time and under the hub's access control. Neither protocol requires the
other. Running a bridge as a service is out of scope for desk 0.2; this is the mapping one follows.

## Two ways a desk record becomes an observation

1. **Export** (`desk export --cloudevents --profile monitor-protocol`). Each record becomes a
   standalone CloudEvent whose `source` is the desk writer (`desk:<desk-id>/<kind>/<name>@<scope>`)
   and whose `id` is the record's `seq`. Every event validates against the Monitor Protocol's
   `schemas/observation.json` with that repository's own validator (D28). This is what a hub would
   ingest from a `file` or `log` source kind, which the Monitor objects spec declares but its reference
   server does not ingest yet (intent §6).
2. **Publish** (`monitors/publish` on a hub). The hub assigns its own `source` (`monitor:<id>`) and
   sequence, so the desk reference travels in `data.provenance.source_ref`
   (`desk:<desk-id>/<kind>/<name>@<scope>#<seq>`) and `data.record`. The bridge publishes one
   observation per desk record, in each writer's `seq` order.

## Operations to types and lease methods

| Desk | Observation `type` | Lease method (hub subscription with `act`) |
|---|---|---|
| `ask` | `desk.ask` | none; the ask's full reference becomes the lease `subject` |
| `claim` | `desk.claim` | `leases/claim` with `subject` = the ask and `lease_duration_seconds` from the record |
| renewing claim by the holder | `desk.claim` | `leases/renew` |
| `release` | `desk.release` | `leases/release` with the record's `reason` |
| `report` | `desk.report` | none (a `note` on `leases/renew` if the reporter holds the lease) |
| `verify` | `desk.verify` | none; the result travels in `data.record.result` |
| `close`, accepted | `desk.close` | `leases/complete` with `outcome` and `evidence: [{source, id}]` citing the qualifying verify |
| `close`, withdrawn or superseded | `desk.close` | `leases/release` |
| `checkpoint` | `desk.checkpoint` | none; see cadence below |
| a line the reader does not accept | `desk.rejected` | none; the Monitor's P2: a rejection is still evidence |

The type prefix is the desk's `namespace` (default `desk`), which the family namespace decision may
change (owner decision 1). A hub monitor that carries desk records declares these types in its
`types` list, or a subscriber's `types` filter is refused as unknown (Monitor P11, C03).

**Leases are stricter on a hub.** A desk claim is advisory: overlapping claims are recorded and the
ask is `contested` (R9). A hub lease is one conditional write, and a second claimant gets
`LEASE_HELD`. A bridge therefore reports a contested desk ask as the hub's answer to the second
claim; it never grants two leases. Neither protocol proves exclusive control of the work itself.

## Identities, kinds and levels

| Desk | Monitor | Rule |
|---|---|---|
| identity `kind:name@scope` | `actor` (URI reference) | unchanged; the family grammar (registry R.2) |
| kind `human` | origin `human` | |
| kind `agent` | origin `agent` | |
| kind `system` | origin `system` | desk input aliases `hook:`, `webhook:`, `probe:` are stored as `system:`, so a bridge publishes `system` |
| level (R20) | `verified` | never above the origin's ceiling (`ORIGIN_VERIFICATION_CEILING`) |
| unsigned record | `tier: unverified` | |
| signed `system` record | `tier: measured` | the Monitor's machine ceiling |
| a person's signed `verify` or `close` | `tier: src`, `verified: human_verified` | only a person reaches the top (Monitor P1) |
| `supersedes` with a reason | `data.provenance.supersedes: {source, id}` | the reason stays in `data.record.reason` |
| `on_behalf_of` | `data.provenance.on_behalf_of` | see below |

**The provenance ceiling.** An agent's verify never maps to a person's level of certainty: an agent
record is `unverified` on both sides, whatever it says, and `on_behalf_of` never raises it (desk R19,
Monitor P1). The desk never emits `certified` (owner decision 4).

**`on_behalf_of` is narrower on a hub.** On a desk it may name any person (a member, when roles are
configured). On a hub it may name only the monitor's owner, and an agent borrows the owner's level
only through the owner's token. A bridge publishes `on_behalf_of` only when it names the hub
monitor's owner, and otherwise leaves it in `data.record`, where it is data.

## Time, liveness and positions

| Desk | Monitor | Note |
|---|---|---|
| `lease_duration_seconds`, `renew_time` = `ts` of the holder's latest claim | Lease `lease_duration_seconds`, `renew_time` | same expiry rule: expired once now is past `renew_time + lease_duration_seconds` |
| checkpoint `heartbeat_seconds` | monitor `cadence.heartbeat_seconds` | the same name |
| `silent` writer | gap `stale_source` | registry R.5 |
| committed position per writer (next `seq` to deliver) | subscription `cursor` (next `seq` to deliver) | both are Kafka's committed position |
| `ack <ref>`, `ack --upto <ref>` | `feeds/ack` (cumulative) | the desk's strict form refuses to skip unacknowledged records |
| `seek <identity> <seq> --reason` | `feeds/seek` with a reason | the only way backwards on both sides |
| reader state outside the desk | cursor held by the hub | |

## The watch client

Both protocols give a Claude Code session the same pattern: one long-lived `watch` per session,
printing one line per event, started with `--catch-up` and re-armed at the Monitor tool's deadline
(at most 30 minutes). They differ on one point. The Monitor Protocol's `watch` acknowledges each
observation after printing it (`src/watch.ts`, `ackAfterPrint` defaults to true); a desk `watch` never
acknowledges, and the agent acknowledges after handling (desk principle 5, R7). Printing is not
handling: a session that dies between receiving a line and acting on it loses that observation under
ack-after-print. The desk's mutation check shows the cost: a copy of the desk tool that acknowledges
on printing loses most of the records in D03 (`evidence/phase-2/mutants.json`). `RESULT.md` proposes
the matching change to the Monitor Protocol.
