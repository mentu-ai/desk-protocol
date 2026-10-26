# Changelog

Specification versions and tool versions are separate: the specification is 0.2.0-draft, the
reference tool `desk.py` is 0.1.0, and the conformance suite is 0.2.0. Each spec change also has a
row in `docs/decisions.md`, which says whether it is additive or breaking.

## Unreleased

- 2026-09-24: scaffold, context and sources for the v0.2 build.
- 2026-09-24: Phase 0. Sibling pins (Monitor Protocol `e7c5225`, v0.1.3; Commitment Protocol
  `7ef5050`, v2.3), the name check, prior art read from primary sources, harness capabilities from
  official documentation, and decision rows 1–22.
- 2026-09-24: Phase 1. `spec/SPEC.md`, `spec/schemas/record.schema.json`,
  `spec/schemas/desk.schema.json` and `spec/CONFORMANCE.md` (D01–D37 with the command interface),
  and decision rows 23–48. Against the v0.1 prompt the identity grammar, references, lease fields,
  mandatory supersede reasons and exit code 2 are breaking; everything else is additive.
- 2026-09-24: Phase 2. `desk.py` 0.1.0 (one file, standard library, Python 3.9+), the black-box
  conformance suite, the mutation check and unit tests; decision rows 49–55.
- 2026-09-24: Phase 3. Harness adapters with generated and tested snippets, the Monitor and
  Commitment crosswalks, the CloudEvents export description, the help-desk example, pilot metrics,
  `SECURITY.md`, and CI workflows pinned by commit (inert until the build is its own repository);
  decision rows 56–60.
- 2026-09-24: §8 says what acknowledging means for a record that waits on someone else, and `inbox`
  lists the asks a reader's latest checkpoint names in `blocked_on` as `waiting` (row 61, check D38).
  Additive. Found by the monitoring session while dogfooding.
- 2026-09-24: `desk.py`: when a writer cites the report it verifies, or the verify its close rests on,
  the tool no longer adds a second, automatic citation of the same record (seen in the monitoring
  session's records on the dogfooding desk). Tool only; the specification is unchanged.
- 2026-09-24: harness snippets: a watcher checkpoints each time it starts the watch, with a heartbeat
  longer than the watch's cycle (2400 seconds for a 29-minute watch). Learned on the dogfooding desk,
  where a 1800-second heartbeat missed its bound at a re-arm. Instruction text only.
- 2026-09-25: `docs/horizons.md` states how the family's horizon principle applies to a desk, and the
  builder takes the role of horizon guard for this build (row 62).
