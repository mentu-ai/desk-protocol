# Desk Protocol 0.2.0: release folder, prepared 2026-10-24

This folder is the specification, conformance suite and reference tool of the Desk Protocol at the commit the field
study pins, `8ba5ee78` of the research corpus (2026-09-25), taken from `prototypes/desk-protocol` with the build's
internal files left out (its build prompts, evidence notes, launch notes, packets and examples). Nothing in the kept
files was changed. The field study (*Coordination Records Across Agent Sessions*, draft 1.0.1) and Paper II of the
continuity trilogy cite this specification as 0.2.0-draft with conformance clauses D01 to D38, and the review of both
asked for a frozen, citable release (OPERON, 24 October 2026, mandatory item 11).

## Contents and digests

- `spec/SPEC.md` (0.2.0-draft), `spec/CONFORMANCE.md` (D01 to D38), `spec/schemas/`, `spec/registry-draft.json`
- `conformance/run.py`, `conformance/mutants.py`, `conformance/README.md`
- `desk.py`, the reference tool (0.1.0, Python 3.9 or later, standard library only), and `tests/test_desk.py`
- `docs/`: decisions, prior art (read 2026-09-24), the two crosswalks, CloudEvents mapping, horizons, pilot metrics
- `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`
- `LICENSE`: the Apache License 2.0 text, added here; the README calls the licence provisional (decision row 12),
  so **the owner confirms it before publication**

sha256 of `spec/SPEC.md`: `f4d7e52725a2a9f886325e78450587fdb99b54a8aed2dc26ee2c1b1075c0ec81`
sha256 of `desk.py`: `51bcb8a1e77edfaefd2b73afe7cb97cb58590ebe9a1a95e7339fa3b5874f09b6` (the desks studied pin a later tool, `217ae555…`; this is the 0.2.0-draft tool)
sha256 of `LICENSE`: `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`
`MANIFEST.sha256` lists every file.

## Conformance at this commit

Run here on 2026-10-24 with `python3 conformance/run.py --impl "python3 desk.py"`, twice:

- without the sibling clones: 36 PASS, 0 FAIL, 2 SKIP of 38 (D28 and D34 skip: they need the Monitor Protocol and
  the Commitment Protocol at their pinned commits);
- with `--monitor` at Monitor Protocol `e7c52250cd57ca6877096c6acf068b4b94629414` (tag v0.1.3) and `--commitment` at
  Commitment Protocol `7ef5050f5dd7821adb3c6509ba3f223fd28db7e7` (tag v2.3), the pins of `docs/decisions.md` row 16:
  **38 PASS, 0 FAIL, 0 SKIP of 38**. The full report is `CONFORMANCE-RESULT-2026-10-24.txt`.

## What the owner does to release it

1. Confirm the licence (Apache-2.0 or another), and remove this section's note.
2. Create the public repository `mentu-ai/desk-protocol`, add these files as the first commit, tag it `v0.2.0`.
3. Deposit the tagged tree on Zenodo for a DOI (as with the Monitor Protocol), with the author as sole author.
4. Tell the research seat the tag's commit and the DOI, so that the field study's reference 11 and Paper II's
   reference point to them in their next versions.

Not included on purpose: the later working draft (0.4) that the programme's desks now run, which stays unreleased
until its own review.
