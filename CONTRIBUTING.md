# Contributing

The Desk Protocol is a specification first. `spec/SPEC.md`, `spec/schemas/` and `spec/CONFORMANCE.md`
are the product; `desk.py` is one implementation of them, and `conformance/` tests any implementation
from the outside.

## Changing the specification

A change to `spec/` lands in one pull request together with:

1. a row in `docs/decisions.md` (append-only): the date, the decision, the reason and its source, the
   conformance check it affects, and whether it is **additive** or **breaking**. A change is breaking
   if a desk, record or verdict that was valid before becomes invalid, or its meaning changes;
2. the conformance check that would fail without the change, in `spec/CONFORMANCE.md` and in
   `conformance/run.py`, with a positive control;
3. the schema update in `spec/schemas/`, when a record or `desk.json` changes, and the matching copy
   embedded in `desk.py` (`python3 tests/test_desk.py` checks that the two agree);
4. a line in `CHANGELOG.md`.

Use RFC 2119 keywords for normative statements. Vocabularies are closed: a new operation, flag, level,
outcome or value is a spec change with a decision row and, for family words, a change to
`spec/registry-draft.json`.

## Running the checks

Python 3.9 or newer is the only requirement for the tool and the suite.

```bash
python3 -m unittest discover -s tests -v                      # unit tests of the reference tool
python3 conformance/run.py --impl "python3 desk.py"            # the black-box suite, D01-D37
python3 conformance/mutants.py                                 # does each check fail a broken tool?
```

D28 and D34 need the sibling repositories at their pinned commits; the suite reports them as SKIP,
with the reason, when the repositories or Node.js are not available.

## Commits

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`), one logical change per commit.
Never force-push and never amend a published commit. Commit messages carry no AI attribution: no
co-author trailers naming a model or its vendor and no "generated with" footers; CI rejects them.

## Licence

Apache-2.0 for code and specification is the provisional choice (`docs/decisions.md` row 12). By
contributing you agree that your contribution is licensed under the licence the repository adopts.
