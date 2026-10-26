# Conformance suite

A black-box suite for any implementation of the Desk Protocol, spec 0.2. It tests an implementation
only from the outside, through the command interface in `spec/CONFORMANCE.md` §2, and writes raw lines
itself to test the echo-and-tail path. It needs Python 3.9 or newer and nothing else; D02 also needs a
POSIX shell, D19 `ssh-keygen` (OpenSSH 8.0+), D20 git, D28 Node.js and the Monitor Protocol clone,
and D34 the Commitment Protocol clone.

## Running it

```bash
python3 conformance/run.py --impl "python3 desk.py"                  # all of D01-D38
python3 conformance/run.py --impl "python3 desk.py" --only D01,D27    # a subset
python3 conformance/run.py --impl "node dist/desk.js" --json out.json # another implementation
```

- `--impl` (or `DESK_IMPL`) is the command template; the suite appends the command and its options.
- `--monitor` and `--commitment` (or `MP_DIR`, `CP_DIR`) point at the sibling clones; by default the
  suite looks in `.siblings/`. Pin them at the commits in `docs/decisions.md` row 16.
- Every desk, state directory and key lives in a temporary directory, removed afterwards (`--keep`
  keeps it). The suite clears `DESK_*` variables and points `DESK_CONFIG` at a missing file, so your own
  participant settings never leak into a run.
- `DESK_CONFORMANCE_D03_RECORDS` (default 1000), `DESK_CONFORMANCE_D03_KILLS` (20) and
  `DESK_CONFORMANCE_D20_ROUNDS` (100) scale the two long checks. A conformance claim uses the defaults.

## Output

One line per check while it runs, then the family report (registry `conformance_report`): the date,
the suite version, the implementation, the commit tested, Python and the platform, and a table of
check id, rule, and PASS, FAIL or SKIP with the reason. The exit code is 1 if any check failed.

## When a check may SKIP

| Check | SKIP only when |
|---|---|
| D02 | no POSIX shell with `shasum` or `sha256sum` (Windows) |
| D19 | no `ssh-keygen` with `-Y sign` |
| D20 | no git |
| D22 | the platform will not create symbolic links |
| D28 | no Node.js, no Monitor Protocol clone, or its validator cannot run under this Node.js |
| D34 | no Commitment Protocol clone, or no fixture in `docs/crosswalk-commitment-protocol.md` |
| D37 | no check in the same invocation printed a family word |

D28 runs the Monitor Protocol's own validator (`dist/schema.js` when built, otherwise `src/schema.ts`
through Node's type stripping; it has no dependencies) and its own ceiling tables (`vocab`), and
checks `source` and `time` syntax separately, because that validator treats `format` as an annotation.

## Does the suite discriminate?

`conformance/mutants.py` makes copies of the reference tool, at least one per check, each with one named defect (a watch
that acknowledges on printing, a lease that expires a millisecond early, a supersede that needs no
reason, …), and runs the check named after each defect against its copy. Every copy must fail. The
results of the last run are in `RESULT.md`.

```bash
python3 conformance/mutants.py [--only D03,D27] [--json mutants.json]
```
