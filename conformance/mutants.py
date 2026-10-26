#!/usr/bin/env python3
"""Mutation check: does each conformance check fail a tool that breaks the rule it is named after?

Each mutant reintroduces one named defect into a copy of the reference tool. The check named after it
must FAIL against the mutant (the mutant is "killed"). The unmodified tool passing the same checks is
the positive control (conformance/run.py). A surviving mutant means the check does not discriminate.

    python3 conformance/mutants.py [--only D03,D08] [--json report.json]

Every snippet must occur exactly once in desk.py, so a mutant can never silently become a no-op.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent / "desk.py"

MUTANTS = [
    ("D01", "closes never close the ask",
     [("    if qualifying:\n        winner", "    if False:\n        winner")]),
    ("D02", "prev is checked against canonical JSON instead of the exact bytes",
     [("            elif prev != lines[idx - 1].digest:",
       "            elif prev != sha256_digest(canonical_json(lines[idx - 1].record or {}).encode()):")]),
    ("D03", "watch acknowledges after printing",
     [('''                    out({"type": "record", "ref": rec.ref, "op": rec.op, "from": rec.writer, "ts": rec.ts,
                         "record": rec.r}, watch_line(rec, width))
''', '''                    out({"type": "record", "ref": rec.ref, "op": rec.op, "from": rec.writer, "ts": rec.ts,
                         "record": rec.r}, watch_line(rec, width))
                    with state.locked():
                        state.positions[w] = max(state.position(w), rec.seq + 1)
                        state.save()
''')]),
    ("D04", "a trailing partial line is consumed as a record",
     [("            else:\n                view.partials[identity] = seg.partial_len",
       "            else:\n                counter['n'] += 1\n                lines.append(Line(identity, len(lines), seg_path, counter['n'], seg.partial, seg.partial_len, _tail_digest(seg_path, seg.complete_bytes)))")]),
    ("D05", "a malformed line is skipped silently",
     [('                view.add("invalid", line.location(desk), "%s; raw %s" % (line.problem, raw_preview(line.raw)))',
       "                pass")]),
    ("D06", "duplicate sequence numbers are not reported",
     [('                info["duplicates"].append(seq)\n', ""),
      ('                view.add("duplicate", identity, "seq %d repeated at %s" % (seq, line.location(desk)))\n', "")]),
    ("D07", "the writer lock is never taken",
     [("            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n            return True", "            return True")]),
    ("D08", "the latest claim, not the earliest, is named holder",
     [("    live.sort(key=lambda pair: pair[0].order)", "    live.sort(key=lambda pair: pair[0].order, reverse=True)")]),
    ("D09", "a lease is expired at exactly renew_time + duration",
     [("at <= parse_time(latest.ts) + dt.timedelta(seconds=_duration(desk, latest))",
       "at < parse_time(latest.ts) + dt.timedelta(seconds=_duration(desk, latest))")]),
    ("D10", "the tool writes an accepted close without a qualifying verify",
     [("        if thread is None or not _qualifying_close(view, thread, probe):", "        if False:")]),
    ("D11", "a self-verify counts as independent",
     [('    return (verify.writer != report.writer) or not desk.policy["independent_verify"]', "    return True")]),
    ("D12", "unknown needs no reason",
     [("    errors = RECORD_SCHEMA.errors(record)\n    if errors:",
       "    errors = [e for e in RECORD_SCHEMA.errors(record) if 'reason' not in e and 'allowed forms' not in e]\n    if errors:")]),
    ("D13", "an ask past its deadline is never expired",
     [('    if thread.state != "closed" and at > thread.deadline:', "    if False:")]),
    ("D14", "the declared heartbeat is ignored",
     [('        heartbeat = (last_cp.r["state"].get("heartbeat_seconds") if last_cp else None) or desk.policy["heartbeat_seconds"]',
       '        heartbeat = desk.policy["heartbeat_seconds"]')]),
    ("D15", "a supersede does not replace the original",
     [("            target.superseded_by = rec.ref", "            pass")]),
    ("D16", "an unknown operation is invalid",
     [('    """Schema plus the checks a schema cannot express (spec §4). Returns a problem string or None."""\n',
       '    """Schema plus the checks a schema cannot express (spec §4). Returns a problem string or None."""\n'
       '    if record.get("op") not in OPS:\n        return "unknown operation"\n')]),
    ("D17", "watch prints record text raw",
     [('    return head + " " + quote(text, max(12, width - len(head) - 1)) if text else head[:width]',
       '    return head + " " + text if text else head[:width]')]),
    ("D18", "oversized records are written",
     [("        if len(line) > cap:\n            raise refuse", "        if False:\n            raise refuse")]),
    ("D19", "readers accept unsigned records under signing: required",
     [('        if mode == "required" and not ok:', "        if False:")]),
    ("D20", "every writer appends to one shared log",
     [("    wdir = _ensure_writer_dir(desk, identity)\n", '    wdir = _ensure_writer_dir(desk, "agent:shared@t")\n')]),
    ("D21", "a missing evidence file is not noticed",
     [("                    os.lstat(path)\n", "                    pass\n")]),
    ("D22", "symbolic links inside log/ are followed",
     [('                if w_entry.is_symlink():\n                    view.add("invalid", where, "symbolic link, not followed (R14)")\n                    continue\n', ""),
      ("                if not w_entry.is_dir(follow_symlinks=False) or not NAME_SCOPE_RE.match(w_entry.name):",
       "                if not w_entry.is_dir() or not NAME_SCOPE_RE.match(w_entry.name):"),
      ('        if f.is_symlink():\n            view.add("invalid", where, "symbolic link, not followed (R14)")\n            continue\n', ""),
      ("        if not SEGMENT_RE.match(f.name) or not f.is_file(follow_symlinks=False):", "        if not SEGMENT_RE.match(f.name) or not f.is_file():"),
      ("    flags = os.O_RDONLY | getattr(os, \"O_BINARY\", 0) | getattr(os, \"O_NOFOLLOW\", 0)\n    st = os.lstat(path)\n    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):",
       "    flags = os.O_RDONLY | getattr(os, \"O_BINARY\", 0)\n    st = os.stat(path)\n    if not stat.S_ISREG(st.st_mode):"),
      ("            if stat.S_ISLNK(st.st_mode):\n                raise DeskError(\"refusing to write through a symbolic link", "            if False:\n                raise DeskError(\"refusing to write through a symbolic link")]),
    ("D23", "read memory is never compared",
     [('            if seg.complete_bytes < mem["bytes"] or seg.prefix_digest != mem["digest"]:', "            if False:")]),
    ("D24", "prev is never compared",
     [("            elif prev != lines[idx - 1].digest:", "            elif False:")]),
    ("D25", "cited digests are never compared",
     [('                elif "digest" in item and item["digest"] != target.line.digest:', "                elif False:")]),
    ("D26", "seen heads are never compared",
     [('                elif head["digest"] != target.line.digest:', "                elif False:")]),
    ("D27", "ack stores the last delivered seq instead of the next to deliver",
     [("            pos = seq + 1\n            state.positions[writer] = pos", "            pos = seq\n            state.positions[writer] = pos")]),
    ("D28", "the export lets an agent's record claim the top tier",
     [('    if not rec.signed or desk.policy["signing"] == "off":\n        return "unverified"',
       '    if not rec.signed or desk.policy["signing"] == "off":\n        return "src"')]),
    ("D29", "malformed identities are accepted",
     [("    if not ID_RE.match(candidate):", "    if False:")]),
    ("D29", "identity aliases are not normalized",
     [("    kind = ALIASES.get(kind, kind)\n", "")]),
    ("D30", "a supersede needs no reason",
     [('        if not fields.get("reason"):\n            raise refuse("a supersede needs', '        if False:\n            raise refuse("a supersede needs'),
      ("    errors = RECORD_SCHEMA.errors(record)\n    if errors:",
       "    errors = [e for e in RECORD_SCHEMA.errors(record) if 'requires reason' not in e]\n    if errors:")]),
    ("D31", "on_behalf_of raises an agent's level",
     [('    if kind == "agent":\n        return "unverified"',
       '    if kind == "agent":\n        return "human_verified" if rec.r.get("on_behalf_of") else "unverified"')]),
    ("D32", "roles are ignored",
     [('        allowed = self.roles.get("permissions", {}).get(role, [])', '        allowed = ["*"]')]),
    ("D33", "unchained records do not make a desk incomplete",
     [('    incomplete = (c["unchained"] and view.desk.policy["chain"] == "warn") or c["unresolved"] or c["gaps"]',
       '    incomplete = c["unresolved"] or c["gaps"]')]),
    ("D34", "the export leaves asks out",
     [("            if rec is not None and not rec.invalid and not rec.refused and not rec.unpermitted:",
       "            if rec is not None and not rec.invalid and not rec.refused and not rec.unpermitted and rec.op != 'ask':")]),
    ("D35", "show refuses --as (the file-desk 0.1.0 defect)",
     [("def cmd_show(args, settings):\n    desk = open_desk(settings)",
       "def cmd_show(args, settings):\n    if getattr(args, 'as_', None):\n        raise usage('show does not take --as')\n    desk = open_desk(settings)")]),
    ("D36", "inbox ignores role addressing",
     [('    elif to.startswith("role:") and my_role and to[5:] == my_role:', "    elif False:")]),
    ("D38", "a checkpoint's blocked_on is ignored by inbox",
     [('        if thread is not None and thread.state != "closed" and thread not in threads:', "        if False:")]),
    ("D37", "a flag word outside the registry",
     [('        view.add("contested", thread.root,', '        view.add("conflicted", thread.root,')]),
]
EXTRA_CHECKS = {"D37": "D08,D37"}


def make_mutant(source, pairs):
    for old, new in pairs:
        count = source.count(old)
        if count != 1:
            raise SystemExit("snippet occurs %d times, expected 1:\n%s" % (count, old[:200]))
        source = source.replace(old, new)
    return source


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--only", help="comma-separated check ids")
    parser.add_argument("--json", dest="json_out")
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args(argv)
    only = {x.strip().upper() for x in args.only.split(",")} if args.only else None
    source = TOOL.read_text()
    results = []
    with tempfile.TemporaryDirectory(prefix="desk-mutants-") as tmp:
        for check_id, name, pairs in MUTANTS:
            if only and check_id not in only:
                continue
            mutant = Path(tmp) / ("desk_%s_%d.py" % (check_id.lower(), len(results)))
            mutant.write_text(make_mutant(source, pairs))
            report = Path(tmp) / ("report_%s_%d.json" % (check_id.lower(), len(results)))
            started = time.monotonic()
            proc = subprocess.run([args.python, str(HERE / "run.py"), "--impl", "%s %s" % (args.python, mutant),
                                   "--only", EXTRA_CHECKS.get(check_id, check_id), "--json", str(report)],
                                  capture_output=True, text=True, timeout=1800)
            data = json.loads(report.read_text()) if report.exists() else {"results": []}
            row = next((r for r in data["results"] if r["id"] == check_id), None)
            outcome = row["result"] if row else "ERROR"
            killed = outcome == "FAIL"
            results.append({"check": check_id, "mutant": name, "result_against_mutant": outcome, "killed": killed,
                            "detail": (row or {}).get("detail", proc.stderr[-300:])[:300],
                            "seconds": round(time.monotonic() - started, 1)})
            print("%s %-8s %s -> %s" % (check_id, "killed" if killed else "SURVIVED", name, (row or {}).get("detail", "")[:150]), flush=True)
    killed = sum(1 for r in results if r["killed"])
    print("\nmutants killed: %d of %d" % (killed, len(results)))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps({"tool": str(TOOL.name), "killed": killed, "total": len(results),
                                                   "results": results}, indent=1) + "\n")
    return 0 if killed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
