#!/usr/bin/env python3
"""Black-box conformance suite for the Desk Protocol, spec 0.2 (spec/CONFORMANCE.md).

It drives an implementation only through the command interface in spec/CONFORMANCE.md §2, and writes
raw lines itself to test the echo-and-tail path. Standard library only; Python 3.9 or newer.

    python3 conformance/run.py --impl "python3 desk.py" [--only D01,D05] [--json report.json]

Results follow the family report format: one row per check (id, rule, PASS/FAIL/SKIP with a reason),
with the date, the suite version, the implementation and the commit tested.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import random
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from decimal import Decimal
from pathlib import Path

SUITE_VERSION = "0.2.0"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
REGISTRY = ROOT / "spec" / "registry-draft.json"
CROSSWALK_DOC = ROOT / "docs" / "crosswalk-commitment-protocol.md"

A, B, C, H = "agent:asker@t", "agent:worker@t", "agent:checker@t", "human:hana@t"
T0 = dt.datetime(2026, 9, 24, 12, 0, 0, tzinfo=dt.timezone.utc)
FAR = "2099-01-01T00:00:00Z"
WORDS = {"flags": set(), "levels": set(), "outcomes": set(), "gaps": set()}


class Fail(Exception):
    pass


class Skip(Exception):
    pass


def ts(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (moment.microsecond // 1000)


def at(seconds):
    return ts(T0 + dt.timedelta(seconds=seconds))


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def check(condition, message):
    if not condition:
        raise Fail(message)


# --- driving the implementation ---------------------------------------------------------------------
class Impl:
    def __init__(self, template):
        self.argv = shlex.split(template)

    def run(self, ctx, args, stdin=None, timeout=120, env_extra=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith("DESK_")}
        env["DESK_CONFIG"] = str(ctx.tmp / "no-participant-settings.json")
        if env_extra:
            env.update(env_extra)
        full = self.argv + list(args)
        proc = subprocess.run(full, input=stdin, capture_output=True, timeout=timeout, env=env)
        ctx.calls.append((args, proc.returncode))
        return proc


class Ctx:
    def __init__(self, impl, root_tmp, siblings):
        self.impl = impl
        self.tmp = Path(tempfile.mkdtemp(prefix="desk-conf-", dir=root_tmp))
        self.desk = self.tmp / "desk"
        self.state = self.tmp / "state"
        self.calls = []
        self.siblings = siblings

    # generic runners --------------------------------------------------------------------------------
    def cmd(self, args, desk=None, stdin=None, env_extra=None, timeout=120):
        args = list(args) + ["--desk", str(desk or self.desk), "--state-dir", str(self.state)]
        return self.impl.run(self, args, stdin=stdin, env_extra=env_extra, timeout=timeout)

    def json_of(self, proc, what):
        try:
            data = json.loads(proc.stdout.decode("utf-8"))
        except ValueError:
            raise Fail("%s did not print JSON (exit %d): %s %s" % (what, proc.returncode, proc.stdout[:200], proc.stderr[:300]))
        collect_words(data)
        return data

    # setup -------------------------------------------------------------------------------------------
    def init(self, policy=None, roles=None, members=None, desk=None):
        desk = Path(desk or self.desk)
        proc = self.impl.run(self, ["init", str(desk), "--json"])
        check(proc.returncode == 0, "init failed (exit %d): %s" % (proc.returncode, proc.stderr[:300]))
        conf_path = desk / "desk.json"
        conf = json.loads(conf_path.read_text())
        if policy:
            conf.setdefault("policy", {}).update(policy)
        if roles is not None:
            conf["roles"] = roles
        if members is not None:
            conf["members"] = members
        conf_path.write_text(json.dumps(conf, indent=1))
        return conf

    def desk_id(self, desk=None):
        return json.loads((Path(desk or self.desk) / "desk.json").read_text())["id"]

    def w(self, who, op, *args, expect=0, desk=None, stdin=None):
        proc = self.cmd([op] + list(args) + ["--as", who, "--json"], desk=desk, stdin=stdin)
        if expect is not None and proc.returncode != expect:
            raise Fail("%s %s as %s: expected exit %s, got %d: %s" % (op, " ".join(args), who, expect, proc.returncode,
                                                                     proc.stderr.decode(errors="replace")[:300]))
        if proc.returncode == 0 and expect == 0:
            return self.json_of(proc, op)["ref"]
        return proc

    def status(self, as_of=None, reader=None, desk=None):
        args = ["status", "--json"]
        if as_of:
            args += ["--as-of", as_of]
        if reader:
            args += ["--as", reader]
        proc = self.cmd(args, desk=desk)
        check(proc.returncode == 0, "status exited %d: %s" % (proc.returncode, proc.stderr[:300]))
        return self.json_of(proc, "status")

    def show(self, ref, reader=None):
        args = ["show", ref, "--json"] + (["--as", reader] if reader else [])
        proc = self.cmd(args)
        check(proc.returncode == 0, "show %s exited %d: %s" % (ref, proc.returncode, proc.stderr[:300]))
        return self.json_of(proc, "show")

    def validate(self, profile="default", desk=None):
        proc = self.cmd(["validate", "--profile", profile, "--json"], desk=desk)
        return proc.returncode, self.json_of(proc, "validate")

    def watch_json(self, reader, *extra, seconds=1.5):
        proc = self.cmd(["watch", "--as", reader, "--format", "json", "--exit-after", str(seconds), "--poll", "0.1"] + list(extra),
                        timeout=60)
        check(proc.returncode == 0, "watch exited %d: %s" % (proc.returncode, proc.stderr[:300]))
        lines = [json.loads(l) for l in proc.stdout.decode("utf-8").splitlines() if l.strip()]
        for l in lines:
            collect_words(l)
        return lines

    def lines_of(self, identity, desk=None):
        kind, rest = identity.split(":", 1)
        path = Path(desk or self.desk) / "log" / kind / rest / "000001.jsonl"
        return path.read_bytes().split(b"\n")[:-1] if path.exists() else []


def ask_of(status, ref):
    for ask in status["asks"]:
        if ask["ref"] == ref:
            return ask
    raise Fail("status does not list the ask %s (asks: %s)" % (ref, [a["ref"] for a in status["asks"]]))


def findings(data, flag, subject=None):
    return [f for f in data.get("findings", []) if f["flag"] == flag and (subject is None or f["subject"] == subject)]


def writer_of(status, identity):
    for w in status["writers"]:
        if w["identity"] == identity:
            return w
    raise Fail("status does not list the writer %s" % identity)


def collect_words(data):
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "flag" and isinstance(value, str):
                WORDS["flags"].add(value)
            elif key == "flags" and isinstance(value, list):
                WORDS["flags"].update(v for v in value if isinstance(v, str))
            elif key in ("level", "verification", "verified") and isinstance(value, str):
                WORDS["levels"].add(value)
            elif key == "result" and isinstance(value, str):
                WORDS["outcomes"].add(value)
            elif key == "gaps" and isinstance(value, list) and all(isinstance(v, str) for v in value):
                WORDS["gaps"].update(value)
            if key != "record":
                collect_words(value)
    elif isinstance(data, list):
        for item in data:
            collect_words(item)


# --- raw writing (the echo-and-tail path) ------------------------------------------------------------
class Raw:
    def __init__(self, desk, identity, segment="000001.jsonl"):
        kind, rest = identity.split(":", 1)
        self.identity = identity
        self.dir = Path(desk) / "log" / kind / rest
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / segment
        self.seq, self.last = 0, None
        if self.path.exists():
            lines = self.path.read_bytes().split(b"\n")[:-1]
            if lines:
                self.last = lines[-1]
                try:
                    self.seq = json.loads(lines[-1])["seq"]
                except (ValueError, KeyError, TypeError):
                    pass

    def build(self, fields, seq=None, when=None, prev=True, prev_value=None):
        seq = self.seq + 1 if seq is None else seq
        record = {"v": "0.2", "seq": seq, "ts": when or ts(dt.datetime.now(dt.timezone.utc)), "from": self.identity}
        record.update(fields)
        if prev_value is not None:
            record["prev"] = prev_value
        elif prev and self.last is not None:
            record["prev"] = sha(self.last)
        return record

    def append(self, fields, seq=None, when=None, prev=True, prev_value=None, sign=None):
        record = self.build(fields, seq, when, prev, prev_value)
        if sign:
            record["sig"] = sign(record)
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.write(line + b"\n")
        self.last = line
        self.seq = record["seq"]
        return "%s#%d" % (self.identity, record["seq"])

    def write(self, data):
        with open(self.path, "ab") as fh:
            fh.write(data)

    def append_bytes(self, line):
        self.write(line + b"\n")
        self.last = line


def rewrite_line(path, index, new_line):
    lines = Path(path).read_bytes().split(b"\n")
    lines[index] = new_line
    Path(path).write_bytes(b"\n".join(lines))


# --- RFC 8785 for the signing check (independent of any implementation) ------------------------------
def jcs(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value == 0:
            return "0"
        _, digits, exp = Decimal(repr(abs(value))).normalize().as_tuple()
        digits = "".join(map(str, digits))
        k, n = len(digits), exp + len(digits)
        if k <= n <= 21:
            body = digits + "0" * (n - k)
        elif 0 < n <= 21:
            body = digits[:n] + "." + digits[n:]
        elif -6 < n <= 0:
            body = "0." + "0" * -n + digits
        else:
            body = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if n - 1 >= 0 else "-") + str(abs(n - 1))
        return ("-" if value < 0 else "") + body
    if isinstance(value, str):
        out = ['"']
        for ch in value:
            o = ord(ch)
            out.append('\\"' if ch == '"' else "\\\\" if ch == "\\" else
                       {8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r"}.get(o, "\\u%04x" % o) if o < 0x20 else ch)
        return "".join(out) + '"'
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
    return "{" + ",".join(jcs(k) + ":" + jcs(value[k]) for k in keys) + "}"


def ssh_signer(ctx, key):
    def sign(record):
        body = {k: v for k, v in record.items() if k != "sig"}
        proc = subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", "desk", "-q"],
                              input=jcs(body).encode("utf-8"), capture_output=True, timeout=30)
        if proc.returncode != 0:
            raise Skip("ssh-keygen -Y sign failed: %s" % proc.stderr.decode(errors="replace")[:200])
        return "".join(l for l in proc.stdout.decode().splitlines() if l and not l.startswith("-----"))
    return sign


def make_key(ctx, name):
    if not shutil.which("ssh-keygen"):
        raise Skip("ssh-keygen is not on PATH")
    key = ctx.tmp / ("key-" + name)
    proc = subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key), "-q"], capture_output=True)
    if proc.returncode != 0:
        raise Skip("ssh-keygen cannot make an ed25519 key: %s" % proc.stderr.decode(errors="replace")[:200])
    probe = subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", "desk", "-q"], input=b"x", capture_output=True)
    if probe.returncode != 0:
        raise Skip("this ssh-keygen has no -Y sign (OpenSSH 8.0 or newer is needed)")
    return key, (ctx.tmp / ("key-" + name + ".pub")).read_text().strip()


# --- the checks --------------------------------------------------------------------------------------
def cycle(ctx):
    a = ctx.w(A, "ask", "--text", "Which base URL should staging tests use?", "--settle", "a URL whose /health answers 200")
    c = ctx.w(B, "claim", a)
    r = ctx.w(B, "report", a, "--text", "Use https://staging.example.test")
    v = ctx.w(C, "verify", r, "--result", "established")
    x = ctx.w(A, "close", a, "--outcome", "accepted")
    return a, c, r, v, x


def d01(ctx):
    ctx.init()
    a, c, r, v, x = cycle(ctx)
    st = ctx.status()
    ask = ask_of(st, a)
    check(ask["state"] == "closed", "state is %r, not closed" % ask["state"])
    check((ask["close"] or {}).get("outcome") == "accepted", "close is %r" % ask["close"])
    check((ask["verify"] or {}).get("result") == "established", "verify is %r" % ask["verify"])
    check((ask["verify"] or {}).get("independent") is True, "the verify is not independent: %r" % ask["verify"])
    for ref in (a, c, r, v, x):
        level = ctx.show(ref)["level"]
        check(level == "unverified", "%s has level %s; an agent's record is unverified" % (ref, level))
    check(not st["findings"], "a clean cycle has findings: %s" % st["findings"])
    return "closed/accepted, independent established verify, five agent records unverified"


def d02(ctx):
    sh = shutil.which("sh")
    digest = "shasum -a 256" if shutil.which("shasum") else "sha256sum" if shutil.which("sha256sum") else None
    if not sh or not digest or os.name == "nt":
        raise Skip("needs a POSIX shell with shasum or sha256sum")
    ctx.init()
    script = r'''set -e
L="$DESK/log/human/pat@shell"
mkdir -p "$L"
printf '%s\n' '{"v":"0.2","seq":1,"ts":"TS1","from":"human:pat@shell","op":"ask","text":"Is the build green?","settle":"the CI run for main shows success","by":"2099-01-01T00:00:00Z"}' >> "$L/000001.jsonl"
P=$(tail -n 1 "$L/000001.jsonl" | tr -d '\n' | DIGEST | cut -d' ' -f1)
printf '%s\n' '{"v":"0.2","seq":2,"ts":"TS2","from":"human:pat@shell","op":"checkpoint","state":{"next":"wait for an answer","heartbeat_seconds":86400},"prev":"sha256:'"$P"'"}' >> "$L/000001.jsonl"
'''
    now = dt.datetime.now(dt.timezone.utc)
    script = script.replace("TS1", ts(now)).replace("TS2", ts(now + dt.timedelta(milliseconds=5))).replace("DIGEST", digest)
    proc = subprocess.run([sh, "-c", script], env=dict(os.environ, DESK=str(ctx.desk)), capture_output=True)
    check(proc.returncode == 0, "the shell script failed: %s" % proc.stderr[:300])
    code, data = ctx.validate()
    check(data["verdict"] == "verified" and code == 0, "validate: %s (exit %d), findings %s" % (data["verdict"], code, data["findings"]))
    check(data["counts"].get("chain_broken", 0) == 0 and data["counts"].get("unchained", 0) == 0, "chain counts %s" % data["counts"])
    ask = ask_of(ctx.status(), "human:pat@shell#1")
    check(ask["state"] == "open", "the printf ask is %s" % ask["state"])
    return "printf ask and checkpoint with a shell-computed prev: validate verified (exit 0)"


def d03(ctx):
    total = int(os.environ.get("DESK_CONFORMANCE_D03_RECORDS", "1000"))
    min_kills = int(os.environ.get("DESK_CONFORMANCE_D03_KILLS", "20"))
    ctx.init()
    raw = Raw(ctx.desk, B)
    done = threading.Event()

    def writer():
        for i in range(total):
            raw.append({"op": "ask", "text": "item %d" % i, "settle": "handled", "by": FAR})
            if i % 25 == 24:
                time.sleep(0.01)
        done.set()
    rng = random.Random(20260924)
    handled, handled_log = set(), []
    kills, deliveries, redelivered_unhandled = 0, 0, 0
    pending_unhandled = set()
    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    deadline = time.monotonic() + 900
    base = ctx.impl.argv + ["watch", "--as", A, "--catch-up", "--format", "json", "--poll", "0.05", "--exit-after", "4",
                            "--desk", str(ctx.desk), "--state-dir", str(ctx.state)]
    env = {k: v for k, v in os.environ.items() if not k.startswith("DESK_")}
    env["DESK_CONFIG"] = str(ctx.tmp / "none.json")
    while len(handled) < total or kills < min_kills:
        check(time.monotonic() < deadline, "timed out with %d of %d handled and %d kills" % (len(handled), total, kills))
        writer_done = done.is_set()
        proc = subprocess.Popen(base, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        budget = rng.randint(3, max(4, total // (min_kills + 5)))
        seen_here = 0
        try:
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                event = json.loads(line)
                if event.get("type") != "record":
                    continue
                ref = event["ref"]
                deliveries += 1
                if ref in pending_unhandled:
                    redelivered_unhandled += 1
                    pending_unhandled.discard(ref)
                seen_here += 1
                phase = rng.random() if seen_here >= budget else None
                if phase is not None and phase < 0.34:
                    pending_unhandled.add(ref)     # killed before handling: must come back
                    break
                if ref not in handled:
                    handled.add(ref)
                    handled_log.append(ref)
                if phase is not None and phase < 0.67:
                    break                          # killed after handling, before the acknowledgment
                ack = ctx.impl.run(ctx, ["ack", ref, "--as", A, "--desk", str(ctx.desk), "--state-dir", str(ctx.state)])
                check(ack.returncode == 0, "ack %s exited %d: %s" % (ref, ack.returncode, ack.stderr[:300]))
                if phase is not None:
                    break                          # killed after the acknowledgment
                if len(handled) >= total and kills >= min_kills:
                    break
        finally:
            if proc.poll() is None:
                proc.send_signal(signal.SIGKILL if hasattr(signal, "SIGKILL") else signal.SIGTERM)
                kills += 1
                natural_end = False
            else:
                natural_end = True
            proc.wait()
            proc.stdout.close()
            proc.stderr.close()
        if natural_end and writer_done and seen_here == 0:
            # a caught-up watcher delivered nothing after the writer finished: whatever is missing is lost
            check(not pending_unhandled, "%d records killed before handling never came back, e.g. %s" % (
                len(pending_unhandled), sorted(pending_unhandled)[:3]))
            check(len(handled) >= total, "%d records were never delivered" % (total - len(handled)))
            check(kills >= min_kills, "every record was handled after only %d kills" % kills)
    thread.join()
    expected = {"%s#%d" % (B, i) for i in range(1, total + 1)}
    check(handled == expected, "lost %d records, e.g. %s" % (len(expected - handled), sorted(expected - handled)[:3]))
    check(len(handled_log) == len(set(handled_log)), "a record was handled twice")
    check(kills >= min_kills, "only %d kills" % kills)
    check(not pending_unhandled, "%d records killed before handling never came back: %s" % (len(pending_unhandled), sorted(pending_unhandled)[:3]))
    return "%d records, %d kills, %d deliveries (%d redeliveries of unhandled records), none lost, each handled once" % (
        total, kills, deliveries, redelivered_unhandled)


def d04(ctx):
    ctx.init()
    raw = Raw(ctx.desk, B)
    first = raw.append({"op": "ask", "text": "first", "settle": "s", "by": FAR})
    record = raw.build({"op": "ask", "text": "second", "settle": "s", "by": FAR})
    line = json.dumps(record, separators=(",", ":")).encode()
    raw.write(line)                                                  # no newline yet
    st = ctx.status()
    refs = [a["ref"] for a in st["asks"]]
    check(refs == [first], "a partial line was consumed: asks %s" % refs)
    check(not findings(st, "invalid"), "a waiting partial line was reported invalid: %s" % findings(st, "invalid"))
    got = [e["ref"] for e in ctx.watch_json(A, "--catch-up") if e["type"] == "record"]
    check(got == [first], "watch delivered %s before the line was complete" % got)
    raw.write(b"\n")
    refs = [a["ref"] for a in ctx.status()["asks"]]
    check(refs == [first, "%s#2" % B], "the completed line is not read: %s" % refs)
    got = [e["ref"] for e in ctx.watch_json(A, "--catch-up") if e["type"] == "record"]
    check("%s#2" % B in got, "watch does not deliver the completed line: %s" % got)
    return "the partial line waited, then was read once complete"


def d05(ctx):
    ctx.init()
    raw = Raw(ctx.desk, B)
    raw.append({"op": "ask", "text": "before", "settle": "s", "by": FAR})
    raw.append_bytes(b'{"v":"0.2","seq":2,garbage-here')
    after = raw.append({"op": "ask", "text": "after the garbage", "settle": "s", "by": FAR}, seq=2)
    st = ctx.status()
    bad = findings(st, "invalid")
    check(bad, "no invalid finding for a malformed line")
    check(any("garbage-here" in f["detail"] for f in bad), "the invalid finding does not show the raw bytes: %s" % bad)
    check(ask_of(st, after)["state"] == "open", "the record after the malformed line is not read")
    events = ctx.watch_json(A, "--catch-up")
    check(any(e["type"] == "record" and e["ref"] == after for e in events), "watch did not deliver the record after the malformed line")
    check(any(e["type"] == "flag" and e["flag"] == "invalid" for e in events), "watch did not report the invalid line")
    return "invalid with raw bytes shown; the next record flowed"


def d06(ctx):
    ctx.init()
    raw = Raw(ctx.desk, B)
    raw.append({"op": "ask", "text": "one", "settle": "s", "by": FAR}, seq=1)
    raw.append({"op": "ask", "text": "three", "settle": "s", "by": FAR}, seq=3)
    raw.append({"op": "ask", "text": "three again", "settle": "s", "by": FAR}, seq=3)
    st = ctx.status()
    w = writer_of(st, B)
    check(w["gaps"] == [[2, 2]], "gaps %s, expected [[2, 2]]" % w["gaps"])
    check(w["duplicates"] == [3], "duplicates %s, expected [3]" % w["duplicates"])
    check(findings(st, "gap", B) and findings(st, "duplicate", B), "gap or duplicate finding missing: %s" % st["findings"])
    return "gap 2 and duplicate 3 reported for the writer"


def d07(ctx):
    ctx.init()
    first = ctx.w(B, "ask", "--text", "make the directory", "--settle", "s")
    lock_path = ctx.desk / "log" / "agent" / "worker@t" / ".lock"
    before = len(ctx.lines_of(B))
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        proc = ctx.w(B, "ask", "--text", "while locked", "--settle", "s", expect=None)
        check(proc.returncode == 4, "a write while the identity is locked exited %d, not 4" % proc.returncode)
        check(len(ctx.lines_of(B)) == before, "a line was appended while the identity was locked")
    finally:
        os.close(fd)
    ctx.w(B, "ask", "--text", "after the lock", "--settle", "s")
    proc = ctx.w(B, "append", stdin=json.dumps({"op": "ask", "from": C, "text": "x", "settle": "y"}).encode(), expect=None)
    check(proc.returncode == 3, "append with another writer's from exited %d, not 3" % proc.returncode)
    raw = Raw(ctx.desk, B)
    raw.append({"op": "ask", "text": "spoofed", "settle": "s", "by": FAR, "from": C})
    st = ctx.status()
    check(any("from" in f["detail"] for f in findings(st, "invalid")), "a line naming another writer is not invalid: %s" % st["findings"])
    check(all(w["identity"] != C for w in st["writers"]), "the spoofed record was attributed to %s" % C)
    return "exit 4 while locked; append as another writer exit 3; spoofed line invalid"


def d08(ctx):
    ctx.init()
    a = ctx.w(A, "ask", "--text", "who takes this?", "--settle", "s")
    b = ctx.w(B, "claim", a)
    ctx.w(C, "claim", a)
    ask = ask_of(ctx.status(), a)
    check("contested" in ask["flags"], "overlapping claims are not contested: %s" % ask["flags"])
    check(ask["holder"] == b, "holder is %s, expected the earlier claim %s" % (ask["holder"], b))
    yak, xen = Raw(ctx.desk, "agent:yak@t"), Raw(ctx.desk, "agent:xen@t")
    q = Raw(ctx.desk, "agent:quinn@t").append({"op": "ask", "text": "tie", "settle": "s", "by": FAR}, when=at(0))
    yak.append({"op": "claim", "re": q, "lease_duration_seconds": 600}, when=at(10))
    xc = xen.append({"op": "claim", "re": q, "lease_duration_seconds": 600}, when=at(10))
    holders = {ask_of(ctx.status(as_of=at(20)), q)["holder"] for _ in range(2)}
    check(holders == {xc}, "tied claims: holder %s, expected %s by from order" % (holders, xc))
    return "contested with the earlier claim as holder; a tie on ts breaks by from"


def d09(ctx):
    ctx.init()
    q = Raw(ctx.desk, A).append({"op": "ask", "text": "lease", "settle": "s", "by": FAR}, when=at(0))
    wb = Raw(ctx.desk, B)
    c1 = wb.append({"op": "claim", "re": q, "lease_duration_seconds": 60}, when=at(10))
    live = ask_of(ctx.status(as_of=at(70)), q)
    check(live["live_claims"] == [c1] and live["state"] == "claimed", "at renew_time + duration the lease should hold: %s" % live)
    gone = ask_of(ctx.status(as_of=ts(T0 + dt.timedelta(seconds=70, milliseconds=1))), q)
    check(gone["live_claims"] == [] and gone["state"] == "open", "1 ms later the lease should be expired: %s" % gone)
    wb.append({"op": "claim", "re": q, "lease_duration_seconds": 60}, when=at(40))
    renewed = ask_of(ctx.status(as_of=at(100)), q)
    check(renewed["live_claims"] == [c1], "the renewal did not move renew_time: %s" % renewed)
    expired = ask_of(ctx.status(as_of=ts(T0 + dt.timedelta(seconds=100, milliseconds=1))), q)
    check(expired["live_claims"] == [], "the renewed lease should expire 60 s after the renewal: %s" % expired)
    return "held at exactly renew_time + 60 s, expired 1 ms later; renewal moved the expiry"


def d10(ctx):
    ctx.init()
    a = ctx.w(A, "ask", "--text", "fix it", "--settle", "tests pass")
    ctx.w(B, "claim", a)
    ctx.w(B, "report", a, "--text", "fixed")
    before = len(ctx.lines_of(A))
    proc = ctx.w(A, "close", a, "--outcome", "accepted", expect=None)
    check(proc.returncode == 3, "an accepted close with no verify exited %d, not 3" % proc.returncode)
    check(len(ctx.lines_of(A)) == before, "the refused close was written")
    raw = Raw(ctx.desk, A)
    close = raw.append({"op": "close", "re": a, "outcome": "accepted"})
    st = ctx.status()
    check(findings(st, "unverified_close", close), "a raw unverified close is not flagged: %s" % st["findings"])
    check(ask_of(st, a)["state"] != "closed", "the ask was treated as closed")
    return "tool refused (exit 3); raw close flagged unverified_close, ask not closed"


def d11(ctx):
    ctx.init()
    a = ctx.w(A, "ask", "--text", "fix it", "--settle", "tests pass")
    r = ctx.w(B, "report", a, "--text", "fixed")
    ctx.w(B, "verify", r, "--result", "established")
    ask = ask_of(ctx.status(), a)
    check(ask["verify"] and ask["verify"]["independent"] is False, "a self-verify counted as independent: %s" % ask["verify"])
    proc = ctx.w(A, "close", a, "--outcome", "accepted", expect=None)
    check(proc.returncode == 3, "an accepted close on a self-verify exited %d, not 3" % proc.returncode)
    return "self-verify not independent; accepted close refused"


def d12(ctx):
    ctx.init()
    a = ctx.w(A, "ask", "--text", "is it safe?", "--settle", "a scan finds nothing")
    r = ctx.w(B, "report", a, "--text", "looks fine")
    proc = ctx.w(C, "verify", r, "--result", "unknown", expect=None)
    check(proc.returncode == 3, "unknown without a reason exited %d, not 3" % proc.returncode)
    ctx.w(C, "verify", r, "--result", "unknown", "--reason", "the scanner was down")
    ask = ask_of(ctx.status(), a)
    check(ask["state"] == "verified" and ask["verify"]["result"] == "unknown", "state %s verify %s" % (ask["state"], ask["verify"]))
    check(ask["close"] is None, "the ask was closed")
    proc = ctx.w(A, "close", a, "--outcome", "accepted", expect=None)
    check(proc.returncode == 3, "an accepted close on an unknown verify exited %d, not 3" % proc.returncode)
    return "unknown needs a reason; the ask stays unclosed"


def d13(ctx):
    ctx.init()
    q = Raw(ctx.desk, A).append({"op": "ask", "text": "by a time", "settle": "s", "by": at(3600).replace(".000Z", "Z")}, when=at(0))
    after = ask_of(ctx.status(as_of=at(3601)), q)
    before = ask_of(ctx.status(as_of=at(3599)), q)
    check("expired" in after["flags"], "not expired one second after the deadline: %s" % after["flags"])
    check("expired" not in before["flags"], "expired one second before the deadline")
    return "expired at deadline + 1 s, not at deadline - 1 s"


def d14(ctx):
    ctx.init()
    Raw(ctx.desk, B).append({"op": "checkpoint", "state": {"next": "work", "heartbeat_seconds": 60}}, when=at(0))
    check(writer_of(ctx.status(as_of=at(61)), B)["silent"] is True, "not silent 61 s after a 60 s heartbeat")
    check(writer_of(ctx.status(as_of=at(59)), B)["silent"] is False, "silent 59 s after a 60 s heartbeat")
    return "silent at 61 s, not at 59 s"


def d15(ctx):
    ctx.init()
    a1 = ctx.w(A, "ask", "--text", "the old wording", "--settle", "s")
    a2 = ctx.w(A, "ask", "--text", "the new wording", "--settle", "s", "--supersedes", a1, "--reason", "clarified")
    st = ctx.status()
    check(len(st["asks"]) == 1, "expected one thread, got %s" % [a["ref"] for a in st["asks"]])
    ask = st["asks"][0]
    check(ask["ref"] == a1 and ask["text"] == "the new wording", "the thread is %s with text %r" % (ask["ref"], ask["text"]))
    check(ctx.show(a1)["superseded_by"] == a2, "show does not name the successor")
    check(any(b"the old wording" in l for l in ctx.lines_of(A)), "the original line is gone")
    return "one thread with the new text; the original stays in the log"


def d16(ctx):
    ctx.init()
    raw = Raw(ctx.desk, B)
    first = raw.append({"op": "ask", "text": "future", "settle": "s", "by": FAR, "x_future": {"a": 1}})
    later = raw.append({"op": "ponder", "text": "an operation from a later version"})
    code, data = ctx.validate()
    check(data["verdict"] == "verified" and code == 0, "validate %s (exit %d): %s" % (data["verdict"], code, data["findings"]))
    check(data["counts"].get("ignored") == 1, "ignored count %s" % data["counts"].get("ignored"))
    check(ctx.show(first)["record"].get("x_future") == {"a": 1}, "the unknown field did not survive")
    check(later in ctx.status()["ignored"], "the unknown operation is not listed as ignored")
    return "unknown field preserved; unknown operation ignored and counted"


def d17(ctx):
    ctx.init()
    canary = ctx.tmp / "CANARY"
    c = str(canary)
    payloads = ["$(touch %s)" % c, "`touch %s`" % c, "; touch %s" % c, "| sh -c 'touch %s'" % c, "&& touch %s" % c,
                "\x1b[31mred\x1b[0m\x1b]0;title\x07", "'; touch %s; '" % c]
    raw = Raw(ctx.desk, B)
    refs = []
    for i, p in enumerate(payloads):
        refs.append(raw.append({"op": "ask", "text": p, "settle": p, "by": FAR}))
    r = raw.append({"op": "report", "re": refs[0], "text": payloads[5],
                    "evidence": [{"kind": "command", "ref": "touch %s" % c}, {"kind": "file", "ref": "$(touch %s)" % c}]})
    refs.append(r)
    refs.append(raw.append({"op": "verify", "re": r, "result": "refuted", "reason": payloads[0]}))
    outputs = []
    for args in (["status"], ["inbox", "--as", A], ["validate"], ["stats"], ["export", "--cloudevents"],
                 ["watch", "--as", A, "--catch-up", "--exit-after", "1", "--poll", "0.1"]):
        proc = ctx.cmd(args, timeout=60)
        outputs.append((args[0], proc.stdout))
    for ref in refs:
        outputs.append(("show", ctx.cmd(["show", ref]).stdout))
    render = ctx.cmd(["render", "--html"])
    if render.returncode == 0:
        outputs.append(("render", render.stdout))
    check(not canary.exists(), "record content was executed: the canary file exists")
    escaped = [name for name, out in outputs if b"\x1b" in out or b"\x07" in out]
    check(not escaped, "raw control bytes reached the terminal output of: %s" % escaped)
    return "no canary after %d read commands; no raw escape bytes in output" % len(outputs)


def d18(ctx):
    ctx.init()
    before = len(ctx.lines_of(A))
    proc = ctx.w(A, "ask", "--text", "x" * 20000, "--settle", "s", expect=None)
    check(proc.returncode == 3, "an oversized record exited %d, not 3" % proc.returncode)
    check(len(ctx.lines_of(A)) == before, "the oversized record was written")
    secret = "use AKIA" + "ABCDEFGHIJKLMNOP" + " for the upload"
    proc = ctx.w(A, "ask", "--text", secret, "--settle", "s", expect=None)
    check(proc.returncode == 0 and proc.stderr.strip(), "secrets: warn should write with a warning (exit %d, stderr %r)" % (proc.returncode, proc.stderr[:100]))
    conf = json.loads((ctx.desk / "desk.json").read_text())
    conf["policy"]["secrets"] = "refuse"
    (ctx.desk / "desk.json").write_text(json.dumps(conf))
    count = len(ctx.lines_of(A))
    proc = ctx.w(A, "ask", "--text", secret, "--settle", "s", expect=None)
    check(proc.returncode == 3 and len(ctx.lines_of(A)) == count, "secrets: refuse did not refuse (exit %d)" % proc.returncode)
    return "oversized refused; a likely secret warned, then refused under secrets: refuse"


def d19(ctx):
    kh, ph = make_key(ctx, "hana")
    kb, pb = make_key(ctx, "worker")
    ctx.init(policy={"signing": "required"}, members=[{"identity": H, "keys": [ph]}, {"identity": B, "keys": [pb]}])
    sh, sb = ssh_signer(ctx, kh), ssh_signer(ctx, kb)
    rh, rb = Raw(ctx.desk, H), Raw(ctx.desk, B)
    unsigned = rh.append({"op": "ask", "text": "unsigned", "settle": "s", "by": FAR})
    bad = rh.append({"op": "ask", "text": "bad signature", "settle": "s", "by": FAR},
                    sign=lambda rec: sh(dict(rec, text="something else")))
    good = rh.append({"op": "ask", "text": "signed", "settle": "s", "by": FAR}, sign=sh)
    report = rb.append({"op": "report", "re": good, "text": "done"}, sign=sb)
    verify = rh.append({"op": "verify", "re": report, "result": "established",
                        "evidence": [{"kind": "record", "ref": report, "digest": sha(rb.last)}]}, sign=sh)
    st = ctx.status()
    refs = [a["ref"] for a in st["asks"]]
    check(unsigned not in refs and bad not in refs, "an unsigned or mis-signed ask was accepted: %s" % refs)
    check(len(findings(st, "invalid")) >= 2, "expected two invalid findings: %s" % findings(st, "invalid"))
    check(good in refs, "the correctly signed ask was not accepted: %s" % st["findings"])
    check(ctx.show(verify)["level"] == "human_verified", "a member's signed verify is %s" % ctx.show(verify)["level"])
    check(ctx.show(report)["level"] == "unverified", "a signed agent record rose above unverified")
    proc = ctx.w(A, "ask", "--text", "no key", "--settle", "s", expect=None)
    check(proc.returncode == 3, "an unsigned write under signing: required exited %d, not 3" % proc.returncode)
    return "unsigned and mis-signed invalid; signed accepted; a person's signed verify human_verified"


def d20(ctx):
    git = shutil.which("git")
    if not git:
        raise Skip("git is not on PATH")
    rounds = int(os.environ.get("DESK_CONFORMANCE_D20_ROUNDS", "100"))
    env = dict(os.environ, GIT_AUTHOR_NAME="d20", GIT_AUTHOR_EMAIL="d20@example.test", GIT_COMMITTER_NAME="d20",
               GIT_COMMITTER_EMAIL="d20@example.test", GIT_TERMINAL_PROMPT="0")

    def g(cwd, *args):
        proc = subprocess.run([git, "-c", "init.defaultBranch=main", "-c", "pull.rebase=false"] + list(args),
                              cwd=cwd, capture_output=True, env=env)
        if proc.returncode != 0:
            raise Fail("git %s in %s failed: %s %s" % (" ".join(args), Path(cwd).name, proc.stdout[-300:], proc.stderr[-300:]))
        return proc
    remote = ctx.tmp / "remote.git"
    g(ctx.tmp, "init", "-q", "--bare", str(remote))
    c1, c2 = ctx.tmp / "c1", ctx.tmp / "c2"
    g(ctx.tmp, "clone", "-q", str(remote), str(c1))
    ctx.init(desk=c1)
    g(c1, "add", "desk.json", ".gitignore") if (c1 / ".gitignore").exists() else g(c1, "add", "desk.json")
    g(c1, "commit", "-q", "-m", "desk")
    g(c1, "push", "-q", "origin", "HEAD:main")
    g(ctx.tmp, "clone", "-q", "--branch", "main", str(remote), str(c2))
    g(c1, "branch", "-q", "--set-upstream-to=origin/main")
    for i in range(rounds):
        for clone, who in ((c1, A), (c2, B)):
            ctx.w(who, "ask", "--text", "round %d from %s" % (i, who), "--settle", "s", desk=clone)
            own = "log/" + who.replace(":", "/", 1)
            g(clone, "add", "--", own)
            g(clone, "commit", "-q", "-m", "desk: %s round %d" % (who, i), "--", own)
            g(clone, "pull", "-q", "--no-edit", "origin", "main")
            g(clone, "push", "-q", "origin", "HEAD:main")
    g(c1, "pull", "-q", "--no-edit", "origin", "main")
    code, data = ctx.validate(desk=c1)
    check(code == 0 and data["verdict"] == "verified", "the merged desk: %s (exit %d) %s" % (data["verdict"], code, data["findings"][:3]))
    check(data["counts"]["records"] == 2 * rounds, "records %s, expected %d" % (data["counts"]["records"], 2 * rounds))
    return "%d rounds through git, no merge conflict, merged desk verified with %d records" % (rounds, 2 * rounds)


def d21(ctx):
    ctx.init()
    a = ctx.w(A, "ask", "--text", "prove it", "--settle", "a log file")
    raw_b, raw_c, raw_a = Raw(ctx.desk, B), Raw(ctx.desk, C), Raw(ctx.desk, A)
    report = raw_b.append({"op": "report", "re": a, "text": "see the log",
                           "evidence": [{"kind": "file", "ref": str(ctx.tmp / "no-such-file.log")}]})
    verify = raw_c.append({"op": "verify", "re": report, "result": "established",
                           "evidence": [{"kind": "record", "ref": "agent:ghost@t#9", "digest": sha(b"ghost")}]})
    close = raw_a.append({"op": "close", "re": a, "outcome": "accepted",
                          "evidence": [{"kind": "record", "ref": "agent:ghost@t#10"}]})
    shown = ctx.show(report)
    check(shown["evidence"] and shown["evidence"][0]["flag"] == "unresolved", "the missing file is not unresolved: %s" % shown["evidence"])
    st = ctx.status()
    check(findings(st, "unresolved", verify), "the verify citing a missing record is not unresolved")
    check(findings(st, "unresolved", close) and findings(st, "unverified_close", close), "the close citing a missing verify: %s" % st["findings"])
    check(ask_of(st, a)["state"] != "closed", "the ask was closed on unresolved evidence")
    return "missing file, record and verify each unresolved; ask not closed"


def d22(ctx):
    ctx.init()
    elsewhere = ctx.tmp / "elsewhere"
    Raw(elsewhere, "agent:evil@t").append({"op": "ask", "text": "outside", "settle": "s", "by": FAR})
    target = elsewhere / "log" / "agent" / "evil@t"
    link = ctx.desk / "log" / "agent" / "evil@t"
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        raise Skip("cannot create symlinks here: %s" % exc)
    raw = Raw(ctx.desk, B)
    raw.append({"op": "ask", "text": "real", "settle": "s", "by": FAR})
    os.symlink(target / "000001.jsonl", raw.dir / "000002.jsonl")
    st = ctx.status()
    check(all(w["identity"] != "agent:evil@t" for w in st["writers"]), "a symlinked writer directory was read")
    check(any("evil@t" in f["subject"] for f in findings(st, "invalid")), "the symlinked directory is not reported: %s" % st["findings"])
    check(any("000002" in f["subject"] for f in findings(st, "invalid")), "the symlinked segment is not reported")
    check(writer_of(st, B)["records"] == 1, "records were read through the symlinked segment")
    proc = ctx.w("agent:evil@t", "ask", "--text", "x", "--settle", "s", expect=None)
    check(proc.returncode == 5, "a write through a symlinked log directory exited %d, not 5" % proc.returncode)
    return "symlinked directory and segment invalid and unread; write through a link exit 5"


def d23(ctx):
    ctx.init()
    raw = Raw(ctx.desk, B)
    for word in ("alpha", "bravo", "charl"):
        raw.append({"op": "ask", "text": word, "settle": "s", "by": FAR})
    st = ctx.status(reader=A)
    check(not findings(st, "rewritten"), "rewritten before any change")
    lines = raw.path.read_bytes().split(b"\n")
    rewrite_line(raw.path, 2, lines[2].replace(b"charl", b"delta"))
    for attempt in (1, 2):
        st = ctx.status(reader=A)
        check(findings(st, "rewritten", B), "read %d after an in-place edit: no rewritten finding (%s)" % (attempt, st["findings"]))
        check(writer_of(st, B)["rewritten"] is True, "the writer is not marked rewritten")
    proc = ctx.cmd(["seek", B, "1", "--reason", "reviewed the edit", "--as", A])
    check(proc.returncode == 0, "seek exited %d" % proc.returncode)
    check(not findings(ctx.status(reader=A), "rewritten", B), "seek did not re-baseline the read memory")
    data = raw.path.read_bytes().split(b"\n")
    raw.path.write_bytes(b"\n".join(data[:2]) + b"\n")
    check(findings(ctx.status(reader=A), "rewritten", B), "truncating an already-read line is not rewritten")
    return "in-place edit and truncation reported rewritten on every read until seek"


def d24(ctx):
    ctx.init()
    rb = Raw(ctx.desk, B)
    rb.append({"op": "ask", "text": "one", "settle": "s", "by": FAR})
    broken = rb.append({"op": "ask", "text": "two", "settle": "s", "by": FAR}, prev_value=sha(b"not the previous line"))
    rc = Raw(ctx.desk, C)
    rc.append({"op": "ask", "text": "one", "settle": "s", "by": FAR})
    loose = rc.append({"op": "ask", "text": "two", "settle": "s", "by": FAR}, prev=False)
    st = ctx.status()
    check(findings(st, "chain_broken", broken) and writer_of(st, B)["chain"] == "chain_broken", "broken prev not chain_broken")
    check(findings(st, "unchained", loose) and writer_of(st, C)["chain"] == "unchained", "missing prev not unchained under warn")
    req = ctx.tmp / "required"
    ctx.init(policy={"chain": "required"}, desk=req)
    rd = Raw(req, "agent:dan@t")
    rd.append({"op": "ask", "text": "one", "settle": "s", "by": FAR})
    excluded = rd.append({"op": "ask", "text": "two", "settle": "s", "by": FAR}, prev=False)
    st = ctx.status(desk=req)
    check(excluded not in [a["ref"] for a in st["asks"]], "under chain: required a record without prev was accepted")
    check(findings(st, "unchained", excluded), "the refused record is not reported")
    code, data = ctx.validate(desk=req)
    check(data["verdict"] == "failed" and code == 1, "validate under required: %s (exit %d)" % (data["verdict"], code))
    ref = ctx.w(A, "ask", "--text", "tool writes prev", "--settle", "s", desk=req)
    ref2 = ctx.w(A, "ask", "--text", "and again", "--settle", "s", desk=req)
    for r in (ref, ref2):
        check("unchained" not in ctx.cmd(["show", r, "--json"], desk=req).stdout.decode(), "the tool wrote an unchained record")
    return "chain_broken; unchained under warn; refused and failed under required; the tool always chains"


def d25(ctx):
    ctx.init()
    a = ctx.w(A, "ask", "--text", "which port?", "--settle", "the service answers there")
    rb = Raw(ctx.desk, B)
    rb.append({"op": "claim", "re": a, "lease_duration_seconds": 900})
    report = rb.append({"op": "report", "re": a, "text": "port 8080"})
    rb.append({"op": "checkpoint", "state": {"next": "wait for verify"}})
    verify = ctx.w(C, "verify", report, "--result", "established")
    check(not findings(ctx.status(), "rewritten"), "rewritten before any change")
    lines = rb.path.read_bytes().split(b"\n")[:-1]
    lines[1] = lines[1].replace(b"8080", b"9090")
    third = json.loads(lines[2])
    third["prev"] = sha(lines[1])
    lines[2] = json.dumps(third, separators=(",", ":")).encode()
    rb.path.write_bytes(b"\n".join(lines) + b"\n")
    st = ctx.status()
    check(writer_of(st, B)["chain"] == "chained", "the re-forged chain should check: %s" % writer_of(st, B)["chain"])
    hits = findings(st, "rewritten", report)
    check(hits and any(verify in f["detail"] for f in hits), "the witness did not catch the rewrite: %s" % st["findings"])
    return "re-forged chain checks, and the verify's digest reports the report rewritten"


def d26(ctx):
    ctx.init()
    rb = Raw(ctx.desk, B)
    head = rb.append({"op": "ask", "text": "uncited head", "settle": "s", "by": FAR})
    cp = ctx.w(C, "checkpoint", "--next", "keep reading")
    check(not findings(ctx.status(), "rewritten"), "rewritten before any change")
    rb.path.write_bytes(rb.path.read_bytes().replace(b"uncited head", b"changed head"))
    hits = findings(ctx.status(), "rewritten", head)
    check(hits and any(cp in f["detail"] for f in hits), "the seen head did not catch the rewrite: %s" % ctx.status()["findings"])
    return "a rewrite of an uncited head listed in seen is rewritten, witnessed by the checkpoint"


def d27(ctx):
    ctx.init()
    raw = Raw(ctx.desk, B)
    for i in range(5):
        raw.append({"op": "ask", "text": "n%d" % (i + 1), "settle": "s", "by": FAR})
    proc = ctx.cmd(["ack", "--upto", "%s#3" % B, "--as", A, "--json"])
    check(proc.returncode == 0 and json.loads(proc.stdout)["position"] == 4, "ack --upto #3: exit %d %s" % (proc.returncode, proc.stdout[:100]))
    got = [e["ref"] for e in ctx.watch_json(A, "--catch-up") if e["type"] == "record" and e["from"] == B]
    check(got[:2] == ["%s#4" % B, "%s#5" % B], "after ack up to #3 the deliveries were %s" % got)
    proc = ctx.cmd(["ack", "%s#5" % B, "--as", A])
    check(proc.returncode == 3, "ack of #5 with #4 unacknowledged exited %d, not 3" % proc.returncode)
    proc = ctx.cmd(["ack", "%s#3" % B, "--as", A, "--json"])
    check(proc.returncode == 0 and json.loads(proc.stdout)["position"] == 4, "re-acknowledging #3 changed the position")
    return "next delivery #4; skipping ack refused; re-ack a no-op"


def _node():
    node = shutil.which("node")
    if not node:
        return None
    return node


def d28(ctx):
    mp = ctx.siblings.get("monitor")
    if not mp or not (Path(mp) / "schemas" / "observation.json").exists():
        raise Skip("the Monitor Protocol repository is not available (pass --monitor <clone at the pinned commit>)")
    node = _node()
    if not node:
        raise Skip("Node.js is not on PATH; the Monitor Protocol's validator is TypeScript")
    mp = Path(mp).resolve()
    schema_mod = mp / "dist" / "schema.js" if (mp / "dist" / "schema.js").exists() else mp / "src" / "schema.ts"
    vocab_mod = mp / "dist" / "vocab.js" if (mp / "dist" / "vocab.js").exists() else mp / "src" / "vocab.ts"
    signed = True
    try:
        kh, ph = make_key(ctx, "hana")
        ks, ps = make_key(ctx, "ci")
        members = [{"identity": H, "keys": [ph]}, {"identity": "system:ci@t", "keys": [ps]}]
    except Skip:
        signed, members = False, []
    ctx.init(policy={"signing": "warn"}, members=members)
    a = ctx.w(A, "ask", "--text", "does the build pass?", "--settle", "CI is green")
    c = ctx.w(B, "claim", a)
    ctx.w(B, "release", c, "--reason", "handing over")
    ctx.w(C, "claim", a)
    r = ctx.w(C, "report", a, "--text", "green on main")
    ctx.w("system:ci@t", "checkpoint", "--next", "idle")
    ctx.w(H, "ask", "--text", "a person's question", "--settle", "s")
    if signed:
        rs = Raw(ctx.desk, "system:ci@t")
        rs.append({"op": "report", "re": a, "text": "run 412 passed"}, sign=ssh_signer(ctx, ks))
        rh = Raw(ctx.desk, H)
        rh.append({"op": "verify", "re": r, "result": "established",
                   "evidence": [{"kind": "record", "ref": r, "digest": sha(ctx.lines_of(C)[-1])}]}, sign=ssh_signer(ctx, kh))
        x = rh.append({"op": "close", "re": a, "outcome": "accepted",
                       "evidence": [{"kind": "record", "ref": "%s#%d" % (H, rh.seq), "digest": sha(rh.last)}]}, sign=ssh_signer(ctx, kh))
    Raw(ctx.desk, "agent:mess@t").append_bytes(b"not json at all")
    proc = ctx.cmd(["export", "--cloudevents", "--profile", "monitor-protocol"])
    check(proc.returncode == 0, "export exited %d: %s" % (proc.returncode, proc.stderr[:300]))
    events = json.loads(proc.stdout)
    collect_words(events)
    types = {e["type"] for e in events}
    for op in ("ask", "claim", "release", "report", "verify", "close", "checkpoint") if signed else ("ask", "claim", "release", "report", "checkpoint"):
        check("desk." + op in types, "no desk.%s event in the sample" % op)
    check("desk.rejected" in types, "the malformed line was not exported as rejected")
    uri = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]*$")
    for e in events:
        check(uri.match(e["source"]), "source is not a URI reference: %s" % e["source"])
        check(re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$", e["time"]), "time is not a timestamp: %s" % e["time"])
    path = ctx.tmp / "events.json"
    path.write_text(json.dumps(events))
    script = ctx.tmp / "validate.mjs"
    script.write_text("""
import { readFileSync } from "node:fs";
const { SchemaSet } = await import(%s);
const vocab = await import(%s);
const s = new SchemaSet(%s);
const events = JSON.parse(readFileSync(%s, "utf8"));
const ladder = ["unverified", "reported", "machine_verified", "certified", "human_verified"];
const tiers = ["falsified", "unverified", "derived", "measured", "src"];
const bad = [];
for (const e of events) {
  const errors = s.validate("observation", e);
  if (errors.length) bad.push([e.type, e.id, errors]);
  const vcap = vocab.ORIGIN_VERIFICATION_CEILING[e.origin], tcap = vocab.ORIGIN_TIER_CEILING[e.origin];
  if (ladder.indexOf(e.verified) > ladder.indexOf(vcap)) bad.push([e.type, e.id, "verified above the ceiling " + vcap]);
  if (tiers.indexOf(e.tier) > tiers.indexOf(tcap)) bad.push([e.type, e.id, "tier above the ceiling " + tcap]);
  if (e.origin !== "human" && (vocab.HUMAN_PRINCIPAL_ONLY.verifications.includes(e.verified) || vocab.HUMAN_PRINCIPAL_ONLY.tiers.includes(e.tier)))
    bad.push([e.type, e.id, "a human-only value on a non-human origin"]);
  if (e.verified === "certified") bad.push([e.type, e.id, "the desk never emits certified"]);
}
console.log(JSON.stringify({ total: events.length, bad }));
""" % (json.dumps(schema_mod.as_uri()), json.dumps(vocab_mod.as_uri()), json.dumps(str(mp / "schemas")), json.dumps(str(path))))
    proc = subprocess.run([node, "--no-warnings", str(script)], capture_output=True, timeout=120)
    if proc.returncode != 0 and b"Unknown file extension" in proc.stderr:
        proc = subprocess.run([node, "--no-warnings", "--experimental-strip-types", str(script)], capture_output=True, timeout=120)
    if proc.returncode != 0:
        raise Skip("the Monitor validator could not run under this Node.js: %s" % proc.stderr.decode(errors="replace")[-300:])
    result = json.loads(proc.stdout.decode().strip().splitlines()[-1])
    check(not result["bad"], "%d of %d events fail: %s" % (len(result["bad"]), result["total"], result["bad"][:3]))
    commit = subprocess.run(["git", "-C", str(mp), "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    return "%d of %d events valid against observation.json at %s with its own validator (%s); ceilings hold%s" % (
        result["total"], result["total"], commit or "?", schema_mod.relative_to(mp), "" if signed else "; unsigned writers only (no ssh-keygen)")


def d29(ctx):
    ctx.init()
    for bad in ("agent:bad", "robot:x@t", "agent:-x@t", "agent:a b@t", "agent:" + "n" * 70 + "@t", "agent:x@", "agent::x@t", "agent:x@y@z"):
        proc = ctx.w(bad, "ask", "--text", "x", "--settle", "s", expect=None)
        check(proc.returncode == 64, "the malformed identity %r exited %d, not 64" % (bad, proc.returncode))
    ref = ctx.w("user:Alex@Laptop", "ask", "--text", "alias", "--settle", "s")
    check(ref.startswith("human:alex@laptop#"), "the alias was not normalized: %s" % ref)
    check((ctx.desk / "log" / "human" / "alex@laptop" / "000001.jsonl").exists(), "the log is not at log/human/alex@laptop/000001.jsonl")
    colons = [str(p) for p in ctx.desk.rglob("*") if ":" in p.name]
    check(not colons, "paths contain a colon: %s" % colons)
    return "8 malformed identities exit 64; user: alias normalized; no colon in any path"


def d30(ctx):
    ctx.init()
    a1 = ctx.w(A, "ask", "--text", "old", "--settle", "s")
    proc = ctx.w(A, "ask", "--text", "new", "--settle", "s", "--supersedes", a1, expect=None)
    check(proc.returncode == 3, "a supersede without a reason exited %d, not 3" % proc.returncode)
    raw = Raw(ctx.desk, "agent:ray@t")
    first = raw.append({"op": "ask", "text": "original", "settle": "s", "by": FAR})
    raw.append({"op": "ask", "text": "silent correction", "settle": "s", "by": FAR, "supersedes": first})
    st = ctx.status()
    check(any("supersede" in f["detail"] or "reason" in f["detail"] for f in findings(st, "invalid")), "the raw supersede is not invalid: %s" % st["findings"])
    check(ask_of(st, first)["text"] == "original", "the raw supersede changed derived state")
    return "tool refused (exit 3); raw supersede without a reason invalid, state unchanged"


def d31(ctx):
    ctx.init()
    a = ctx.w(B, "ask", "--text", "for my person", "--settle", "s", "--on-behalf-of", H)
    shown = ctx.show(a)
    check(shown["level"] == "unverified", "on_behalf_of raised the level to %s" % shown["level"])
    check(shown["on_behalf_of"] == H and shown["record"]["from"] == B, "both identities are not shown: %s" % shown)
    try:
        key, pub = make_key(ctx, "worker")
    except Skip:
        return "unsigned: level stays unverified with both identities shown (signed case skipped: no ssh-keygen -Y)"
    desk2 = ctx.tmp / "signed"
    ctx.init(policy={"signing": "warn"}, members=[{"identity": B, "keys": [pub]}], desk=desk2)
    r = Raw(desk2, B).append({"op": "ask", "text": "signed, for a person", "settle": "s", "by": FAR, "on_behalf_of": H},
                             sign=ssh_signer(ctx, key))
    level = json.loads(ctx.cmd(["show", r, "--json"], desk=desk2).stdout)["level"]
    check(level == "unverified", "a signed agent record on behalf of a person is %s" % level)
    return "on_behalf_of never raised an agent's level, signed or not; both identities shown"


def d32(ctx):
    roles = {"actors": [{"id": "human:*", "role": "lead"}, {"id": "agent:*", "role": "worker"}],
             "permissions": {"lead": ["*"], "worker": ["ask", "claim", "release", "report", "verify", "checkpoint"]}}
    ctx.init(roles=roles)
    a = ctx.w(A, "ask", "--text", "roles", "--settle", "s")
    ctx.w(B, "claim", a)
    r = ctx.w(B, "report", a, "--text", "done")
    v = ctx.w(H, "verify", r, "--result", "established")
    proc = ctx.w(A, "close", a, "--outcome", "accepted", expect=None)
    check(proc.returncode == 3, "an agent's close under roles exited %d, not 3" % proc.returncode)
    digest = sha(ctx.lines_of(H)[-1])
    close = Raw(ctx.desk, A).append({"op": "close", "re": a, "outcome": "accepted",
                                     "evidence": [{"kind": "record", "ref": v, "digest": digest}]})
    st = ctx.status()
    check(findings(st, "unpermitted", close), "the agent's raw close is not unpermitted: %s" % st["findings"])
    check(ask_of(st, a)["state"] == "verified", "the unpermitted close changed state: %s" % ask_of(st, a)["state"])
    ctx.w(H, "close", a, "--outcome", "accepted")
    check(ask_of(ctx.status(), a)["state"] == "closed", "a permitted close did not close the ask")
    return "agent close refused (exit 3) and raw one unpermitted; a lead's close closes"


def d33(ctx):
    ctx.init()
    cycle(ctx)
    for profile in ("default", "strict"):
        code, data = ctx.validate(profile)
        check(code == 0 and data["verdict"] == "verified", "clean desk under %s: %s (exit %d)" % (profile, data["verdict"], code))
    for key in ("lines", "records", "invalid", "chain_broken", "unchained", "rewritten", "unresolved"):
        check(key in data["counts"], "validate counts lack %s" % key)
    rx = Raw(ctx.desk, "agent:xavi@t")
    rx.append({"op": "ask", "text": "one", "settle": "s", "by": FAR})
    rx.append({"op": "ask", "text": "two", "settle": "s", "by": FAR}, prev=False)
    code, data = ctx.validate("default")
    check(code == 2 and data["verdict"] == "incomplete", "unchained under default: %s (exit %d)" % (data["verdict"], code))
    code, data = ctx.validate("strict")
    check(code == 1 and data["verdict"] == "failed", "unchained under strict: %s (exit %d)" % (data["verdict"], code))
    ry = Raw(ctx.desk, "agent:yuri@t")
    ry.append({"op": "ask", "text": "one", "settle": "s", "by": FAR})
    ry.append({"op": "ask", "text": "two", "settle": "s", "by": FAR}, prev_value=sha(b"wrong"))
    for profile in ("default", "strict"):
        code, data = ctx.validate(profile)
        check(code == 1 and data["verdict"] == "failed", "chain_broken under %s: %s (exit %d)" % (profile, data["verdict"], code))
    return "verified 0 / incomplete 2 / failed 1 under both profiles, with counts"


def load_fixture():
    text = CROSSWALK_DOC.read_text(encoding="utf-8") if CROSSWALK_DOC.exists() else ""
    m = re.search(r"<!-- fixture:start -->\s*```python\n(.*?)```\s*<!-- fixture:end -->", text, re.S)
    return m.group(1) if m else None


def d34(ctx):
    cp = ctx.siblings.get("commitment")
    if not cp or not (Path(cp) / "tools" / "verify_ledger.py").exists():
        raise Skip("the Commitment Protocol repository is not available (pass --commitment <clone at the pinned commit>)")
    source = load_fixture()
    if source is None:
        raise Skip("no fixture found in docs/crosswalk-commitment-protocol.md (between fixture markers)")
    ctx.init()
    cycle(ctx)
    events = json.loads(ctx.cmd(["export", "--cloudevents"]).stdout)
    namespace = {}
    exec(compile(source, str(CROSSWALK_DOC), "exec"), namespace)
    ledger = ctx.tmp / "ledger.jsonl"
    added = namespace["bridge"](events, ledger, workspace="desk-conformance")
    rows = [json.loads(l) for l in ledger.read_text().splitlines() if l.strip()] if ledger.exists() else []
    check(rows, "the bridge wrote no rows from this export (%d events)" % len(events))
    check(added == len(rows), "the bridge reported %s rows but wrote %d" % (added, len(rows)))
    keys = [r.get("source_key") for r in rows]
    check(all(keys) and len(set(keys)) == len(keys), "source_key missing or repeated: %s" % keys)
    proc = subprocess.run([sys.executable, str(Path(cp) / "tools" / "verify_ledger.py"), "--json", str(ledger)], capture_output=True, text=True)
    verdict = json.loads(proc.stdout)["verdict"] if proc.stdout.strip().startswith("{") else proc.stdout[-200:]
    check(proc.returncode == 0 and verdict == "verified", "the reference verifier returned %s (exit %d)" % (verdict, proc.returncode))
    again = namespace["bridge"](events, ledger, workspace="desk-conformance")
    check(again == 0 and len(ledger.read_text().splitlines()) == len(rows), "a second bridge added %d rows" % again)
    commit = subprocess.run(["git", "-C", str(cp), "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    ops = [r["op"] for r in rows]
    return "%d rows (%s): verifier at %s says verified (exit 0); keys unique; second bridge added 0" % (len(rows), ", ".join(ops), commit or "?")


def d35(ctx):
    ctx.init()
    a, *_ = cycle(ctx)
    for args in (["show", a], ["status"], ["validate"], ["stats"], ["export", "--cloudevents"]):
        proc = ctx.cmd(args + ["--as", A])
        check(proc.returncode == 0, "%s --as exited %d: %s" % (args[0], proc.returncode, proc.stderr[:200]))
    return "show, status, validate, stats and export accept --as"


def d36(ctx):
    R = "agent:reader@t"
    roles = {"actors": [{"id": R, "role": "reviewers"}, {"id": "*", "role": "member"}],
             "permissions": {"reviewers": ["*"], "member": ["*"]}}
    ctx.init(roles=roles)
    to_me = ctx.w("agent:x@t", "ask", "--text", "for the reader", "--settle", "s", "--to", R)
    to_role = ctx.w("agent:x@t", "ask", "--text", "for reviewers", "--settle", "s", "--to", "role:reviewers")
    mine = ctx.w(R, "ask", "--text", "the reader's question", "--settle", "s", "--to", "agent:y@t")
    cites = ctx.w("agent:y@t", "report", mine, "--text", "an answer")
    open_ask = ctx.w("agent:z@t", "ask", "--text", "anyone?", "--settle", "s")
    unrelated_ask = ctx.w("agent:z@t", "ask", "--text", "a private matter", "--settle", "s", "--to", "agent:q@t")
    unrelated = ctx.w("agent:z@t", "claim", unrelated_ask)
    data = ctx.json_of(ctx.cmd(["inbox", "--as", R, "--json"]), "inbox")
    items = {i["ref"]: set(i["why"]) for i in data["items"]}
    expect = {to_me: "to_me", to_role: "to_role", cites: "cites_mine", open_ask: "open_ask"}
    for ref, why in expect.items():
        check(ref in items and why in items[ref], "%s missing or without %s: %s" % (ref, why, data["items"]))
    check(unrelated not in items and unrelated_ask not in items, "records that need nothing from the reader were listed")
    check(data["other_unacknowledged"] >= 2, "the others were not counted: %s" % data["other_unacknowledged"])
    proc = ctx.cmd(["ack", "--upto", unrelated, "--as", R])
    check(proc.returncode == 0, "ack --upto exited %d" % proc.returncode)
    data = ctx.json_of(ctx.cmd(["inbox", "--as", R, "--json"]), "inbox")
    zs = [i for i in data["items"] if i["from"] == "agent:z@t"]
    check(not zs, "acknowledged records still listed: %s" % zs)
    return "addressed, role, cites-mine, thread and open asks listed; the rest counted, then cleared by ack --upto"


def d38(ctx):
    ctx.init()
    R, O = "agent:reader@t", "agent:owner@t"
    wait = ctx.w(O, "ask", "--text", "a decision that someone else must make", "--settle", "the decision is written")
    other = ctx.w(O, "ask", "--text", "nothing for the reader", "--settle", "s", "--to", "agent:q@t")
    before = [e["ref"] for e in ctx.watch_json(R, "--catch-up") if e["type"] == "record"]
    check(wait in before and other in before, "positive control: before any acknowledgment both asks are delivered: %s" % before)
    ctx.w(R, "checkpoint", "--blocked-on", "%s: waiting for the owner's decision" % wait, "--heartbeat", "3600")
    proc = ctx.cmd(["ack", "--upto", other, "--as", R])
    check(proc.returncode == 0, "ack --upto exited %d: %s" % (proc.returncode, proc.stderr[:200]))
    again = [e["ref"] for e in ctx.watch_json(R, "--catch-up") if e["type"] == "record" and e["from"] == O]
    check(not again, "acknowledged records were delivered again: %s" % again)

    def inbox():
        data = ctx.json_of(ctx.cmd(["inbox", "--as", R, "--json"]), "inbox")
        return {i["ref"]: set(i["why"]) for i in data["items"]}
    items = inbox()
    check("waiting" in items.get(wait, set()), "the ask the reader waits on is not listed as waiting: %s" % items)
    check(other not in items, "an acknowledged record that needs nothing is still listed: %s" % items)
    answer = ctx.w("agent:helper@t", "report", wait, "--text", "the owner decided")
    items = inbox()
    check("thread" in items.get(answer, set()), "a new record on the awaited thread is not listed as thread: %s" % items)
    ctx.w(O, "close", wait, "--outcome", "withdrawn", "--reason", "decided elsewhere")
    items = inbox()
    check("waiting" not in items.get(wait, set()), "a closed ask is still listed as waiting: %s" % items)
    return "waiting written on the desk, then acknowledged: not re-delivered, listed as waiting until closed, its thread followed"


def d37(ctx):
    registry = json.loads(REGISTRY.read_text())
    allowed = {"flags": set(registry["desk_flags"]), "levels": set(registry["levels"]),
               "outcomes": set(registry["outcomes"]), "gaps": set(registry["shared_gaps"])}
    if not any(WORDS.values()):
        raise Skip("no check in this run printed a flag, level, outcome or gap word")
    stray = {k: sorted(v - allowed[k]) for k, v in WORDS.items() if v - allowed[k]}
    check(not stray, "words outside the registry draft: %s" % stray)
    return "%d flags, %d levels, %d outcomes, %d gaps seen, all in the registry" % tuple(len(WORDS[k]) for k in ("flags", "levels", "outcomes", "gaps"))


CHECKS = [
    ("D01", "§5, R8, §7.2", d01), ("D02", "P9, R16", d02), ("D03", "R7", d03), ("D04", "R4", d04),
    ("D05", "R4, P14", d05), ("D06", "R5", d06), ("D07", "R2", d07), ("D08", "R9", d08), ("D09", "R9", d09),
    ("D10", "R8", d10), ("D11", "R8, P7", d11), ("D12", "P8, §5", d12), ("D13", "R10", d13), ("D14", "R10", d14),
    ("D15", "R18, R1", d15), ("D16", "R11", d16), ("D17", "R6, P4", d17), ("D18", "R12", d18), ("D19", "§9", d19),
    ("D20", "§11, P2", d20), ("D21", "R17, R14", d21), ("D22", "R14", d22), ("D23", "R15", d23), ("D24", "R16", d24),
    ("D25", "R17", d25), ("D26", "R17", d26), ("D27", "R7", d27), ("D28", "§12", d28), ("D29", "§3", d29),
    ("D30", "R18", d30), ("D31", "R19, R20", d31), ("D32", "R21", d32), ("D33", "§7.5", d33), ("D34", "§12", d34),
    ("D35", "D35 (CONTEXT §3)", d35), ("D36", "§8, Monitor P12", d36), ("D38", "§8", d38), ("D37", "§13", d37),
]


def commit_of(impl):
    for token in impl.argv:
        path = Path(token)
        if path.exists():
            proc = subprocess.run(["git", "-C", str(path.resolve().parent), "rev-parse", "--short", "HEAD"], capture_output=True, text=True)
            if proc.returncode == 0:
                dirty = subprocess.run(["git", "-C", str(path.resolve().parent), "status", "--porcelain", "--", str(path.resolve())],
                                       capture_output=True, text=True).stdout.strip()
                return proc.stdout.strip() + ("+uncommitted" if dirty else "")
    return "unknown"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Desk Protocol conformance suite, spec 0.2")
    parser.add_argument("--impl", default=os.environ.get("DESK_IMPL"), help='the command template, e.g. "python3 desk.py"')
    parser.add_argument("--only", help="comma-separated check ids")
    parser.add_argument("--json", dest="json_out", help="also write the report as JSON to this path")
    parser.add_argument("--monitor", default=os.environ.get("MP_DIR") or str(ROOT / ".siblings" / "monitor-protocol"))
    parser.add_argument("--commitment", default=os.environ.get("CP_DIR") or str(ROOT / ".siblings" / "commitment-protocol"))
    parser.add_argument("--commit", help="the commit tested (default: git of the implementation's file)")
    parser.add_argument("--keep", action="store_true", help="keep the temporary directories")
    args = parser.parse_args(argv)
    if not args.impl:
        parser.error("pass --impl or set DESK_IMPL")
    impl = Impl(args.impl)
    only = {x.strip().upper() for x in args.only.split(",")} if args.only else None
    root_tmp = Path(tempfile.mkdtemp(prefix="desk-conformance-"))
    siblings = {"monitor": args.monitor if Path(args.monitor).exists() else None,
                "commitment": args.commitment if Path(args.commitment).exists() else None}
    started = dt.datetime.now(dt.timezone.utc)
    results = []
    for cid, rule, fn in CHECKS:
        if only and cid not in only:
            continue
        ctx = Ctx(impl, root_tmp, siblings)
        t = time.monotonic()
        try:
            detail = fn(ctx)
            result = "PASS"
        except Skip as exc:
            result, detail = "SKIP", str(exc)
        except Fail as exc:
            result, detail = "FAIL", str(exc)
        except Exception as exc:  # a crash in a check is a failure of that check, reported with its trace
            result, detail = "FAIL", "%s: %s | %s" % (type(exc).__name__, exc, traceback.format_exc(limit=3).replace("\n", " ")[-400:])
        results.append({"id": cid, "rule": rule, "result": result, "detail": detail, "seconds": round(time.monotonic() - t, 2)})
        print("%s %-4s %s" % (cid, result, detail), flush=True)
    if not args.keep:
        shutil.rmtree(root_tmp, ignore_errors=True)
    counts = {k: sum(1 for r in results if r["result"] == k) for k in ("PASS", "FAIL", "SKIP")}
    header = {"date": started.strftime("%Y-%m-%dT%H:%M:%SZ"), "suite_version": SUITE_VERSION, "implementation": args.impl,
              "commit": args.commit or commit_of(impl), "python": sys.version.split()[0], "platform": sys.platform}
    print()
    print("Desk Protocol conformance report")
    print("date %s | suite %s | implementation %s | commit %s | python %s | %s" % (
        header["date"], header["suite_version"], header["implementation"], header["commit"], header["python"], header["platform"]))
    print()
    print("| Check | Rule | Result | Detail |")
    print("|---|---|---|---|")
    for r in results:
        print("| %s | %s | %s | %s |" % (r["id"], r["rule"], r["result"], r["detail"].replace("|", "\\|")))
    print()
    print("summary: %d PASS, %d FAIL, %d SKIP of %d checks" % (counts["PASS"], counts["FAIL"], counts["SKIP"], len(results)))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps({"header": header, "results": results, "summary": counts}, indent=1) + "\n")
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
