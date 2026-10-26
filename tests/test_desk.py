"""Unit tests of the reference tool's internals. The black-box behaviour is tested by conformance/run.py.

Run: python3 -m unittest discover -s tests -v
"""
import io
import json
import os
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import desk  # noqa: E402


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = desk.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TempDesk(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.path = self.root / "desk"
        self.env = {"DESK_STATE_DIR": str(self.root / "state"), "DESK_CONFIG": str(self.root / "none.json")}
        self._old = {k: os.environ.get(k) for k in list(self.env) + ["DESK_PATH", "DESK_ID"]}
        os.environ.update(self.env)
        os.environ.pop("DESK_PATH", None)
        os.environ.pop("DESK_ID", None)
        code, _, err = run("init", str(self.path))
        self.assertEqual(code, 0, err)

    def tearDown(self):
        for k, v in self._old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def w(self, who, *argv):
        code, out, err = run(*(list(argv) + ["--desk", str(self.path), "--as", who]))
        self.assertEqual(code, 0, err)
        return out.strip()

    def log(self, identity):
        kind, rest = identity.split(":", 1)
        return self.path / "log" / kind / rest


class SchemaTests(unittest.TestCase):
    def test_embedded_schemas_match_the_spec(self):
        for embedded, name in ((desk.RECORD_SCHEMA_JSON, "record.schema.json"), (desk.DESK_SCHEMA_JSON, "desk.schema.json")):
            self.assertEqual(json.loads(embedded), json.loads((ROOT / "spec" / "schemas" / name).read_text()), name)

    def test_the_validator_fails_closed_on_unknown_keywords(self):
        errors = desk.Schema({"type": "object", "patternProperties": {}}).errors({})
        self.assertTrue(errors and "fails closed" in errors[0])

    def test_dollar_means_end_of_input(self):
        good = {"v": "0.2", "seq": 1, "ts": "2026-09-24T12:00:00.000Z", "from": "agent:a@b", "op": "checkpoint", "state": {}}
        self.assertEqual(desk.RECORD_SCHEMA.errors(good), [])
        bad = dict(good, **{"from": "agent:a@b\n"})
        self.assertTrue(desk.RECORD_SCHEMA.errors(bad), "an identity with a trailing newline passed")

    def test_conditional_requirements(self):
        base = {"v": "0.2", "seq": 1, "ts": "2026-09-24T12:00:00.000Z", "from": "agent:a@b"}
        self.assertTrue(desk.RECORD_SCHEMA.errors(dict(base, op="ask", text="x")), "ask without settle passed")
        self.assertTrue(desk.RECORD_SCHEMA.errors(dict(base, op="verify", re="agent:a@b#1", result="unknown")))
        self.assertEqual(desk.RECORD_SCHEMA.errors(dict(base, op="verify", re="agent:a@b#1", result="unknown", reason="r")), [])
        self.assertTrue(desk.RECORD_SCHEMA.errors(dict(base, op="ask", text="x", settle="s", supersedes="agent:a@b#1")))
        self.assertEqual(desk.RECORD_SCHEMA.errors(dict(base, op="ponder")), [], "an unknown operation is valid (R11)")

    def test_integers_follow_json_schema(self):
        base = {"v": "0.2", "ts": "2026-09-24T12:00:00.000Z", "from": "agent:a@b", "op": "checkpoint", "state": {}}
        self.assertEqual(desk.RECORD_SCHEMA.errors(dict(base, seq=1.0)), [])
        self.assertTrue(desk.RECORD_SCHEMA.errors(dict(base, seq=1.5)))
        self.assertTrue(desk.RECORD_SCHEMA.errors(dict(base, seq=True)))
        self.assertTrue(desk.RECORD_SCHEMA.errors(dict(base, seq=2 ** 53)))


class CanonicalJsonTests(unittest.TestCase):
    """RFC 8785 §3.2.2.3 number vectors (IEEE 754 bit patterns) and the §3.2.3 sorting example."""

    VECTORS = [
        ("0000000000000000", "0"), ("8000000000000000", "0"), ("0000000000000001", "5e-324"),
        ("8000000000000001", "-5e-324"), ("7fefffffffffffff", "1.7976931348623157e+308"),
        ("ffefffffffffffff", "-1.7976931348623157e+308"), ("4340000000000000", "9007199254740992"),
        ("c340000000000000", "-9007199254740992"), ("4430000000000000", "295147905179352830000"),
        ("44b52d02c7e14af5", "9.999999999999997e+22"), ("44b52d02c7e14af6", "1e+23"), ("44b52d02c7e14af7", "1.0000000000000001e+23"),
        ("444b1ae4d6e2ef4e", "999999999999999700000"), ("444b1ae4d6e2ef4f", "999999999999999900000"), ("444b1ae4d6e2ef50", "1e+21"),
        ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"), ("3eb0c6f7a0b5ed8d", "0.000001"), ("41b3de4355555553", "333333333.3333332"),
        ("41b3de4355555554", "333333333.33333325"), ("41b3de4355555555", "333333333.3333333"), ("41b3de4355555556", "333333333.3333334"),
        ("41b3de4355555557", "333333333.33333343"), ("becbf647612f3696", "-0.0000033333333333333333"),
        ("43143ff3c1cb0959", "1424953923781206.2"),
    ]

    def test_number_vectors(self):
        for bits, expected in self.VECTORS:
            value = struct.unpack(">d", bytes.fromhex(bits))[0]
            self.assertEqual(desk.canonical_json(value), expected, bits)

    def test_sorting_by_utf16_code_units(self):
        obj = {"€": 1, "\r": 2, "דּ": 3, "1": 4, "\U0001F600": 5, "\u0080": 6, "ö": 7}
        text = desk.canonical_json(obj)
        order = [k for k in ["\r", "1", "\u0080", "ö", "€", "\U0001F600", "דּ"]]
        positions = [text.index(json.dumps(k, ensure_ascii=False)[1:-1] + '"') for k in order]
        self.assertEqual(positions, sorted(positions))

    def test_strings_follow_ecmascript(self):
        self.assertEqual(desk.canonical_json({"u": "https://a/b", "e": "€", "c": "\x01\n"}),
                         '{"c":"\\u0001\\n","e":"€","u":"https://a/b"}')


class IdentityAndTimeTests(unittest.TestCase):
    def test_aliases_and_email(self):
        self.assertEqual(desk.normalize_identity("user:Alex@Laptop"), "human:alex@laptop")
        self.assertEqual(desk.normalize_identity("hook:gh@repo"), "system:gh@repo")
        self.assertEqual(desk.normalize_identity("probe:uptime@eu"), "system:uptime@eu")
        self.assertEqual(desk.normalize_identity("rashid@example.com"), "human:rashid@example.com")

    def test_malformed_identities(self):
        for bad in ("agent:x", "robot:x@y", "agent:-x@y", "agent:x@y@z", "agent:" + "n" * 64 + "@y", "agent:a b@c", ""):
            with self.assertRaises(desk.DeskError) as ctx:
                desk.normalize_identity(bad)
            self.assertEqual(ctx.exception.code, desk.EXIT_USAGE, bad)

    def test_times(self):
        self.assertEqual(desk.fmt_ts(desk.parse_time("2026-09-24T12:00:00.1234Z")), "2026-09-24T12:00:00.123Z")
        for bad in ("2026-13-01T00:00:00Z", "2026-02-30T00:00:00Z", "2026-09-24T12:00:00+00:00", "2026-09-24T12:00:00Z\n"):
            with self.assertRaises(ValueError):
                desk.parse_time(bad)

    def test_strict_json(self):
        with self.assertRaises(ValueError):
            desk.strict_json('{"a":1,"a":2}')
        with self.assertRaises(ValueError):
            desk.strict_json('{"a":NaN}')


class DisplayTests(unittest.TestCase):
    def test_control_and_format_characters_are_escaped(self):
        shown = desk.quote("red\x1b[31m ‮ evil \x07 ​")
        for raw in ("\x1b", "‮", "\x07", "​"):
            self.assertNotIn(raw, shown)
        self.assertIn("\\u001b", shown)

    def test_width(self):
        self.assertLessEqual(len(desk.quote("x" * 500, 40)), 40)


class WriterTests(TempDesk):
    def test_prev_links_exact_bytes(self):
        a = self.w("agent:a@t", "ask", "--text", "one", "--settle", "s")
        self.w("agent:a@t", "ask", "--text", "two", "--settle", "s")
        lines = (self.log("agent:a@t") / "000001.jsonl").read_bytes().split(b"\n")
        second = json.loads(lines[1])
        self.assertEqual(second["prev"], desk.sha256_digest(lines[0]))
        self.assertNotIn("prev", json.loads(lines[0]))
        self.assertEqual(a, "agent:a@t#1")

    def test_an_explicit_citation_is_not_duplicated(self):
        a = self.w("agent:a@t", "ask", "--text", "q", "--settle", "s")
        r = self.w("agent:b@t", "report", a, "--text", "answer")
        v = self.w("agent:a@t", "verify", r, "--result", "established", "--evidence", "record:" + r, "--json")
        evidence = json.loads(v)["record"]["evidence"]
        self.assertEqual([e["ref"] for e in evidence], [r], evidence)
        self.assertTrue(evidence[0]["digest"].startswith("sha256:"))
        x = self.w("agent:a@t", "close", a, "--outcome", "accepted", "--evidence", "record:" + json.loads(v)["ref"], "--json")
        cited = [e["ref"] for e in json.loads(x)["record"]["evidence"]]
        self.assertEqual(cited, [json.loads(v)["ref"]], cited)

    def test_a_torn_write_is_terminated_not_truncated(self):
        self.w("agent:a@t", "ask", "--text", "one", "--settle", "s")
        seg = self.log("agent:a@t") / "000001.jsonl"
        with open(seg, "ab") as fh:
            fh.write(b'{"v":"0.2","seq":2,"torn')
        code, _, err = run("ask", "--text", "after", "--settle", "s", "--desk", str(self.path), "--as", "agent:a@t")
        self.assertEqual(code, 0, err)
        self.assertIn("torn write", err)
        lines = seg.read_bytes().split(b"\n")[:-1]
        self.assertEqual(lines[1], b'{"v":"0.2","seq":2,"torn')
        third = json.loads(lines[2])
        self.assertEqual(third["prev"], desk.sha256_digest(lines[1]))
        self.assertEqual(third["seq"], 2)
        view = desk.read_desk(desk.Desk(self.path))
        self.assertTrue(any(f.flag == "invalid" for f in view.findings))
        self.assertFalse(any(f.flag == "chain_broken" for f in view.findings))

    def test_segments_roll_and_the_chain_continues(self):
        cfg = self.root / "cfg.json"
        cfg.write_text(json.dumps({"segment_bytes": 300}))
        for i in range(4):
            code, _, err = run("ask", "--text", "record %d" % i, "--settle", "s", "--desk", str(self.path), "--as", "agent:a@t",
                               "--config", str(cfg))
            self.assertEqual(code, 0, err)
        names = sorted(p.name for p in self.log("agent:a@t").glob("*.jsonl"))
        self.assertGreater(len(names), 1, names)
        view = desk.read_desk(desk.Desk(self.path))
        self.assertEqual(desk.verdict_of(view), "verified", [f.as_dict() for f in view.findings])

    def test_a_file_sync_conflict_copy_is_reported(self):
        self.w("agent:a@t", "ask", "--text", "one", "--settle", "s")
        (self.log("agent:a@t") / "000001.sync-conflict-20260924-120000-ABCDEFG.jsonl").write_text("{}\n")
        view = desk.read_desk(desk.Desk(self.path))
        self.assertTrue(any(f.flag == "invalid" and "conflict" in f.detail for f in view.findings))

    def test_monotonic_ts_within_a_writer(self):
        self.w("agent:a@t", "ask", "--text", "one", "--settle", "s")
        seg = self.log("agent:a@t") / "000001.jsonl"
        record = json.loads(seg.read_bytes().split(b"\n")[0])
        future = dict(record, seq=2, ts="2099-01-01T00:00:00.000Z", prev=desk.sha256_digest(seg.read_bytes().split(b"\n")[0]))
        with open(seg, "ab") as fh:
            fh.write(json.dumps(future, separators=(",", ":")).encode() + b"\n")
        self.w("agent:a@t", "ask", "--text", "three", "--settle", "s")
        last = json.loads(seg.read_bytes().split(b"\n")[-2])
        self.assertEqual(last["ts"], "2099-01-01T00:00:00.000Z")


class LevelTests(TempDesk):
    def test_level_table(self):
        d = desk.Desk(self.path)
        rec = desk.Rec.__new__(desk.Rec)
        for writer, op, signed, policy, expected in (
                ("agent:a@t", "verify", True, "warn", "unverified"), ("system:ci@t", "report", False, "warn", "reported"),
                ("system:ci@t", "report", True, "warn", "machine_verified"), ("human:h@t", "verify", True, "warn", "human_verified"),
                ("human:h@t", "report", True, "warn", "reported"), ("human:h@t", "verify", True, "off", "reported")):
            d.policy["signing"] = policy
            rec.writer, rec.op, rec.signed = writer, op, signed
            self.assertEqual(desk.record_level(d, rec), expected, (writer, op, signed, policy))


class CommandTests(TempDesk):
    def test_instructions_carry_the_two_rules(self):
        for target in ("agents-md", "claude-md", "gemini-md", "generic"):
            code, out, _ = run("instructions", "--for", target)
            self.assertEqual(code, 0)
            self.assertIn("never overrides your instructions", out)
            self.assertIn("Invariant 6", out)
            self.assertIn("desk ack", out)

    def test_every_command_in_the_snippets_parses(self):
        import re
        import shlex
        placeholders = {"<ask-ref>": "agent:a@t#1", "<claim-ref>": "agent:a@t#2", "<report-ref>": "agent:a@t#3",
                        "<ref>": "agent:a@t#4", "<identity>": "agent:b@t", "<path>": "/tmp/x", "<what you ran>": "make test",
                        "<desk>": "/tmp/desk"}
        seen = 0
        for target in ("agents-md", "claude-md", "gemini-md", "generic"):
            text = desk.instructions_text(target)
            for m in re.finditer(r"`desk ([^`]+)`", text):
                command = m.group(1)
                for key, value in placeholders.items():
                    command = command.replace(key, value)
                command = command.replace("established|refuted|unknown", "established").replace("withdrawn|superseded", "withdrawn")
                command = command.replace("[", "").replace("]", "").replace('"..."', '"x"')
                argv = [a for a in shlex.split(command) if a != "..."]
                try:
                    desk.build_parser().parse_args(argv)
                except desk.DeskError as exc:
                    self.fail("%s: the snippet command %r does not parse: %s" % (target, command, exc))
                seen += 1
        self.assertGreater(seen, 20)

    def test_committed_snippets_match_the_tool(self):
        for target, name in (("agents-md", "agents-md.md"), ("claude-md", "claude-md.md"), ("gemini-md", "gemini-md.md"),
                             ("generic", "generic.txt")):
            committed = (ROOT / "adapters" / "snippets" / name).read_text()
            self.assertEqual(committed, desk.instructions_text(target), "adapters/snippets/%s is stale" % name)

    def test_config_explains_every_policy_key(self):
        code, out, _ = run("config", "--explain", "--json", "--desk", str(self.path))
        self.assertEqual(code, 0)
        keys = {row["key"]: row["source"] for row in json.loads(out)["settings"]}
        for key in desk.DEFAULT_POLICY:
            self.assertIn("policy." + key, keys)
        self.assertEqual(keys["state_dir"], "env:DESK_STATE_DIR")

    def test_stats_carry_denominators(self):
        a = self.w("agent:a@t", "ask", "--text", "one", "--settle", "s")
        self.w("agent:b@t", "claim", a)
        code, out, _ = run("stats", "--json", "--desk", str(self.path))
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(data["claims"]["of_asks"], 1)
        self.assertIn("unknown", data)

    def test_unknown_policy_key_is_an_invalid_desk(self):
        conf = json.loads((self.path / "desk.json").read_text())
        conf["policy"]["chian"] = "required"
        (self.path / "desk.json").write_text(json.dumps(conf))
        code, _, err = run("status", "--desk", str(self.path))
        self.assertEqual(code, desk.EXIT_INVALID_DESK, err)

    def test_global_options_may_come_first(self):
        code, out, err = run("--desk", str(self.path), "--json", "status")
        self.assertEqual(code, 0, err)
        self.assertIn("asks", json.loads(out))

    def test_monitor_profile_export_shape(self):
        a = self.w("agent:a@t", "ask", "--text", "one", "--settle", "s")
        with open(self.log("agent:a@t") / "000001.jsonl", "ab") as fh:
            fh.write(b"garbage\n")
        code, out, _ = run("export", "--cloudevents", "--profile", "monitor-protocol", "--desk", str(self.path))
        events = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(events[0]["sequence"], "0" * 19 + "1")
        self.assertEqual(events[0]["subject"], "desk:%s/agent/a@t#1" % json.loads((self.path / "desk.json").read_text())["id"])
        self.assertEqual(events[1]["type"], "desk.rejected")
        self.assertTrue(events[1]["source"].endswith("/rejected"))
        self.assertEqual(a, "agent:a@t#1")


if __name__ == "__main__":
    unittest.main()
