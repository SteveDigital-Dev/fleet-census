"""Hostile-input tests: names, SSH targets, malformed census files.
Run: python3 -m unittest discover tests   (no internet or SSH server needed)"""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import fleet  # noqa: E402
import schema  # noqa: E402

HOSTILE_NAMES = ["a'b", "$(touch /tmp/fleet-pwned)", "../../evil", "x;id", "two words", "名前", "-x", "..", "a" * 65,
                 "`id`", "x\nid", ""]


class Names(unittest.TestCase):
    def test_safe_name(self):
        for ok in ("pi-garage", "studio.mini", "box_1", "A"):
            self.assertTrue(schema.safe_name(ok), ok)
        for bad in HOSTILE_NAMES:
            self.assertFalse(schema.safe_name(bad), repr(bad))

    def test_census_rejects_hostile_names(self):
        for bad in HOSTILE_NAMES[:-1]:  # an empty --name means "use the hostname"
            r = subprocess.run(["bash", str(ROOT / "census.sh"), "--name", bad, "--out", "-"],
                               capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 2, repr(bad))
            self.assertIn("Machine names may only use", r.stderr)
        self.assertFalse(Path("/tmp/fleet-pwned").exists())

    def test_collect_rejects_before_ssh(self):
        out = tempfile.mkdtemp()
        cases = [f"user@host={n}" for n in HOSTILE_NAMES if n] + \
                ["-oProxyCommand=touch /tmp/fleet-pwned2", "user@ho`id`st=x", "user@ho st=x", "-x=ok"]
        for spec in cases:
            r = subprocess.run(["bash", str(ROOT / "collect.sh"), "--out-dir", out, "--", spec],
                               capture_output=True, text=True, timeout=30)
            self.assertNotEqual(r.returncode, 0, spec)
            self.assertIn("FAILED", r.stdout, spec)
            self.assertNotIn("ssh:", r.stdout + r.stderr, spec)  # rejected before ssh ever ran
        self.assertEqual(list(Path(out).iterdir()), [])
        self.assertFalse(Path("/tmp/fleet-pwned2").exists())


class Validation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.good = json.loads((ROOT / "examples" / "census" / "shared-server.json").read_text())

    def bad(self, mutate):
        d = copy.deepcopy(self.good)
        mutate(d)
        return schema.validate(d)

    def test_examples_valid(self):
        for p in (ROOT / "examples" / "census").glob("*.json"):
            self.assertEqual(schema.validate_file(p)[1], [], p.name)

    def test_structural_problems(self):
        cases = {
            "missing host": lambda d: d.pop("host"),
            "unsafe name": lambda d: d["host"].update(name="../x"),
            "port as text": lambda d: d["listening"][0].update(port="22"),
            "port out of range": lambda d: d["listening"][0].update(port=70000),
            "port as bool": lambda d: d["listening"][0].update(port=True),
            "bad exposure": lambda d: d["listening"][0].update(exposure="everywhere"),
            "software not list": lambda d: d.update(software={"php": "8"}),
            "software without name": lambda d: d["software"].append({"version": "1"}),
            "negative pending": lambda d: d["updates"].update(pending=-3),
            "bool firewall as text": lambda d: d["security"].update(firewall_active="yes"),
            "bad version": lambda d: d.update(census_version="latest"),
            "bad time": lambda d: d.update(collected_at="yesterday"),
            "huge string": lambda d: d["host"].update(role="x" * 10000),
            "bad family": lambda d: d["os"].update(family="templeos"),
            "account mode": lambda d: d["accounts"].update(mode="everyone"),
            "account tools": lambda d: d["accounts"]["users"][1]["software"].update(pipx="httpie"),
            "secret count": lambda d: d["secrets_present"].update(env_files=-1),
        }
        for label, mutate in cases.items():
            self.assertNotEqual(self.bad(mutate), [], label)
        self.assertEqual(schema.validate([1, 2]), ["top level: must be a JSON object"])

    def test_file_problems(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "empty.json").write_text("")
        (tmp / "banner.json").write_text("Welcome to the server!\n" + json.dumps(self.good))
        (tmp / "cut.json").write_text(json.dumps(self.good)[:500])
        (tmp / "big.json").write_text(" " * (schema.MAX_BYTES + 1))
        (tmp / "binary.json").write_bytes(b"\xff\xfe\x00garbage")
        for f, needle in (("empty", "empty"), ("banner", "login banner"), ("cut", "not valid JSON"),
                          ("big", "larger than any real census"), ("binary", "isn't text")):
            doc, errors = schema.validate_file(tmp / f"{f}.json")
            self.assertIsNone(doc, f)
            self.assertIn(needle, " ".join(errors), f)
        ok = tmp / "ok.json"
        ok.write_text(json.dumps(self.good))
        self.assertEqual(schema.validate_file(ok, expect_name="shared-server")[1], [])
        self.assertIn("was expected", schema.validate_file(ok, expect_name="other")[1][0])

    def test_load_census_skips_invalid(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "good.json").write_text(json.dumps(self.good))
        bad = copy.deepcopy(self.good)
        bad["listening"][0]["port"] = "not-a-port"
        (tmp / "bad.json").write_text(json.dumps(bad))
        (tmp / "junk.json").write_text("{not json")
        hosts = fleet.load_census(tmp)
        self.assertEqual([fleet.name_of(h) for h in hosts], ["shared-server"])

    def test_validate_cli(self):
        r = subprocess.run([sys.executable, str(ROOT / "fleet.py"), "validate",
                            str(ROOT / "examples" / "census" / "pi-garage.json")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        tmp = Path(tempfile.mkdtemp()) / "x.json"
        tmp.write_text('{"census_version": "1.0.0"}')
        r = subprocess.run([sys.executable, str(ROOT / "fleet.py"), "validate", str(tmp)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("NOT a valid census", r.stderr)


if __name__ == "__main__":
    unittest.main()
