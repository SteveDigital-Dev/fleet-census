"""Weekly bulletin tests. Run: python3 -m unittest discover tests   (no internet needed)"""
import datetime as dt
import json
import os
import plistlib
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("FLEET_CACHE_DIR", tempfile.mkdtemp())
import bulletin as bu  # noqa: E402
import fleet  # noqa: E402

RECEIVED = []


class Ntfy(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        RECEIVED.append((self.headers.get("Title"), self.rfile.read(int(self.headers["Content-Length"])).decode()))
        self.send_response(200); self.end_headers()


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        bu.SETTINGS, bu.SNOOZE, bu.OUT = cls.tmp / "settings.json", cls.tmp / "snooze.json", cls.tmp / "bulletins"
        cls.hosts = fleet.load_census(ROOT / "examples" / "census")
        cls.inv = json.loads((ROOT / "inventory.example.json").read_text())
        cls.adv = json.loads((ROOT / "rules" / "advisories.json").read_text())["advisories"]

    def items(self):
        return bu.explain(bu.collect_items(self.hosts, self.inv, self.adv, None), self.hosts)

    def test_defaults_are_conservative(self):
        s = bu.default_settings()
        self.assertTrue(all(v is False for v in s["extras"].values()))
        self.assertFalse(s["schedule"]["enabled"])
        hosts = [h for h, _ in bu.contacts(s)]
        self.assertEqual(hosts, ["www.cisa.gov", "api.osv.dev"])
        s["sources"]["osv"] = False
        s["extras"]["epss"] = True
        self.assertEqual([h for h, _ in bu.contacts(s)], ["www.cisa.gov", "api.first.org"])

    def test_items_have_why_and_how(self):
        its = self.items()
        self.assertTrue(its)
        for i in its:
            self.assertTrue(i["why"]) and self.assertTrue(i["how"])
        port = next(i for i in its if i["title"].startswith("Port 6379"))
        self.assertIn("ss -tulpn | grep :6379", port["how"][0])
        mac = next(i for i in its if i["machine"] == "studio-mini" and "CoreGraphics" in i["title"])
        self.assertIn("System Settings", mac["how"][0])

    def test_level(self):
        its = self.items()
        level, why = bu.threat_level(its, [])
        self.assertEqual(level, "red")  # PHP2Shell is exploited + critical
        calm = [dict(i, severity="low", exploited=False) for i in its]
        self.assertEqual(bu.threat_level(calm, [])[0], "green")
        self.assertEqual(bu.threat_level([dict(its[0], severity="medium", exploited=False)], [])[0], "amber")

    def test_possibly_patched_not_red(self):
        it = {"machine": "x", "severity": "critical", "title": "PHP2Shell (CVE-1): possibly vulnerable (distro package - verify)",
              "detail": "", "action": "", "source": "census check", "exploited": True, "cves": [], "refs": [], "key": "k"}
        bu.explain([it], [])
        self.assertEqual((it["severity"], it["exploited"]), ("high", False))
        self.assertEqual(bu.threat_level([it], [])[0], "amber")

    def test_changes(self):
        its = self.items()
        a = bu.snapshot(self.hosts, its, "red")
        b = json.loads(json.dumps(a))
        b["items"] = b["items"][1:]
        b["ports"]["pi-garage"] = [22, 80, 8188]
        b["software"]["pi-garage"]["nginx"] = "1.22.2"
        d = bu.diff(a, b)
        self.assertEqual(len(d["fixed"]), 1)
        self.assertIn("pi-garage: 8188", d["ports_opened"])
        self.assertIn("pi-garage: 6379", d["ports_closed"])
        self.assertIn("pi-garage: nginx 1.22.1 → 1.22.2", d["software"])
        self.assertIsNone(bu.diff(None, a))

    def test_snooze_and_expiry(self):
        its = self.items()
        today = dt.date.today()
        bu.SNOOZE.write_text(json.dumps([
            {"key": "CVE-2026-86950", "machine": "studio-mini", "reason": "r", "until": (today + dt.timedelta(days=3)).isoformat()},
            {"key": "firewall-is-off", "machine": "*", "reason": "old", "until": (today - dt.timedelta(days=1)).isoformat()}]))
        kept, hidden, expired = bu.apply_snoozes(its)
        self.assertEqual([(i["machine"], i["key"]) for i in hidden], [("studio-mini", "CVE-2026-86950")])
        self.assertEqual([s["key"] for s in expired], ["firewall-is-off"])
        self.assertTrue(any(i["key"] == "firewall-is-off" for i in kept))  # expired snooze no longer hides
        bu.SNOOZE.unlink()

    def test_eol(self):
        orig = bu.th._get_json
        bu.th._get_json = lambda url, *a, **k: (
            [{"cycle": "7.4", "eol": "2022-11-28", "latest": "7.4.33"}] if url.endswith("/php.json") else
            [{"cycle": "12", "eol": (dt.date.today() + dt.timedelta(days=30)).isoformat()}] if url.endswith("/debian.json") else
            [{"cycle": "26", "eol": False}])
        try:
            eol = bu.check_eol(self.hosts, self.inv, offline=True, log=lambda m: None)
        finally:
            bu.th._get_json = orig
        titles = {(e["machine"], e["severity"]): e["title"] for e in eol}
        self.assertIn("no longer gets security fixes", titles[("pi-garage", "high")])   # php 7.4 (manual install)
        self.assertIn("Debian 12 stops getting", titles[("pi-garage", "medium")])      # within 90 days
        self.assertFalse(any(e["machine"] == "studio-mini" for e in eol))              # macOS 26 still supported

    def test_epss(self):
        its = self.items()
        orig = bu.th._get_json
        bu.th._get_json = lambda url, *a, **k: {"data": [{"cve": "CVE-2026-86950", "epss": "0.93", "percentile": "0.99"}]}
        try:
            n = bu.add_epss(its, offline=True, log=lambda m: None)
        finally:
            bu.th._get_json = orig
        self.assertEqual(n, 1)
        self.assertAlmostEqual(next(i for i in its if "CVE-2026-86950" in i["cves"])["epss"], 0.93)

    def test_alert_only_when_it_matters(self):
        srv = HTTPServer(("127.0.0.1", 0), Ntfy)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        s = bu.default_settings()
        s["alerts"].update(ntfy_url=f"http://127.0.0.1:{srv.server_port}/t", min_level="red")
        its = self.items()
        self.assertFalse(bu.send_alert(s, "amber", its, log=lambda m: None))
        self.assertTrue(bu.send_alert(s, "red", its, log=lambda m: None))
        srv.shutdown()
        title, body = RECEIVED[-1]
        self.assertEqual(title, "Fleet health check")
        self.assertNotIn("studio-mini", body)  # names only if allowed

    def test_markdown_respects_extras(self):
        its = self.items()
        level, why = bu.threat_level(its, [])
        b = {"date": "2026-10-24", "level": level, "why": why, "headlines": its, "minor": [], "eol": [],
             "snoozed": [], "snooze_expired": [], "changes": None, "extras": {k: False for k in bu.EXTRAS},
             "contacts": [], "checklist": []}
        md = bu.render_md(b)
        self.assertIn("Threat level: RED", md)
        self.assertIn("Why this matters", md)
        for section in ("## What changed", "## End of life", "## Home devices", "fleet.py snooze"):
            self.assertNotIn(section, md)
        b["extras"] = {k: True for k in bu.EXTRAS}
        md = bu.render_md(b)
        for section in ("## What changed", "## End of life", "## Home devices", "fleet.py snooze"):
            self.assertIn(section, md)

    def test_plist_is_valid(self):
        d = plistlib.loads(bu.plist_xml({"weekday": 1, "hour": 9, "minute": 17}).encode())
        self.assertEqual(d["StartCalendarInterval"], {"Weekday": 1, "Hour": 9, "Minute": 17})
        self.assertIn("fleet.py bulletin --quiet", d["ProgramArguments"][2])

    def test_setup_walkthrough(self):
        answers = iter(["mybox", "", "n",              # name, CISA yes (default), OSV no
                        "y", "", "", "", "", "y",      # extras: changes yes ... checklist yes
                        "",                            # weekly schedule: no (default)
                        "n"])                          # don't run now
        rc = bu.setup_cmd(type("A", (), {"defaults": False})(), inp=lambda q: next(answers))
        s = bu.load_settings()
        self.assertEqual(rc, 0)
        self.assertEqual(s["machine_name"], "mybox")
        self.assertEqual(s["sources"], {"cisa_kev": True, "osv": False})
        self.assertEqual([k for k, v in s["extras"].items() if v], ["changes", "home_checklist"])
        self.assertFalse(s["schedule"]["enabled"])


if __name__ == "__main__":
    unittest.main()
