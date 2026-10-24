"""Run: python3 -m unittest discover tests   (no internet needed)"""
import datetime as dt
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
FIX = ROOT / "tests" / "fixtures"


class FakeOSV(BaseHTTPRequestHandler):
    """Pretends to be api.osv.dev: nginx 1.22.1-9 on Debian 12 has one vuln."""
    def log_message(self, *a):
        pass

    def _send(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        res = []
        for q in body["queries"]:
            hit = q["package"] == {"name": "nginx", "ecosystem": "Debian:12"} and q["version"] == "1.22.1-9"
            res.append({"vulns": [{"id": "DSA-9999-1"}]} if hit else {})
        self._send({"results": res})

    def do_GET(self):
        self._send({"id": "DSA-9999-1", "summary": "nginx - test vuln", "aliases": ["CVE-2099-0004"],
                    "affected": [{"package": {"name": "nginx", "ecosystem": "Debian:12"},
                                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.22.1-9+deb12u3"}]}]}]})


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), FakeOSV)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        os.environ["FLEET_OSV_URL"] = f"http://127.0.0.1:{cls.srv.server_port}"
        cls.tmp = tempfile.mkdtemp()
        os.environ["FLEET_CACHE_DIR"] = cls.tmp
        import fleet, threats  # noqa: E402  (import after env is set)
        cls.fleet, cls.threats = fleet, threats
        # set directly too: another test module may have imported threats first
        threats.OSV_URL, threats.CACHE = os.environ["FLEET_OSV_URL"], Path(cls.tmp)
        cls.hosts = fleet.load_census(ROOT / "examples" / "census")
        cls.inv = json.loads((ROOT / "inventory.example.json").read_text())
        cls.adv = json.loads((ROOT / "rules" / "advisories.json").read_text())["advisories"]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_version_rules(self):
        by = {self.fleet.name_of(h): self.fleet.check_host(h, self.adv, 30) for h in self.hosts}
        titles = lambda n: " ".join(f["title"] for f in by[n])
        self.assertIn("PHP2Shell", titles("pi-garage"))        # 7.4 -> unsupported branch
        self.assertIn("PHP2Shell", titles("studio-mini"))      # 8.4.20 < 8.4.27
        self.assertIn("CoreGraphics", titles("studio-mini"))   # macOS 26.6 < 26.7.1
        self.assertIn("Port 6379", titles("pi-garage"))
        self.assertIn("SSH accepts passwords", titles("pi-garage"))

    def test_fixed_versions_pass(self):
        h = {"software": [{"name": "php", "version": "8.4.27", "source": "manual"}], "os": {}}
        self.assertEqual(self.fleet.check_advisories(h, self.adv), [])
        h = {"software": [], "os": {"family": "macos", "version": "27.0"}}
        self.assertEqual(self.fleet.check_advisories(h, self.adv), [])

    def test_manual_ipad(self):
        mf = self.fleet.manual_findings(self.inv, self.adv)
        self.assertIn("old-ipad", mf)

    def test_threat_scan(self):
        res = self.threats.scan(self.hosts, self.inv, days=30, kev_file=FIX / "kev-sample.json", log=lambda m: None)
        mini = {x["id"]: x for x in res["machines"]["studio-mini"]}
        pi = {x["id"]: x for x in res["machines"]["pi-garage"]}
        self.assertIn("CVE-2026-86950", mini)                  # Apple macOS via "Multiple Products"
        self.assertIn("CVE-2099-0001", mini)                   # PHP via homebrew php
        self.assertNotIn("CVE-2099-0003", mini)                # Exchange must not match
        if (dt.date.today() - dt.date(2026, 10, 22)).days <= 30:
            self.assertEqual(mini["CVE-2099-0001"]["severity"], "critical")  # recent + ransomware
        self.assertEqual(pi["CVE-2099-0002"]["severity"], "info") if "CVE-2099-0002" in pi else None
        osv = [x for x in res["machines"]["pi-garage"] if x["source"] == "OSV"]
        self.assertEqual(len(osv), 1)
        self.assertEqual(osv[0]["fixed"], "1.22.1-9+deb12u3")
        self.assertEqual(osv[0]["severity"], "critical")       # OSV CVE is also in KEV
        self.assertIn("my-iphone (manual)", res["machines"])

    def test_dashboard(self):
        import dashboard
        res = self.threats.scan(self.hosts, self.inv, kev_file=FIX / "kev-sample.json", log=lambda m: None)
        data = dashboard.build_data(self.hosts, self.inv, self.adv, 30, res)
        out = Path(self.tmp) / "d.html"
        files = dashboard.write(data, out)
        self.assertTrue((Path(self.tmp) / "fleet-data.js").read_text().startswith("window.FLEET_SECURITY = "))
        one = dashboard.write(data, Path(self.tmp) / "one.html", inline=True)[0].read_text()
        self.assertNotIn('src="fleet-data.js"', one)
        self.assertEqual(len(files), 2)

    def test_osv_ecosystems(self):
        e = self.threats.osv_ecosystem
        self.assertEqual(e({"os": {"id": "ubuntu", "version": "24.04"}}), "Ubuntu:24.04:LTS")
        self.assertEqual(e({"os": {"id": "linuxmint", "version": "22.3"}}), "Ubuntu:24.04:LTS")
        self.assertEqual(e({"os": {"id": "debian", "version": "12"}}), "Debian:12")
        self.assertIsNone(e({"os": {"id": "arch", "version": ""}}))


if __name__ == "__main__":
    unittest.main()
