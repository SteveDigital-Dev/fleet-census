"""
dashboard.py - build an offline HTML dashboard from census + findings + threats.

Writes two files by default:
  dashboard.html   the page (no data inside, safe to share as a template)
  fleet-data.js    the data, loaded as  window.FLEET_SECURITY = {...}

Both open straight from disk (file://), no server, no internet, no libraries.
With --inline the data goes inside the HTML instead, giving one file.
"""
import datetime as dt
import json
from pathlib import Path

import fleet

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE / "dashboard_template.html"


def build_data(hosts, inv, advisories, stale_days, threats=None):
    machines = []
    threat_map = (threats or {}).get("machines", {})
    for h in hosts:
        name = fleet.name_of(h)
        hd, os_, sec, upd, ts = (h.get(k) or {} for k in ("host", "os", "security", "updates", "tailscale"))
        findings = fleet.check_host(h, advisories, stale_days)
        exposed = [{"port": l.get("port"), "exposure": l.get("exposure"), "proto": l.get("proto"),
                    "process": l.get("process"), "what": fleet.RISKY_PORTS.get(l.get("port"))}
                   for l in h.get("listening") or [] if l.get("exposure") != "localhost"]
        machines.append({
            "name": name, "role": hd.get("role"), "tags": hd.get("tags") or {},
            "os": os_.get("name"), "os_family": os_.get("family"), "kernel": os_.get("kernel"),
            "model": hd.get("model"), "cpu": hd.get("cpu"), "memory_gb": hd.get("memory_gb"),
            "gpus": [f"{g.get('name')}" + (f" (driver {g['driver']})" if g.get("driver") else "") for g in hd.get("gpus") or []],
            "collected_at": h.get("collected_at"),
            "posture": {
                "auto_updates": upd.get("automatic"), "pending_updates": upd.get("pending"),
                "firewall": sec.get("firewall_active"), "disk_encrypted": sec.get("disk_encrypted"),
                "ssh_server": sec.get("ssh_server_running"),
                "ssh_password": sec.get("ssh_password_auth") in ("yes", "yes-default") if sec.get("ssh_server_running") else None,
                "tailscale": ts.get("installed"), "tailscale_tags": ts.get("tags") or [],
            },
            "findings": findings,
            "threats": threat_map.get(name, []),
            "exposed": exposed,
            "software": [{"name": s.get("name"), "version": s.get("version"), "source": s.get("source"),
                          "package_version": s.get("package_version")} for s in h.get("software") or []],
        })
    manual = []
    mf = fleet.manual_findings(inv, advisories)
    for d in (inv or {}).get("devices", []):
        if d.get("census") == "manual":
            manual.append({"name": d.get("name"), "platform": d.get("platform"), "version": d.get("version"),
                           "status": d.get("status"), "last_checked": d.get("last_checked"),
                           "findings": mf.get(d.get("name"), []),
                           "threats": threat_map.get(f"{d.get('name')} (manual)", [])})
    software = [{"name": k[0], "version": k[1], "machines": sorted(v)}
                for k, v in sorted(fleet.software_map(hosts).items())]
    inventory = [{"name": r[0], "role": r[1], "status": r[2], "census": r[3], "notes": r[4]}
                 for r in fleet.inventory_status(inv, hosts)] if inv else []
    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "threats_generated_at": (threats or {}).get("generated_at"),
        "threats_window_days": (threats or {}).get("window_days"),
        "kev_catalog": (threats or {}).get("kev_catalog"),
        "machines": machines, "manual": manual, "inventory": inventory, "software": software,
    }


def write(data, out_html, inline=False):
    tpl = TEMPLATE.read_text(encoding="utf-8")
    payload = "window.FLEET_SECURITY = " + json.dumps(data, indent=1).replace("</", "<\\/") + ";\n"
    out_html = Path(out_html)
    if inline:
        html = tpl.replace('<script src="fleet-data.js"></script>', "<script>\n" + payload + "</script>")
        out_html.write_text(html, encoding="utf-8")
        return [out_html]
    js = out_html.with_name("fleet-data.js")
    out_html.write_text(tpl, encoding="utf-8")
    js.write_text(payload, encoding="utf-8")
    return [out_html, js]
