#!/usr/bin/env python3
"""
fleet.py - turn census files into a fleet report, security findings,
and a watch list. Uses only the Python standard library.

  python3 fleet.py report      # write FLEET.md (overview + findings)
  python3 fleet.py check       # print findings; exit code 1 if anything is high/critical
  python3 fleet.py watchlist   # write watchlist.json (software to keep an eye on)
  python3 fleet.py threats     # search live threat feeds for your hardware + software
  python3 fleet.py dashboard   # write dashboard.html (open it in any browser, works offline)

Options:
  --census DIR      folder of census JSON files   (default: ./census)
  --inventory FILE  devices you expect to exist    (default: ./inventory.json if present)
  --rules FILE      advisories to check (repeatable; default: ./rules/advisories.json)
  --stale-days N    warn when a census is older than N days (default: 30)
  --days N          threats: how recent counts as "immediate" (default: 30)
  --offline         threats: use cached feeds only
  --kev FILE        threats: use a downloaded CISA KEV JSON instead of fetching
  --no-osv          threats: skip exact package-version lookups
  --threats FILE    threats output / report+dashboard input (default: threats.json)
  --inline          dashboard: put the data inside the HTML (one file, easy to share)
"""
import argparse
import os
import datetime as dt
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}

# Ports that should almost never be open to every interface.
RISKY_PORTS = {
    11434: "Ollama API (no login by default)",
    8188: "ComfyUI (no login; custom nodes run code)",
    1234: "LM Studio server",
    7860: "Gradio / Stable Diffusion web UI",
    7861: "Gradio web UI",
    8080: "llama.cpp server / Open WebUI / misc web app",
    8000: "dev web server / vLLM",
    5000: "dev web server",
    3000: "dev web server / Open WebUI / Grafana",
    8888: "Jupyter (code execution)",
    6006: "TensorBoard",
    2375: "Docker API without TLS (full host takeover)",
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    5900: "VNC screen sharing",
    3389: "Remote Desktop",
    9090: "Prometheus",
    8006: "Proxmox web UI",
}

PORT_FIX = {
    11434: "Set OLLAMA_HOST=127.0.0.1 (or your Tailscale IP) and restart Ollama. On macOS: launchctl setenv OLLAMA_HOST 127.0.0.1, then restart the app.",
    8188: "Start ComfyUI without --listen (it defaults to 127.0.0.1), or use --listen <your Tailscale IP>.",
    2375: "Turn off the unencrypted Docker TCP socket now - anyone who can reach it owns the machine.",
    6379: "In redis.conf set 'bind 127.0.0.1' and 'protected-mode yes', then restart Redis.",
}


# ---------- helpers ----------
def vtuple(v):
    """'8.4.27' -> (8, 4, 27). Non-numeric parts are ignored."""
    if v is None:
        return ()
    return tuple(int(x) for x in re.findall(r"\d+", str(v)))


def branch_of(v, parts):
    t = vtuple(v)
    return ".".join(str(x) for x in t[:parts]) if len(t) >= parts else None


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_census(folder):
    hosts = []
    for p in sorted(Path(folder).glob("*.json")):
        try:
            d = load_json(p)
            d["_file"] = p.name
            hosts.append(d)
        except Exception as e:  # keep going; report the broken file
            print(f"Skipping {p.name}: not valid JSON ({e})", file=sys.stderr)
    return hosts


def name_of(h):
    return (h.get("host") or {}).get("name") or (h.get("host") or {}).get("hostname") or h.get("_file")


def finding(sev, title, detail="", fix="", refs=None):
    return {"severity": sev, "title": title, "detail": detail, "fix": fix, "refs": refs or []}


# ---------- checks ----------
def check_advisories(h, advisories):
    out = []
    items = list(h.get("software") or [])
    os_ = h.get("os") or {}
    if os_.get("family") == "macos" and os_.get("version"):
        items.append({"name": "macos", "version": os_["version"], "source": "vendor"})

    for adv in advisories:
        names = set(adv.get("software", []))
        parts = int(adv.get("branch_parts", 2))
        fixed = adv.get("fixed_in", {})
        known_branches = sorted((vtuple(b) for b in fixed), reverse=True)
        for sw in items:
            if sw.get("name") not in names or not sw.get("version"):
                continue
            v = vtuple(sw["version"])
            if v < vtuple(adv.get("affected_from", "0")):
                continue
            br = branch_of(sw["version"], parts)
            label = f"{adv['id']} ({', '.join(adv.get('cves', []))})"
            exploited = " Actively exploited." if adv.get("exploited") else ""
            vulnerable, how = False, ""
            if br in fixed:
                if v < vtuple(fixed[br]):
                    vulnerable, how = True, f"{sw['name']} {sw['version']} is below the fixed {fixed[br]}."
            elif adv.get("unsupported_below") and v < vtuple(adv["unsupported_below"]):
                vulnerable, how = True, (f"{sw['name']} {sw['version']} is on a branch that gets no fix "
                                         f"(older than {adv['unsupported_below']}). Upgrade to a supported version or remove it.")
            elif known_branches and vtuple(br) > known_branches[0]:
                continue  # newer branch than any listed: assumed fixed
            else:
                out.append(finding("info", f"{label}: {sw['name']} {sw['version']} not covered by this rule",
                                   "This version's branch isn't listed in the advisory, so fleet.py can't tell.",
                                   "Check the vendor's advisory for your version.", adv.get("refs")))
                continue
            if not vulnerable:
                continue

            sev = adv.get("severity", "high")
            src = sw.get("source")
            if src in ("apt", "pacman", "rpm", "snap"):
                # Distros often backport the fix without changing the upstream number.
                how += (f" Installed from {src} package {sw.get('package') or '?'} {sw.get('package_version') or ''}. "
                        f"Your distro may already have patched it without changing the version - check its "
                        f"security tracker, or just run your system update.")
                title = f"{label}: possibly vulnerable (distro package - verify)"
            else:
                title = f"{label}: vulnerable"
            out.append(finding(sev, title, adv.get("summary", "") + exploited + " " + how,
                               adv.get("action", ""), adv.get("refs")))
    return out


def check_host(h, advisories, stale_days):
    f = []
    sec = h.get("security") or {}
    upd = h.get("updates") or {}
    os_ = h.get("os") or {}
    ts = h.get("tailscale") or {}

    # Census age
    try:
        when = dt.datetime.strptime(h.get("collected_at", ""), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
        age = (dt.datetime.now(dt.timezone.utc) - when).days
        if age > stale_days:
            f.append(finding("low", f"Census is {age} days old",
                             fix="Run ./census.sh on this machine again."))
    except ValueError:
        pass

    f += check_advisories(h, advisories)

    # Network exposure
    for l in h.get("listening") or []:
        port, exp = l.get("port"), l.get("exposure")
        if exp != "all":
            continue
        if port in RISKY_PORTS:
            f.append(finding("high", f"Port {port} open on every network interface",
                             f"{RISKY_PORTS[port]}{' - process ' + l['process'] if l.get('process') else ''}.",
                             PORT_FIX.get(port, "Bind it to 127.0.0.1 (this machine only) or to the Tailscale IP, "
                                                "or block it with the firewall.")))
    open_all = sorted({l["port"] for l in h.get("listening") or [] if l.get("exposure") == "all"
                       and l.get("port") not in RISKY_PORTS and l.get("port") != 22})
    if open_all:
        f.append(finding("info", f"{len(open_all)} other port(s) open on every interface",
                         "Ports: " + ", ".join(map(str, open_all[:25])),
                         "Make sure you recognise each one; close or bind the ones you don't need."))

    # Firewall
    if sec.get("firewall_active") is False:
        if os_.get("family") == "macos":
            fw_fix = "System Settings > Network > Firewall > turn on."
        else:
            fw_fix = ("sudo ufw allow OpenSSH   (first, so you don't lock yourself out), then "
                      "sudo ufw default deny incoming && sudo ufw allow in on tailscale0 && sudo ufw enable")
        f.append(finding("medium", "Firewall is off", fix=fw_fix))
    # SSH
    if sec.get("ssh_server_running"):
        if sec.get("ssh_password_auth") in ("yes", "yes-default"):
            f.append(finding("high", "SSH accepts passwords",
                             "Password logins can be brute-forced.",
                             "Set up SSH keys, then put 'PasswordAuthentication no' in /etc/ssh/sshd_config "
                             "and restart sshd. Or use Tailscale SSH."))
        if sec.get("ssh_root_login") == "yes":
            f.append(finding("high", "SSH allows root login",
                             fix="Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd."))
    # Updates
    if upd.get("automatic") is False and upd.get("package_manager") not in ("pacman",):
        f.append(finding("medium", "Automatic security updates are off",
                         fix=("Debian/Ubuntu/Mint/Pi: sudo apt install unattended-upgrades && "
                              "sudo dpkg-reconfigure -plow unattended-upgrades. "
                              "macOS: System Settings > General > Software Update > Automatic Updates.")))
    if upd.get("package_manager") == "pacman":
        f.append(finding("info", "Arch-based system: updates are manual",
                         fix="Run sudo pacman -Syu (or your AUR helper) at least weekly."))
    if isinstance(upd.get("pending"), int) and upd["pending"] > 0:
        sev = "medium" if upd["pending"] >= 20 else "low"
        f.append(finding(sev, f"{upd['pending']} updates waiting",
                         fix="sudo apt update && sudo apt upgrade (or your system's updater)."))
    # Disk encryption
    if sec.get("disk_encrypted") is False:
        f.append(finding("low", "Disk is not encrypted",
                         "Matters most for laptops and anything that could be stolen.",
                         "macOS: turn on FileVault. Linux: LUKS (usually chosen at install time)."))
    # Tailscale
    if ts.get("installed") is False:
        f.append(finding("info", "Tailscale not installed",
                         fix="Skip if this machine isn't meant to be on your tailnet."))
    elif ts.get("installed") and ts.get("tags") == []:
        f.append(finding("low", "Tailscale node has no tags",
                         fix="Tag nodes by role so access rules (ACLs) can limit who reaches what."))
    # Containers we couldn't see
    if h.get("containers") == "no-permission-or-not-running":
        f.append(finding("info", "Couldn't list Docker containers",
                         fix="Docker isn't running, or this user can't reach it. Re-run with a user in the docker group to include containers."))
    # ComfyUI custom nodes
    for c in h.get("comfyui") or []:
        n = len(c.get("custom_nodes") or [])
        if n:
            f.append(finding("info", f"ComfyUI has {n} custom node(s) at {c.get('path')}",
                             "Custom nodes are arbitrary Python code with full access to your user account.",
                             "Remove ones you don't use; only install from authors you trust."))
    # Secrets
    s = h.get("secrets_present") or {}
    flags = [k for k in ("aws_credentials", "github_cli_token", "netrc", "docker_config", "huggingface_token") if s.get(k)]
    count = (s.get("ssh_private_keys") or 0) + (s.get("env_files") or 0) + len(flags)
    if count:
        f.append(finding("info", "Credentials stored on this machine",
                         f"{s.get('ssh_private_keys', 0)} SSH private key(s), {s.get('env_files', 0)} .env file(s)"
                         + (", plus: " + ", ".join(flags) if flags else "") + ". (Only counted - never read.)",
                         "Know what's here so you can rotate it if this machine is ever compromised or retired."))

    f.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))
    return f


# ---------- inventory ----------
def manual_findings(inv, advisories):
    """Check hand-entered devices (phones, microcontrollers) against the advisories."""
    res = {}
    for d in (inv or {}).get("devices", []):
        if d.get("census") != "manual" or not d.get("platform") or not d.get("version"):
            continue
        fake = {"software": [{"name": d["platform"], "version": d["version"], "source": "vendor"}], "os": {}}
        fl = check_advisories(fake, advisories)
        if fl:
            res[d.get("name", "?")] = fl
    return res


def inventory_status(inv, hosts):
    seen = {name_of(h).lower() for h in hosts} | {((h.get("host") or {}).get("hostname") or "").lower() for h in hosts}
    rows = []
    for d in inv.get("devices", []):
        name = d.get("name", "?")
        kind = d.get("census", "script")
        if kind == "manual":
            state = f"manual - last checked {d.get('last_checked') or 'never'}"
        elif name.lower() in seen or (d.get("hostname") or "").lower() in seen:
            state = "census ✓"
        elif d.get("status") in ("retired", "offline"):
            state = d["status"]
        else:
            state = "MISSING census"
        rows.append((name, d.get("role", ""), d.get("status", ""), state, d.get("notes", "")))
    return rows


# ---------- outputs ----------
def md_escape(s):
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")


def yes_no(v, good=True):
    if v is None:
        return "?"
    return "✅" if bool(v) == good else "❌"


def reconcile_threats(res, hosts, inv, advisories):
    """KEV has no versions. If one of our version rules covers the same CVE and the
    machine is at or above the fixed version, mark the match as already patched."""
    by_cve = {}
    for adv in advisories:
        for c in adv.get("cves", []):
            by_cve.setdefault(c, []).append(adv)
    subjects = {name_of(h): h for h in hosts}
    for d in (inv or {}).get("devices", []):
        if d.get("census") == "manual" and d.get("platform") and d.get("version"):
            subjects[f"{d.get('name')} (manual)"] = {
                "software": [{"name": d["platform"], "version": d["version"], "source": "vendor"}], "os": {}}
    for m, hits in res.get("machines", {}).items():
        h = subjects.get(m)
        if not h:
            continue
        for x in hits:
            advs = by_cve.get(x.get("id"))
            if not advs or x["severity"] == "info":
                continue
            names = {n for a in advs for n in a.get("software", [])}
            sw = [s.get("name") for s in h.get("software") or []]
            if (h.get("os") or {}).get("family") == "macos":
                sw.append("macos")
            if not names & set(sw):
                continue  # no version info for this product - can't tell, keep the warning
            if not check_advisories(h, advs):
                x["severity"] = "info"
                x["patched"] = True
                x["title"] += " (your version is already patched)"
    return res


def threats_section(threats):
    if not threats:
        return []
    lines = ["## Immediate threats", "",
             f"_From CISA KEV (catalog {threats.get('kev_catalog') or '?'}) and OSV, searched "
             f"{threats.get('generated_at', '')[:16].replace('T', ' ')} UTC. \"Recent\" = added in the last "
             f"{threats.get('window_days')} days. Run `python3 fleet.py threats` to refresh._", ""]
    any_hit = False
    for m, hits in threats.get("machines", {}).items():
        urgent = [x for x in hits if x["severity"] in ("critical", "high", "medium")]
        if not urgent:
            continue
        any_hit = True
        lines.append(f"### {m}")
        for x in sorted(urgent, key=lambda x: SEVERITY_ORDER.get(x["severity"], 9)):
            rw = " · ransomware" if x.get("ransomware") else ""
            lines.append(f"- {ICON.get(x['severity'], '')} **{x['id']}** ({x['source']}{rw}): {x['title']}")
            lines.append(f"  - Matched: {x['matched']}" + (f" · added {x['date_added']}" if x.get("date_added") else ""))
            lines.append(f"  - **Do:** {x['action']}")
        lines.append("")
    if not any_hit:
        lines += ["Nothing recent in the feeds matches this fleet. ✅", ""]
    return lines


def build_report(hosts, inv, advisories, stale_days, threats=None):
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [f"# Fleet report", "", f"_Generated {now} from {len(hosts)} census file(s)._", ""]
    all_f = {name_of(h): check_host(h, advisories, stale_days) for h in hosts}
    for dev, fl in manual_findings(inv, advisories).items():
        all_f[f"{dev} (manual entry)"] = fl
    totals = {}
    for fl in all_f.values():
        for x in fl:
            totals[x["severity"]] = totals.get(x["severity"], 0) + 1
    summary = ", ".join(f"{ICON[s]} {totals[s]} {s}" for s in SEVERITY_ORDER if totals.get(s)) or "no findings"
    lines += [f"**Findings:** {summary}", ""]
    lines += threats_section(threats)

    lines += ["## Machines", "",
              "| Name | Role | OS | Auto-updates | Firewall | Disk enc. | SSH pw | Tailscale | Open to all | Census |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for h in hosts:
        sec, upd, ts = h.get("security") or {}, h.get("updates") or {}, h.get("tailscale") or {}
        ssh_pw = "off" if not sec.get("ssh_server_running") else ("❌ on" if sec.get("ssh_password_auth") in ("yes", "yes-default") else "✅ keys")
        exposed = sum(1 for l in h.get("listening") or [] if l.get("exposure") == "all")
        lines.append("| " + " | ".join(md_escape(x) for x in [
            name_of(h), (h.get("host") or {}).get("role") or "", (h.get("os") or {}).get("name") or "",
            yes_no(upd.get("automatic")), yes_no(sec.get("firewall_active")), yes_no(sec.get("disk_encrypted")),
            ssh_pw, (ts.get("node_name") or "✅") if ts.get("installed") else "—", exposed,
            (h.get("collected_at") or "")[:10]]) + " |")
    lines.append("")

    if inv:
        lines += ["## Inventory check", "", "| Device | Role | Status | Census | Notes |", "|---|---|---|---|---|"]
        for r in inventory_status(inv, hosts):
            lines.append("| " + " | ".join(md_escape(x) for x in r) + " |")
        lines.append("")

    lines += ["## Findings by machine", ""]
    for name, fl in all_f.items():
        lines += [f"### {name}", ""]
        if not fl:
            lines += ["No findings. 🎉", ""]
            continue
        for x in fl:
            lines.append(f"- {ICON[x['severity']]} **{x['severity'].upper()}: {x['title']}**")
            if x["detail"]:
                lines.append(f"  - {x['detail'].strip()}")
            if x["fix"]:
                lines.append(f"  - **Fix:** {x['fix']}")
            for r in x["refs"]:
                lines.append(f"  - {r}")
        lines.append("")

    lines += ["## Software across the fleet", "", "| Software | Version | Machines |", "|---|---|---|"]
    for (sw, ver), names in sorted(software_map(hosts).items()):
        lines.append(f"| {md_escape(sw)} | {md_escape(ver)} | {md_escape(', '.join(sorted(names)))} |")
    lines.append("")
    return "\n".join(lines), all_f


def software_map(hosts):
    m = {}
    for h in hosts:
        n = name_of(h)
        os_ = h.get("os") or {}
        if os_.get("name"):
            m.setdefault((os_.get("id") or os_["family"], os_.get("version") or os_["name"]), set()).add(n)
        if os_.get("family") == "linux" and os_.get("kernel"):
            m.setdefault(("linux-kernel", os_["kernel"]), set()).add(n)
        for g in (h.get("host") or {}).get("gpus") or []:
            if g.get("driver"):
                m.setdefault((f"{g.get('vendor') or 'gpu'}-driver", g["driver"]), set()).add(n)
        ts = h.get("tailscale") or {}
        if ts.get("installed") and ts.get("version"):
            m.setdefault(("tailscale", ts["version"]), set()).add(n)
        for sw in h.get("software") or []:
            m.setdefault((sw["name"], sw.get("version") or "?"), set()).add(n)
        for c in h.get("containers") or [] if isinstance(h.get("containers"), list) else []:
            m.setdefault(("container-image", c.get("image") or "?"), set()).add(n)
        for c in h.get("comfyui") or []:
            for node in c.get("custom_nodes") or []:
                m.setdefault(("comfyui-custom-node", node), set()).add(n)
    return m


def build_watchlist(hosts, inv):
    items = {}
    for (sw, ver), names in software_map(hosts).items():
        items.setdefault(sw, {"name": sw, "versions": {}, "machines": set()})
        items[sw]["versions"][ver] = sorted(names)
        items[sw]["machines"] |= names
    for d in (inv or {}).get("devices", []):
        if d.get("census") == "manual" and d.get("platform"):
            p = d["platform"]
            items.setdefault(p, {"name": p, "versions": {}, "machines": set()})
            items[p]["versions"].setdefault(d.get("version") or "unknown", []).append(d.get("name"))
            items[p]["machines"].add(d.get("name"))
    for extra in (inv or {}).get("also_watch", []):
        items.setdefault(extra, {"name": extra, "versions": {}, "machines": set()})
    out = []
    for v in sorted(items.values(), key=lambda x: x["name"]):
        v["machines"] = sorted(v["machines"])
        out.append(v)
    return {"generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "note": "Feed this to your security-watch prompt (see watch/WATCH-PROMPT.md).",
            "software": out}


# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description="Fleet census reporting")
    ap.add_argument("command", choices=["report", "check", "watchlist", "threats", "dashboard"])
    ap.add_argument("--census", default=str(Path.cwd() / "census"))
    ap.add_argument("--inventory", default=None)
    ap.add_argument("--rules", action="append", default=None)
    ap.add_argument("--stale-days", type=int, default=30)
    ap.add_argument("--out", default=None, help="output file (report/watchlist/dashboard)")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--kev", default=None)
    ap.add_argument("--no-osv", action="store_true")
    ap.add_argument("--threats", default="threats.json")
    ap.add_argument("--inline", action="store_true")
    a = ap.parse_args()

    hosts = load_census(a.census)
    if not hosts:
        print(f"No census files found in {a.census}. Run ./census.sh first.", file=sys.stderr)
        return 2

    inv_path = Path(a.inventory) if a.inventory else Path.cwd() / "inventory.json"
    inv = load_json(inv_path) if inv_path.exists() else None

    rule_files = a.rules or [str(HERE / "rules" / "advisories.json")]
    advisories = []
    for rf in rule_files:
        if Path(rf).exists():
            advisories += load_json(rf).get("advisories", [])

    threats_path = Path(a.threats)
    if a.command == "threats":
        import threats as th
        print("Searching CISA KEV" + ("" if a.no_osv else " and OSV") + " for your hardware and software...")
        res = th.scan(hosts, inv, days=a.days, offline=a.offline, kev_file=a.kev,
                      use_osv=not a.no_osv, log=lambda m: print(m, file=sys.stderr))
        reconcile_threats(res, hosts, inv, advisories)
        threats_path.write_text(json.dumps(res, indent=2), encoding="utf-8")
        print(th.summarize(res))
        urgent = sum(1 for hs in res["machines"].values() for x in hs if x["severity"] in ("critical", "high"))
        print(f"\n{'URGENT: ' + str(urgent) + ' item(s) need action' if urgent else 'No urgent matches.'} "
              f"Saved {threats_path}. Run 'report' or 'dashboard' to include it.")
        return 1 if urgent else 0

    threats = load_json(threats_path) if threats_path.exists() else None

    if a.command == "dashboard":
        import dashboard as db
        out = Path(a.out or "dashboard.html")
        data = db.build_data(hosts, inv, advisories, a.stale_days, threats)
        written = db.write(data, out, inline=a.inline)
        print("Wrote " + " and ".join(map(str, written)) + " - open the HTML file in your browser.")
        return 0

    if a.command == "report":
        text, _ = build_report(hosts, inv, advisories, a.stale_days, threats)
        out = Path(a.out or "FLEET.md")
        out.write_text(text, encoding="utf-8")
        print(f"Wrote {out} ({len(hosts)} machines)")
        return 0
    if a.command == "watchlist":
        out = Path(a.out or "watchlist.json")
        out.write_text(json.dumps(build_watchlist(hosts, inv), indent=2), encoding="utf-8")
        print(f"Wrote {out}")
        return 0
    # check
    worst = 9
    groups = [(name_of(h), check_host(h, advisories, a.stale_days)) for h in hosts]
    groups += [(f"{k} (manual entry)", v) for k, v in manual_findings(inv, advisories).items()]
    for name, fl in groups:
        print(f"\n== {name} ==")
        if not fl:
            print("  no findings")
        for x in fl:
            worst = min(worst, SEVERITY_ORDER.get(x["severity"], 9))
            print(f"  [{x['severity'].upper()}] {x['title']}")
            if x["fix"]:
                print(f"      fix: {x['fix']}")
    return 1 if worst <= SEVERITY_ORDER["high"] else 0


if __name__ == "__main__":
    sys.exit(main())
