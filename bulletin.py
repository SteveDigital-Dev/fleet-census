"""
bulletin.py - the weekly health check.

  python3 fleet.py setup                 first-time walkthrough (plain English)
  python3 fleet.py bulletin              run this week's health check
  python3 fleet.py bulletin --offline    use saved copies only; contact nothing
  python3 fleet.py sources               what gets contacted, and what is sent
  python3 fleet.py snooze KEY --reason "..." --days 30
  python3 fleet.py schedule on|off|status
  python3 fleet.py uninstall             remove everything this tool created

The basic bulletin uses the sources you agreed to in setup. Every extra
(changes since last week, attack likelihood, end-of-life warnings, snooze
list, phone alerts, home-devices checklist) is OFF until you turn it on.
Standard library only.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import urllib.request
from pathlib import Path

import fleet
import threats as th

HERE = Path(__file__).resolve().parent
SETTINGS = HERE / "settings.json"
SNOOZE = HERE / "snooze.json"
OUT = HERE / "bulletins"
EPSS_URL = os.environ.get("FLEET_EPSS_URL", "https://api.first.org/data/v1/epss")
EOL_URL = os.environ.get("FLEET_EOL_URL", "https://endoflife.date")
LEVEL_ORDER = {"red": 0, "amber": 1, "green": 2}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ---------------------------------------------------------------- settings
EXTRAS = {
    "changes": ("What changed since last week",
                "Shows only what's new or fixed since the last bulletin: new problems, solved ones, newly "
                "opened ports, software that changed. Uses no internet."),
    "epss": ("How likely each bug is to be attacked",
             "Asks FIRST.org's free EPSS service how likely each matched bug is to be attacked in the next "
             "30 days, so the truly dangerous ones rise to the top. Sends only the bug ID numbers (CVEs)."),
    "eol": ("End-of-life warnings",
            "Asks endoflife.date when your operating system and software stop getting security fixes, and "
            "warns you before (and after) that date. Sends only product names like 'php' or 'ubuntu'."),
    "snooze": ("Snooze list",
               "Lets you hide a warning you've handled or decided doesn't apply, with a reason and a date "
               "when it comes back. Uses no internet."),
    "alerts": ("Phone alerts (only when it matters)",
               "Sends a short push notification through ntfy (a free notification app) when the threat level "
               "is red. Sends one line of text to the ntfy address you choose."),
    "home_checklist": ("Home devices checklist",
                       "Adds a short list of things this tool can't check for you, like your router, phone "
                       "and smart devices. Uses no internet."),
}
SOURCES = {
    "cisa_kev": {
        "name": "CISA Known Exploited Vulnerabilities", "host": "www.cisa.gov",
        "what": "A US government agency's public list of security bugs that attackers are using right now.",
        "sends": "Nothing about you: it just downloads the public list."},
    "osv": {
        "name": "OSV.dev", "host": "api.osv.dev",
        "what": "An open database (run by Google) of known bugs in software packages.",
        "sends": "Names and versions of packages installed with apt, e.g. 'openssl 3.0.13'. "
                 "No computer names, no IP addresses."},
}
EXTRA_HOSTS = {
    "epss": ("api.first.org", "Bug ID numbers (CVEs) that matched your machines."),
    "eol": ("endoflife.date", "Product names such as 'php', 'ubuntu' or 'macos' (one request each)."),
    "alerts": ("your ntfy address", "One line, e.g. 'RED: 2 urgent items'. Machine names only if you allow it."),
}


def default_settings():
    return {
        "version": 1,
        "machine_name": socket.gethostname().split(".")[0],
        "refresh_census": True,
        "sources": {"cisa_kev": True, "osv": True},
        "extras": {k: False for k in EXTRAS},
        "alerts": {"ntfy_url": "", "min_level": "red", "include_names": False},
        "schedule": {"enabled": False, "weekday": 1, "hour": 9, "minute": 17},
    }


def load_settings():
    if not SETTINGS.exists():
        return None
    s = default_settings()
    try:
        saved = json.loads(SETTINGS.read_text(encoding="utf-8"))
    except ValueError:
        print(f"{SETTINGS.name} is damaged; run 'python3 fleet.py setup' to recreate it.", file=sys.stderr)
        return None
    for k, v in saved.items():
        if isinstance(v, dict) and isinstance(s.get(k), dict):
            s[k].update(v)
        else:
            s[k] = v
    return s


def save_settings(s):
    SETTINGS.write_text(json.dumps(s, indent=2) + "\n", encoding="utf-8")


def contacts(s, extras=None):
    """[(host, what is sent)] for a run with these settings."""
    extras = extras if extras is not None else s["extras"]
    out = [(v["host"], v["sends"]) for k, v in SOURCES.items() if s["sources"].get(k)]
    for k, (host, sends) in EXTRA_HOSTS.items():
        if extras.get(k):
            if k == "alerts":
                host = s["alerts"].get("ntfy_url") or host
            out.append((host, sends))
    return out


# ---------------------------------------------------------------- explanations
def kind_of(item):
    t = (item.get("title") or "").lower()
    src = item.get("source")
    if src == "CISA KEV":
        return "kev"
    if src == "OSV":
        return "osv"
    if src == "end-of-life":
        return "eol"
    for k, words in (("advisory", ["cve-"]), ("port", ["port "]), ("ssh-pw", ["ssh accepts passwords"]),
                     ("ssh-root", ["root login"]), ("firewall", ["firewall"]),
                     ("autoupdate", ["automatic security updates", "updates are manual"]),
                     ("pending", ["updates waiting"]), ("disk", ["not encrypted"]),
                     ("stale", ["census is"]), ("comfy", ["comfyui"]), ("secrets", ["credentials"]),
                     ("tailscale", ["tailscale"]), ("docker", ["docker"])):
        if any(w in t for w in words):
            return k
    return "other"


WHY = {
    "kev": "Attackers are using this bug in real attacks right now, so it jumps the queue.",
    "osv": "An installed package has a known flaw, and a newer version already fixes it.",
    "advisory": "A widely reported bug affects a version you run. Fixed versions exist.",
    "eol": "Software past its end-of-life gets no more security fixes, so new bugs in it stay open for good.",
    "port": "This service answers anything on every network this computer joins. A hacked smart plug or a "
            "stranger on café Wi-Fi could try to talk to it.",
    "ssh-pw": "Bots try thousands of passwords a minute against SSH. Keys can't be guessed that way.",
    "ssh-root": "Logging in straight as the all-powerful 'root' user removes a safety layer.",
    "firewall": "A firewall is a doorman: it turns away connections you didn't ask for.",
    "autoupdate": "Most attacks use bugs that already have fixes. Automatic updates close them without you "
                  "having to remember.",
    "pending": "Waiting updates often include security fixes. Until they're installed, the old bugs are still there.",
    "disk": "If this computer is lost or stolen, encryption keeps your files unreadable.",
    "stale": "This check is only as good as its last look at the machine.",
    "comfy": "Custom nodes are other people's code running with your permissions.",
    "secrets": "Knowing where your keys live means you can change them fast if something goes wrong.",
    "tailscale": "Tags let you limit which devices can reach which, so one compromised device can't reach everything.",
    "docker": "Some checks were skipped because containers couldn't be listed.",
    "other": "Worth a look. The detail below explains it.",
}


def os_steps(family, pm, platform_name=None):
    p = (platform_name or "").lower()
    if p in ("ios", "ipados"):
        return ["On the device: Settings → General → Software Update.", "Install everything offered, then restart."]
    if p == "windows":
        return ["Start → Settings → Windows Update → Check for updates.", "Install everything, then restart."]
    if family == "macos":
        return ["Apple menu → System Settings → General → Software Update.",
                "Install everything offered, then restart when asked.",
                "If you use Homebrew, also run in Terminal:  brew update && brew upgrade"]
    if pm == "pacman":
        return ["Open a terminal.", "Run:  sudo pacman -Syu   (on Omarchy:  omarchy-update)",
                "Reboot if the kernel was updated."]
    if pm == "dnf":
        return ["Open a terminal.", "Run:  sudo dnf upgrade --refresh", "Reboot if asked."]
    return ["Open a terminal.", "Run:  sudo apt update && sudo apt upgrade",
            "If the file /var/run/reboot-required exists afterwards, reboot."]


def how_steps(item, host):
    k = kind_of(item)
    os_ = (host or {}).get("os") or {}
    pm = ((host or {}).get("updates") or {}).get("package_manager")
    fam = os_.get("family")
    action = (item.get("action") or "").strip()
    confirm = "Run  python3 fleet.py bulletin  again. This item should be gone."
    if k in ("kev", "osv", "advisory", "pending", "eol"):
        steps = os_steps(fam, pm, item.get("platform"))
        if action:
            steps.append("Specific advice: " + action)
        if k == "eol":
            steps = ["Plan an upgrade to a supported version (see the link).",
                     "Until then, keep this software away from the internet and other people's devices."] + \
                    ([f"Specific advice: {action}"] if action else [])
        return steps + [confirm]
    if k == "port":
        port = re.search(r"Port (\d+)", item.get("title") or "")
        p = port.group(1) if port else "PORT"
        find = (f"Find what is listening:  sudo lsof -iTCP:{p} -sTCP:LISTEN" if fam == "macos"
                else f"Find what is listening:  sudo ss -tulpn | grep :{p}")
        return [find, action or "Change that program's setting so it listens on 127.0.0.1 (this computer only).",
                "If you don't use the program, stop or uninstall it.", confirm]
    if k == "firewall" and fam == "macos":
        return ["Apple menu → System Settings → Network → Firewall → turn it on.", confirm]
    if k == "firewall":
        return ["Open a terminal.", "Allow SSH first so you can't lock yourself out:  sudo ufw allow OpenSSH",
                "Block everything else coming in:  sudo ufw default deny incoming",
                "Turn it on:  sudo ufw enable", confirm]
    if k == "autoupdate" and fam == "macos":
        return ["Apple menu → System Settings → General → Software Update → Automatic Updates.",
                "Turn on everything, especially 'Install Security Responses and system files'.", confirm]
    if k == "autoupdate" and pm == "apt":
        return ["Open a terminal.", "Run:  sudo apt install unattended-upgrades",
                "Then:  sudo dpkg-reconfigure -plow unattended-upgrades   (answer Yes)", confirm]
    if k == "ssh-pw":
        return ["On the computer you connect FROM, make a key:  ssh-keygen -t ed25519",
                "Copy it to this machine:  ssh-copy-id you@this-machine",
                "Check you can log in without a password.",
                "Then edit /etc/ssh/sshd_config, set  PasswordAuthentication no , and run  sudo systemctl restart ssh",
                confirm]
    if k == "disk" and fam == "macos":
        return ["Apple menu → System Settings → Privacy & Security → FileVault → Turn On.",
                "Store the recovery key somewhere safe (not on this computer)."]
    if k == "disk":
        return ["On Linux, full-disk encryption (LUKS) is normally chosen when installing.",
                "For an existing install, back up first. Re-installing with encryption is the safe route.",
                "Laptops matter most; desktops that never leave home matter less."]
    return ([action] if action else []) + [confirm]


HOME_CHECKLIST = [
    ("Router", "Log in to your router's admin page, install firmware updates, and change the admin "
               "password if it's still the one printed on the sticker.",
     "The router guards everything else, and old router firmware is a favourite target."),
    ("Phones and tablets", "Settings → Software Update on each one; turn on automatic updates.",
     "Phones carry your email and passwords, and get many security fixes."),
    ("Smart devices", "Cameras, plugs, TVs, speakers: update them in their apps and change any default passwords.",
     "Cheap smart devices are often the weakest link on a home network."),
    ("Guest Wi-Fi", "Put smart devices and visitors on a guest network, separate from your computers.",
     "If one smart device is hacked, it can't reach your computers."),
    ("Email and passwords", "Turn on two-step login for your email and use a password manager.",
     "Your email can reset every other password you have."),
    ("Backups", "Check your backup ran recently, and once in a while try restoring one file.",
     "A backup you've never restored is a hope, not a backup."),
]


# ---------------------------------------------------------------- items
def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")[:60]


def collect_items(hosts, inv, advisories, tres):
    items = []
    tmap = (tres or {}).get("machines", {})

    def add_findings(machine, findings, platform_name=None):
        for f in findings:
            cves = re.findall(r"CVE-\d{4}-\d+", f["title"] + " " + f.get("detail", ""))
            items.append({
                "machine": machine, "severity": f["severity"], "title": f["title"],
                "detail": f.get("detail", ""), "action": f.get("fix", ""), "source": "census check",
                "exploited": "actively exploited" in (f.get("detail", "") + f["title"]).lower(),
                "cves": sorted(set(cves)), "refs": f.get("refs") or [], "platform": platform_name,
                "key": cves[0] if cves else slug(f["title"])})

    def add_threats(machine, hits, platform_name=None):
        seen = {c for i in items if i["machine"] == machine for c in i["cves"]}
        for x in hits:
            if x.get("severity") == "info":
                continue
            ids = [x["id"]] if str(x.get("id", "")).startswith("CVE-") else []
            ids += x.get("cves") or []
            if ids and set(ids) <= seen:
                for i in items:  # census check already reports it: mark as confirmed exploited
                    if i["machine"] == machine and set(i["cves"]) & set(ids) and x["source"] == "CISA KEV":
                        i["exploited"] = True
                continue
            items.append({
                "machine": machine, "severity": x["severity"], "title": x["title"],
                "detail": (x.get("summary") or "") + (f" (matched {x['matched']})" if x.get("matched") else ""),
                "action": x.get("action", ""), "source": x["source"],
                "exploited": x["source"] == "CISA KEV" or x["severity"] == "critical",
                "ransomware": bool(x.get("ransomware")), "fixed": x.get("fixed"),
                "cves": sorted(set(c for c in ids if c.startswith("CVE-"))),
                "refs": [x["url"]] if x.get("url") else [], "platform": platform_name,
                "key": x["id"] if str(x.get("id", "")).startswith("CVE-") else slug(x["source"] + "-" + x.get("matched", ""))})

    for h in hosts:
        m = fleet.name_of(h)
        add_findings(m, fleet.check_host(h, advisories, 30))
        add_threats(m, tmap.get(m, []))
    mf = fleet.manual_findings(inv, advisories)
    for d in (inv or {}).get("devices", []):
        if d.get("census") != "manual" or d.get("status") == "retired":
            continue
        m = d.get("name")
        add_findings(m, mf.get(m, []), d.get("platform"))
        add_threats(m, tmap.get(f"{m} (manual)", []), d.get("platform"))
    return items


POSSIBLY_PATCHED = ("Your system's own package may already include the fix: Linux distributions often patch "
                    "without changing the version number. Running your normal update settles it either way.")


def explain(items, hosts):
    """Add 'why this matters' and 'show me how' to every item."""
    host_by = {fleet.name_of(h): h for h in hosts}
    for i in items:
        k = kind_of(i)
        if "possibly vulnerable" in i["title"]:
            # distro package: likely already patched, so don't let it drive the level to red
            i["exploited"], i["severity"] = False, ("high" if i["severity"] == "critical" else i["severity"])
            i["why"] = POSSIBLY_PATCHED
        elif k == "advisory" and i.get("exploited"):
            i["why"] = WHY["kev"]
        else:
            i["why"] = WHY[k]
        i["how"] = how_steps(i, host_by.get(i["machine"]))
    return items


# ---------------------------------------------------------------- extras: EPSS
def add_epss(items, offline, log):
    cves = sorted({c for i in items for c in i["cves"]})
    if not cves:
        return 0
    scores = {}
    for start in range(0, len(cves), 80):
        chunk = cves[start:start + 80]
        name = "epss_" + hashlib.sha1(",".join(chunk).encode()).hexdigest()[:16] + ".json"
        try:
            res = th._get_json(f"{EPSS_URL}?cve={','.join(chunk)}", name, 24, offline)
        except Exception as e:
            log(f"EPSS lookup failed: {e}")
            continue
        for row in (res or {}).get("data", []):
            try:
                scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, ValueError):
                pass
    for i in items:
        best = max((scores[c] for c in i["cves"] if c in scores), default=None)
        if best:
            i["epss"], i["epss_percentile"] = best
    return len(scores)


# ---------------------------------------------------------------- extras: end of life
EOL_SLUGS = {"php": "php", "php-fpm": "php", "node": "nodejs", "python3": "python",
             "postgres": "postgresql", "redis": "redis", "nginx": "nginx", "openssl": "openssl",
             "mysql": "mysql", "ollama": None}
OS_LABELS = {"ubuntu": "Ubuntu", "debian": "Debian", "linuxmint": "Linux Mint", "fedora": "Fedora",
             "macos": "macOS", "raspbian": "Raspberry Pi OS"}
OS_SLUGS = {"ubuntu": "ubuntu", "debian": "debian", "linuxmint": "linuxmint", "fedora": "fedora",
            "macos": "macos", "raspbian": "debian"}
MANUAL_SLUGS = {"ios": "ios", "ipados": "ipados", "windows": "windows"}


def _eol_candidates(version):
    parts = re.findall(r"\d+", version or "")
    return [".".join(parts[:n]) for n in (3, 2, 1) if len(parts) >= n]


def check_eol(hosts, inv, offline, log, soon_days=90):
    subjects = []
    for h in hosts:
        m, os_ = fleet.name_of(h), h.get("os") or {}
        oid = (os_.get("id") or "").lower()
        if OS_SLUGS.get(oid) and os_.get("version"):
            subjects.append((m, OS_SLUGS[oid], OS_LABELS.get(oid, oid), os_["version"], "os"))
        for sw in h.get("software") or []:
            # distro packages follow the distro's support dates, which the OS check covers
            if sw.get("source") in ("apt", "pacman", "rpm", "snap"):
                continue
            sl = EOL_SLUGS.get(sw.get("name"))
            if sl and sw.get("version"):
                subjects.append((m, sl, sw["name"], sw["version"], sw.get("source")))
    for d in (inv or {}).get("devices", []):
        sl = MANUAL_SLUGS.get((d.get("platform") or "").lower())
        if sl and d.get("version") and d.get("status") != "retired":
            subjects.append((d["name"], sl, d["platform"], d["version"], "manual"))
    out, today, cache = [], dt.date.today(), {}
    for m, sl, label, ver, src in subjects:
        if sl not in cache:
            try:
                cache[sl] = th._get_json(f"{EOL_URL}/api/{sl}.json", f"eol_{sl}.json", 24 * 7, offline) or []
            except Exception as e:
                log(f"endoflife.date lookup for {sl} failed: {e}")
                cache[sl] = []
        rows = cache[sl] if isinstance(cache[sl], list) else []
        cycles = {str(r.get("cycle")).lower(): r for r in rows}
        row = next((cycles[c] for c in _eol_candidates(ver) if c in cycles), None)
        if row is None and sl == "windows" and ver.startswith("10"):
            row = next((r for k, r in cycles.items() if k.startswith("10")), None)
        if not row:
            continue
        eol = row.get("eol")
        if eol is True:
            when, ended = None, True
        elif isinstance(eol, str):
            try:
                when = dt.date.fromisoformat(eol)
            except ValueError:
                continue
            ended = when <= today
            if not ended and (when - today).days > soon_days:
                continue
        else:
            continue
        cyc = row.get("cycle")
        if ended:
            title = f"{label} {cyc} no longer gets security fixes" + (f" (ended {when})" if when else "")
        else:
            title = f"{label} {cyc} stops getting security fixes on {when} ({(when - today).days} days)"
        out.append({
            "machine": m, "severity": "high" if ended else "medium", "title": title,
            "detail": f"Installed: {ver}. Latest in that line: {row.get('latest') or '?'}.",
            "action": "Upgrade to a supported version." + (
                " Windows 10: Extended Security Updates enrolment can extend fixes." if sl == "windows" else ""),
            "source": "end-of-life", "exploited": False, "cves": [],
            "refs": [f"https://endoflife.date/{sl}"], "platform": label if src == "manual" else None,
            "key": slug(f"eol-{sl}-{cyc}")})
    return out


# ---------------------------------------------------------------- extras: snooze
def load_snoozes():
    try:
        return json.loads(SNOOZE.read_text(encoding="utf-8")) if SNOOZE.exists() else []
    except ValueError:
        return []


def apply_snoozes(items):
    today = dt.date.today().isoformat()
    active = [s for s in load_snoozes() if s.get("until", "9999") >= today]
    kept, hidden = [], []
    for i in items:
        hit = next((s for s in active if s["key"] == i["key"] and s.get("machine", "*") in ("*", i["machine"])), None)
        (hidden if hit else kept).append(dict(i, snoozed=hit) if hit else i)
    expired = [s for s in load_snoozes() if s.get("until", "9999") < today]
    return kept, hidden, expired


def snooze_cmd(a):
    snz = load_snoozes()
    if a.list or not a.key:
        if not snz:
            print("Nothing snoozed.")
        for s in snz:
            print(f"  {s['key']}  machine={s.get('machine', '*')}  until {s['until']}  - {s.get('reason', '')}")
        return 0
    if a.remove:
        new = [s for s in snz if s["key"] != a.key]
        SNOOZE.write_text(json.dumps(new, indent=2) + "\n", encoding="utf-8")
        print(f"Removed {len(snz) - len(new)} snooze(s) for {a.key}.")
        return 0
    if not a.reason:
        print("Please give a reason, e.g.  --reason \"only reachable over Tailscale\"", file=sys.stderr)
        return 2
    until = (dt.date.today() + dt.timedelta(days=a.days)).isoformat()
    snz = [s for s in snz if not (s["key"] == a.key and s.get("machine", "*") == (a.machine or "*"))]
    snz.append({"key": a.key, "machine": a.machine or "*", "reason": a.reason, "until": until,
                "added": dt.date.today().isoformat()})
    SNOOZE.write_text(json.dumps(snz, indent=2) + "\n", encoding="utf-8")
    print(f"Snoozed {a.key} until {until}. It comes back after that.")
    s = load_settings()
    if s and not s["extras"].get("snooze"):
        print("Note: the snooze list is turned off. Turn it on in  python3 fleet.py setup  "
              "or run the bulletin with  --with snooze.")
    return 0


# ---------------------------------------------------------------- extras: changes
def snapshot(hosts, items, level):
    return {"date": dt.date.today().isoformat(), "level": level,
            "items": sorted({f"{i['machine']}|{i['key']}|{i['title']}" for i in items}),
            "ports": {fleet.name_of(h): sorted({l["port"] for l in h.get("listening") or []
                                                if l.get("exposure") != "localhost"}) for h in hosts},
            "software": {fleet.name_of(h): {s["name"]: s.get("version") for s in h.get("software") or []}
                         for h in hosts}}


def diff(prev, cur):
    if not prev:
        return None
    pi, ci = set(prev.get("items", [])), set(cur["items"])
    lab = lambda k: k.split("|", 2)[0] + ": " + k.split("|", 2)[2]  # noqa: E731
    out = {"since": prev.get("date"), "level_before": prev.get("level"),
           "new": sorted(lab(k) for k in ci - pi), "fixed": sorted(lab(k) for k in pi - ci),
           "ports_opened": [], "ports_closed": [], "software": []}
    for m, ports in cur["ports"].items():
        before = set(prev.get("ports", {}).get(m, ports))
        out["ports_opened"] += [f"{m}: {p}" for p in sorted(set(ports) - before)]
        out["ports_closed"] += [f"{m}: {p}" for p in sorted(before - set(ports))]
    for m, sw in cur["software"].items():
        old = prev.get("software", {}).get(m)
        if old is None:
            continue
        for n in sorted(set(sw) | set(old)):
            if n not in old:
                out["software"].append(f"{m}: {n} {sw[n]} (new)")
            elif n not in sw:
                out["software"].append(f"{m}: {n} removed")
            elif sw[n] != old[n]:
                out["software"].append(f"{m}: {n} {old[n]} → {sw[n]}")
    return out


# ---------------------------------------------------------------- level + alerts
def urgent_items(items):
    return [i for i in items if i["severity"] == "critical" or (i["severity"] == "high" and i.get("exploited"))]


def threat_level(items, eol):
    urgent = urgent_items(items)
    if urgent:
        ms = sorted({i["machine"] for i in urgent})
        return "red", (f"{len(urgent)} urgent problem{'s' if len(urgent) != 1 else ''} "
                       f"(actively exploited or critical) on {', '.join(ms)}. Fix these first.")
    warn = [i for i in items if i["severity"] in ("high", "medium")] + [e for e in eol if e["severity"] == "high"]
    if warn:
        return "amber", f"{len(warn)} thing{'s' if len(warn) != 1 else ''} to fix, none under active attack."
    return "green", "Nothing urgent. Keep automatic updates on and check again next week."


def send_alert(s, level, items, log):
    a = s["alerts"]
    url = (a.get("ntfy_url") or "").strip()
    if not url or LEVEL_ORDER[level] > LEVEL_ORDER.get(a.get("min_level", "red"), 0):
        return False
    urgent = urgent_items(items) or [i for i in items if i["severity"] in ("high", "medium")]
    msg = f"{level.upper()}: {len(urgent)} {'urgent ' if level == 'red' else ''}item(s) to fix"
    if a.get("include_names"):
        msg += " on " + ", ".join(sorted({i["machine"] for i in urgent}))
    msg += ". Open your fleet bulletin."
    req = urllib.request.Request(url, data=msg.encode("utf-8"), method="POST", headers={
        "Title": "Fleet health check", "Priority": "5" if level == "red" else "4",
        "Tags": "rotating_light" if level == "red" else "warning"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return 200 <= r.status < 300
    except Exception as e:
        log(f"Alert not sent: {e}")
        return False


# ---------------------------------------------------------------- output
EMOJI = {"red": "🔴", "amber": "🟠", "green": "🟢"}


def render_md(b):
    L = [f"# Fleet health check: {b['date']}", "",
         f"## {EMOJI[b['level']]} Threat level: {b['level'].upper()}", "", b["why"], ""]
    if b["headlines"]:
        L += ["## Headlines", ""]
        for i in b["headlines"]:
            tags = [i["severity"].upper()]
            if i.get("exploited"):
                tags.append("being exploited")
            if i.get("ransomware"):
                tags.append("ransomware")
            if i.get("epss") is not None:
                tags.append(f"{i['epss'] * 100:.1f}% chance of attack in 30 days")
            L.append(f"### {i['title']}")
            L.append(f"**{i['machine']}** · {' · '.join(tags)} · source: {i['source']}")
            L.append("")
            if i.get("detail"):
                L.append(i["detail"])
                L.append("")
            L.append(f"*Why this matters:* {i['why']}")
            L.append("")
            L.append("**Show me how:**")
            L += [f"{n}. {step}" for n, step in enumerate(i["how"], 1)]
            if i.get("refs"):
                L.append("")
                L.append("More: " + " · ".join(i["refs"][:3]))
            if b["extras"].get("snooze"):
                L.append("")
                L.append(f"<sub>Handled or not relevant? `python3 fleet.py snooze {i['key']} --machine {i['machine']} "
                         f"--reason \"...\" --days 30`</sub>")
            L.append("")
    else:
        L += ["No headlines this week. ✅", ""]
    if b.get("minor"):
        L += [f"<details><summary>{len(b['minor'])} minor note(s)</summary>", ""]
        L += [f"- {i['machine']}: {i['title']}" for i in b["minor"]]
        L += ["", "</details>", ""]
    c = b.get("changes")
    if b["extras"].get("changes"):
        L += ["## What changed", ""]
        if not c:
            L += ["First bulletin. Next week this section shows only what's new or fixed.", ""]
        else:
            L.append(f"Since {c['since']} (level then: {(c.get('level_before') or '?').upper()}):")
            L.append("")
            for label, key in (("New", "new"), ("Fixed", "fixed"), ("Ports opened", "ports_opened"),
                               ("Ports closed", "ports_closed"), ("Software changed", "software")):
                if c[key]:
                    L.append(f"**{label}:**")
                    L += [f"- {x}" for x in c[key]]
                    L.append("")
            if not any(c[k] for k in ("new", "fixed", "ports_opened", "ports_closed", "software")):
                L += ["Nothing changed.", ""]
    if b["extras"].get("eol"):
        L += ["## End of life", ""]
        L += [f"- {e['machine']}: {e['title']}" for e in b["eol"]] or ["Nothing at or near end of life. ✅"]
        L.append("")
    if b["extras"].get("snooze") and (b["snoozed"] or b["snooze_expired"]):
        L += ["## Snoozed", ""]
        L += [f"- {i['machine']}: {i['title']} (until {i['snoozed']['until']}: {i['snoozed'].get('reason', '')})"
              for i in b["snoozed"]]
        L += [f"- Snooze expired: {s['key']} ({s.get('reason', '')}). It's back in the list if it still applies."
              for s in b["snooze_expired"]]
        L.append("")
    if b["extras"].get("home_checklist"):
        L += ["## Home devices checklist", "", "Things this tool can't see. Tick them off once a month or so.", ""]
        L += [f"- [ ] **{t}:** {what} *{why}*" for t, what, why in HOME_CHECKLIST]
        L.append("")
    L += ["---", f"Contacted: {', '.join(h for h, _ in b['contacts']) or 'nothing (offline)'}. "
          f"Change what runs with `python3 fleet.py setup`."]
    return "\n".join(L) + "\n"


def summary_text(b):
    L = [f"{EMOJI[b['level']]} Threat level: {b['level'].upper()}: {b['why']}"]
    for i in b["headlines"][:10]:
        mark = " (being exploited)" if i.get("exploited") else ""
        L.append(f"  [{i['severity'].upper()}] {i['machine']}: {i['title']}{mark}")
    if len(b["headlines"]) > 10:
        L.append(f"  ...and {len(b['headlines']) - 10} more")
    return "\n".join(L)


# ---------------------------------------------------------------- bulletin run
def run_bulletin(a):
    s = load_settings()
    if s is None:
        print("First time here? Run  python3 fleet.py setup  - it takes two minutes and explains "
              "what this tool looks at.")
        return 2
    extras = dict(s["extras"])
    for k in filter(None, (a.with_ or "").split(",")):
        if k not in EXTRAS:
            print(f"Unknown extra '{k}'. Choose from: {', '.join(EXTRAS)}", file=sys.stderr)
            return 2
        extras[k] = True
    for k in filter(None, (a.without or "").split(",")):
        extras[k] = False
    log = (lambda m: None) if a.quiet else (lambda m: print(m, file=sys.stderr))
    say = (lambda m: None) if a.quiet else print

    cts = contacts(s, extras)
    if a.offline:
        say("Offline: using saved copies only. Nothing will be contacted.")
    elif cts:
        say("This run will contact:")
        for host, sends in cts:
            say(f"  • {host}: {sends}")
    else:
        say("No online sources are turned on, so this run contacts nothing.")

    census_dir = Path(a.census) if a.census else HERE / "census"
    if s.get("refresh_census", True) and not a.no_refresh:
        say(f"Looking at this computer ({s['machine_name']})...")
        r = subprocess.run(["bash", str(HERE / "census.sh"), "--name", s["machine_name"],
                            "--out", str(census_dir / f"{s['machine_name']}.json")],
                           capture_output=True, text=True)
        if r.returncode != 0:
            log("Census of this computer failed:\n" + r.stderr[-500:])
    hosts = fleet.load_census(census_dir)
    inv_path = Path(a.inventory) if a.inventory else HERE / "inventory.json"
    inv = fleet.load_json(inv_path) if inv_path.exists() else None
    advisories = []
    for rf in (a.rules or [str(HERE / "rules" / "advisories.json")]):
        if Path(rf).exists():
            advisories += fleet.load_json(rf).get("advisories", [])

    tres = None
    use_kev, use_osv = bool(s["sources"].get("cisa_kev")), bool(s["sources"].get("osv"))
    if use_kev or use_osv:
        tres = th.scan(hosts, inv, days=a.days, offline=a.offline, kev_file=a.kev,
                       use_osv=use_osv, use_kev=use_kev, log=log)
        fleet.reconcile_threats(tres, hosts, inv, advisories)
        (HERE / "threats.json").write_text(json.dumps(tres, indent=2), encoding="utf-8")

    items = collect_items(hosts, inv, advisories, tres)
    eol = check_eol(hosts, inv, a.offline, log) if extras.get("eol") else []
    items += eol
    explain(items, hosts)
    if extras.get("epss") and not (a.offline and not any(i["cves"] for i in items)):
        add_epss(items, a.offline, log)
    snoozed, expired = [], []
    if extras.get("snooze"):
        items, snoozed, expired = apply_snoozes(items)

    items.sort(key=lambda i: (SEV_ORDER.get(i["severity"], 9), not i.get("exploited"),
                              -(i.get("epss") or 0), i["machine"]))
    level, why = threat_level(items, eol)
    headlines = [i for i in items if i["severity"] in ("critical", "high", "medium")]
    minor = [i for i in items if i["severity"] in ("low", "info")]

    OUT.mkdir(exist_ok=True)
    state_file = OUT / "state.json"
    snap = snapshot(hosts, items + snoozed, level)  # snoozed items aren't "fixed"
    prev = json.loads(state_file.read_text(encoding="utf-8")) if state_file.exists() else None
    changes = diff(prev, snap) if extras.get("changes") else None

    b = {"date": dt.date.today().isoformat(), "level": level, "why": why, "headlines": headlines,
         "minor": minor, "eol": eol, "snoozed": snoozed, "snooze_expired": expired,
         "changes": changes, "extras": extras, "contacts": [] if a.offline else cts,
         "checklist": [{"title": t, "what": w, "why": y} for t, w, y in HOME_CHECKLIST]
         if extras.get("home_checklist") else [],
         "machines": [fleet.name_of(h) for h in hosts]}
    md = render_md(b)
    dated = OUT / f"{b['date']}.md"
    dated.write_text(md, encoding="utf-8")
    (OUT / "latest.md").write_text(md, encoding="utf-8")
    state_file.write_text(json.dumps(snap, indent=1), encoding="utf-8")

    import dashboard as db
    data = db.build_data(hosts, inv, advisories, 30, tres)
    data["bulletin"] = b
    db.write(data, HERE / "dashboard.html")

    if a.quiet:  # scheduled runs: one line in the log so you can see it ran
        print(f"{dt.datetime.now():%Y-%m-%d %H:%M} {level.upper()}: {why} -> {dated}")
    alerted = False
    if extras.get("alerts") and not a.offline:
        alerted = send_alert(s, level, items, log)
    say("")
    say(summary_text(b))
    say("")
    say(f"Full bulletin: {dated}")
    say(f"Dashboard:     {HERE / 'dashboard.html'}  (open it in your browser)")
    if alerted:
        say("Phone alert sent.")
    return 1 if level == "red" else 0


# ---------------------------------------------------------------- schedule
MARK = "# fleet-census-bulletin"
PLIST = Path.home() / "Library" / "LaunchAgents" / "org.fleet-census.bulletin.plist"
DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]


def _job_cmd():
    # cron and launchd start with a bare PATH; give the census the usual tool locations
    return (f"cd '{HERE}' && PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin "
            f"/usr/bin/env python3 fleet.py bulletin --quiet "
            f">> '{OUT / 'schedule.log'}' 2>&1")


def plist_xml(sch):
    from xml.sax.saxutils import escape
    cmd = escape(_job_cmd())
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>org.fleet-census.bulletin</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>-lc</string><string>{cmd}</string></array>
  <key>StartCalendarInterval</key><dict>
    <key>Weekday</key><integer>{sch['weekday']}</integer>
    <key>Hour</key><integer>{sch['hour']}</integer><key>Minute</key><integer>{sch['minute']}</integer>
  </dict>
</dict></plist>
"""


def schedule_on(s, quiet=False):
    sch = s["schedule"]
    system = platform.system()
    OUT.mkdir(exist_ok=True)
    if system == "Darwin":
        PLIST.parent.mkdir(parents=True, exist_ok=True)
        PLIST.write_text(plist_xml(sch), encoding="utf-8")
        subprocess.run(["launchctl", "unload", str(PLIST)], capture_output=True)
        r = subprocess.run(["launchctl", "load", "-w", str(PLIST)], capture_output=True, text=True)
        ok = r.returncode == 0
    elif system == "Linux":
        if not shutil.which("crontab"):
            print("This computer has no 'crontab' command, so it can't schedule itself.\n"
                  "Install cron (e.g. 'sudo apt install cron' or 'sudo pacman -S cronie'), then run\n"
                  "  python3 fleet.py schedule on")
            return False
        cur = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
        lines = [l for l in cur.splitlines() if MARK not in l]
        lines.append(f"{sch['minute']} {sch['hour']} * * {sch['weekday']} {_job_cmd()} {MARK}")
        r = subprocess.run(["crontab", "-"], input="\n".join(lines) + "\n", capture_output=True, text=True)
        ok = r.returncode == 0
    else:
        print("Automatic scheduling isn't supported on this system yet. Run  python3 fleet.py bulletin  weekly.")
        return False
    if ok:
        s["schedule"]["enabled"] = True
        save_settings(s)
        if not quiet:
            print(f"Scheduled: every {DAYS[sch['weekday']]} at {sch['hour']:02d}:{sch['minute']:02d}. "
                  f"Turn off any time with  python3 fleet.py schedule off")
    else:
        print("Couldn't set up the schedule: " + (r.stderr or "").strip())
    return ok


def schedule_off(s=None, quiet=False):
    removed = False
    if PLIST.exists():
        subprocess.run(["launchctl", "unload", "-w", str(PLIST)], capture_output=True)
        PLIST.unlink()
        removed = True
    if shutil.which("crontab"):
        cur = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
        if MARK in cur:
            keep = [l for l in cur.splitlines() if MARK not in l]
            subprocess.run(["crontab", "-"], input="\n".join(keep) + ("\n" if keep else ""), text=True)
            removed = True
    if s:
        s["schedule"]["enabled"] = False
        save_settings(s)
    if not quiet:
        print("Weekly schedule removed." if removed else "No schedule was set.")
    return removed


def schedule_status():
    found = PLIST.exists()
    if shutil.which("crontab"):
        found = found or MARK in subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
    return found


def schedule_cmd(a):
    s = load_settings()
    if s is None:
        print("Run  python3 fleet.py setup  first.")
        return 2
    if a.action == "on":
        if a.day:
            s["schedule"]["weekday"] = [d.lower()[:3] for d in DAYS].index(a.day.lower()[:3])
        if a.time:
            hh, mm = a.time.split(":")
            s["schedule"]["hour"], s["schedule"]["minute"] = int(hh), int(mm)
        return 0 if schedule_on(s) else 1
    if a.action == "off":
        schedule_off(s)
        return 0
    sch = s["schedule"]
    if schedule_status():
        print(f"On: every {DAYS[sch['weekday']]} at {sch['hour']:02d}:{sch['minute']:02d}. Log: {OUT / 'schedule.log'}")
    else:
        print("Off. Turn on with  python3 fleet.py schedule on")
    return 0


# ---------------------------------------------------------------- sources
def sources_cmd(_a):
    s = load_settings() or default_settings()
    print("What this tool can contact, and exactly what it sends:\n")
    for k, v in SOURCES.items():
        state = "ON " if s["sources"].get(k) else "off"
        print(f" [{state}] {v['name']}  ({v['host']})\n        {v['what']}\n        Sends: {v['sends']}\n")
    for k, (host, sends) in EXTRA_HOSTS.items():
        state = "ON " if s["extras"].get(k) else "off"
        if k == "alerts" and s["alerts"].get("ntfy_url"):
            host = s["alerts"]["ntfy_url"]
        print(f" [{state}] {EXTRAS[k][0]}  ({host})\n        Sends: {sends}\n")
    print("Never sent anywhere: your IP addresses, open ports, passwords, keys, or file contents.")
    print("Add --offline to any bulletin to contact nothing at all.")
    return 0


# ---------------------------------------------------------------- setup
def ask(q, default=False, inp=input):
    hint = "[Y/n]" if default else "[y/N]"
    while True:
        try:
            ans = inp(f"{q} {hint} ").strip().lower()
        except EOFError:
            return default
        if not ans:
            return default
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("  Please answer y or n.")


def para(text):
    import textwrap
    print(textwrap.fill(text, 76, initial_indent="  ", subsequent_indent="  "))


def setup_cmd(a, inp=input):
    s = load_settings() or default_settings()
    if a.defaults:
        save_settings(s)
        print(f"Saved default settings to {SETTINGS.name}: the two main sources on, all extras off, no schedule.")
        return 0
    print("\n== Fleet health check: setup ==\n")
    para("This tool looks at what's installed on your computers and checks it against public lists "
         "of known security problems. It only reads. It never installs, changes or deletes anything "
         "on your machines.")
    para("It takes about two minutes. Press Enter to accept the answer in capitals.")
    print()
    name = ""
    try:
        name = inp(f"What should we call this computer? [{s['machine_name']}] ").strip()
    except EOFError:
        pass
    if name:
        s["machine_name"] = re.sub(r"[^A-Za-z0-9._-]", "-", name)

    print("\n-- Where it looks --\n")
    para("To spot problems it downloads information from these public sources. "
         "You can say no to any of them; the check just gets less thorough.")
    for k, v in SOURCES.items():
        print()
        print(f"  {v['name']}  ({v['host']})")
        para(v["what"])
        para("What it sends: " + v["sends"])
        s["sources"][k] = ask("  OK to check this?", default=s["sources"].get(k, True), inp=inp)

    print("\n-- Extras (all optional, all start as No) --\n")
    for k, (title, text) in EXTRAS.items():
        print(f"  {title}")
        para(text)
        s["extras"][k] = ask("  Turn this on?", default=s["extras"].get(k, False), inp=inp)
        if k == "alerts" and s["extras"][k]:
            para("ntfy is a free app (ntfy.sh, or one you host yourself). You pick a hard-to-guess "
                 "topic name, and anyone who knows it can read your alerts, so treat it like a password.")
            try:
                url = inp("  Your ntfy address (e.g. https://ntfy.sh/my-secret-topic-8271): ").strip()
            except EOFError:
                url = ""
            if not url.startswith(("http://", "https://")):
                print("  No valid address given, so alerts stay off.")
                s["extras"][k] = False
            else:
                s["alerts"]["ntfy_url"] = url
                s["alerts"]["include_names"] = ask("  Include your computer names in the alert?", False, inp)
                s["alerts"]["min_level"] = "amber" if ask(
                    "  Also alert for AMBER (not just RED)?", False, inp) else "red"
        print()

    print("-- Run it automatically? --\n")
    para("It can run itself once a week (Monday morning) and save a fresh bulletin. "
         "You can turn this off at any time.")
    want_schedule = ask("  Run automatically every week?", default=False, inp=inp)
    save_settings(s)
    if want_schedule:
        schedule_on(s)
    elif schedule_status():
        schedule_off(s, quiet=True)

    print("\n== All set ==\n")
    on = [EXTRAS[k][0] for k, v in s["extras"].items() if v]
    print(f"  Sources: {', '.join(SOURCES[k]['name'] for k, v in s['sources'].items() if v) or 'none (offline only)'}")
    print(f"  Extras:  {', '.join(on) if on else 'none'}")
    print(f"  Weekly:  {'yes' if s['schedule']['enabled'] else 'no'}")
    print()
    print("  Change any of this:      python3 fleet.py setup")
    print("  See what gets contacted: python3 fleet.py sources")
    print("  Remove everything:       python3 fleet.py uninstall")
    print()
    if ask("Run your first health check now?", default=True, inp=inp):
        return run_bulletin(argparse.Namespace(offline=False, quiet=False, with_="", without="", census=None,
                                               inventory=None, rules=None, days=30, kev=None, no_refresh=False))
    print("Run it any time with:  python3 fleet.py bulletin")
    return 0


# ---------------------------------------------------------------- uninstall
def uninstall_cmd(a, inp=input):
    targets = [p for p in (SETTINGS, SNOOZE, OUT, HERE / "dashboard.html", HERE / "fleet-data.js",
                           HERE / "threats.json", HERE / "FLEET.md", HERE / "watchlist.json") if p.exists()]
    census = [p for p in (HERE / "census").glob("*.json")] if not a.keep_census else []
    cache = th.CACHE if th.CACHE.exists() else None
    sched = schedule_status()
    if not (targets or census or cache or sched):
        print("Nothing to remove. To delete the program itself, delete this folder:\n  " + str(HERE))
        return 0
    print("This will remove:")
    if sched:
        print("  • the weekly schedule")
    for p in targets:
        print(f"  • {p.relative_to(HERE)}")
    if census:
        print(f"  • {len(census)} census file(s) in census/")
    if cache:
        print(f"  • downloaded feed copies in {cache}")
    if not a.yes and not ask("Go ahead?", default=False, inp=inp):
        print("Nothing removed.")
        return 0
    schedule_off(quiet=True)
    for p in targets + census:
        shutil.rmtree(p) if p.is_dir() else p.unlink()
    if cache:
        shutil.rmtree(cache, ignore_errors=True)
    print("Done. To delete the program itself too, delete this folder:\n  " + str(HERE))
    return 0


# ---------------------------------------------------------------- CLI
COMMANDS = ("setup", "bulletin", "snooze", "schedule", "sources", "uninstall")


def cli(argv):
    ap = argparse.ArgumentParser(prog="fleet.py", description="Weekly fleet health check")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("setup", help="first-time walkthrough")
    p.add_argument("--defaults", action="store_true", help="save default settings without questions")
    p = sub.add_parser("bulletin", help="run the weekly health check")
    p.add_argument("--offline", action="store_true", help="contact nothing; use saved copies")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--with", dest="with_", default="", help="extras to turn on for this run, e.g. changes,epss")
    p.add_argument("--without", default="", help="extras to turn off for this run")
    p.add_argument("--census", default=None)
    p.add_argument("--inventory", default=None)
    p.add_argument("--rules", action="append", default=None)
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--kev", default=None, help="use a downloaded CISA KEV file")
    p.add_argument("--no-refresh", action="store_true", help="don't re-run the census of this computer")
    p = sub.add_parser("snooze", help="hide a handled warning for a while")
    p.add_argument("key", nargs="?")
    p.add_argument("--reason", default="")
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--machine", default=None)
    p.add_argument("--list", action="store_true")
    p.add_argument("--remove", action="store_true")
    p = sub.add_parser("schedule", help="weekly automatic run: on, off or status")
    p.add_argument("action", choices=["on", "off", "status"], nargs="?", default="status")
    p.add_argument("--day", default=None, help="e.g. monday")
    p.add_argument("--time", default=None, help="24h, e.g. 09:17")
    sub.add_parser("sources", help="what gets contacted and what is sent")
    p = sub.add_parser("uninstall", help="remove everything this tool created")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--keep-census", action="store_true")
    a = ap.parse_args(argv)
    return {"setup": setup_cmd, "bulletin": run_bulletin, "snooze": snooze_cmd, "schedule": schedule_cmd,
            "sources": sources_cmd, "uninstall": uninstall_cmd}[a.cmd](a)
