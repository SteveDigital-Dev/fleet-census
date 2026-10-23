"""
threats.py - quick "is anything on my fleet under attack right now?" search.

Two public sources, both free, no account needed:

1. CISA Known Exploited Vulnerabilities (KEV): bugs that are being exploited
   in the wild right now. Matched by vendor/product against every machine's
   OS, hardware (CPU, GPU, board), software and manually listed devices.
   KEV has no version numbers, so a match means "this kind of thing is under
   attack, check you're patched" - not proof you're vulnerable.

2. OSV.dev: exact version lookups for packages installed by apt on
   Debian/Ubuntu/Mint/Raspberry Pi OS. A match means the installed package
   version is known-vulnerable and a newer version fixes it.

Results are cached in ~/.cache/fleet-census so repeat runs are fast and
work offline (use --offline).
Uses only the Python standard library.
"""
import datetime as dt
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

KEV_URL = os.environ.get(
    "FLEET_KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
OSV_URL = os.environ.get("FLEET_OSV_URL", "https://api.osv.dev")
CACHE = Path(os.environ.get("FLEET_CACHE_DIR", Path.home() / ".cache" / "fleet-census"))
UA = {"User-Agent": "fleet-census/1.1 (+https://github.com/SteveDigital-Dev/fleet-census)",
      "Content-Type": "application/json"}

# What to look for in KEV. Each entry: (vendor regex, product regex). Empty
# product regex = any product from that vendor (only used for vendors with
# a small, relevant product range).
SOFTWARE_KEYS = {
    "php": [("php", "php")], "php-fpm": [("php", "php")],
    "openssh": [("openbsd|openssh", "openssh")],
    "sudo": [("sudo|todd miller", "sudo")],
    "glibc": [("gnu", "glibc|c library")],
    "openssl": [("openssl", "openssl")],
    "nginx": [("nginx|f5", "nginx")],
    "apache2": [("apache", "http server|httpd")], "httpd": [("apache", "http server|httpd")],
    "caddy": [("caddy", "")],
    "redis": [("redis", "redis")],
    "postgres": [("postgresql", "postgresql")],
    "mysql": [("oracle|mysql", "mysql")],
    "docker": [("docker", "")], "podman": [("red hat|podman", "podman")],
    "git": [("git", "^git")],
    "node": [("node|nodejs", "node")],
    "python3": [("python", "python")],
    "tailscale": [("tailscale", "")],
    "ollama": [("ollama", "")],
    "llama-server": [("ggml|llama", "")],
    "lms": [("lm studio|element labs", "")],
    "proxmox": [("proxmox", "")],
    "code": [("microsoft", "visual studio code")],
    "blender": [("blender", "")],
    "systemd": [("systemd|freedesktop", "systemd")],
    "brew": [("homebrew", "")],
    # also_watch / inventory names
    "chrome": [("google", "chrom")], "chromium": [("google", "chrom")],
    "firefox": [("mozilla", "firefox")], "safari": [("apple", "safari|webkit|multiple products")],
    "comfyui": [("comfy", "")], "swarmui": [("swarm", "")], "chromadb": [("chroma", "")],
    "portainer": [("portainer", "")], "openclaw": [("openclaw", "")],
    "unreal-engine": [("epic games", "unreal")], "godot": [("godot", "")],
    "nvidia-driver": [("nvidia", "")], "cuda": [("nvidia", "")],
    "pytorch": [("pytorch|meta|linux foundation", "torch")],
    "huggingface-hub": [("hugging", "")],
    "forgejo": [("forgejo|codeberg", "")], "gitea": [("gitea", "")],
    "github": [("github", "")], "notion": [("notion", "")],
    "rdp": [("microsoft", "remote desktop")], "smb": [("microsoft", "smb|server message block")],
    "windows-10": [("microsoft", "windows")],
}
OS_KEYS = {
    "linux": [("linux", "kernel")],
    "macos": [("apple", "macos|multiple products")],
    "ios": [("apple", "ios|ipados|iphone|multiple products")],
    "ipados": [("apple", "ios|ipados|multiple products")],
    "windows": [("microsoft", "windows|win32k")],
    "meta-horizon-os": [("meta|oculus", "")],
    "esp-idf": [("espressif", "")],
    "rp2040-firmware": [("raspberry", "")],
}


def _hw_keys(host):
    keys = []
    cpu = ((host.get("host") or {}).get("cpu") or "").lower()
    model = ((host.get("host") or {}).get("model") or "").lower()
    if "intel" in cpu:
        keys.append(("cpu: Intel", [("intel", "")]))
    if "amd" in cpu or "ryzen" in cpu:
        keys.append(("cpu: AMD", [("amd", "")]))
    if "raspberry pi" in model:
        keys.append(("board: Raspberry Pi", [("raspberry|broadcom", "")]))
    for g in (host.get("host") or {}).get("gpus") or []:
        v = (g.get("vendor") or g.get("name") or "").lower()
        if "nvidia" in v:
            keys.append((f"gpu: {g.get('name')} driver {g.get('driver') or '?'}", [("nvidia", "")]))
    return keys


def targets_for_host(host):
    """[(label, [(vendor_re, product_re), ...]), ...] for one census file."""
    out = []
    os_ = host.get("os") or {}
    fam = os_.get("family")
    if fam == "linux":
        out.append((f"linux kernel {os_.get('kernel') or ''}", OS_KEYS["linux"]))
    elif fam in OS_KEYS:
        out.append((f"{fam} {os_.get('version') or ''}", OS_KEYS[fam]))
    out += _hw_keys(host)
    for sw in host.get("software") or []:
        k = SOFTWARE_KEYS.get(sw.get("name"))
        if k:
            out.append((f"{sw['name']} {sw.get('version') or ''}", k))
    ts = host.get("tailscale") or {}
    if ts.get("installed"):
        out.append((f"tailscale {ts.get('version') or ''}", SOFTWARE_KEYS["tailscale"]))
    for c in host.get("containers") or [] if isinstance(host.get("containers"), list) else []:
        img = (c.get("image") or "").split("/")[-1].split(":")[0].lower()
        if img in SOFTWARE_KEYS:
            out.append((f"container {c.get('image')}", SOFTWARE_KEYS[img]))
    return out


def targets_for_manual(device):
    out = []
    p = (device.get("platform") or "").lower()
    if p in OS_KEYS:
        out.append((f"{p} {device.get('version') or ''}".strip(), OS_KEYS[p]))
    elif p in SOFTWARE_KEYS:
        out.append((p, SOFTWARE_KEYS[p]))
    if device.get("vendor"):  # e.g. a router: "vendor": "TP-Link"
        out.append((f"vendor {device['vendor']}", [(re.escape(device["vendor"].lower()), "")]))
    return out


# ---------- fetching with cache ----------
def _get_json(url, cache_name, max_age_h, offline, data=None):
    CACHE.mkdir(parents=True, exist_ok=True)
    f = CACHE / cache_name
    fresh = f.exists() and (time.time() - f.stat().st_mtime) < max_age_h * 3600
    if f.exists() and (fresh or offline):
        return json.loads(f.read_text(encoding="utf-8"))
    if offline:
        return None
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None, headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        body = json.loads(r.read().decode("utf-8"))
    f.write_text(json.dumps(body), encoding="utf-8")
    return body


def load_kev(path=None, offline=False):
    if path:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    return _get_json(KEV_URL, "kev.json", 6, offline)


# ---------- KEV matching ----------
def match_kev(kev, targets, days):
    today = dt.date.today()
    hits = []
    for v in (kev or {}).get("vulnerabilities", []):
        vendor = (v.get("vendorProject") or "").lower()
        product = (v.get("product") or "").lower()
        for label, keys in targets:
            if any(re.search(vr, vendor) and (not pr or re.search(pr, product)) for vr, pr in keys):
                try:
                    added = dt.date.fromisoformat(v.get("dateAdded", "1970-01-01"))
                except ValueError:
                    added = dt.date(1970, 1, 1)
                age = (today - added).days
                hits.append({
                    "source": "CISA KEV", "id": v.get("cveID"), "matched": label,
                    "title": f"{v.get('vendorProject')} {v.get('product')}: {v.get('vulnerabilityName')}",
                    "summary": v.get("shortDescription", ""),
                    "action": v.get("requiredAction", ""),
                    "date_added": v.get("dateAdded"), "age_days": age,
                    "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
                    "recent": age <= days,
                    "severity": "critical" if age <= days and (v.get("knownRansomwareCampaignUse") or "").lower() == "known"
                    else ("high" if age <= days else "info"),
                    "url": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}",
                })
                break
    return hits


# ---------- OSV ----------
def osv_ecosystem(host):
    os_ = host.get("os") or {}
    oid, ver = (os_.get("id") or "").lower(), os_.get("version") or ""
    if oid == "debian" or (oid == "raspbian"):
        return f"Debian:{ver.split('.')[0]}" if ver else None
    if oid == "ubuntu" and ver:
        return f"Ubuntu:{ver}:LTS" if ver.split(".")[1:2] == ["04"] and int(ver.split(".")[0]) % 2 == 0 else f"Ubuntu:{ver}"
    if oid == "linuxmint" and ver:
        # Mint 22.x is built on Ubuntu 24.04, 21.x on 22.04, 20.x on 20.04
        base = {"22": "24.04", "21": "22.04", "20": "20.04"}.get(ver.split(".")[0])
        return f"Ubuntu:{base}:LTS" if base else None
    return None


def match_osv(host, offline=False, max_details=150):
    eco = osv_ecosystem(host)
    if not eco:
        return [], None
    pkgs = []
    for sw in host.get("software") or []:
        if sw.get("source") == "apt" and sw.get("package_version"):
            name = sw.get("package_source") or sw.get("package")
            if name and (name, sw["package_version"]) not in [(p[0], p[1]) for p in pkgs]:
                pkgs.append((name, sw["package_version"], sw["name"]))
    if not pkgs:
        return [], eco
    queries = [{"package": {"name": n, "ecosystem": eco}, "version": v} for n, v, _ in pkgs]
    key = re.sub(r"[^a-zA-Z0-9]+", "_", f"osv_{eco}_{'_'.join(n + v for n, v, _ in pkgs)}")[:180] + ".json"
    res = _get_json(f"{OSV_URL}/v1/querybatch", key, 12, offline, data={"queries": queries})
    if not res:
        return [], eco
    hits, fetched = [], 0
    for (name, ver, swname), r in zip(pkgs, res.get("results", [])):
        ids = [v["id"] for v in r.get("vulns") or []]
        if not ids:
            continue
        details = []
        for vid in ids:
            if fetched >= max_details:
                break
            d = _get_json(f"{OSV_URL}/v1/vulns/{vid}", f"vuln_{re.sub(r'[^A-Za-z0-9-]', '_', vid)}.json", 24 * 7, offline)
            fetched += 1
            if d:
                details.append(d)
        cves = sorted({a for d in details for a in d.get("aliases") or [] if a.startswith("CVE-")}
                      | {d["id"] for d in details if d.get("id", "").startswith("CVE-")})
        fixed = _fixed_version(details, name, eco)
        hits.append({
            "source": "OSV", "id": f"{len(ids)} known vulns", "matched": f"{swname} ({name} {ver})",
            "title": f"{name} {ver} has {len(ids)} known vulnerabilit{'y' if len(ids) == 1 else 'ies'}",
            "summary": "; ".join(sorted({(d.get('summary') or d.get('id'))[:90] for d in details})[:5]),
            "action": (f"Update to {fixed} or newer (sudo apt update && sudo apt upgrade)" if fixed
                       else "Run your system update; some of these may not have a fix yet."),
            "cves": cves, "ids": ids, "fixed": fixed, "recent": False, "ransomware": False,
            "severity": "medium", "url": f"https://osv.dev/list?ecosystem={eco.split(':')[0]}&q={name}",
        })
    return hits, eco


def _fixed_version(details, name, eco):
    best = None
    for d in details:
        for a in d.get("affected") or []:
            pk = a.get("package") or {}
            if pk.get("name") != name:
                continue
            for rg in a.get("ranges") or []:
                for ev in rg.get("events") or []:
                    if "fixed" in ev:
                        best = ev["fixed"] if best is None or _deb_key(ev["fixed"]) > _deb_key(best) else best
    return best


def _deb_key(v):
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", v or "") if x]


# ---------- main entry ----------
def scan(hosts, inventory, days=30, offline=False, kev_file=None, use_osv=True, log=print):
    try:
        kev = load_kev(kev_file, offline)
    except Exception as e:
        log(f"Couldn't fetch the CISA KEV list ({e}). Try again online, or pass --kev FILE.")
        kev = None
    out = {"generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "window_days": days,
           "kev_catalog": (kev or {}).get("catalogVersion"), "kev_count": len((kev or {}).get("vulnerabilities", [])),
           "machines": {}}
    for h in hosts:
        name = (h.get("host") or {}).get("name") or h.get("_file")
        hits = match_kev(kev, targets_for_host(h), days) if kev else []
        if use_osv:
            try:
                osv_hits, _ = match_osv(h, offline)
                kev_cves = {x["id"] for x in hits}
                for oh in osv_hits:
                    if kev_cves & set(oh.get("cves") or []):
                        oh["severity"] = "critical"
                        oh["title"] += " - includes ACTIVELY EXPLOITED bug(s)"
                hits += osv_hits
            except Exception as e:
                log(f"OSV lookup failed for {name}: {e}")
        out["machines"][name] = hits
    for d in (inventory or {}).get("devices", []):
        if d.get("census") == "manual" and d.get("status") not in ("retired",):
            t = targets_for_manual(d)
            if t and kev:
                out["machines"][f"{d.get('name')} (manual)"] = match_kev(kev, t, days)
    return out


def summarize(result):
    """Human-readable lines, most urgent first."""
    lines, clear = [], []
    order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    for m, hits in result["machines"].items():
        urgent = [x for x in hits if x["severity"] in ("critical", "high", "medium")]
        older = len(hits) - len(urgent)
        if not urgent:
            clear.append(m)
            continue
        lines.append(f"\n== {m} == {len(urgent)} to act on" + (f" ({older} older KEV matches, see JSON)" if older else ""))
        for x in sorted(urgent, key=lambda x: order.get(x["severity"], 9)):
            tag = " [RANSOMWARE]" if x.get("ransomware") else ""
            when = f" added {x['date_added']}" if x.get("date_added") else ""
            lines.append(f"  [{x['severity'].upper()}]{tag} {x['id']} - {x['title']}")
            lines.append(f"      matched: {x['matched']}{when}")
            lines.append(f"      do: {x['action']}")
    if clear:
        lines.append(f"\nNo recent matches: {', '.join(clear)}")
    return "\n".join(lines)


if __name__ == "__main__":
    print("Run this through fleet.py:  python3 fleet.py threats", file=sys.stderr)
