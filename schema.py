"""
schema.py - check that a census file is what it claims to be before anything trusts it.

A census can arrive from another machine over SSH, or be copied in by hand, so it is
treated as untrusted input: right size, valid JSON, expected structure, sensible types,
and a machine name that is safe to use in file names and on the dashboard.

  python3 fleet.py validate census/*.json
  python3 fleet.py validate incoming.json --expect-name pi-garage

Standard library only.
"""
import json
import re
from pathlib import Path

MAX_BYTES = 5 * 1024 * 1024         # a real census is a few KB to a few hundred KB
MAX_STR = 4000                      # longest allowed text value
MAX_LIST = 5000                     # longest allowed list
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def safe_name(s):
    """True if s can be used as a machine name / file name."""
    return isinstance(s, str) and bool(NAME_RE.match(s)) and s not in (".", "..")


class _V:
    def __init__(self):
        self.errors = []

    def err(self, path, msg):
        if len(self.errors) < 50:
            self.errors.append(f"{path}: {msg}")

    def type(self, path, val, kinds, required=False):
        """kinds: tuple of python types; None in kinds means null is allowed."""
        if val is None:
            if required:
                self.err(path, "is required")
            elif None not in kinds:
                self.err(path, "must not be null")
            return False
        real = tuple(k for k in kinds if k is not None)
        # bool is a subclass of int; don't let True pass as a number or vice versa
        if isinstance(val, bool) and bool not in real:
            self.err(path, f"must be {self._names(real)}, not true/false")
            return False
        if not isinstance(val, real):
            self.err(path, f"must be {self._names(real)}, got {type(val).__name__}")
            return False
        if isinstance(val, str) and len(val) > MAX_STR:
            self.err(path, f"is too long ({len(val)} characters)")
            return False
        if isinstance(val, list) and len(val) > MAX_LIST:
            self.err(path, f"has too many items ({len(val)})")
            return False
        return True

    @staticmethod
    def _names(kinds):
        m = {str: "text", int: "a whole number", float: "a number", bool: "true/false",
             list: "a list", dict: "an object"}
        return " or ".join(m.get(k, k.__name__) for k in kinds)

    def obj(self, path, val, fields, required=False):
        """fields: {key: (kinds, required)}"""
        if not self.type(path, val, (dict, None), required):
            return
        for k, (kinds, req) in fields.items():
            self.type(f"{path}.{k}", val.get(k), kinds, req)


S, N, B, I = (str, None), (int, float, None), (bool, None), (int, None)


def validate(doc):
    """Return a list of problems (empty list = valid)."""
    v = _V()
    if not isinstance(doc, dict):
        return ["top level: must be a JSON object"]
    if v.type("census_version", doc.get("census_version"), (str,), True) and \
            not VERSION_RE.match(doc["census_version"]):
        v.err("census_version", "must look like 1.2.0")
    if v.type("collected_at", doc.get("collected_at"), (str,), True) and not TIME_RE.match(doc["collected_at"]):
        v.err("collected_at", "must look like 2026-10-24T12:00:00Z")

    host = doc.get("host")
    v.obj("host", host, {"hostname": (S, False), "role": (S, False), "model": (S, False), "cpu": (S, False),
                         "arch": (S, False), "memory_gb": (N, False), "uptime": (S, False),
                         "tags": ((dict, None), False), "gpus": ((list, None), False)}, required=True)
    if isinstance(host, dict):
        name = host.get("name")
        if not safe_name(name):
            v.err("host.name", "is required and may only use letters, numbers, '.', '-' and '_' (max 64)")
        for k, t in (host.get("tags") or {}).items():
            v.type(f"host.tags.{k}", t, (str,))
        for n, g in enumerate(host.get("gpus") or []):
            v.obj(f"host.gpus[{n}]", g, {"vendor": (S, False), "name": (S, False), "driver": (S, False),
                                         "cuda": (S, False)}, True)

    os_ = doc.get("os")
    v.obj("os", os_, {"id": (S, False), "name": (S, False), "version": (S, False), "build": (S, False),
                      "kernel": (S, False)}, required=True)
    if isinstance(os_, dict) and os_.get("family") not in ("linux", "macos", "windows", "unknown"):
        v.err("os.family", "must be linux, macos, windows or unknown")

    v.obj("updates", doc.get("updates"), {"package_manager": (S, False), "automatic": (B, False),
                                          "pending": (I, False)})
    if isinstance(doc.get("updates"), dict) and isinstance(doc["updates"].get("pending"), int) \
            and doc["updates"]["pending"] < 0:
        v.err("updates.pending", "can't be negative")
    v.obj("security", doc.get("security"), {"firewall_active": (B, False), "firewall_tool": (S, False),
                                            "disk_encrypted": (B, False), "ssh_server_running": (B, False),
                                            "ssh_password_auth": (S, False), "ssh_root_login": (S, False)})
    ts = doc.get("tailscale")
    v.obj("tailscale", ts, {"installed": (B, False), "version": (S, False), "node_name": (S, False),
                            "ips": (S, False), "tags": ((list, None), False), "key_expiry": (S, False),
                            "online": (B, False)})
    for n, t in enumerate((ts or {}).get("tags") or [] if isinstance(ts, dict) else []):
        v.type(f"tailscale.tags[{n}]", t, (str,))

    if v.type("listening", doc.get("listening"), (list,), True):
        for n, l in enumerate(doc["listening"]):
            p = f"listening[{n}]"
            if not v.type(p, l, (dict,), True):
                continue
            v.obj(p, l, {"proto": ((str,), True), "address": (S, False), "process": (S, False),
                         "user": (S, False)}, True)
            port = l.get("port")
            if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
                v.err(f"{p}.port", "must be a whole number from 1 to 65535")
            if l.get("exposure") not in ("localhost", "all", "specific"):
                v.err(f"{p}.exposure", "must be localhost, all or specific")

    if v.type("software", doc.get("software"), (list,), True):
        for n, sw in enumerate(doc["software"]):
            v.obj(f"software[{n}]", sw, {"name": ((str,), True), "version": (S, False), "source": (S, False),
                                         "package": (S, False), "package_version": (S, False),
                                         "package_source": (S, False), "raw": (S, False), "path": (S, False)}, True)

    c = doc.get("containers")
    if isinstance(c, list):
        for n, x in enumerate(c):
            v.obj(f"containers[{n}]", x, {"name": (S, False), "image": (S, False), "ports": (S, False)}, True)
    else:
        v.type("containers", c, (str, None))

    def comfy(path, val):
        if v.type(path, val, (list, None)):
            for n, x in enumerate(val or []):
                v.obj(f"{path}[{n}]", x, {"path": (S, False), "custom_nodes": ((list, None), False)}, True)
                for m, node in enumerate((x or {}).get("custom_nodes") or [] if isinstance(x, dict) else []):
                    v.type(f"{path}[{n}].custom_nodes[{m}]", node, (str,))
    comfy("comfyui", doc.get("comfyui"))

    def secrets(path, val):
        if v.type(path, val, (dict, None)):
            for k, x in (val or {}).items():
                if isinstance(x, bool) or x is None:
                    continue
                if not isinstance(x, int) or x < 0:
                    v.err(f"{path}.{k}", "must be a count (0 or more) or true/false")
    secrets("secrets_present", doc.get("secrets_present"))

    acc = doc.get("accounts")
    if acc is not None:
        if not v.type("accounts", acc, (dict,)):
            pass
        elif acc.get("mode") not in ("single-user", "all-users"):
            v.err("accounts.mode", "must be single-user or all-users")
        else:
            v.type("accounts.collected_as", acc.get("collected_as"), S)
            if acc["mode"] == "single-user":
                v.type("accounts.other_accounts", acc.get("other_accounts"), I)
            elif v.type("accounts.users", acc.get("users"), (list,), True):
                for n, u in enumerate(acc["users"]):
                    p = f"accounts.users[{n}]"
                    v.obj(p, u, {"name": ((str,), True), "uid": ((int,), False), "admin": (B, False),
                                 "password": (S, False), "login_shell": (S, False),
                                 "autostart": ((dict, None), False), "software": ((dict, None), False)}, True)
                    if isinstance(u, dict):
                        for k, names in (u.get("software") or {}).items():
                            if v.type(f"{p}.software.{k}", names, (list, None)):
                                for m, s in enumerate(names or []):
                                    v.type(f"{p}.software.{k}[{m}]", s, (str,))
                        comfy(f"{p}.comfyui", u.get("comfyui"))
                        secrets(f"{p}.secrets_present", u.get("secrets_present"))
    return v.errors


def validate_file(path, expect_name=None):
    """(document or None, list of problems)."""
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError as e:
        return None, [f"can't read the file ({e.strerror})"]
    if size == 0:
        return None, ["the file is empty (the census on that machine probably failed)"]
    if size > MAX_BYTES:
        return None, [f"the file is {size // 1024} KB, larger than any real census ({MAX_BYTES // 1048576} MB limit)"]
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        return None, ["the file isn't text (not a census)"]
    except ValueError as e:
        return None, [f"not valid JSON ({e.msg} at line {e.lineno}): the census output was cut off or mixed "
                      "with other text, e.g. a login banner"]
    errors = validate(doc)
    if expect_name and not errors and doc["host"]["name"] != expect_name:
        errors.append(f"host.name is '{doc['host']['name']}' but '{expect_name}' was expected")
    return (doc if not errors else None), errors
