# fleet-census

A small, read-only toolkit for people who run a few computers at home (a
homelab, a studio, a pile of Raspberry Pis) and want answers to:

- **What's actually running on each machine?**
- **Is any of it exposed or out of date?**
- **When the next big bug hits the news, does it affect me?**

It's two scripts with no installs and no accounts:

| | What it does |
|---|---|
| `census.sh` | Runs on one machine (Linux, macOS, Raspberry Pi). Records OS, updates, firewall, SSH, disk encryption, Tailscale, open ports, installed software, Docker containers, ComfyUI custom nodes, and *whether* credential files exist. Saves one JSON file. |
| `fleet.py` | Reads all the JSON files and writes a **report** (`FLEET.md`) with findings and exact fixes, a **check** (good for scripts), and a **watch list** to feed a daily "any new vulnerabilities for me?" prompt. |
| `fleet.py threats` | **Threat search.** Checks every machine's hardware (CPU, GPU, board), OS and software against live public feeds: CISA's list of bugs being exploited *right now*, and OSV.dev for exact package versions. |
| `fleet.py dashboard` | **Dashboard.** One page that opens straight from disk in any browser (no server, no internet). It shows an "Act now" list with copy-paste fixes, machine cards, manual devices, inventory, and a search box across everything. |

It changes nothing, needs no root, and **never reads secret values**. It only
counts things like SSH keys and `.env` files so you know what to rotate if a
machine is compromised.

---

## Quick start (5 minutes)

```bash
git clone <this repo> fleet-census
cd fleet-census

# 1. On each machine (or see "Collect from many machines" below):
./census.sh --name my-laptop --role "daily driver"

# 2. Search for live threats against what you actually run:
python3 fleet.py threats

# 3. Build the dashboard and/or the written report:
python3 fleet.py dashboard     # then open dashboard.html in your browser
python3 fleet.py report        # FLEET.md
```

Want to see it with example data first?

```bash
python3 fleet.py threats   --census examples/census --inventory inventory.example.json --kev tests/fixtures/kev-sample.json --no-osv
python3 fleet.py dashboard --census examples/census --inventory inventory.example.json --out /tmp/example.html --inline
```
(The sample threat feed in `tests/fixtures` is fake test data. Leave out `--kev` to use the real feed.)

## Collect from many machines

If you can SSH into your machines (Tailscale SSH works great), run this from one machine:

```bash
./collect.sh pi-garage studio-mini me@100.64.0.22=old-laptop
python3 fleet.py report
```

Or run `./census.sh` on each machine and copy the files from `census/` into
one place. A shared folder, `tailscale file cp`, or a USB stick all work.

## Keep a list of what you own

Copy `inventory.example.json` to `inventory.json` and list every device,
including the ones the script can't run on, like phones, tablets, ESP32s and
your router. Mark those `"census": "manual"` and type in their version. The
report then shows:

- which machines still need a census
- whether a manually listed iPhone or iPad is on a vulnerable version

## When a big vulnerability hits the news

1. Add it to `rules/advisories.json`. Copy an existing entry and set the fixed versions.
2. Run `python3 fleet.py check`. Every affected machine is listed.

The file already includes **PHP2Shell** (CVE-2026-109618/109619) and the
**Apple CoreGraphics zero-day** (CVE-2026-86950) as examples.

> **Distro packages:** Ubuntu, Debian and others often patch a bug *without*
> changing the version number, so a distro-installed version may look old
> even after the fix. Findings for those say "possibly vulnerable (verify)".
> Run your system update and check your distro's security notices.

## Threat search: how it works

`python3 fleet.py threats` builds a list of what each machine is made of:

- **OS:** Linux kernel, macOS, iOS, Windows
- **Hardware:** Intel or AMD CPU, NVIDIA GPU, Raspberry Pi board
- **Software and containers:** everything the census found
- **Manual devices:** phones, headsets, microcontrollers, plus any `"vendor"` you set, e.g. your router's maker

It then checks those against two free public sources:

| Source | What a match means |
|---|---|
| [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Attackers are using this bug **right now**. KEV doesn't list versions, so a match means "check you're patched". Matches added in the last 30 days (`--days`) count as **immediate**. Ones linked to ransomware are marked critical. If one of your `rules/advisories.json` rules shows you're already on the fixed version, the match drops to info. |
| [OSV.dev](https://osv.dev) | **Exact** version check for packages installed with apt (Debian, Ubuntu, Mint, Raspberry Pi OS). Tells you which update fixes it. If any of those bugs is also on CISA's list, it's marked critical. |

Results are cached in `~/.cache/fleet-census`, so `--offline` works on a plane. Exit code 1 means
something urgent, so it can drive scripts and alerts.

## Daily security watch (optional)

```bash
python3 fleet.py watchlist     # writes watchlist.json
```

Paste the prompt in `watch/WATCH-PROMPT.md`, plus your `watchlist.json`, into
any AI assistant that can search the web, or schedule it daily. It reports
only new problems that match software you actually run.

## Keep your census private

A census is effectively a **map of your attack surface**: every machine, open
port and version. So, by default:

- `census/`, `inventory.json`, `FLEET.md`, `watchlist.json`, `threats.json` and the generated dashboard are listed in
  `.gitignore`. Forking this repo and pushing won't leak your fleet.
- `./census.sh --redact` leaves out IP addresses.

If you *want* your census in git (a great way to see what changed over time),
use a **private** repo, ideally a self-hosted one (Forgejo or Gitea on a
Pi, reachable only over Tailscale). Then remove those lines from `.gitignore`.
`docs/PRIVATE-REPO.md` shows how.

## What's in here

```
census.sh                 collect one machine
collect.sh                collect many machines over SSH
fleet.py                  report / check / watchlist / threats / dashboard
threats.py                CISA KEV + OSV threat search (used by fleet.py)
dashboard.py              builds the dashboard (used by fleet.py)
dashboard_template.html   the dashboard page itself
rules/advisories.json     known vulnerabilities to check against
inventory.example.json    list of devices you own (copy to inventory.json)
watch/WATCH-PROMPT.md     daily security-watch prompt
docs/HARDENING.md         plain-language hardening checklist
docs/PRIVATE-REPO.md      using this with your own private fleet repo
examples/census/          fake census files for trying it out
tests/                    python3 -m unittest discover tests   (no internet needed)
```

## Requirements

- `census.sh`: bash (including the old 3.2 on macOS) and standard tools. Missing tools are skipped.
- `fleet.py`: Python 3.8+ (standard library only).
- Windows: not supported yet (use WSL for the Linux side).

## Contributing

Useful additions: checks for more software, better detection on other distros,
or new advisories. Keep it read-only and dependency-free, and never collect
secret values.

MIT licensed.
