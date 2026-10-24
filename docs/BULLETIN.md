# The weekly health check

Once a week (or whenever you like) the health check looks at your computers and tells you,
in plain English:

- **The threat level:** 🟢 green, 🟠 amber or 🔴 red, with one line on why.
- **Headlines:** each problem worth your time. Every headline shows:
  - how serious it is
  - whether attackers are using it right now
  - which machine it affects
  - **why it matters**
  - **show me how**, with step-by-step fix instructions for that machine's system

It only **reads**. It never installs, changes or deletes anything on your machines.

## Start

```bash
python3 fleet.py setup
```

Setup takes about two minutes and asks about each source and each extra before anything is
contacted. Press Enter to accept the answer shown in capitals. You can run it again at any
time to change your answers.

Then, whenever you like:

```bash
python3 fleet.py bulletin
```

It saves `bulletins/<date>.md` and refreshes `dashboard.html`. The dashboard opens offline in
any browser, with the bulletin at the top.

## What it contacts

Before every run it prints exactly what it will contact. `python3 fleet.py sources` shows the
full list at any time.

| Source | Why | What it sends |
|---|---|---|
| CISA Known Exploited Vulnerabilities (www.cisa.gov) | US government list of bugs attackers are using right now | Nothing: it downloads the public list |
| OSV.dev (api.osv.dev) | Open database of known bugs in software packages | Names and versions of apt packages, e.g. `openssl 3.0.13` |
| *Extra:* EPSS (api.first.org) | How likely each bug is to be attacked in the next 30 days | The bug IDs (CVEs) that matched |
| *Extra:* endoflife.date | When software stops getting security fixes | Product names, e.g. `php`, `ubuntu` |
| *Extra:* ntfy (your address) | Phone alert when the level is red | One line, e.g. `RED: 2 urgent items to fix` |

**Never sent anywhere:** your IP addresses, open ports, computer names (unless you allow them
in alerts), passwords, keys or file contents.

**Contact nothing at all:** `python3 fleet.py bulletin --offline` uses the copies saved by the
last run.

## Extras: all off until you turn them on

| Extra | What you get | Internet? |
|---|---|---|
| `changes` | Only what's new or fixed since last week: problems, ports, software versions | No |
| `epss` | "X% chance of attack in 30 days" on each bug, so the dangerous ones rise to the top | Yes (bug IDs) |
| `eol` | Warnings when your OS or software has stopped, or will soon stop (90 days), getting security fixes | Yes (product names) |
| `snooze` | Hide a warning you've handled, with a reason and a date when it comes back | No |
| `alerts` | A phone notification through ntfy, only when the level is red (or amber, if you choose) | Yes (one line) |
| `home_checklist` | Reminders for things it can't check: router, phones, smart devices, backups | No |

Turn them on in `setup`, or for a single run:

```bash
python3 fleet.py bulletin --with changes,epss
python3 fleet.py bulletin --without alerts
```

## Snoozing a warning

Every headline shows its own snooze command when the snooze extra is on:

```bash
python3 fleet.py snooze CVE-2026-86950 --machine old-ipad --reason "updating tonight" --days 7
python3 fleet.py snooze --list
python3 fleet.py snooze CVE-2026-86950 --remove
```

When the date passes, the warning comes back if it still applies.

## Running it every week automatically

```bash
python3 fleet.py schedule on                          # Mondays 09:17
python3 fleet.py schedule on --day friday --time 18:30
python3 fleet.py schedule status
python3 fleet.py schedule off
```

Linux uses your user's crontab and macOS uses a LaunchAgent; neither needs admin rights.
Each run adds one line to `bulletins/schedule.log`.

## Shared computers

The weekly check runs as you, without admin rights. If other people use the computer, run
`sudo ./census.sh --all-users` once in a while. The bulletin then includes every account
(no-password accounts, startup items, login keys, which account runs each open port) and keeps
those results between admin runs. It tells you when they're more than 30 days old.

## How the threat level is decided

- 🔴 **Red:** anything critical, or anything serious that attackers are using right now. Fix these first.
- 🟠 **Amber:** problems worth fixing, none under active attack. This includes software past end-of-life.
- 🟢 **Green:** nothing that needs you this week.

A distro package that *might* already be patched (Linux distributions often fix bugs without
changing the version number) is never enough on its own to turn the level red.

## Removing it

```bash
python3 fleet.py uninstall
```

It lists everything it will remove and asks first: the schedule, your settings, snoozes,
bulletins, saved feed copies, census files and generated pages. After that, delete the folder
to remove the program itself.
