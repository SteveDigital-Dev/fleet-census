# Using fleet-census with your own private fleet repo

The public toolkit stays generic. Your real data (census files, inventory,
reports, custom advisories) lives in **your own private repo**, which pulls
the toolkit in.

## Layout

```
my-fleet/                     <- private repo
  security/
    tools/                    <- this toolkit (git subtree)
    census/                   <- real census files, committed so you get history
    inventory.json            <- your devices
    rules/local.json          <- your own advisories (optional)
    FLEET.md                  <- generated report
```

## Set up

```bash
cd my-fleet
git subtree add --prefix security/tools <toolkit-repo-url> main --squash
```

Pull toolkit updates later:

```bash
git subtree pull --prefix security/tools <toolkit-repo-url> main --squash
```

## Run from the private repo

```bash
cd my-fleet/security
tools/census.sh --name studio-mini --out census/studio-mini.json
python3 tools/fleet.py report \
  --census census \
  --inventory inventory.json \
  --rules tools/rules/advisories.json --rules rules/local.json \
  --out FLEET.md
```

Each new census is a commit, so `git diff census/` shows exactly what changed
on a machine since the last run: new open ports, updated drivers, new software.

## Where to host it

The census describes where your machines are weakest, so keep it off the
public internet:

1. **Best:** self-host Forgejo or Gitea on a Raspberry Pi or server, reachable only over Tailscale.
2. **OK:** a *private* GitHub or GitLab repo, with 2FA on the account.

Either way, add a secret scanner before the first commit:

```bash
# with pre-commit installed (pip install pre-commit):
pre-commit install   # uses the .pre-commit-config.yaml from the toolkit
```
