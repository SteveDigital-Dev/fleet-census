#!/usr/bin/env bash
# Run the census on several machines over SSH (or Tailscale SSH) and save
# the results into ./census/ on THIS machine. Nothing is installed remotely:
# the script is copied to a temp file, run once, and deleted.
#
# Usage:
#   ./collect.sh pi-garage studio-mini old-laptop
#   ./collect.sh user@192.168.1.20
#
# Each host must accept SSH from this machine (keys recommended).
# Optional: name a machine differently from its SSH address with host=name:
#   ./collect.sh me@100.64.0.22=pi-garage

set -u
DIR=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$DIR/census"
[ $# -eq 0 ] && { sed -n '2,13p' "$0"; exit 2; }

ok=0; fail=0
for spec in "$@"; do
  target=${spec%%=*}
  name=${spec#*=}; [ "$name" = "$spec" ] && name=${target#*@}
  printf '%-24s ' "$name"
  tmp=$(mktemp)
  # Copy the script to a temp file on the remote machine, run it, delete it.
  remote='t=$(mktemp) && cat > "$t" && bash "$t" --name "$1" --out -; rc=$?; rm -f "$t"; exit $rc'
  if ssh -o BatchMode=yes -o ConnectTimeout=10 "$target" "sh -c '$remote' _ '$name'" < "$DIR/census.sh" > "$tmp" 2>/dev/null \
     && [ -s "$tmp" ] && head -c1 "$tmp" | grep -q '{'; then
    mv "$tmp" "$DIR/census/$name.json"; echo "ok"; ok=$((ok+1))
  else
    rm -f "$tmp"; echo "FAILED (can't SSH in, or bash missing)"; fail=$((fail+1))
  fi
done
echo "Done: $ok collected, $fail failed. Next: python3 fleet.py report"
