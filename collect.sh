#!/usr/bin/env bash
# Run the census on several machines over SSH (or Tailscale SSH) and save
# the results into ./census/ on THIS machine. Nothing is installed remotely:
# the script is copied to a temp file, run once, and deleted.
#
# Usage:
#   ./collect.sh pi-garage studio-mini old-laptop
#   ./collect.sh user@192.168.1.20
#   ./collect.sh --all-users me@shared-box     # every account; asks for sudo there
#   ./collect.sh --out-dir ../census host      # save somewhere else
#
# Each host must accept SSH from this machine (keys recommended).
# Optional: name a machine differently from its SSH address with host=name:
#   ./collect.sh me@100.64.0.22=pi-garage

set -u
DIR=$(cd "$(dirname "$0")" && pwd)
OUTDIR="$DIR/census"; ALL=0; HOSTS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --all-users) ALL=1; shift ;;
    --out-dir) OUTDIR="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) HOSTS+=("$1"); shift ;;
  esac
done
[ ${#HOSTS[@]} -eq 0 ] && { sed -n '2,15p' "$0"; exit 2; }
mkdir -p "$OUTDIR"
SSH=(ssh -o ConnectTimeout=10)

ok=0; fail=0
for spec in "${HOSTS[@]}"; do
  target=${spec%%=*}
  name=${spec#*=}; [ "$name" = "$spec" ] && name=${target#*@}
  tmp=$(mktemp)
  if [ "$ALL" = 0 ]; then
    printf '%-24s ' "$name"
    # Copy the script to a temp file on the remote machine, run it, delete it.
    remote='t=$(mktemp) && cat > "$t" && bash "$t" --name "$1" --out -; rc=$?; rm -f "$t"; exit $rc'
    "${SSH[@]}" -o BatchMode=yes "$target" "sh -c '$remote' _ '$name'" < "$DIR/census.sh" > "$tmp" 2>/dev/null
  else
    echo "== $name: all accounts (sudo will ask for the password on $name) =="
    # 1) copy the script over  2) run it with sudo in a terminal  3) fetch the result, clean up
    rs=$("${SSH[@]}" -o BatchMode=yes "$target" 't=$(mktemp) && cat > "$t" && echo "$t"' < "$DIR/census.sh" 2>/dev/null)
    ro="$rs.json"
    if [ -n "$rs" ] && "${SSH[@]}" -tt "$target" \
         "sudo bash '$rs' --all-users --name '$name' --out '$ro' >/dev/null && sudo chown \"\$(id -un)\" '$ro'"; then
      "${SSH[@]}" -o BatchMode=yes "$target" "cat '$ro'" > "$tmp" 2>/dev/null
    fi
    [ -n "$rs" ] && "${SSH[@]}" -o BatchMode=yes "$target" "rm -f '$rs' '$ro'" >/dev/null 2>&1
    printf '%-24s ' "$name"
  fi
  if [ -s "$tmp" ] && head -c1 "$tmp" | grep -q '{'; then
    mv "$tmp" "$OUTDIR/$name.json"; echo "ok"; ok=$((ok+1))
  else
    rm -f "$tmp"; echo "FAILED (can't SSH in, sudo refused, or bash missing)"; fail=$((fail+1))
  fi
done
echo "Done: $ok collected, $fail failed. Next: python3 fleet.py report"
