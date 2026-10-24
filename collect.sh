#!/usr/bin/env bash
# Run the census on several machines over SSH (or Tailscale SSH) and save
# the results into ./census/ on THIS machine. Nothing is installed remotely:
# the script is copied to a private temp file, run once, and deleted.
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
#
# Safety: machine names may only use letters, numbers, '.', '-' and '_', and
# SSH targets may not start with '-' (that would make ssh read them as
# options). Every report is checked with fleet.py validate before it's saved.

set -u
umask 077
DIR=$(cd "$(dirname "$0")" && pwd)
OUTDIR="$DIR/census"; ALL=0; HOSTS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --all-users) ALL=1; shift ;;
    --out-dir) OUTDIR="${2:?--out-dir needs a folder}"; shift 2 ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    --) shift; HOSTS+=("$@"); break ;;
    -*) echo "Unknown option: $1 (try --help)" >&2; exit 2 ;;
    *) HOSTS+=("$1"); shift ;;
  esac
done
[ ${#HOSTS[@]} -eq 0 ] && { sed -n '2,19p' "$0"; exit 2; }
mkdir -p "$OUTDIR"

PY=""; command -v python3 >/dev/null 2>&1 && PY=python3
[ -z "$PY" ] && echo "Note: python3 not found here, so reports get only a basic check before saving." >&2

# Whole-string check (grep would test each line separately and miss embedded newlines).
valid_name() {
  case "$1" in ""|.|..|[!A-Za-z0-9]*|*[!A-Za-z0-9._-]*) return 1 ;; esac
  [ "${#1}" -le 64 ]
}
# user@host, host, user@100.64.0.1, user@[::1] - but never an option like -oProxyCommand=...
valid_target() {
  case "$1" in ""|-*|*[!][A-Za-z0-9._@:%-]*) return 1 ;; esac
  [ "${#1}" -le 255 ]
}
q() { printf '%q' "$1"; }   # quote a value for the remote shell

SSH=(ssh -o ConnectTimeout=10)
LOCAL_TMP=""; REMOTE_TARGET=""; REMOTE_FILES=""
cleanup_remote() {
  if [ -n "$REMOTE_TARGET" ] && [ -n "$REMOTE_FILES" ]; then
    "${SSH[@]}" -o BatchMode=yes -- "$REMOTE_TARGET" "rm -rf $REMOTE_FILES" >/dev/null 2>&1
  fi
  REMOTE_TARGET=""; REMOTE_FILES=""
}
cleanup() {
  [ -n "$LOCAL_TMP" ] && rm -f "$LOCAL_TMP"
  LOCAL_TMP=""
  cleanup_remote
}
trap 'cleanup; echo; echo "Stopped. Temporary files cleaned up."; exit 130' INT TERM
trap cleanup EXIT

check_report() {  # $1=file $2=expected name -> 0 if valid
  if [ -n "$PY" ]; then
    "$PY" "$DIR/fleet.py" validate --expect-name "$2" --quiet "$1"
  else
    [ -s "$1" ] && head -c1 "$1" | grep -q '{'
  fi
}

ok=0; fail=0
for spec in "${HOSTS[@]}"; do
  target=${spec%%=*}
  if [ "$target" = "$spec" ]; then name=${target#*@}; name=${name//[\[\]]/}; name=${name//:/-}; else name=${spec#*=}; fi
  if ! valid_target "$target"; then
    printf '%-24s FAILED (not a valid SSH target: %s)\n' "$name" "$target"; fail=$((fail+1)); continue
  fi
  if ! valid_name "$name"; then
    printf '%-24s FAILED (machine names may only use letters, numbers, . - _; add =a-name)\n' "$name"; fail=$((fail+1)); continue
  fi
  LOCAL_TMP=$(mktemp)
  if [ "$ALL" = 0 ]; then
    printf '%-24s ' "$name"
    # Remote: private temp file, run once, delete. The name is passed quoted, never spliced in raw.
    "${SSH[@]}" -o BatchMode=yes -- "$target" \
      "umask 077; t=\$(mktemp) && cat > \"\$t\" && bash \"\$t\" --name $(q "$name") --out -; rc=\$?; rm -f \"\$t\"; exit \$rc" \
      < "$DIR/census.sh" > "$LOCAL_TMP" 2>/dev/null
  else
    echo "== $name: all accounts (sudo will ask for the password on $name) =="
    # 1) copy the script into a private temp folder  2) run it with sudo in a terminal
    # 3) fetch the result  4) clean up (also on failure or Ctrl-C)
    rd=$("${SSH[@]}" -o BatchMode=yes -- "$target" \
      'umask 077; d=$(mktemp -d) && cat > "$d/census.sh" && : > "$d/out.json" && echo "$d"' < "$DIR/census.sh" 2>/dev/null)
    if printf '%s' "$rd" | grep -Eq '^/[A-Za-z0-9._/-]+$'; then
      REMOTE_TARGET=$target; REMOTE_FILES=$(q "$rd")
      # out.json already exists (mode 600, owned by you), so the root-run census writes into it
      # without changing who can read it.
      if "${SSH[@]}" -tt -- "$target" \
           "sudo bash $(q "$rd/census.sh") --all-users --name $(q "$name") --out $(q "$rd/out.json") >/dev/null"; then
        "${SSH[@]}" -o BatchMode=yes -- "$target" "cat $(q "$rd/out.json")" > "$LOCAL_TMP" 2>/dev/null
      fi
      cleanup_remote
    fi
    printf '%-24s ' "$name"
  fi
  if check_report "$LOCAL_TMP" "$name" 2>/tmp/fleet-collect-err.$$; then
    mv "$LOCAL_TMP" "$OUTDIR/$name.json"; LOCAL_TMP=""; echo "ok"; ok=$((ok+1))
  else
    why=$(head -3 /tmp/fleet-collect-err.$$ | tr '\n' ' ' | sed "s#$LOCAL_TMP: ##; s/  */ /g")
    [ -s "$LOCAL_TMP" ] || why="no report came back (can't SSH in, sudo refused, or bash missing)"
    [ -n "$why" ] || why="the report did not pass the check"; echo "FAILED ($why)"; fail=$((fail+1))
    rm -f "$LOCAL_TMP"; LOCAL_TMP=""
  fi
  rm -f /tmp/fleet-collect-err.$$
done
echo "Done: $ok collected, $fail failed. Next: python3 fleet.py report"
[ "$fail" -eq 0 ]
