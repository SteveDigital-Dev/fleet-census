#!/usr/bin/env bash
# fleet-census: take a read-only snapshot of one machine's security-relevant state.
#
# Works on Linux (Debian/Ubuntu/Mint/Raspberry Pi OS/Arch/Fedora) and macOS.
# Needs no root, installs nothing, changes nothing. Anything it can't see
# without root is recorded as "unknown" rather than guessed.
#
# It NEVER reads secret values. For secrets it only records whether common
# credential files exist and how many there are.
#
# Usage:
#   ./census.sh                         # writes census/<hostname>.json
#   ./census.sh --name studio-mini --role "inference box" --tag agent=helper
#   ./census.sh --out -                 # print JSON to stdout instead
#   ./census.sh --redact                # leave out IP addresses
#
# Compatible with the old bash 3.2 that ships on macOS.

set -u
CENSUS_VERSION="1.1.0"

# ---------- arguments ----------
NAME=""; ROLE=""; OUT=""; REDACT=0; TAGS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --name)   NAME="${2:-}"; shift 2 ;;
    --role)   ROLE="${2:-}"; shift 2 ;;
    --tag)    TAGS="${TAGS}${2:-}"$'\n'; shift 2 ;;
    --out)    OUT="${2:-}"; shift 2 ;;
    --redact) REDACT=1; shift ;;
    -h|--help) sed -n '2,20p' "$0" 2>/dev/null; exit 0 ;;
    *) echo "Unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
done

# ---------- helpers ----------
has() { command -v "$1" >/dev/null 2>&1; }

# Run a command with a time limit so nothing can hang the census.
TIME_LIMIT=8
run() {
  if has timeout; then timeout "$TIME_LIMIT" "$@" 2>/dev/null </dev/null
  elif has gtimeout; then gtimeout "$TIME_LIMIT" "$@" 2>/dev/null </dev/null
  else
    ( "$@" 2>/dev/null </dev/null ) &
    local pid=$!
    ( sleep "$TIME_LIMIT"; kill "$pid" 2>/dev/null ) >/dev/null 2>&1 &
    local watcher=$!
    wait "$pid" 2>/dev/null; local rc=$?
    kill "$watcher" 2>/dev/null; wait "$watcher" 2>/dev/null
    return $rc
  fi
}
# Same as run, but keeps stderr (some tools print their version there).
runall() {
  if has timeout; then timeout "$TIME_LIMIT" "$@" 2>&1 </dev/null
  elif has gtimeout; then gtimeout "$TIME_LIMIT" "$@" 2>&1 </dev/null
  else run sh -c '"$@" 2>&1' _ "$@"; fi
}

# Escape a string for JSON.
esc() {
  local s
  s=$(printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037')
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\t'/\\t}; s=${s//$'\r'/}; s=${s//$'\n'/\\n}
  printf '"%s"' "$s"
}
# JSON value: string, or null when empty.
str() { if [ -n "$1" ]; then esc "$1"; else printf 'null'; fi; }
# JSON boolean from "yes"/"no"/other -> true/false/null
tri() { case "$1" in yes) printf 'true';; no) printf 'false';; *) printf 'null';; esac; }
# First dotted version number in a string.
ver() { printf '%s' "$1" | grep -Eo '[0-9]+(\.[0-9]+)+' | head -1; }
firstline() { printf '%s' "$1" | head -1; }

OS_FAMILY="unknown"
case "$(uname -s)" in
  Linux)  OS_FAMILY="linux" ;;
  Darwin) OS_FAMILY="macos" ;;
esac

# macOS ships a python3 "stub" that pops up an installer dialog if the
# developer tools aren't installed. Only use python3 when it's real.
PY=""
if has python3; then
  if [ "$OS_FAMILY" = "macos" ] && [ "$(command -v python3)" = "/usr/bin/python3" ] && ! xcode-select -p >/dev/null 2>&1; then
    PY=""
  else
    PY="python3"
  fi
fi

# ---------- identity ----------
HOST=$(hostname 2>/dev/null | cut -d. -f1)
[ -z "$HOST" ] && HOST=$(uname -n | cut -d. -f1)
[ -z "$NAME" ] && NAME="$HOST"
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ---------- operating system & hardware ----------
OS_NAME=""; OS_ID=""; OS_VERSION=""; OS_BUILD=""; MODEL=""; CPU=""; MEM_GB=""
KERNEL=$(uname -r); ARCH=$(uname -m)
if [ "$OS_FAMILY" = "linux" ]; then
  if [ -r /etc/os-release ]; then
    OS_NAME=$(. /etc/os-release; printf '%s' "${PRETTY_NAME:-$NAME}")
    OS_ID=$(. /etc/os-release; printf '%s' "${ID:-}")
    OS_VERSION=$(. /etc/os-release; printf '%s' "${VERSION_ID:-}")
  fi
  [ -r /proc/device-tree/model ] && MODEL=$(tr -d '\000' < /proc/device-tree/model)
  [ -z "$MODEL" ] && [ -r /sys/class/dmi/id/product_name ] && MODEL=$(cat /sys/class/dmi/id/product_name 2>/dev/null)
  CPU=$(grep -m1 -E '^(model name|Model)' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//')
  MEM_KB=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null)
  [ -n "${MEM_KB:-}" ] && MEM_GB=$(awk -v k="$MEM_KB" 'BEGIN{printf "%.1f", k/1048576}')
elif [ "$OS_FAMILY" = "macos" ]; then
  OS_NAME="$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null)"
  OS_ID="macos"
  OS_VERSION=$(sw_vers -productVersion 2>/dev/null)
  OS_BUILD=$(sw_vers -buildVersion 2>/dev/null)
  MODEL=$(sysctl -n hw.model 2>/dev/null)
  CPU=$(sysctl -n machdep.cpu.brand_string 2>/dev/null)
  MEM_B=$(sysctl -n hw.memsize 2>/dev/null)
  [ -n "${MEM_B:-}" ] && MEM_GB=$(awk -v b="$MEM_B" 'BEGIN{printf "%.1f", b/1073741824}')
fi
UPTIME=$(uptime 2>/dev/null | sed 's/^ *//')

# ---------- GPUs ----------
GPUS=""
if has nvidia-smi; then
  CUDA=$(run nvidia-smi | grep -Eo 'CUDA Version: *[0-9.]+' | grep -Eo '[0-9.]+$' | head -1)
  while IFS=, read -r gname gdriver; do
    [ -z "$gname" ] && continue
    GPUS="${GPUS}{\"vendor\":\"nvidia\",\"name\":$(str "$(echo "$gname" | sed 's/^ *//;s/ *$//')"),\"driver\":$(str "$(echo "$gdriver" | sed 's/^ *//;s/ *$//')"),\"cuda\":$(str "${CUDA:-}")},"
  done <<EOF
$(run nvidia-smi --query-gpu=name,driver_version --format=csv,noheader)
EOF
elif [ "$OS_FAMILY" = "linux" ] && has lspci; then
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    GPUS="${GPUS}{\"vendor\":null,\"name\":$(str "$(echo "$line" | cut -d: -f3- | sed 's/^ *//')"),\"driver\":null,\"cuda\":null},"
  done <<EOF
$(run lspci | grep -Ei 'vga|3d controller')
EOF
elif [ "$OS_FAMILY" = "macos" ]; then
  G=$(run system_profiler SPDisplaysDataType | awk -F': ' '/Chipset Model/ {print $2; exit}')
  [ -n "$G" ] && GPUS="{\"vendor\":\"apple\",\"name\":$(str "$G"),\"driver\":null,\"cuda\":null},"
fi
GPUS="[${GPUS%,}]"

# ---------- updates ----------
AUTO_UPDATES="unknown"; PENDING=""; PKG_MANAGER=""
if [ "$OS_FAMILY" = "linux" ]; then
  if has apt-get; then
    PKG_MANAGER="apt"
    if grep -qsE 'Unattended-Upgrade\s+"1"' /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/*auto* 2>/dev/null; then
      AUTO_UPDATES="yes"
    elif [ -e /etc/apt/apt.conf.d/20auto-upgrades ] || dpkg -s unattended-upgrades >/dev/null 2>&1; then
      AUTO_UPDATES="no"
    else
      AUTO_UPDATES="no"
    fi
    # Uses the last 'apt update' cache, so may be stale.
    PENDING=$(run apt list --upgradable 2>/dev/null | grep -c 'upgradable from')
  elif has pacman; then
    PKG_MANAGER="pacman"
    AUTO_UPDATES="no"   # Arch has no standard auto-update; manual by design.
    has checkupdates && PENDING=$(run checkupdates | grep -c .)
  elif has dnf; then
    PKG_MANAGER="dnf"
    if systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1 || systemctl is-enabled dnf-automatic-install.timer >/dev/null 2>&1; then
      AUTO_UPDATES="yes"; else AUTO_UPDATES="no"; fi
  fi
elif [ "$OS_FAMILY" = "macos" ]; then
  PKG_MANAGER="softwareupdate"
  AI=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null)
  CR=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null)
  if [ "$AI" = "1" ] || [ "$CR" = "1" ]; then AUTO_UPDATES="yes"
  elif [ "$AI" = "0" ] && [ "$CR" = "0" ]; then AUTO_UPDATES="no"; fi
fi

# ---------- firewall ----------
FIREWALL="unknown"; FIREWALL_TOOL=""
if [ "$OS_FAMILY" = "linux" ]; then
  if has systemctl; then
    for svc in ufw firewalld nftables; do
      if systemctl is-active "$svc" >/dev/null 2>&1; then FIREWALL="yes"; FIREWALL_TOOL="$svc"; break; fi
    done
    if [ "$FIREWALL" = "unknown" ] && { has ufw || has firewall-cmd || has nft; }; then
      FIREWALL="no"; FIREWALL_TOOL="installed-but-inactive"
    fi
  fi
  # ufw can be "active" as a service but disabled; only root can tell for sure.
elif [ "$OS_FAMILY" = "macos" ]; then
  FIREWALL_TOOL="application-firewall"
  FW=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
  case "$FW" in *enabled*) FIREWALL="yes";; *disabled*) FIREWALL="no";; esac
fi

# ---------- SSH server ----------
SSHD_RUNNING="no"; SSH_PASSWORD="unknown"; SSH_ROOT="unknown"
if pgrep -x sshd >/dev/null 2>&1; then SSHD_RUNNING="yes"; fi
if [ "$OS_FAMILY" = "macos" ] && run systemsetup -getremotelogin 2>/dev/null | grep -qi ': on'; then SSHD_RUNNING="yes"; fi
read_sshd() {  # sshd uses the FIRST value it finds (drop-in files are read first)
  local key="$1"
  cat /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null \
    | grep -iE "^[[:space:]]*${key}[[:space:]]" | head -1 | awk '{print tolower($2)}'
}
if [ -r /etc/ssh/sshd_config ]; then
  P=$(read_sshd PasswordAuthentication)
  case "$P" in no) SSH_PASSWORD="no";; yes) SSH_PASSWORD="yes";; "") SSH_PASSWORD="yes-default";; esac
  R=$(read_sshd PermitRootLogin)
  case "$R" in no) SSH_ROOT="no";; yes) SSH_ROOT="yes";; prohibit-password|without-password) SSH_ROOT="keys-only";; "") SSH_ROOT="default";; *) SSH_ROOT="$R";; esac
fi

# ---------- disk encryption ----------
DISK_ENC="unknown"
if [ "$OS_FAMILY" = "macos" ]; then
  case "$(fdesetup status 2>/dev/null)" in *"is On"*) DISK_ENC="yes";; *"is Off"*) DISK_ENC="no";; esac
elif has lsblk; then
  if lsblk -o TYPE 2>/dev/null | grep -qx crypt; then DISK_ENC="yes"; else DISK_ENC="no"; fi
fi

# ---------- Tailscale ----------
TS_INSTALLED="no"; TS_VERSION=""; TS_NAME=""; TS_IPS=""; TS_TAGS="[]"; TS_EXPIRY=""; TS_ONLINE="unknown"
TS_BIN=""
if has tailscale; then TS_BIN="tailscale"
elif [ -x /Applications/Tailscale.app/Contents/MacOS/Tailscale ]; then TS_BIN="/Applications/Tailscale.app/Contents/MacOS/Tailscale"; fi
if [ -n "$TS_BIN" ]; then
  TS_INSTALLED="yes"
  TS_VERSION=$(firstline "$(run "$TS_BIN" version)")
  TS_JSON=$(run "$TS_BIN" status --json)
  if [ -n "$TS_JSON" ] && [ -n "$PY" ]; then
    TS_PARSED=$(printf '%s' "$TS_JSON" | "$PY" -c '
import json,sys
try:
    s=json.load(sys.stdin).get("Self") or {}
except Exception:
    sys.exit(0)
print(s.get("HostName","")); print(",".join(s.get("TailscaleIPs") or []))
print(json.dumps(s.get("Tags") or [])); print(s.get("KeyExpiry","")); print("yes" if s.get("Online") else "no")
' 2>/dev/null)
    TS_NAME=$(printf '%s\n' "$TS_PARSED" | sed -n 1p)
    TS_IPS=$(printf '%s\n' "$TS_PARSED" | sed -n 2p)
    T=$(printf '%s\n' "$TS_PARSED" | sed -n 3p); [ -n "$T" ] && TS_TAGS="$T"
    TS_EXPIRY=$(printf '%s\n' "$TS_PARSED" | sed -n 4p)
    TS_ONLINE=$(printf '%s\n' "$TS_PARSED" | sed -n 5p)
  else
    TS_IPS=$(run "$TS_BIN" ip -4 | head -1)
  fi
  [ "$REDACT" = "1" ] && TS_IPS=""
fi

# ---------- listening ports ----------
# exposure: "localhost" (this machine only), "all" (every network interface),
# or "specific" (one address, e.g. only the Tailscale IP).
LISTEN=""
add_listen() {  # proto addr port process
  local proto="$1" addr="$2" port="$3" proc="$4" exposure="specific"
  case "$addr" in
    127.*|::1|localhost|\[::1\]) exposure="localhost" ;;
    0.0.0.0|\*|::|\[::\]|"") exposure="all" ;;
  esac
  local shown="$addr"; [ "$REDACT" = "1" ] && [ "$exposure" = "specific" ] && shown="redacted"
  LISTEN="${LISTEN}{\"proto\":\"$proto\",\"address\":$(str "$shown"),\"port\":$port,\"exposure\":\"$exposure\",\"process\":$(str "$proc")},"
}
if [ "$OS_FAMILY" = "linux" ] && has ss; then
  while read -r proto local proc; do
    [ -z "${local:-}" ] && continue
    port=${local##*:}; addr=${local%:*}; addr=${addr%%%*}
    case "$port" in ''|*[!0-9]*) continue;; esac
    pname=$(printf '%s' "${proc:-}" | grep -Eo '"[^"]+"' | head -1 | tr -d '"')
    add_listen "$proto" "$addr" "$port" "$pname"
  done <<EOF
$(run ss -H -tuln -p 2>/dev/null | awk '{ if ($1=="udp" && $2!="UNCONN") next; print $1, $5, $7 }' | sort -u)
EOF
elif [ "$OS_FAMILY" = "macos" ]; then
  while read -r local; do
    [ -z "$local" ] && continue
    port=${local##*.}; addr=${local%.*}
    case "$port" in ''|*[!0-9]*) continue;; esac
    add_listen "tcp" "$addr" "$port" ""
  done <<EOF
$(run netstat -an -p tcp | awk '$NF=="LISTEN" {print $4}' | sort -u)
EOF
fi
LISTEN="[${LISTEN%,}]"

# ---------- software versions ----------
# name|command   (the first version-looking number in the output is used)
SOFTWARE=""
check_sw() {
  local name="$1"; shift
  has "$1" || return 0
  local raw; raw=$(runall "$@" | head -3 | tr '\n' ' ')
  local v; v=$(ver "$raw")
  local path; path=$(command -v "$1")
  # Which package installed it? Distro packages (apt, pacman) often get
  # security fixes "backported" without the upstream version number changing,
  # so the package version is what to compare against your distro's advisory.
  local real pkg="" pkgver="" pkgsrc="" source="manual"
  real=$(readlink -f "$path" 2>/dev/null || printf '%s' "$path")
  case "$real" in
    /opt/homebrew/*|/usr/local/Cellar/*|/home/linuxbrew/*) source="homebrew" ;;
    /snap/*) source="snap" ;;
    "$HOME"/*) source="user" ;;
  esac
  if [ "$source" = "manual" ]; then
    if has dpkg-query; then
      pkg=$(dpkg-query -S "$real" 2>/dev/null | head -1 | cut -d: -f1)
      [ -n "$pkg" ] && pkgver=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null) && source="apt"
      [ -n "$pkg" ] && pkgsrc=$(dpkg-query -W -f='${source:Package}' "$pkg" 2>/dev/null)
    elif has pacman; then
      pkg=$(pacman -Qoq "$real" 2>/dev/null | head -1)
      [ -n "$pkg" ] && pkgver=$(pacman -Q "$pkg" 2>/dev/null | awk '{print $2}') && source="pacman"
    elif has rpm; then
      pkg=$(rpm -qf --qf '%{NAME}' "$real" 2>/dev/null) || pkg=""
      [ -n "$pkg" ] && pkgver=$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$pkg" 2>/dev/null) && source="rpm"
    fi
  fi
  SOFTWARE="${SOFTWARE}{\"name\":\"$name\",\"version\":$(str "$v"),\"source\":\"$source\",\"package\":$(str "$pkg"),\"package_version\":$(str "$pkgver"),\"package_source\":$(str "$pkgsrc"),\"raw\":$(str "$(printf '%s' "$raw" | cut -c1-160)"),\"path\":$(str "$path")},"
}
check_sw php        php -v
check_sw php-fpm    php-fpm -v
for f in php-fpm8.5 php-fpm8.4 php-fpm8.3 php-fpm8.2 php-fpm8.1 php-fpm8.0 php-fpm7.4; do check_sw "$f" "$f" -v; done
check_sw node       node --version
check_sw npm        npm --version
[ -n "$PY" ] && check_sw python3 python3 --version
check_sw pip3       pip3 --version
check_sw docker     docker --version
check_sw podman     podman --version
check_sw nginx      nginx -v
check_sw apache2    apache2 -v
check_sw httpd      httpd -v
check_sw caddy      caddy version
check_sw ollama     ollama --version
check_sw llama-server llama-server --version
check_sw lms        lms version
check_sw git        git --version
check_sw openssh    ssh -V
check_sw sudo       sudo -V
check_sw glibc      ldd --version
check_sw systemd    systemctl --version
check_sw openssl    openssl version
check_sw brew       brew --version
check_sw blender    blender --version
check_sw proxmox    pveversion
check_sw mysql      mysql --version
check_sw postgres   psql --version
check_sw redis      redis-server --version
check_sw code       code --version
SOFTWARE="[${SOFTWARE%,}]"

# ---------- containers ----------
CONTAINERS="null"
if has docker; then
  CL=$(run docker ps --format '{{.Names}}|{{.Image}}|{{.Ports}}')
  if [ $? -eq 0 ]; then
    CONTAINERS=""
    while IFS='|' read -r cname cimage cports; do
      [ -z "$cname" ] && continue
      CONTAINERS="${CONTAINERS}{\"name\":$(str "$cname"),\"image\":$(str "$cimage"),\"ports\":$(str "$cports")},"
    done <<EOF
$CL
EOF
    CONTAINERS="[${CONTAINERS%,}]"
  else
    CONTAINERS="\"no-permission-or-not-running\""
  fi
fi

# ---------- ComfyUI custom nodes (they run arbitrary Python) ----------
COMFY=""
for d in "$HOME/ComfyUI" "$HOME/comfyui" "$HOME/ComfyUI_windows_portable/ComfyUI" "$HOME/Documents/ComfyUI" "/opt/ComfyUI"; do
  if [ -d "$d/custom_nodes" ]; then
    NODES=""
    for n in "$d"/custom_nodes/*/; do
      [ -d "$n" ] || continue
      NODES="${NODES}$(str "$(basename "$n")"),"
    done
    COMFY="${COMFY}{\"path\":$(str "${d/#$HOME/~}"),\"custom_nodes\":[${NODES%,}]},"
  fi
done
COMFY="[${COMFY%,}]"

# ---------- secrets presence (never contents) ----------
yesno() { if [ -e "$1" ]; then printf 'yes'; else printf 'no'; fi; }
SSH_KEYS=0
if [ -d "$HOME/.ssh" ]; then
  for k in "$HOME"/.ssh/*; do
    [ -f "$k" ] || continue
    # Only peek at the first line to see if it is a private key header.
    if head -1 "$k" 2>/dev/null | grep -q 'PRIVATE KEY'; then SSH_KEYS=$((SSH_KEYS+1)); fi
  done
fi
ENV_FILES=$(find "$HOME" -maxdepth 4 \( -name node_modules -o -name .git -o -name Library -o -name .cache -o -name .venv -o -name venv \) -prune -o -type f -name '.env*' -print 2>/dev/null | grep -vcE '\.env\.(example|sample|template)$')

# ---------- user tags ----------
TAGJSON=""
while IFS= read -r t; do
  [ -z "$t" ] && continue
  k=${t%%=*}; v=${t#*=}
  TAGJSON="${TAGJSON}$(esc "$k"):$(esc "$v"),"
done <<EOF
$TAGS
EOF
TAGJSON="{${TAGJSON%,}}"

# ---------- assemble ----------
JSON=$(cat <<EOF
{
  "census_version": "$CENSUS_VERSION",
  "collected_at": "$NOW",
  "host": {
    "hostname": $(str "$HOST"),
    "name": $(str "$NAME"),
    "role": $(str "$ROLE"),
    "tags": $TAGJSON,
    "model": $(str "$MODEL"),
    "cpu": $(str "$CPU"),
    "arch": $(str "$ARCH"),
    "memory_gb": ${MEM_GB:-null},
    "gpus": $GPUS,
    "uptime": $(str "$UPTIME")
  },
  "os": {
    "family": "$OS_FAMILY",
    "id": $(str "$OS_ID"),
    "name": $(str "$OS_NAME"),
    "version": $(str "$OS_VERSION"),
    "build": $(str "$OS_BUILD"),
    "kernel": $(str "$KERNEL")
  },
  "updates": {
    "package_manager": $(str "$PKG_MANAGER"),
    "automatic": $(tri "$AUTO_UPDATES"),
    "pending": ${PENDING:-null}
  },
  "security": {
    "firewall_active": $(tri "$FIREWALL"),
    "firewall_tool": $(str "$FIREWALL_TOOL"),
    "disk_encrypted": $(tri "$DISK_ENC"),
    "ssh_server_running": $(tri "$SSHD_RUNNING"),
    "ssh_password_auth": $(str "$SSH_PASSWORD"),
    "ssh_root_login": $(str "$SSH_ROOT")
  },
  "tailscale": {
    "installed": $(tri "$TS_INSTALLED"),
    "version": $(str "$TS_VERSION"),
    "node_name": $(str "$TS_NAME"),
    "ips": $(str "$TS_IPS"),
    "tags": $TS_TAGS,
    "key_expiry": $(str "$TS_EXPIRY"),
    "online": $(tri "$TS_ONLINE")
  },
  "listening": $LISTEN,
  "software": $SOFTWARE,
  "containers": $CONTAINERS,
  "comfyui": $COMFY,
  "secrets_present": {
    "ssh_private_keys": $SSH_KEYS,
    "env_files": ${ENV_FILES:-0},
    "aws_credentials": $(tri "$(yesno "$HOME/.aws/credentials")"),
    "github_cli_token": $(tri "$(yesno "$HOME/.config/gh/hosts.yml")"),
    "netrc": $(tri "$(yesno "$HOME/.netrc")"),
    "docker_config": $(tri "$(yesno "$HOME/.docker/config.json")"),
    "huggingface_token": $(tri "$(yesno "$HOME/.cache/huggingface/token")")
  }
}
EOF
)

# Validate before saving, when python is available.
if [ -n "$PY" ] && ! printf '%s' "$JSON" | "$PY" -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
  echo "Warning: census produced invalid JSON - please report this as a bug." >&2
fi

if [ "$OUT" = "-" ]; then
  printf '%s\n' "$JSON"
else
  DIR=$(cd "$(dirname "$0")" && pwd)
  [ -z "$OUT" ] && OUT="$DIR/census/$NAME.json"
  mkdir -p "$(dirname "$OUT")"
  printf '%s\n' "$JSON" > "$OUT"
  echo "Census saved to $OUT"
  echo "Next: python3 fleet.py report"
fi
