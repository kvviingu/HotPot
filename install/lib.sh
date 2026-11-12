# Shared helpers for install/front.sh and install/backend.sh (sourced, not run).

step() { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
ok()   { printf '\033[1;32m%s\033[0m' "$*"; }

LIB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=install/os.sh
source "$LIB_DIR/os.sh"

need_root() { [ "$(id -u)" = 0 ] || die "run as root (sudo bash $0)"; }

# ---- install log --------------------------------------------------------------------------------------
# Everything the installer prints also goes to /var/log/hotpot-install.log. If a step fails, the
# message says where it stopped; re-running the same command continues safely (every step is
# idempotent, and finished slow steps are skipped).
INSTALL_LOG=/var/log/hotpot-install.log
start_log() {
  touch "$INSTALL_LOG" && chmod 600 "$INSTALL_LOG"
  exec > >(tee -a "$INSTALL_LOG") 2>&1
  printf '\n===== %s  %s %s =====\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')" "$1" "${*:2}"
  set -E
  trap 'on_fail $LINENO "$BASH_COMMAND"' ERR
}
on_fail() {
  trap - ERR
  printf '\n\033[1;31merror:\033[0m the installer stopped (line %s of %s: %s).\n' "$1" "$(basename "$0")" "$2" >&2
  printf '       Full log: %s. Fix the cause, then run the same command again; it continues where it can.\n' "$INSTALL_LOG" >&2
}

# ---- markers for finished slow steps ------------------------------------------------------------------
# A step is skipped when its marker exists and holds the same fingerprint (e.g. the package list and the
# OS version), so a changed configuration still re-runs it.
STATE_DIR=/var/lib/hotpot/state
step_done() { [ -f "$STATE_DIR/$1" ] && [ "$(cat "$STATE_DIR/$1")" = "$2" ]; }
mark_done() { install -d -m 700 "$STATE_DIR"; printf '%s' "$2" > "$STATE_DIR/$1"; }

# ---- honeypot.conf ------------------------------------------------------------------------------------
# KEY=value lines of a config file, without comments and Windows line endings
conf_lines() { sed 's/\r$//' "$1" | grep -E '^[A-Za-z_][A-Za-z0-9_]*='; }

load_conf() {
  [ -f "$1" ] || die "$1 not found (copy honeypot.conf.example to honeypot.conf and fill it in)"
  set -a
  # shellcheck disable=SC1090
  source <(conf_lines "$1")
  set +a
}

require_vars() {
  local v
  for v in "$@"; do
    [ -n "${!v:-}" ] || die "$v is not set in honeypot.conf"
  done
}

# remove CR from every text file under the given paths (the repo may have been edited on Windows)
strip_cr() {
  # (grep exits 1 when no file has CRs; that is fine, hence the "|| true" under pipefail)
  { find "$@" -type f ! -name '*.pickle' ! -name '*.gz' -print0 | xargs -0 -r grep -lIZ $'\r' 2>/dev/null \
      | xargs -0 -r sed -i 's/\r$//'; } || true
}

# domains the backend may reach through Squid during setup: install/mirrors.txt plus EXTRA_APT_MIRRORS
setup_sites() {
  { grep -Ev '^\s*(#|$)' "$LIB_DIR/mirrors.txt" | sed 's/\r$//'
    tr ', ' '\n\n' <<< "${EXTRA_APT_MIRRORS:-}" | grep -v '^$' || true; } \
    | grep -E '^\.?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$' | sort -u     # plain host names only
}
