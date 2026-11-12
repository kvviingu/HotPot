# Preflight checks (sourced by install/lib.sh users). They look, never change anything, and report
# every problem at once instead of stopping at the first one.
#   preflight_front / preflight_backend   print a report; return 1 if anything would make the install fail

PF_FAIL=0 PF_WARN=0
pf_ok()   { printf '  \033[1;32mok\033[0m    %s\n' "$*"; }
pf_warn() { printf '  \033[1;33mwarn\033[0m  %s\n' "$*"; PF_WARN=$((PF_WARN + 1)); }
pf_fail() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$*"; PF_FAIL=$((PF_FAIL + 1)); }

mem_mib()  { awk '/^MemTotal:/ { print int($2 / 1024) }' /proc/meminfo; }
free_gib() { df -P -BG "$1" 2>/dev/null | awk 'NR == 2 { sub("G", "", $4); print $4 + 0 }'; }
# size like 560MiB / 18GiB / 2G -> MiB
to_mib() {
  local v=${1%%[iI][bB]} n
  n=${v%%[!0-9]*}
  case "${v#"$n"}" in [Gg]*) echo $((n * 1024)) ;; [Tt]*) echo $((n * 1024 * 1024)) ;; *) echo "${n:-0}" ;; esac
}
# name of the process listening on a TCP port, empty if none
port_owner() { ss -Hltnp "( sport = :$1 )" 2>/dev/null | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | head -1; }

pf_common() {
  if [ "$(id -u)" = 0 ]; then pf_ok "running as root"; else pf_fail "not running as root (use sudo)"; fi
  detect_os
  if os_supported; then pf_ok "$OS_NAME, $ARCH"
  elif [ "${HOTPOT_FORCE:-0}" = 1 ] && [ "$OS_FAMILY" = debian ]; then pf_warn "$OS_NAME ($ARCH) is not supported; HOTPOT_FORCE=1 is set"
  else pf_fail "$OS_NAME ($ARCH) is not supported; use $SUPPORTED_TEXT"; fi
  if [ "$(ps -p 1 -o comm= 2>/dev/null)" = systemd ]; then pf_ok "systemd"; else pf_fail "systemd is not running as PID 1 (needed for the timers and services)"; fi
  if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qx yes; then pf_ok "clock synchronised"
  else pf_warn "clock is not synchronised (NTP); log times may be off"; fi
  local cloud
  cloud=$(detect_cloud)
  [ "$cloud" = unknown ] && pf_ok "cloud provider: not recognised" || pf_ok "cloud provider: $cloud"
}

# the private address from honeypot.conf must be on this machine
pf_own_ip() {
  local name=$1 ip=$2 have
  if ip -4 -o addr 2>/dev/null | awk '{ print $4 }' | grep -q "^$ip/"; then pf_ok "$name=$ip is an address of this VM"
  else
    have=$(ip -4 -o addr 2>/dev/null | awk '$2 != "lo" { sub("/.*", "", $4); print $4 }' | paste -sd, -)
    pf_fail "$name=$ip is not an address of this VM (it has: ${have:-none}); fix honeypot.conf"
  fi
}

preflight_front() {
  printf '\nPreflight checks, front VM\n'
  pf_common
  pf_own_ip FRONT_PRIVATE_IP "$FRONT_PRIVATE_IP"

  local mem need=900
  mem=$(mem_mib)
  if [ "$mem" -lt "$need" ]; then pf_fail "${mem} MiB RAM; the front VM needs at least 1 GB"
  elif [ "${IDS_ENABLED:-0}" = 1 ] && [ "$mem" -lt 1800 ]; then
    pf_warn "${mem} MiB RAM is tight with the IDS on (Suricata takes up to 450 MB); consider IDS_ENABLED=0"
  else pf_ok "${mem} MiB RAM"; fi

  local disk
  disk=$(free_gib /var/lib)
  if [ "${disk:-0}" -lt 3 ]; then pf_fail "${disk:-0} GB free on /var/lib; needs at least 3 GB (images and logs)"
  elif [ "$disk" -lt 8 ]; then pf_warn "${disk} GB free on /var/lib; 8 GB or more is better for months of logs"
  else pf_ok "${disk} GB free on /var/lib"; fi

  # public ports the honeypots will take. Our own containers (docker-proxy) or sshd on 22 before the
  # move are fine; anything else is in the way.
  local ports="23 80 443" p owner bad=""
  [ "${DECOYS_ENABLED:-0}" = 1 ] && ports+=" 6379 2375 9200 3306 11434 6443 3389 445"
  for p in $ports; do
    owner=$(port_owner "$p")
    case "$owner" in "" | docker-proxy) ;; *) bad+=" $p ($owner)" ;; esac
  done
  owner=$(port_owner 22)
  case "$owner" in "" | docker-proxy | sshd | systemd) ;; *) bad+=" 22 ($owner)" ;; esac
  if [ -n "$bad" ]; then pf_fail "ports already in use by other programs:$bad; stop them first"
  else pf_ok "honeypot ports are free"; fi
  if [ "$ADMIN_SSH_PORT" = 22 ]; then pf_fail "ADMIN_SSH_PORT is 22, but Cowrie needs port 22; pick another (e.g. 22222)"
  else
    owner=$(port_owner "$ADMIN_SSH_PORT")
    case "$owner" in "" | sshd | systemd) pf_ok "admin SSH port $ADMIN_SSH_PORT" ;;
      *) pf_fail "ADMIN_SSH_PORT $ADMIN_SSH_PORT is used by $owner" ;; esac
  fi

  # outbound internet: packages, container images, rules
  local url
  for url in https://registry-1.docker.io/v2/ https://rules.emergingthreats.net/; do
    if curl -s -o /dev/null --max-time 10 "$url" 2>/dev/null || wget -q -O /dev/null -T 10 "$url" 2>/dev/null \
       || [ $? = 8 ]; then pf_ok "can reach ${url#https://}"
    else pf_fail "cannot reach $url (the front VM needs outbound HTTPS)"; fi
  done
  pf_sshd_include
  pf_report
}

# sshd must read /etc/ssh/sshd_config.d/ for the admin port drop-in
pf_sshd_include() {
  if [ ! -f /etc/ssh/sshd_config ]; then pf_fail "no /etc/ssh/sshd_config (OpenSSH server missing?)"
  elif grep -Eqi '^\s*Include\s+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config; then pf_ok "sshd reads sshd_config.d"
  else pf_fail "/etc/ssh/sshd_config has no 'Include /etc/ssh/sshd_config.d/*.conf' line; add it at the top"; fi
}

preflight_backend() {
  printf '\nPreflight checks, backend VM\n'
  pf_common
  pf_own_ip BACKEND_IP "$BACKEND_IP"

  local mem ct
  mem=$(mem_mib) ct=$(to_mib "$CT_MEMORY")
  if [ "$mem" -lt $((ct + 300)) ]; then pf_fail "${mem} MiB RAM; the container alone gets $CT_MEMORY, the host needs about 300 MB more"
  else pf_ok "${mem} MiB RAM (container gets $CT_MEMORY)"; fi

  local disk pool
  disk=$(free_gib /var/lib) pool=$(( $(to_mib "$CT_DISK_POOL_SIZE") / 1024 ))
  if incus storage show default >/dev/null 2>&1; then pf_ok "storage pool exists (${disk} GB free on /var/lib)"
  elif [ "${disk:-0}" -lt $((pool + 2)) ]; then pf_fail "${disk:-0} GB free on /var/lib; CT_DISK_POOL_SIZE=$CT_DISK_POOL_SIZE needs $((pool + 2)) GB"
  else pf_ok "${disk} GB free on /var/lib (pool $CT_DISK_POOL_SIZE)"; fi

  if [ -f /sys/fs/cgroup/cgroup.controllers ]; then pf_ok "cgroup v2"
  else pf_warn "cgroup v1; container memory limits may not apply"; fi

  if timeout 8 bash -c "exec 3<>/dev/tcp/$FRONT_PRIVATE_IP/3128" 2>/dev/null; then pf_ok "front VM proxy $FRONT_PRIVATE_IP:3128 reachable"
  else pf_fail "cannot reach the front VM's proxy at $FRONT_PRIVATE_IP:3128 (install the front VM first; check the private network firewall)"; fi

  # every apt mirror this VM uses must be allowed through the proxy
  local allowed host bad="" sfx ok
  allowed=$(setup_sites)
  for host in $(apt_hosts); do
    ok=0
    while read -r sfx; do
      case "$sfx" in
        .*) case ".$host" in *"$sfx") ok=1 ;; esac ;;
        *) [ "$host" = "$sfx" ] && ok=1 ;;
      esac
    done <<< "$allowed"
    [ $ok = 1 ] || bad+=" $host"
  done
  if [ -n "$bad" ]; then pf_fail "apt mirrors not allowed through the proxy:$bad; add them to EXTRA_APT_MIRRORS in honeypot.conf and run ./deploy.sh front again"
  else pf_ok "apt mirrors are allowed through the proxy"; fi
  pf_report
}

# host names of the apt sources configured on this machine
apt_hosts() {
  { cat /etc/apt/sources.list 2>/dev/null; cat /etc/apt/sources.list.d/*.list 2>/dev/null
    cat /etc/apt/sources.list.d/*.sources 2>/dev/null; } \
    | sed 's/\r$//' | grep -Ev '^\s*#' | grep -Eo '(https?|mirror\+https?)://[^/ ]+' | sed -E 's#^[a-z+]*://##; s#:.*##' | sort -u
}

pf_report() {
  if [ "$PF_FAIL" -gt 0 ]; then
    printf '\n\033[1;31m%s problem(s) must be fixed first\033[0m%s. Nothing was changed.\n' "$PF_FAIL" \
      "$([ "$PF_WARN" -gt 0 ] && echo ", $PF_WARN warning(s)")"
    return 1
  fi
  printf '\n\033[1;32mAll checks passed\033[0m%s.\n' "$([ "$PF_WARN" -gt 0 ] && echo " ($PF_WARN warning(s))")"
}
