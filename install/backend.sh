#!/bin/bash
# Install or update the BACKEND VM (private, no internet): the real Ubuntu container attackers land in,
# exec/network auditing, the per-minute sample collector and the nightly reset.
# Run as root from an unpacked copy of the repo that contains honeypot.conf and backend.env
# (BACKEND_PASS=..., generated on the front VM):
#     sudo bash install/backend.sh
# The front VM must be installed first: this host gets its packages through the front VM's Squid.
# deploy.sh does all of this for you. Safe to re-run: the container is first rolled back to its
# clean snapshot, so nothing an attacker left behind gets baked into the new one.
#     sudo bash install/backend.sh --check   preflight checks only, changes nothing
# Log: /var/log/hotpot-install.log
set -euo pipefail
SRC=$(cd "$(dirname "$0")/.." && pwd)
source "$SRC/install/lib.sh"
source "$SRC/install/preflight.sh"

need_root
load_conf "$SRC/honeypot.conf"
require_vars FRONT_PRIVATE_IP BACKEND_IP BACKEND_SSH_PORT BACKEND_TELNET_PORT CT_NAME CT_BRIDGE_CIDR CT_IP \
             CT_MEMORY CT_DISK_POOL_SIZE
case "${1:-}" in
  "") ;;
  --check) preflight_backend; exit $? ;;
  *) die "unknown option $1 (use --check)" ;;
esac
start_log backend.sh "$@"
need_supported_os
preflight_backend || exit 1
[ -s "$SRC/backend.env" ] || die "backend.env missing (it is generated on the front VM: /opt/honeypot/backend.env)"

step "Writing /etc/nb-honeypot.conf and /root/backend.env"
conf_lines "$SRC/honeypot.conf" > /etc/nb-honeypot.conf
chmod 600 /etc/nb-honeypot.conf
install -m 600 "$SRC/backend.env" /root/backend.env
strip_cr /root/backend.env "$SRC/backend" "$SRC/cowrie/honeyfs"

if command -v incus >/dev/null && incus snapshot list "$CT_NAME" -f csv -c n 2>/dev/null | grep -qx clean; then
  step "Rolling $CT_NAME back to its clean snapshot before updating it"
  systemctl stop nb-collect.timer nb-reset.timer 2>/dev/null || true
  incus snapshot restore "$CT_NAME" clean
  incus start "$CT_NAME" 2>/dev/null || true
fi

step "Swap"
ensure_swap 2

step "Host: Incus, firewall, audit rules"
bash "$SRC/backend/setup_host.sh" "$SRC"

step "Container: packages, users, persona, clean snapshot"
tar czf /root/persona.tar.gz -C "$SRC/cowrie/honeyfs" .
bash "$SRC/backend/setup_container.sh"
rm -f /root/persona.tar.gz

step "Collector (every minute), nightly reset, daily clean-up"
install -m 750 "$SRC/backend/nb-collect.py" /usr/local/sbin/nb-collect.py
install -m 750 "$SRC/backend/nb-reset.sh" /usr/local/sbin/nb-reset.sh
install -m 644 "$SRC/backend/nb-collect.service" "$SRC/backend/nb-collect.timer" \
               "$SRC/backend/nb-reset.service" "$SRC/backend/nb-reset.timer" /etc/systemd/system/
pkg_install file zip yara python3
# files the installer itself just wrote into the container are not attacker samples: start watching from now
python3 - <<'EOF'
import json, os, time
p = "/var/lib/nb-quarantine/collect-state.json"
os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
try:
    st = json.load(open(p))
except (OSError, ValueError):
    st = {}
st["ctime"] = time.time()
st["persist"] = []
json.dump(st, open(p, "w"))
EOF
systemctl daemon-reload
systemctl enable --now nb-collect.timer nb-reset.timer
install_retention

incus list "$CT_NAME" -f compact -c ns4
cat <<EOF

$(ok "Backend VM ready.")
  SSH/Telnet logins on the front VM now land in the real container "$CT_NAME".
  Quarantined samples: /var/lib/nb-quarantine/files (root only)   Events: /var/lib/nb-export/backend.jsonl
  Nightly harvest + reset: /var/lib/nb-harvest
EOF
