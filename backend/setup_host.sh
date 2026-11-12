#!/bin/bash
# Run on the backend VM as root (install/backend.sh does). Builds the real-shell honeypot host:
#   an Incus system container (Ubuntu 24.04), reachable only from the front VM on BACKEND_IP:BACKEND_SSH_PORT
#   (SSH) and :BACKEND_TELNET_PORT (Telnet); the container has no internet; every exec is audited.
# The host itself has no internet either; packages come through the Squid proxy on the front VM.
# Settings: /etc/nb-honeypot.conf (copied from honeypot.conf). Argument: the unpacked repo (for install/lib.sh).
set -euo pipefail
source "${1:?usage: setup_host.sh REPO_DIR}/install/lib.sh"
source /etc/nb-honeypot.conf
detect_os
FRONT=$FRONT_PRIVATE_IP
PROXY=http://$FRONT:3128
CT=$CT_NAME
export HOTPOT_PROXY=$PROXY

# --- packages through the setup proxy ------------------------------------------------------------
cat > /etc/apt/apt.conf.d/95nb-proxy <<EOF
Acquire::http::Proxy "$PROXY";
Acquire::https::Proxy "$PROXY";
EOF
APT_UPDATED=0
pkg_install ca-certs curl auditd btrfs iptables iptables-save python3 iproute
ensure_incus

# --- Incus ----------------------------------------------------------------------------------------
if ! incus storage show default >/dev/null 2>&1; then
  cat <<EOF | incus admin init --preseed
config:
  core.proxy_http: $PROXY
  core.proxy_https: $PROXY
storage_pools:
- name: default
  driver: btrfs
  config: {size: $CT_DISK_POOL_SIZE}
networks:
- name: incusbr0
  type: bridge
  config:
    ipv4.address: $CT_BRIDGE_CIDR
    ipv4.nat: "false"
    ipv6.address: none
profiles:
- name: default
  devices:
    root: {path: /, pool: default, type: disk}
    eth0: {name: eth0, network: incusbr0, type: nic}
EOF
fi

if ! incus info "$CT" >/dev/null 2>&1; then
  incus init images:ubuntu/24.04 "$CT"
  incus config device override "$CT" eth0 ipv4.address="$CT_IP"
  incus config set "$CT" limits.memory="$CT_MEMORY" limits.cpu=1 limits.processes=1500 \
      security.nesting=false boot.autostart=true
  # NAT mode so sshd/telnetd in the container see a real network peer, not 127.0.0.1
  incus config device add "$CT" ssh proxy listen=tcp:$BACKEND_IP:$BACKEND_SSH_PORT connect=tcp:$CT_IP:22 nat=true
  incus config device add "$CT" telnet proxy listen=tcp:$BACKEND_IP:$BACKEND_TELNET_PORT connect=tcp:$CT_IP:23 nat=true
  incus start "$CT"
fi

# --- firewall: front VM may reach the container ports; the container may reach nothing ---------------
ipt() { iptables -C "$@" 2>/dev/null || iptables -I "$@"; }
ipt FORWARD -i incusbr0 -j DROP                                         # container -> anywhere: no
ipt FORWARD -i incusbr0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ipt FORWARD -o incusbr0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ipt FORWARD -o incusbr0 -s $FRONT -p tcp -m multiport --dports 22,23 -j ACCEPT
# (-I inserts at the top, so the DROP goes in first and the exceptions land above it)
ipt INPUT -i incusbr0 -j DROP                                           # container -> host: nothing else
ipt INPUT -i incusbr0 -p udp --dport 53 -j ACCEPT                       # dnsmasq on the bridge
ipt INPUT -i incusbr0 -p udp --dport 67 -j ACCEPT                       # DHCP
# IPv6: the bridge has no v6 address and forwarding is off, but don't rely on that staying true
ip6t() { ip6tables -C "$@" 2>/dev/null || ip6tables -I "$@"; }
ip6t INPUT -i incusbr0 -j DROP
ip6t FORWARD -i incusbr0 -j DROP
ip6t FORWARD -o incusbr0 -j DROP
save_firewall
# DNS: the bridge's dnsmasq would forward to the cloud resolver, a tunnel out (iodine/dnscat). It answers
# only local names now; the out-of-band fetcher still captures URLs from attackers' download commands.
incus network set incusbr0 raw.dnsmasq "no-resolv"

# --- audit every program started on the box (container processes included) -------------------------
cat > /etc/audit/rules.d/50-nb.rules <<'EOF'
-a always,exit -F arch=b64 -S execve,execveat -F uid>=1000000 -k nbexec
-a always,exit -F arch=b64 -S connect -F uid>=1000000 -F saddr_fam=2 -k nbconn
-a always,exit -F arch=b64 -S connect -F uid>=1000000 -F saddr_fam=10 -k nbconn
EOF
if [ "$ARCH" = amd64 ]; then
  # 32-bit programs and the old fork/vfork calls exist on x86 only (arm64 has neither)
  cat >> /etc/audit/rules.d/50-nb.rules <<'EOF'
-a always,exit -F arch=b32 -S execve,execveat -F uid>=1000000 -k nbexec
-a always,exit -F arch=b64 -S clone,clone3,fork,vfork -F uid>=1000000 -k nbfork
EOF
else
  echo "-a always,exit -F arch=b64 -S clone,clone3 -F uid>=1000000 -k nbfork" >> /etc/audit/rules.d/50-nb.rules
  # 32-bit ARM programs only run where the kernel has compat support: add the rule when it loads
  if auditctl -a always,exit -F arch=b32 -S execve -F 'uid>=1000000' -k nbprobe 2>/dev/null; then
    auditctl -d always,exit -F arch=b32 -S execve -F 'uid>=1000000' -k nbprobe 2>/dev/null || true
    echo "-a always,exit -F arch=b32 -S execve,execveat -F uid>=1000000 -k nbexec" >> /etc/audit/rules.d/50-nb.rules
  fi
fi
# (uid >= 1000000 = processes of the container, whose ids are shifted by Incus; host activity is not logged)
base=$(incus config get "$CT" volatile.idmap.base 2>/dev/null || true)
[ -z "$base" ] || [ "$base" -ge 1000000 ] || warn "container uids start at $base, below 1000000: the audit rules will miss them"
sed -i 's/^max_log_file = .*/max_log_file = 50/; s/^num_logs = .*/num_logs = 8/' /etc/audit/auditd.conf
augenrules --load
systemctl enable --now auditd
echo "host ready"
