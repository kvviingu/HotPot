#!/bin/bash
# Run on the backend VM as root after setup_host.sh (install/backend.sh does), with /root/persona.tar.gz
# (cowrie/honeyfs) and /root/backend.env (BACKEND_PASS=...) in place. Turns the container into the
# persona as a real Ubuntu system, then takes the "clean" snapshot that nightly resets roll back to.
set -euo pipefail
source /etc/nb-honeypot.conf
CT=$CT_NAME
FRONT=$FRONT_PRIVATE_IP
PROXY=http://$FRONT:3128
CT_NET=$(python3 -c "import ipaddress,sys;print(ipaddress.ip_interface(sys.argv[1]).network)" "$CT_BRIDGE_CIDR")
source /root/backend.env
: "${BACKEND_PASS:?}"

# --- temporary package access: container -> setup proxy, masqueraded as this host ------------------
open_proxy()  { iptables -I FORWARD -i incusbr0 -d "$FRONT" -p tcp --dport 3128 -j ACCEPT
                iptables -t nat -I POSTROUTING -s "$CT_NET" -d "$FRONT" -p tcp --dport 3128 -j MASQUERADE; }
close_proxy() { iptables -D FORWARD -i incusbr0 -d "$FRONT" -p tcp --dport 3128 -j ACCEPT 2>/dev/null || true
                iptables -t nat -D POSTROUTING -s "$CT_NET" -d "$FRONT" -p tcp --dport 3128 -j MASQUERADE 2>/dev/null || true; }
trap close_proxy EXIT
open_proxy

x() { incus exec "$CT" -- "$@"; }
x bash -c "cat > /etc/apt/apt.conf.d/95nb-proxy <<EOF
Acquire::http::Proxy \"$PROXY\";
Acquire::https::Proxy \"$PROXY\";
EOF"
x bash -c 'export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  apt-get install -y -q --no-install-recommends \
    openssh-server inetutils-inetd inetutils-telnetd nginx php8.3-fpm php8.3-cli php8.3-mysql \
    php8.3-xml php8.3-mbstring php8.3-curl mysql-client-core-8.0 cron sudo nano vim-tiny less curl wget \
    ca-certificates iputils-ping iproute2 procps psmisc rsync git unzip python3 bash-completion \
    command-not-found ubuntu-minimal update-motd landscape-common lsb-release logrotate rsyslog
  apt-get clean'
x rm -f /etc/apt/apt.conf.d/95nb-proxy
close_proxy

# --- identity -------------------------------------------------------------------------------------
x hostnamectl set-hostname fileserver01 2>/dev/null || x bash -c 'echo fileserver01 > /etc/hostname; hostname fileserver01'
x bash -c 'id ubuntu >/dev/null 2>&1 || useradd -m -u 1000 -s /bin/bash -c Ubuntu -G adm,sudo ubuntu
  id deploy >/dev/null 2>&1 || useradd -m -u 1001 -s /bin/bash -c "Northbridge deploy,,," -G sudo deploy
  id admin  >/dev/null 2>&1 || useradd -m -u 1002 -s /bin/bash -c "NB IT admin,,," -G sudo admin'
for u in root ubuntu deploy admin; do
  printf '%s:%s\n' "$u" "$BACKEND_PASS" | x chpasswd
done

# --- persona files (homes, histories, web app, nginx site, cron, scripts, hosts, motd, tripwires) -------
bash "$(dirname "$0")/persona.sh"
# self-signed cert for the nginx site in the story
x bash -c '[ -f /etc/ssl/private/nb-intranet.key ] || openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -subj "/CN=intranet.northbridge-logistics.com" -keyout /etc/ssl/private/nb-intranet.key -out /etc/ssl/certs/nb-intranet.crt 2>/dev/null'
x bash -c 'grep -q "^telnet" /etc/inetd.conf || echo "telnet stream tcp nowait root /usr/sbin/tcpd /usr/sbin/telnetd" >> /etc/inetd.conf'
x systemctl enable --now ssh nginx php8.3-fpm inetutils-inetd cron rsyslog
x systemctl restart ssh nginx inetutils-inetd
x bash -c 'nginx -t'

# --- clean snapshot ---------------------------------------------------------------------------------
incus snapshot delete "$CT" clean 2>/dev/null || true
incus snapshot create "$CT" clean
x dpkg-query -W -f='${Version}\n' openssh-server
echo "container ready"
