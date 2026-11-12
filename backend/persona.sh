#!/bin/bash
# Copy the persona (cowrie/honeyfs, packed as /root/persona.tar.gz) into the container: homes, histories,
# web app, nginx site, cron, scripts, hosts, motd and the AI-agent tripwires. Called by setup_container.sh,
# and by refresh_persona.sh to update an existing container.
set -euo pipefail
source /etc/nb-honeypot.conf
CT=$CT_NAME
FRONT=$FRONT_PRIVATE_IP
x() { incus exec "$CT" -- "$@"; }

incus file push /root/persona.tar.gz "$CT/root/persona.tar.gz"
x bash -c 'set -e; mkdir -p /tmp/p && tar xzf /root/persona.tar.gz -C /tmp/p && rm /root/persona.tar.gz
  cd /tmp/p
  find . -type f -exec sed -i "s/\r\$//" {} +            # files were authored on Windows
  for d in home root var/www usr/local/bin etc/cron.d etc/nb etc/nginx/sites-available; do
    [ -d "$d" ] && cp -a "$d/." "/$d/"
  done
  cp etc/hosts /etc/hosts
  ln -sf /etc/nginx/sites-available/northbridge /etc/nginx/sites-enabled/northbridge
  rm -f /etc/nginx/sites-enabled/default
  # static part shown after Ubuntu'"'"'s real dynamic MOTD: only the company banner and the canary
  sed -n "/Northbridge Logistics/,\$p" etc/motd > /etc/motd
  # every proxied login arrives from the front VM; give it a believable name instead of the OCI one
  grep -q vpn-gw01 /etc/hosts || echo "'"$FRONT"'   vpn-gw01.northbridge.local vpn-gw01" >> /etc/hosts
  cp etc/ssh/sshd_config /etc/ssh/sshd_config
  rm -f /etc/ssh/sshd_config.d/*cloudimg*.conf            # would switch password logins off (first match wins)
  chown -R root:root /root /etc/nb /etc/cron.d /usr/local/bin /etc/nginx/sites-available /etc/hosts /etc/motd 2>/dev/null || true
  chown -R ubuntu:ubuntu /home/ubuntu; chown -R deploy:deploy /home/deploy; chown -R admin:admin /home/admin
  chown -R www-data:www-data /var/www/northbridge
  chmod 700 /root /home/*/.ssh 2>/dev/null || true; chmod 600 /root/.bash_history /home/*/.bash_history /var/www/northbridge/.env 2>/dev/null || true
  chmod 755 /usr/local/bin/*.sh /usr/local/bin/nb-healthcheck 2>/dev/null || true
  chmod 600 /etc/nb/monitor.env /root/RUNBOOK.md 2>/dev/null || true
  rm -rf /tmp/p'
