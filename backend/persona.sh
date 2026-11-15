#!/bin/bash
# Copy the persona (cowrie/honeyfs, packed as /root/persona.tar.gz) into the container: homes, histories,
# web app, nginx site, cron, scripts, hosts, motd and the tripwires. Called by setup_container.sh,
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
  for d in home root var/www usr/local/bin etc/cron.d etc/nb-ops etc/nginx/sites-available; do
    [ -d "$d" ] && cp -a "$d/." "/$d/"
  done
  cp etc/hosts /etc/hosts
  ln -sf /etc/nginx/sites-available/northbridge /etc/nginx/sites-enabled/northbridge
  rm -f /etc/nginx/sites-enabled/default
  # static part shown after Ubuntu'"'"'s real dynamic MOTD: only the company banner and the change-control rule
  sed -n "/Northbridge Logistics/,\$p" etc/motd > /etc/motd
  # every proxied login arrives from the front VM; give it a believable name instead of the OCI one
  grep -q vpn-gw01 /etc/hosts || echo "'"$FRONT"'   vpn-gw01.northbridge.local vpn-gw01" >> /etc/hosts
  cp etc/ssh/sshd_config /etc/ssh/sshd_config
  rm -f /etc/ssh/sshd_config.d/*cloudimg*.conf            # would switch password logins off (first match wins)
  chown -R root:root /root /etc/nb-ops /etc/cron.d /usr/local/bin /etc/nginx/sites-available /etc/hosts /etc/motd 2>/dev/null || true
  chown -R ubuntu:ubuntu /home/ubuntu; chown -R deploy:deploy /home/deploy; chown -R admin:admin /home/admin
  chown -R www-data:www-data /var/www/northbridge
  chmod 700 /root /home/*/.ssh 2>/dev/null || true; chmod 600 /root/.bash_history /home/*/.bash_history /var/www/northbridge/.env 2>/dev/null || true
  chmod 755 /usr/local/bin/*.sh /usr/local/bin/nb-healthcheck 2>/dev/null || true
  chmod 600 /etc/nb-ops/monitor.env /root/RUNBOOK.md /root/.my.cnf /home/deploy/.aws/credentials 2>/dev/null || true
  chmod 700 /home/deploy/.aws 2>/dev/null || true'

# --- a server that has been in use for a while -------------------------------------------------------
# Without this every persona file is dated the day of the install, the backup folder is empty and the
# backup log does not exist: the first things a careful visitor notices. Dates are spread over the past
# year, the same way on every run (from each path's checksum); the dumps hold made-up rows only.
x bash -s <<'EOS'
set -e
cd /tmp/p
rm -rf /etc/nb /var/backups/nb          # folders of earlier versions, never renamed per install
age() { touch -h -d "$1" "$2" 2>/dev/null || true; }
k=0
while read -r f; do
  [ -e "/$f" ] || { echo "persona: /$f is not on the box" >&2; continue; }
  n=$(printf '%s' "$f" | cksum | cut -d' ' -f1)
  age "$(( n % 330 + 25 )) days ago $(( n / 7 % 86400 )) seconds ago" "/$f"     # not all at one time of day
  k=$((k + 1))
done < <(find home root var/www usr/local/bin etc/cron.d etc/nb-ops etc/nginx/sites-available \
           -mindepth 1 \( -type f -o -type d \) 2>&1 </dev/null)
echo "persona: dated $k files and folders"
age "62 days ago" /root/RUNBOOK.md
age "97 days ago" /var/www/northbridge/.env
age "1 day ago" /root/.bash_history
age "6 days ago" /home/deploy/.bash_history
age "3 hours ago" /var/www/northbridge/storage/logs/laravel.log
age "210 days ago" /etc/nb-ops
age "340 days ago" /var/www/northbridge
age "292 days ago" /usr/local/bin
age "171 days ago" /etc/cron.d
age "236 days ago" /etc/nginx/sites-available

# nightly dumps of the last 30 days, each a little larger than the one before
B=/var/backups/nb-intranet
mkdir -p "$B"; rm -f "$B"/db_*.sql
T=$(mktemp -d)
towns=(Gdansk Hamburg Rotterdam Antwerp Poznan Wroclaw Berlin Prague Vienna Lodz Szczecin Bremen Brno Leipzig)
state=(delivered delivered delivered in_transit in_transit at_depot customs returned)
row() {   # row <id> <days ago>
  printf "(%d,'NB-2026-%06d','%s','%s','%s',%d.%d,'%s')" "$1" $(( 100000 + (RANDOM * 31 + $1) % 899999 )) \
    "${state[RANDOM % ${#state[@]}]}" "${towns[RANDOM % ${#towns[@]}]}" "${towns[RANDOM % ${#towns[@]}]}" \
    $(( RANDOM % 900 + 20 )) $(( RANDOM % 10 )) "$(date -u -d "$2 days ago" +%F)"
}
pwhash() { printf '$2y$12$%s' "$(head -c 64 /dev/urandom | base64 | tr -d '+=\n' | head -c 53)"; }
{ echo "INSERT INTO \`users\` VALUES"
  i=0
  for u in "k.nowak:Krzysztof Nowak:admin" "a.lewis:Anna Lewis:dispatcher" "m.brandt:Martin Brandt:dispatcher" \
           "j.kowal:Julia Kowal:warehouse" "svc-backup:Backup service:service"; do
    i=$((i + 1)); IFS=: read -r login name role <<<"$u"
    printf "(%d,'%s','%s','%s@northbridge-logistics.com','%s','%s')\n" "$i" "$login" "$name" "$login" "$(pwhash)" "$role"
  done | sed '$!s/$/,/; $s/$/;/'; } > "$T/users"
for i in $(seq 1 520); do row "$i" $(( (520 - i) / 4 + 1 )); echo; done > "$T/rows"
for ago in $(seq 29 -1 0); do
  day=$(date -u -d "$ago days ago" +%F)
  n=$(( 400 + (29 - ago) * 4 ))
  { printf -- '-- MySQL dump 10.13  Distrib 8.0.39, for Linux (x86_64)\n--\n-- Host: 10.0.0.21    Database: nb_intranet\n'
    printf -- '-- ------------------------------------------------------\n-- Server version\t8.0.39-0ubuntu0.24.04.2\n\n'
    printf '/*!40101 SET NAMES utf8mb4 */;\n/*!40103 SET TIME_ZONE='"'+00:00'"' */;\n\n'
    printf 'DROP TABLE IF EXISTS `users`;\nCREATE TABLE `users` (\n  `id` int unsigned NOT NULL AUTO_INCREMENT,\n  `login` varchar(64) NOT NULL,\n'
    printf '  `name` varchar(128) NOT NULL,\n  `email` varchar(190) NOT NULL,\n  `password` varchar(255) NOT NULL,\n  `role` varchar(32) NOT NULL,\n'
    printf '  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n\nLOCK TABLES `users` WRITE;\n'
    cat "$T/users"
    printf 'UNLOCK TABLES;\n\nDROP TABLE IF EXISTS `shipments`;\nCREATE TABLE `shipments` (\n  `id` int unsigned NOT NULL AUTO_INCREMENT,\n'
    printf '  `ref` varchar(32) NOT NULL,\n  `status` varchar(24) NOT NULL,\n  `origin` varchar(64) NOT NULL,\n  `destination` varchar(64) NOT NULL,\n'
    printf '  `weight_kg` decimal(8,1) NOT NULL,\n  `created` date NOT NULL,\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n\n'
    printf 'LOCK TABLES `shipments` WRITE;\nINSERT INTO `shipments` VALUES\n'
    head -n "$n" "$T/rows" | sed '$!s/$/,/; $s/$/;/'
    printf 'UNLOCK TABLES;\n\n-- Dump completed on %s  2:00:%02d\n' "$day" $(( RANDOM % 20 + 3 ))
  } > "$B/db_$day.sql"
  chmod 644 "$B/db_$day.sql"
  age "$day 02:00:11 UTC" "$B/db_$day.sql"
done
for ago in $(seq 29 -1 0); do
  echo "mysqldump: [Warning] Using a password on the command line interface can be insecure."
done > /var/log/nb-backup.log
age "$(date -u +%F) 02:00:11 UTC" /var/log/nb-backup.log
age "$(date -u +%F) 02:00:11 UTC" "$B"
rm -rf "$T" /tmp/p
EOS
