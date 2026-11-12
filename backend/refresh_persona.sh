#!/bin/bash
# Update the persona files in an existing container without reinstalling packages: roll back to the clean
# snapshot (nothing an attacker left gets baked in), copy the persona, take a new clean snapshot.
# Run on the backend VM as root with /root/persona.tar.gz in place (deploy.sh persona does all of it).
set -euo pipefail
source /etc/nb-honeypot.conf
CT=$CT_NAME
systemctl stop nb-collect.timer
trap 'systemctl start nb-collect.timer' EXIT
# harvest what attackers changed and roll back to clean, exactly like the nightly run
mkdir -p /var/lib/nb-harvest
echo '{"reason":"persona update"}' > /var/lib/nb-harvest/.reset-reason
/usr/local/sbin/nb-reset.sh
exec 9>/var/lib/nb-harvest/.lock; flock 9          # no other reset while the persona is copied
for i in $(seq 30); do incus exec "$CT" -- true 2>/dev/null && break; sleep 1; done
bash "$(dirname "$0")/persona.sh"
incus exec "$CT" -- systemctl restart nginx ssh 2>/dev/null || true
incus snapshot delete "$CT" clean
incus snapshot create "$CT" clean
touch /var/lib/nb-harvest/.last-reset
# the persona copy is not an attacker: move the collector's clock past it so it isn't captured or
# mistaken for planted persistence (authorized_keys is part of the persona)
python3 -I -c 'import json,time
p="/var/lib/nb-quarantine/collect-state.json"
try: st=json.load(open(p))
except Exception: st={}
st["ctime"]=time.time(); st["persist"]=[]
json.dump(st,open(p,"w"))'
logger -t nb-persona "persona refreshed, new clean snapshot"
echo "persona refreshed"
