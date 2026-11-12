#!/bin/bash
# Daily IDS upkeep on the front VM (hotpot-ids.timer): rotate eve.json (hotpot-retention deletes old
# ones), refresh the ET Open rules and restart Suricata on them. Also run once by install/front.sh.
#   maintain.sh            all of it
#   maintain.sh rules      only fetch rules (used before the first start)
set -euo pipefail
cd /opt/honeypot
LOG=/var/lib/docker/volumes/honeypot_ids-log/_data

update_rules() {
  # runs in the ids image, on the host network (the rules come from rules.emergingthreats.net)
  docker compose run --rm --no-deps -T --entrypoint suricata-update ids \
    --disable-conf /etc/suricata-hotpot/disable.conf --no-test --no-reload -q
}

if [ "${1:-}" = rules ]; then update_rules; exit 0; fi

if [ -s "$LOG/eve.json" ]; then
  # Suricata keeps writing to the renamed file until SIGHUP makes it reopen eve.json
  mv "$LOG/eve.json" "$LOG/eve-$(date -u +%Y%m%d%H%M).json"
  docker kill -s HUP ids >/dev/null 2>&1 || true
fi

if update_rules; then
  docker restart ids >/dev/null
else
  echo "rule update failed; Suricata keeps running on the previous rules" >&2
fi
