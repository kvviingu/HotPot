#!/bin/bash
# Daily clean-up of old logs and samples on a HotPot VM, front or backend (hotpot-retention.timer).
#   retention.sh             delete what is past its age, then free space if the disk is too full
#   retention.sh --dry-run   only print what would be deleted
#   retention.sh --report    disk use per kind of data, deletes nothing
# Settings (honeypot.conf): LOG_KEEP_DAYS, SAMPLE_KEEP_DAYS, DISK_MAX_PERCENT. Only rotated logs are
# touched, never the file a service is writing to. The dashboard keeps its own copy of every log line
# it has synced, so this only frees the VMs' disks.
set -uo pipefail

MODE=run
case "${1:-}" in
  --dry-run) MODE=dry ;;
  --report)  MODE=report ;;
  "") ;;
  *) echo "usage: $0 [--dry-run|--report]" >&2; exit 2 ;;
esac

# settings: digits only, so nothing in the file is ever executed
# R is only set by the tests, to run this against a fake file tree
R=${RETENTION_ROOT:-}
CONF=$R/opt/honeypot/.env
[ -f "$R/etc/nb-honeypot.conf" ] && CONF=$R/etc/nb-honeypot.conf
num() { local v; v=$(sed -n "s/^$1=\([0-9]\{1,5\}\)[[:space:]]*\$/\1/p" "$CONF" 2>/dev/null | tail -1); echo "${v:-$2}"; }
LOG_DAYS=$(num LOG_KEEP_DAYS 30)
SAMPLE_DAYS=$(num SAMPLE_KEEP_DAYS 90)
DISK_MAX=$(num DISK_MAX_PERCENT 85)
[ "$DISK_MAX" -ge 50 ] && [ "$DISK_MAX" -le 98 ] || DISK_MAX=85

V=$R/var/lib/docker/volumes
L=$R/var/lib
# kind  glob (rotated files only)
CANDIDATES="
logs    $V/honeypot_cowrie-var/_data/log/cowrie/cowrie.json.*
logs    $V/honeypot_cowrie-var/_data/log/cowrie/cowrie.log.*
logs    $V/honeypot_web-data/_data/web.jsonl.*
logs    $V/honeypot_decoy-data/_data/services.jsonl.*
logs    $V/honeypot_ids-log/_data/eve-*.json
logs    $L/nb-export/backend.jsonl.*
tty     $V/honeypot_cowrie-var/_data/lib/cowrie/tty/*
harvest $L/nb-harvest/*-*.tgz
harvest $L/nb-harvest/*-*.list
harvest $L/nb-harvest/*-*.sha256
samples $V/honeypot_cowrie-var/_data/lib/cowrie/downloads/*
samples $L/nb-quarantine/files/*.bin
"

# "<mtime> <bytes> <kind> <path>" for every existing candidate, oldest first; files changed in the last
# hour are left alone (a recording or harvest may still be written)
list() {
  local kind glob f now
  now=$(date +%s)
  while read -r kind glob; do
    [ -n "$kind" ] || continue
    for f in $glob; do
      [ -f "$f" ] && [ ! -L "$f" ] || continue
      stat -c "%Y %s $kind %n" -- "$f"
    done
  done <<< "$CANDIDATES" | awk -v cut=$((now - 3600)) '$1 < cut' | sort -n
}

FREED=0; COUNT=0
remove() {  # mtime bytes kind path
  if [ "$MODE" = dry ]; then
    echo "would delete $3: $4 ($(( $2 / 1024 )) KiB)"
  else
    rm -f -- "$4" || return
  fi
  FREED=$((FREED + $2)); COUNT=$((COUNT + 1))
}

used() { [ -n "${RETENTION_USED:-}" ] && { echo "$RETENTION_USED"; return; }; df -P /var/lib | awk 'NR==2 {gsub("%", "", $5); print $5}'; }

if [ "$MODE" = report ]; then
  echo "disk: $(used)% used (clean-up starts above $DISK_MAX%)"
  echo "keep: logs and recordings $LOG_DAYS days, samples and harvests $SAMPLE_DAYS days (0 = forever)"
  list | awk '{n[$3]++; b[$3]+=$2} END {for (k in n) printf "  %-8s %6d files %9.1f MB\n", k, n[k], b[k]/1048576}'
  exit 0
fi

# harvests are written under this lock by nb-reset; never delete while one is running
LOCK=$L/nb-harvest/.lock
if [ -d "$L/nb-harvest" ]; then exec 9>"$LOCK"; flock -w 900 9 || { echo "nb-reset is busy; try later" >&2; exit 1; }; fi

# 1. by age
now=$(date +%s)
while read -r mt sz kind path; do
  case "$kind" in logs|tty) days=$LOG_DAYS ;; *) days=$SAMPLE_DAYS ;; esac
  [ "$days" -gt 0 ] && [ "$mt" -lt $((now - days * 86400)) ] && remove "$mt" "$sz" "$kind" "$path"
done < <(list)

# 2. disk too full: oldest logs and recordings first, then harvests, then samples
if [ "$MODE" = run ] && [ "$(used)" -gt "$DISK_MAX" ]; then
  echo "disk $(used)% used, above $DISK_MAX%: deleting the oldest data until it is below"
  for k in "logs|tty" harvest samples; do
    while read -r mt sz kind path; do
      [ "$(used)" -gt "$DISK_MAX" ] || break 2
      remove "$mt" "$sz" "$kind" "$path"
    done < <(list | awk -v k="^($k)\$" '$3 ~ k')
  done
  if [ "$(used)" -gt "$DISK_MAX" ] && [ -z "$R" ]; then
    journalctl --vacuum-size=200M >/dev/null 2>&1 || true
    command -v docker >/dev/null && docker image prune -f >/dev/null 2>&1 || true
  fi
  [ "$(used)" -gt "$DISK_MAX" ] && echo "WARNING: disk still $(used)% used; look at 'hotpot cleanup --report'" >&2
fi

verb=deleted; [ "$MODE" = dry ] && verb="would delete"
echo "retention: $verb $COUNT files, $((FREED / 1048576)) MB; disk $(used)% used"
