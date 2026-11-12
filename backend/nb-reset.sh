#!/bin/bash
# Nightly on nb-backend: keep every file attackers created or changed in fileserver01 since the last
# reset, then roll the container back to the "clean" snapshot. Installed as /usr/local/sbin/nb-reset.sh,
# run by nb-reset.timer. Harvests land in /var/lib/nb-harvest (root only, never executed;
# hotpot-retention deletes old ones).
set -euo pipefail
source /etc/nb-honeypot.conf
CT=$CT_NAME
ROOT=/var/lib/incus/storage-pools/default/containers/$CT/rootfs
OUT=/var/lib/nb-harvest
STAMP=$OUT/.last-reset
mkdir -p "$OUT"; chmod 700 "$OUT"
exec 9>"$OUT/.lock"; flock 9          # nightly timer and nb-collect's early reset never overlap
REASON_FILE=$OUT/.reset-reason
REASON='{"reason":"nightly"}'
if [ -s "$REASON_FILE" ]; then REASON=$(head -c 8192 "$REASON_FILE"); fi
rm -f "$REASON_FILE"
[ -f "$STAMP" ] || touch -d '1 day ago' "$STAMP"

TS=$(date -u +%Y%m%dT%H%M%SZ)
LIST=$(mktemp)
trap 'rm -f "$LIST"' EXIT
( cd "$ROOT" && find . -xdev -type f -newer "$STAMP" -size -64M \
    ! -path './proc/*' ! -path './sys/*' ! -path './run/*' ! -path './dev/*' \
    ! -path './var/cache/*' ! -path './var/lib/apt/lists/*' ! -path './var/lib/systemd/*' \
    -print0 ) > "$LIST"
N=$(tr -cd '\0' < "$LIST" | wc -c)
if [ "$N" -gt 0 ]; then
  # a listing with owners/modes/hashes first, so the tarball never has to be unpacked to triage it
  ( cd "$ROOT" && xargs -0 -r stat -c '%y %U %a %s %n' < "$LIST" ) > "$OUT/$CT-$TS.list" 2>/dev/null || true
  ( cd "$ROOT" && xargs -0 -r sha256sum < "$LIST" ) > "$OUT/$CT-$TS.sha256" 2>/dev/null || true
  tar -C "$ROOT" --null -T "$LIST" --ignore-failed-read -czf "$OUT/$CT-$TS.tgz" 2>/dev/null || true
  chmod 600 "$OUT/$CT-$TS".*
fi

incus snapshot restore "$CT" clean
incus start "$CT" 2>/dev/null || true
touch "$STAMP"
# old harvests are deleted by hotpot-retention (SAMPLE_KEEP_DAYS)
logger -t nb-reset "harvested $N files to $OUT/$CT-$TS, restored $CT to clean"
# one line for the dashboard: when, why, and how many files were kept
python3 -I -c 'import json,sys,time
r=json.loads(sys.argv[1]) if sys.argv[1].startswith("{") else {}
r=r if isinstance(r,dict) else {}
e={"type":"reset","t":int(time.time()*1000),"reason":str(r.get("reason","nightly"))[:40],
   "paths":[str(p)[:300] for p in (r.get("paths") or [])][:20],"harvested":int(sys.argv[2]),"archive":sys.argv[3]}
open("/var/lib/nb-export/backend.jsonl","a").write(json.dumps(e)+chr(10))' "$REASON" "$N" "$CT-$TS" || true
