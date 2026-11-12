#!/bin/sh
# HotPot one-line install for Linux and macOS:
#   curl -fsSL https://raw.githubusercontent.com/kvviingu/HotPot/main/get.sh | sh
# Downloads the latest release into ./hotpot (or $HOTPOT_DIR) and starts the setup questions.
# Nothing is installed system-wide; delete the folder to remove it.
set -eu
REPO=kvviingu/HotPot
DIR=${HOTPOT_DIR:-hotpot}

PY=""
for p in python3 python; do
  if command -v "$p" >/dev/null 2>&1 && "$p" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
    PY=$p; break
  fi
done
[ -n "$PY" ] || { echo "HotPot needs Python 3.10 or newer: install it, then run this again." >&2; exit 1; }
command -v ssh >/dev/null 2>&1 || { echo "HotPot needs the OpenSSH client (ssh): install it, then run this again." >&2; exit 1; }
[ ! -e "$DIR" ] || { echo "$DIR already exists. To update it: cd $DIR && ./hotpot update" >&2; exit 1; }

echo "Looking up the latest HotPot release..."
URL=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
      "$PY" -c 'import json, sys; print(json.load(sys.stdin)["tarball_url"])')
mkdir "$DIR"
curl -fsSL "$URL" | tar xz -C "$DIR" --strip-components=1
echo "HotPot is in $(cd "$DIR" && pwd). Starting the setup."
cd "$DIR"
# stdin is this script when piped from curl: answer the questions on the terminal instead
if [ -r /dev/tty ]; then exec "$PY" hotpot.py setup </dev/tty; fi
echo "No terminal to ask questions on. Run: cd $DIR && ./hotpot setup"
