#!/bin/sh
set -e
DATA_DIR="${DATA_DIR:-/data}"
if [ ! -f "$DATA_DIR/tls.crt" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout "$DATA_DIR/tls.key" -out "$DATA_DIR/tls.crt" \
    -subj "/C=PL/O=Northbridge Logistics/CN=intranet.northbridge-logistics.com" 2>/dev/null
fi
exec python -u /app/app.py
