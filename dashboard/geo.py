"""Offline IP geolocation for the dashboard.

Uses the free DB-IP Lite databases (city + ASN, CC BY 4.0, https://db-ip.com). They are downloaded
once a month into dashboard/data/geo/ and queried locally, so attacker IP addresses are never sent
to an outside lookup service.
"""
import gzip
import ipaddress
import json
import os
import re
import shutil
import threading
import time
import urllib.request
from datetime import date

try:
    import maxminddb
except ImportError:  # dashboard still works, just without locations
    maxminddb = None

BASE = os.path.dirname(os.path.abspath(__file__))
GEO_DIR = os.path.join(BASE, "data", "geo")
URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{ym}.mmdb.gz"
MAX_AGE_DAYS = 35
ATTRIBUTION = "IP geolocation by DB-IP (db-ip.com), CC BY 4.0"

HOSTING = re.compile(
    r"amazon|aws|google|microsoft|azure|digitalocean|digital ocean|ovh|hetzner|linode|akamai|vultr|choopa|"
    r"contabo|oracle|alibaba|aliyun|tencent|huawei cloud|huaweicloud|scaleway|online s\.a\.s|ionos|leaseweb|"
    r"m247|datacamp|cdn77|g-core|gcore|psychz|colocrossing|hostinger|hostwinds|ucloud|kaopu|cloudflare|"
    r"fastly|servers\.com|unmanaged|hosting|host|cloud|data ?cent|datacenter|server|vps|dedicated|colo",
    re.I)

_lock = threading.Lock()
_readers = {}
_cache = {}
STATE = {"ready": False, "error": None, "version": None, "downloading": False}


def _months_to_try():
    d = date.today()
    prev = date(d.year - 1, 12, 1) if d.month == 1 else date(d.year, d.month - 1, 1)
    return [d.strftime("%Y-%m"), prev.strftime("%Y-%m")]


def _path(kind):
    return os.path.join(GEO_DIR, f"dbip-{kind}-lite.mmdb")


def _fresh(path):
    return os.path.exists(path) and (time.time() - os.path.getmtime(path)) < MAX_AGE_DAYS * 86400


def _download(kind):
    os.makedirs(GEO_DIR, exist_ok=True)
    last_err = None
    for ym in _months_to_try():
        url = URL.format(kind=kind, ym=ym)
        tmp_gz, tmp_db = _path(kind) + ".gz.part", _path(kind) + ".part"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "honeypot-dashboard/1.0"})
            with urllib.request.urlopen(req, timeout=120) as r, open(tmp_gz, "wb") as f:
                shutil.copyfileobj(r, f, 1 << 20)
            with gzip.open(tmp_gz, "rb") as src, open(tmp_db, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
            if maxminddb:
                maxminddb.open_database(tmp_db).close()  # validate before swapping in
            os.replace(tmp_db, _path(kind))
            return ym
        except Exception as e:
            last_err = e
        finally:
            for p in (tmp_gz, tmp_db):
                if os.path.exists(p):
                    os.remove(p)
    raise RuntimeError(f"download of {kind} database failed: {last_err}")


def _open():
    global _readers
    new = {}
    for kind in ("city", "asn"):
        if os.path.exists(_path(kind)):
            new[kind] = maxminddb.open_database(_path(kind))
    with _lock:
        old, _readers = _readers, new
        _cache.clear()
    for r in old.values():
        r.close()
    STATE["ready"] = "city" in new
    meta = os.path.join(GEO_DIR, "version.json")
    if os.path.exists(meta):
        with open(meta, encoding="utf-8") as f:
            STATE["version"] = json.load(f).get("version")


def ensure(on_ready=None):
    """Open the databases; download or refresh them first if needed. Safe to run in a thread."""
    if maxminddb is None:
        STATE["error"] = "Python package 'maxminddb' is not installed (pip install maxminddb)"
        return
    try:
        if all(os.path.exists(_path(k)) for k in ("city", "asn")):
            _open()
            if on_ready:
                on_ready()
        if not all(_fresh(_path(k)) for k in ("city", "asn")):
            STATE["downloading"] = True
            versions = [_download(k) for k in ("city", "asn")]
            with open(os.path.join(GEO_DIR, "version.json"), "w", encoding="utf-8") as f:
                json.dump({"version": min(versions)}, f)
            _open()
            if on_ready:
                on_ready()
        STATE["error"] = None
    except Exception as e:
        STATE["error"] = f"{type(e).__name__}: {e}"[:300]
    finally:
        STATE["downloading"] = False


def _name(obj):
    if not isinstance(obj, dict):
        return ""
    names = obj.get("names") or {}
    return names.get("en") or next(iter(names.values()), "") if isinstance(names, dict) else ""


BASEMAP_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/land-110m.json"
COUNTRIES_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json"
MAP_W, MAP_H = 1000, 500
_basemap = {"path": None}
_borders = {"path": None}


def project(lon, lat):
    """Equirectangular projection into a MAP_W x MAP_H frame."""
    return (lon + 180) / 360 * MAP_W, (90 - lat) / 180 * MAP_H


def basemap_path():
    """SVG path of the world's land (Natural Earth 1:110m, public domain), built once and cached."""
    if _basemap["path"] is not None:
        return _basemap["path"]
    src = os.path.join(GEO_DIR, "land-110m.json")
    try:
        if not os.path.exists(src):
            os.makedirs(GEO_DIR, exist_ok=True)
            req = urllib.request.Request(BASEMAP_URL, headers={"User-Agent": "honeypot-dashboard/1.0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                raw = r.read(5 * 1024 * 1024)
            json.loads(raw)
            with open(src, "wb") as f:
                f.write(raw)
        with open(src, encoding="utf-8") as f:
            topo = json.load(f)
        (sx, sy), (tx, ty) = topo["transform"]["scale"], topo["transform"]["translate"]
        arcs = []
        for arc in topo["arcs"]:
            x = y = 0
            pts = []
            for dx, dy in arc:
                x += dx
                y += dy
                pts.append((x * sx + tx, y * sy + ty))
            arcs.append(pts)
        obj = topo["objects"]["land"]
        geoms = obj["geometries"] if obj["type"] == "GeometryCollection" else [obj]
        polygons = []
        for g in geoms:
            if g["type"] == "Polygon":
                polygons.append(g["arcs"])
            elif g["type"] == "MultiPolygon":
                polygons.extend(g["arcs"])
        parts = []
        for poly in polygons:
            for ring in poly:
                pts = []
                for i in ring:
                    seg = arcs[i] if i >= 0 else arcs[~i][::-1]
                    pts.extend(seg if not pts else seg[1:])
                if len(pts) < 3:
                    continue
                # Rings that cross the date line jump by ~360 degrees between neighbours, which
                # draws a band across the whole map. Unwrap them, then draw shifted copies too so
                # the part beyond +-180 shows up on the other side (the viewBox clips the rest).
                unwrapped, offset, prev = [], 0.0, None
                for lon, lat in pts:
                    if prev is not None:
                        d = lon - prev
                        if d > 180:
                            offset -= 360
                        elif d < -180:
                            offset += 360
                    prev = lon
                    unwrapped.append((lon + offset, lat))
                lons = [p[0] for p in unwrapped]
                if max(lons) - min(lons) > 350:
                    continue  # a ring around a pole (Antarctica); cropped out of the map anyway
                shifts = [0] + ([360] if min(lons) < -180 else []) + ([-360] if max(lons) > 180 else [])
                for sh in shifts:
                    xy = [project(lon + sh, lat) for lon, lat in unwrapped]
                    parts.append("M" + "L".join(f"{x:.1f},{y:.1f}" for x, y in xy) + "Z")
        _basemap["path"] = "".join(parts)
    except Exception as e:
        STATE["map_error"] = f"{type(e).__name__}: {e}"[:200]
        _basemap["path"] = ""
    return _basemap["path"]


def borders_path():
    """SVG path of the land borders between countries (Natural Earth 1:110m via world-atlas), built once.
    An arc that two countries share is a border; arcs used once are coastline and already drawn by the land."""
    if _borders["path"] is not None:
        return _borders["path"]
    src = os.path.join(GEO_DIR, "countries-110m.json")
    try:
        if not os.path.exists(src):
            os.makedirs(GEO_DIR, exist_ok=True)
            req = urllib.request.Request(COUNTRIES_URL, headers={"User-Agent": "honeypot-dashboard/1.0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                raw = r.read(5 * 1024 * 1024)
            json.loads(raw)
            with open(src, "wb") as f:
                f.write(raw)
        with open(src, encoding="utf-8") as f:
            topo = json.load(f)
        (sx, sy), (tx, ty) = topo["transform"]["scale"], topo["transform"]["translate"]
        uses = {}

        def walk(a, seen):
            if isinstance(a, int):
                seen.add(a if a >= 0 else ~a)
            else:
                for b in a:
                    walk(b, seen)

        for g in topo["objects"]["countries"]["geometries"]:
            seen = set()
            walk(g.get("arcs", []), seen)
            for i in seen:
                uses[i] = uses.get(i, 0) + 1
        parts = []
        for i, arc in enumerate(topo["arcs"]):
            if uses.get(i, 0) < 2:
                continue
            x = y = 0
            line, prev = [], None
            for dx, dy in arc:
                x += dx
                y += dy
                lon, lat = x * sx + tx, y * sy + ty
                if prev is not None and abs(lon - prev) > 180:   # date line: start a new piece
                    if len(line) > 1:
                        parts.append("M" + "L".join(f"{px:.1f},{py:.1f}" for px, py in line))
                    line = []
                prev = lon
                line.append(project(lon, lat))
            if len(line) > 1:
                parts.append("M" + "L".join(f"{px:.1f},{py:.1f}" for px, py in line))
        _borders["path"] = "".join(parts)
    except Exception as e:
        STATE["map_error"] = f"{type(e).__name__}: {e}"[:200]
        _borders["path"] = ""
    return _borders["path"]


def lookup(ip):
    """Return a small dict with location and network for an IP (empty values when unknown)."""
    with _lock:
        if ip in _cache:
            return _cache[ip]
        readers = dict(_readers)
    out = {"cc": "", "country": "", "city": "", "region": "", "lat": None, "lon": None,
           "asn": None, "org": "", "net": ""}
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return out
    if addr.is_private or addr.is_loopback or addr.is_reserved:
        out.update(country="Private network", net="private")
        return out
    try:
        c = readers.get("city") and readers["city"].get(ip)
        if c:
            out["cc"] = (c.get("country") or {}).get("iso_code", "") or ""
            out["country"] = _name(c.get("country"))
            out["city"] = _name(c.get("city"))
            subs = c.get("subdivisions") or []
            out["region"] = _name(subs[0]) if subs else ""
            loc = c.get("location") or {}
            out["lat"], out["lon"] = loc.get("latitude"), loc.get("longitude")
        a = readers.get("asn") and readers["asn"].get(ip)
        if a:
            out["asn"] = a.get("autonomous_system_number")
            out["org"] = a.get("autonomous_system_organization") or ""
    except Exception:
        pass
    if out["org"]:
        out["net"] = "hosting" if HOSTING.search(out["org"]) else "isp"
    with _lock:
        _cache[ip] = out
    return out
