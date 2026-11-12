"""Send new log events from the dashboard's copy of the logs to a SIEM or log platform.

Runs after each sync. Destinations: syslog (RFC 5424 over UDP, TCP or TLS), Elasticsearch/OpenSearch
(bulk API), Splunk (HTTP Event Collector), or any HTTP endpoint that takes NDJSON. Every event is
sent as one JSON document:

    {"@timestamp": "...Z", "sensor": "hotpot", "source": "cowrie", "cowrie": {<the original event>}}

The original sits under its source's name so fields of the same name from different sources never
clash in an index. Everything in it is attacker-controlled text; it is only ever JSON-encoded here.

Progress is kept per log file, keyed by a hash of the file's first line (every source puts a
timestamp or connection id in it, so no two logs share one). The key stays the same as the file grows,
and a log the VM renames when it rotates keeps its first line, so its copy is recognised and only lines
not yet sent go out: nothing is sent twice and nothing is skipped.
"""
import hashlib
import json
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

SOURCES = ("cowrie", "web", "decoys", "ids", "backend")
TYPES = ("syslog", "elasticsearch", "splunk", "http")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-.=:+/]{8,400}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$|^\[[0-9A-Fa-f:.]{2,45}\]$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-]{0,99}$")
MAX_LINE = 64 * 1024
BATCH_EVENTS = 500
BATCH_BYTES = 2 * 1024 * 1024
UDP_MAX = 60_000
TIMEOUT = 15
STATE_VERSION = 1
DEFAULTS = {"enabled": False, "type": "syslog", "address": "", "proto": "tcp", "index": "hotpot",
            "sensor": "hotpot", "ca_file": "", "sources": list(SOURCES)}


# ----------------------------------------------------------------------------- settings

def clean(req: dict, old: dict) -> dict:
    """Validated forwarding settings from a Settings request. The token: absent/None = keep, "" = remove."""
    cfg = {**DEFAULTS, **{k: v for k, v in old.items() if k in DEFAULTS or k == "token"}}
    if "enabled" in req:
        cfg["enabled"] = bool(req["enabled"])
    if "type" in req:
        if req["type"] not in TYPES:
            raise ValueError("unknown forwarding type")
        cfg["type"] = req["type"]
    if "proto" in req:
        if req["proto"] not in ("udp", "tcp", "tls"):
            raise ValueError("syslog protocol must be udp, tcp or tls")
        cfg["proto"] = req["proto"]
    if "address" in req:
        cfg["address"] = str(req["address"] or "").strip()[:500]
    for k in ("index", "sensor"):
        if k in req:
            v = str(req[k] or "").strip().lower() or DEFAULTS[k]
            if not NAME_RE.match(v):
                raise ValueError(f"{k} may only hold lower-case letters, digits, '.', '_' and '-'")
            cfg[k] = v
    if "ca_file" in req:
        v = os.path.expanduser(str(req["ca_file"] or "").strip())[:500]
        if v and not os.path.isfile(v):
            raise ValueError("the CA certificate file was not found on this computer")
        cfg["ca_file"] = v
    if "sources" in req:
        cfg["sources"] = [s for s in SOURCES if s in (req["sources"] or [])]
    if req.get("token") is not None:
        t = str(req["token"]).strip()
        if t and not TOKEN_RE.match(t):
            raise ValueError("the token has characters a token would not have")
        if t:
            cfg["token"] = t
        else:
            cfg.pop("token", None)
    if cfg["enabled"] or cfg["address"]:
        target(cfg)  # raises ValueError when the address does not fit the type
    return cfg


def view(cfg: dict) -> dict:
    """Settings for the browser: the token only as set / last four characters."""
    out = {k: cfg.get(k, v) for k, v in DEFAULTS.items()}
    t = cfg.get("token") or ""
    out["token"] = {"set": bool(t), "hint": ("…" + t[-4:]) if len(t) >= 8 else ""}
    return out


def target(cfg: dict):
    """(host, port) for syslog, or the full URL to POST to."""
    a = cfg.get("address", "")
    if cfg["type"] == "syslog":
        host, _, port = a.rpartition(":")
        if not host or not port.isdigit() or not 1 <= int(port) <= 65535 or not HOST_RE.match(host):
            raise ValueError("syslog address must be host:port, e.g. siem.example.lan:6514")
        return host.strip("[]"), int(port)
    u = urlparse(a)
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        raise ValueError("address must be an http:// or https:// URL without a user name in it")
    base = a.rstrip("/")
    if cfg["type"] == "elasticsearch":
        return base if base.endswith("/_bulk") else base + "/_bulk"
    if cfg["type"] == "splunk":
        return base if "/services/collector" in base else base + "/services/collector/event"
    return a


# ----------------------------------------------------------------------------- events

def event_time(obj: dict) -> float:
    """Seconds since the epoch from whichever time field a source uses; now if there is none."""
    for k in ("timestamp", "ts", "time", "t"):
        v = obj.get(k)
        if isinstance(v, (int, float)) and v > 0:
            return v / 1000 if v > 1e11 else float(v)
        if isinstance(v, str) and v:
            try:
                d = datetime.fromisoformat(v.replace("Z", "+00:00"))
                return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp()
            except ValueError:
                continue
    return time.time()


def document(source: str, obj: dict, sensor: str) -> dict:
    t = datetime.fromtimestamp(event_time(obj), timezone.utc)
    return {"@timestamp": t.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "sensor": sensor, "source": source, source: obj}


def dumps(doc) -> str:
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"))


# ----------------------------------------------------------------------------- senders

def _ssl(cfg):
    """Certificates are always checked: against the system's CAs, or the PEM file the operator chose
    for a destination with a private CA or a self-signed certificate."""
    return ssl.create_default_context(cafile=cfg.get("ca_file") or None)


def _post(cfg, url, body: bytes, headers: dict) -> bytes:
    req = urllib.request.Request(url, data=body, method="POST", headers={"User-Agent": "HotPot-forwarder", **headers})
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ssl(cfg) if url.startswith("https") else None) as r:
        return r.read(1024 * 1024)


def send(cfg: dict, docs: list) -> int:
    """Send documents in one go. Returns how many the destination rejected; raises when it can't be reached."""
    if not docs:
        return 0
    kind, token = cfg["type"], cfg.get("token") or ""
    if kind == "syslog":
        return _syslog(cfg, docs)
    if kind == "elasticsearch":
        op = dumps({"create": {"_index": cfg["index"]}})
        body = "".join(op + "\n" + dumps(d) + "\n" for d in docs).encode()
        h = {"Content-Type": "application/x-ndjson"}
        if token:
            h["Authorization"] = "ApiKey " + token
        r = json.loads(_post(cfg, target(cfg), body, h) or b"{}")
        if not r.get("errors"):
            return 0
        return sum(1 for it in r.get("items", ()) if (next(iter(it.values()), {}) or {}).get("error"))
    if kind == "splunk":
        body = "".join(dumps({"time": round(event_time(d[d["source"]]), 3), "host": d["sensor"],
                              "source": "hotpot", "sourcetype": "hotpot:" + d["source"],
                              **({"index": cfg["index"]} if cfg.get("index") not in ("", "hotpot") else {}),
                              "event": d}) for d in docs).encode()
        _post(cfg, target(cfg), body, {"Content-Type": "application/json", "Authorization": "Splunk " + token})
        return 0
    h = {"Content-Type": "application/x-ndjson"}
    if token:
        h["Authorization"] = "Bearer " + token
    _post(cfg, target(cfg), "".join(dumps(d) + "\n" for d in docs).encode(), h)
    return 0


def syslog_line(d: dict) -> bytes:
    """RFC 5424: <PRI>1 TIMESTAMP HOST APP - MSGID - MSG (facility local0, severity info)."""
    return f"<134>1 {d['@timestamp']} {d['sensor']} hotpot - {d['source']} - {dumps(d)}".encode()


def _syslog(cfg, docs) -> int:
    host, port = target(cfg)
    dropped = 0
    if cfg.get("proto") == "udp":
        fam = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
        with socket.socket(fam[0], socket.SOCK_DGRAM) as s:
            for d in docs:
                m = syslog_line(d)
                if len(m) > UDP_MAX:
                    dropped += 1
                    continue
                s.sendto(m, fam[4])
        return dropped
    with socket.create_connection((host, port), timeout=TIMEOUT) as raw:
        s = _ssl(cfg).wrap_socket(raw, server_hostname=host) if cfg.get("proto") == "tls" else raw
        try:
            # octet counting (RFC 6587): a length prefix, so a message may hold any byte
            s.sendall(b"".join(str(len(m)).encode() + b" " + m for m in map(syslog_line, docs)))
        finally:
            if s is not raw:
                s.close()
    return dropped


# ----------------------------------------------------------------------------- progress

def file_key(path: str):
    """Hash of the first complete line (at most 4 kB of it); None while there is no complete line."""
    with open(path, "rb") as f:
        head = f.read(4096)
    i = head.find(b"\n")
    if i < 0 and len(head) < 4096:
        return None
    return hashlib.sha256(head[:i + 1] if i >= 0 else head).hexdigest()[:20]


class Forwarder:
    """Sends what the mirror holds beyond the last sent offset of each log file."""

    def __init__(self, state_path: str):
        self.path = state_path
        # never run, or progress saved in another format: start from what is there now. Unknown keys would
        # otherwise read as "nothing sent yet" and the whole history would go out.
        self.state = None
        try:
            with open(state_path, encoding="utf-8") as f:
                saved = json.load(f)
            if isinstance(saved, dict) and saved.get("v") == STATE_VERSION and isinstance(saved.get("files"), dict):
                self.state = saved["files"]
        except (OSError, ValueError):
            pass
        self.status = {"sent": 0, "rejected": 0, "last_ok": None, "error": None, "pending": 0}
        self.restart_pending = False

    def restart(self):
        """Forget all progress: the next run starts from what the mirror holds then. (Only flagged here;
        a run may be going on in the sync thread.)"""
        self.restart_pending = True

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"v": STATE_VERSION, "files": self.state}, f)
        os.replace(tmp, self.path)

    def files(self, mirror: str, sources):
        """(source, path, key, size) of every mirrored log file of the chosen sources."""
        out = []
        for fn in sorted(os.listdir(mirror)) if os.path.isdir(mirror) else ():
            src = fn.split("__", 1)[0]
            p = os.path.join(mirror, fn)
            if src in sources and "__" in fn and os.path.isfile(p):
                try:
                    key = file_key(p)
                    if key:
                        out.append((src, p, key, os.path.getsize(p)))
                except OSError:
                    pass
        return out

    def start_from_now(self, mirror: str):
        self.state = {key: size for _src, _p, key, size in self.files(mirror, SOURCES)}
        self.save()

    def run(self, cfg: dict, mirror: str, own_ips=(), deadline: float = 30.0) -> dict:
        """Send new lines until done or `deadline` seconds have passed. Network errors stop the round;
        the same lines are tried again next time."""
        if self.state is None or self.restart_pending:
            self.restart_pending = False
            self.start_from_now(mirror)
        own = set(own_ips)
        stop = time.monotonic() + deadline
        sent = rejected = 0
        try:
            for src, path, key, size in self.files(mirror, set(cfg.get("sources") or SOURCES)):
                off = self.state.get(key, 0)
                if off > size:  # the copy was replaced by a shorter file with the same start: begin again
                    off = 0
                while off < size and time.monotonic() < stop:
                    docs, end = [], off
                    with open(path, "rb") as f:
                        f.seek(off)
                        chunk = f.read(BATCH_BYTES)
                    if b"\n" not in chunk:
                        if len(chunk) < BATCH_BYTES:
                            break  # a line still being written
                        off += len(chunk)  # one absurdly long line: skip it
                        self.state[key] = off
                        continue
                    nbytes = 0
                    for line in chunk[:chunk.rfind(b"\n") + 1].splitlines(keepends=True):
                        end += len(line)
                        if len(line) > MAX_LINE or not line.strip():
                            continue
                        try:
                            obj = json.loads(line)
                        except ValueError:
                            continue
                        if not isinstance(obj, dict) or any(isinstance(obj.get(k), str) and obj[k] in own
                                                            for k in ("src_ip", "ip")):
                            continue
                        docs.append(document(src, obj, cfg.get("sensor") or "hotpot"))
                        nbytes += len(line)
                        if len(docs) >= BATCH_EVENTS or nbytes >= BATCH_BYTES // 2:
                            break
                    rejected += send(cfg, docs)
                    sent += len(docs)
                    off = end
                    self.state[key] = off
                    self.save()
            live = {key for _s, _p, key, _z in self.files(mirror, SOURCES)}
            self.state = {k: v for k, v in self.state.items() if k in live}
            self.save()
            self.status.update(last_ok=int(time.time() * 1000), error=None)
        except (OSError, ValueError, urllib.error.URLError, ssl.SSLError) as e:
            self.status["error"] = f"{type(e).__name__}: {e}"[:300]
        self.status["sent"] += sent
        self.status["rejected"] += rejected
        self.status["pending"] = sum(max(0, size - self.state.get(key, 0))
                                     for _s, _p, key, size in self.files(mirror, set(cfg.get("sources") or SOURCES)))
        return {"sent": sent, "rejected": rejected}


def test_event(cfg: dict) -> dict:
    """Send one harmless event so the operator can check the destination; raises on failure."""
    cfg = {**DEFAULTS, **cfg}
    doc = document("hotpot", {"message": "HotPot forwarding test", "t": int(time.time() * 1000)},
                   cfg.get("sensor") or "hotpot")
    rejected = send(cfg, [doc])
    if rejected:
        raise ValueError("the destination rejected the test event")
    return {"ok": True}
