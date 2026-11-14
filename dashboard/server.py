#!/usr/bin/env python3
"""Local-only honeypot dashboard.

Runs on this PC, listens on 127.0.0.1 only, and pulls the honeypot's JSON logs over the
existing admin SSH connection. Nothing is opened on the honeypot for it.

Start:  python dashboard/server.py     then open http://127.0.0.1:8787

Security model:
  * binds to 127.0.0.1; rejects requests whose Host header is not 127.0.0.1/localhost
    (blocks DNS-rebinding from a web page you happen to have open)
  * everything in the logs is attacker-controlled text: the API returns it as JSON and
    the page inserts it with textContent only; a strict CSP forbids inline script
  * only JSON log files are copied; malware samples captured by Cowrie never leave the VM
  * file names and sizes coming back from the VM are validated before anything is written
"""
import base64
import codecs
import concurrent.futures
import hashlib
import hmac
import io
import itertools
import ipaddress
import json
import os
import re
import secrets
import shutil
import statistics
import struct
import subprocess
import sys
import threading
import time
import zipfile
import zlib
from collections import Counter, defaultdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlencode, urlparse

import abuse
import forward
import geo
import ioc

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import persona  # noqa: E402  (repo root: this install's identity)

IDENT = persona.load()
IDENT_PAIRS = persona.pairs(IDENT)


def ident(text: str) -> str:
    """A reference-persona string as this install has it."""
    return persona.substitute(text, IDENT, IDENT_PAIRS)

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
MIRROR = os.path.join(DATA, "mirror")
STATIC = os.path.join(BASE, "static")
CONFIG_PATH = os.path.join(BASE, "config.json")
STATE_PATH = os.path.join(DATA, "sync_state.json")
SETTINGS_PATH = os.path.join(DATA, "settings.json")
FORWARD_STATE = os.path.join(DATA, "forward_state.json")
ABUSE_STATE = os.path.join(DATA, "abuse_reports.json")
LOOKUPS_PATH = os.path.join(DATA, "lookups.json")

DEFAULT_CONFIG = {
    "ssh_host": "",
    "ssh_port": 22222,
    "ssh_user": "ubuntu",
    "ssh_key": "~/.ssh/honeypot_admin",
    "known_hosts": "~/.ssh/known_hosts_honeypot",
    "ssh_path": "",
    "own_ips": [],
    # optional real-shell backend (Cowrie proxy mode), reached through the front VM; "" disables it
    "backend_host": "",
    "backend_user": "ubuntu",
    "sync_seconds": 60,
    "port": 8787,
}

WEB_SESSION_GAP_MS = 30 * 60 * 1000
MAX_LINE = 64 * 1024
MAX_DECOMPRESSED = 64 * 1024 * 1024
SAFE_NAME = re.compile(r"^(web|cowrie|backend|decoys|ids)/[A-Za-z0-9._-]{1,80}$")

# Runs on the honeypot (as root, read-only). Sends back only the bytes we don't have yet.
REMOTE_SCRIPT = r'''
import base64, glob, hashlib, json, os, sys, zlib
state = json.loads(base64.urlsafe_b64decode(sys.argv[1]))
if sys.argv[2:] == ["backend"]:
    sources = {"backend": sorted(glob.glob("/var/lib/nb-export/backend.jsonl*"))}
else:
    sources = {
        "web": sorted(glob.glob("/var/lib/docker/volumes/honeypot_web-data/_data/web.jsonl*")),
        "cowrie": sorted(glob.glob("/var/lib/docker/volumes/honeypot_cowrie-var/_data/log/cowrie/cowrie.json*")),
        "decoys": sorted(glob.glob("/var/lib/docker/volumes/honeypot_decoy-data/_data/services.jsonl*")),
        "ids": sorted(glob.glob("/var/lib/docker/volumes/honeypot_ids-log/_data/eve*.json")),
    }
budget = 24 * 1024 * 1024
out = []
for kind, files in sources.items():
    for p in files:
        try:
            size = os.path.getsize(p)
            with open(p, "rb") as f:
                sig = hashlib.sha256(f.read(256)).hexdigest()[:16]
                name = kind + "/" + os.path.basename(p)
                st = state.get(name) or {}
                off = st.get("offset", 0)
                if st.get("sig") != sig or off > size:
                    off = 0
                f.seek(off)
                data = f.read(max(0, min(budget, 8 * 1024 * 1024)))
            data = data[:data.rfind(b"\n") + 1]
            budget -= len(data)
            out.append({"name": name, "sig": sig, "from": off, "to": off + len(data), "size": size,
                        "data": base64.b64encode(zlib.compress(data, 6)).decode()})
        except OSError:
            pass
sys.stdout.write(json.dumps(out))
'''

TOOL_UA = re.compile(r"zgrab|masscan|nmap|nuclei|curl|wget|python|go-http|httpx|okhttp|java/|libwww|scrapy|"
                     r"aiohttp|axios|node|censys|shodan|expanse|internet-measurement|bot|crawler|spider|scan|"
                     r"l9explore|palo ?alto|fasthttp|ruby|perl|php/", re.I)
AI_UA = re.compile(r"gptbot|chatgpt|oai-searchbot|claudebot|claude-user|claude-web|anthropic|perplexity|"
                   r"manus|devin|browser-use|langchain|llamaindex|autogpt|crewai|openai|google-extended|"
                   r"bytespider|mistralai|cohere-ai|claude-code|cursor|windsurf|copilot|gemini-cli|codex|"
                   r"goose|openhands|aider|smolagents|pydantic-ai|a2a[-/_]|modelcontextprotocol|mcp-remote|fastmcp",
                   re.I)
BROWSER_UA = re.compile(r"mozilla/5\.0.*(chrome|firefox|safari|edg)/", re.I)
HEADLESS = re.compile(r"headless|phantomjs|puppeteer|playwright|selenium", re.I)
DROPPER = re.compile(r"(wget|curl|tftp|ftpget)\b.*(;|&&|\|)|chmod \+x|/bin/busybox \w+;|cd /tmp.*(wget|curl)", re.I | re.S)
# Commands that keep the shell busy for a while: the pause after one is waiting, not deciding.
SLOW_CMD = re.compile(r"(^|[;&|]\s*|\bsudo\s+)(apt(-get)?|yum|dnf|apk|pip3?|npm|git|make|wget|curl|"
                      r"sleep|tar|unzip|docker|masscan|nmap|zmap|ping|dd|find)\b", re.I)
# A terminal's bracketed-paste markers around typed text: a person pasted it into an interactive client.
PASTE_MARK = re.compile(r"\x1b?\[20[01]~")
# Desktop SSH clients people type into (bots and agent frameworks use SSH libraries instead).
DESKTOP_SSH = re.compile(r"PuTTY|KiTTY|MobaXterm|Termius|SecureCRT|Xshell|Bitvise|SmarTTY|Tabby|WindTerm", re.I)
CANARY_CMD = re.compile(re.escape(IDENT["check"]) + r"|agent-verify", re.I)
# Well-known bot command lines. A match outranks the timing heuristic: proxy lag can make these look slow
# and "thoughtful", but their exact commands give them away. (name, pattern over all commands joined by \n)
KNOWN_BOTS = [
    ("SSH-key botnet (\"mdrfckr\")", re.compile(r"mdrfckr|chattr -ia \.ssh;\s*lockr -ia \.ssh", re.I)),
    ("Mirai busybox check", re.compile(r"/bin/busybox [A-Z]{5,12}\b")),
    ("Miner-competitor cleanup", re.compile(r"pkill -9 (xmrig|kinsing|kdevtmpfsi)|crontab -r;", re.I)),
    ("Redtail / multi-arch dropper", re.compile(r"redtail|\.(x86_64|arm7|mips|mpsl)\b[^\n]{0,300}\|\|", re.I)),
    ("Credential-reset script", re.compile(r"echo -e \"[^\"\n]{0,200}\\n[^\"\n]{0,200}\"\s{0,4}\|\s{0,4}passwd", re.I)),
    ("System survey one-liner", re.compile(r"cat /proc/cpuinfo \| grep name \| (wc -l|head -n 1)", re.I)),
]
MIRAI_WORDS = {"enable", "linuxshell", "system", "shell"}


def known_bot(inputs: list) -> str:
    # Commands are attacker-controlled: cap their size, and keep every pattern free of nested/unbounded
    # repetition so matching stays linear.
    inputs = [i[:2000] for i in inputs[:500]]
    if len(MIRAI_WORDS & {i.strip() for i in inputs}) >= 3:
        return "Mirai-style Telnet probe"
    joined = "\n".join(inputs)[:65536]
    return next((name for name, rx in KNOWN_BOTS if rx.search(joined)), "")

WEB_STAGES = ["Probed only", "Read a bait file", "Tried a login", "Logged in with the leaked password",
              "Explored the admin area", "Downloaded the database dump"]
SSH_STAGES = ["Connected only", "Guessed passwords", "Logged in", "Ran commands", "Transferred files"]
WEB_STAGE_OF = {"admin_login_fail": 2, "wp_login_fail": 2, "admin_login_ok": 3, "admin_dashboard": 4,
                "admin_backups": 4, "admin_users": 4, "admin_forbidden": 4, "admin_sql_dump": 5}
CLASSES = [("script", "Script / scanner"), ("known_bot", "Known bot (signature)"), ("agent_suspected", "AI agent (suspected)"),
           ("agent_confirmed", "AI agent (followed canary)"), ("human_like", "Human-like"),
           ("unknown", "Not enough data")]

lock = threading.Lock()
sync_lock = threading.Lock()
MODEL = {"sessions": [], "by_id": {}, "built": 0, "lines": {"web": 0, "cowrie": 0, "decoys": 0}, "campaigns": {}}
STATUS = {"last_sync": None, "last_ok": None, "error": None, "running": False, "bytes": 0, "backend_error": None}
CSRF = secrets.token_urlsafe(24)


# ----------------------------------------------------------------------------- config / sync

def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, encoding="utf-8") as f:
            cfg.update(json.load(f))
    else:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    return cfg


CFG = load_config()


def find_ssh() -> str:
    for cand in (CFG.get("ssh_path"), shutil.which("ssh"), r"C:\Windows\System32\OpenSSH\ssh.exe",
                 r"C:\Program Files\Git\usr\bin\ssh.exe"):
        if cand and os.path.exists(cand):
            return cand
    raise RuntimeError("ssh client not found; set ssh_path in dashboard/config.json")


def load_state() -> dict:
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def mirror_path(name: str) -> str:
    return os.path.join(MIRROR, name.replace("/", "__"))


def ssh_base() -> list:
    return [find_ssh(), "-i", os.path.expanduser(CFG["ssh_key"]), "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15",
            "-o", "UserKnownHostsFile=" + os.path.expanduser(CFG["known_hosts"])]


def ssh_cmd(backend: bool, remote: str) -> list:
    """ssh argv that runs `remote` on the front VM, or on the backend VM through the front VM."""
    front = f"{CFG['ssh_user']}@{CFG['ssh_host']}"
    if backend:
        jump = ssh_base() + ["-p", str(int(CFG["ssh_port"])), "-W", "%h:%p", front]
        # ProxyCommand is re-parsed by ssh: backslashes would vanish, so use forward slashes on Windows
        jump_cmd = " ".join(f'"{a}"' if " " in a else a for a in (x.replace("\\", "/") for x in jump))
        return ssh_base() + ["-o", "ProxyCommand=" + jump_cmd,
                             f"{CFG.get('backend_user') or 'ubuntu'}@{CFG['backend_host']}", remote]
    return ssh_base() + ["-p", str(int(CFG["ssh_port"])), front, remote]


SHA_RE = re.compile(r"^[0-9a-f]{64}$")
SAMPLE_DIRS = {"backend": ("/var/lib/nb-quarantine/files", ".bin"),
               "front": ("/var/lib/docker/volumes/honeypot_cowrie-var/_data/lib/cowrie/downloads", "")}
MAX_SAMPLE_ZIP = 80 * 1024 * 1024


def fetch_sample_zip(sha: str, where: str) -> bytes:
    """One quarantined sample as a zip encrypted with the password "infected", built on the VM.
    The raw file never crosses the network or touches this machine's disk unencrypted."""
    if not SHA_RE.match(sha) or where not in SAMPLE_DIRS or (where == "backend" and not CFG.get("backend_host")):
        raise ValueError("bad sample reference")
    d, ext = SAMPLE_DIRS[where]
    remote = f"sudo sh -c 'cd {d} && test -f {sha}{ext} && zip -q -P infected - {sha}{ext}'"
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    r = run_tree(ssh_cmd(where == "backend", remote), capture_output=True, timeout=120, creationflags=flags)
    if r.returncode != 0 or not r.stdout.startswith(b"PK"):
        raise RuntimeError("sample not available on the VM " + r.stderr.decode("utf-8", "replace").strip()[-200:])
    if len(r.stdout) > MAX_SAMPLE_ZIP:
        raise RuntimeError("sample too large")
    return r.stdout


def remote_pull(arg: str, backend: bool) -> list:
    """Run REMOTE_SCRIPT as root on the front VM, or on the backend VM through the front VM."""
    cmd = ssh_cmd(backend, f"sudo python3 - {arg} backend" if backend else "sudo python3 - " + arg)
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    r = run_tree(cmd, input=REMOTE_SCRIPT.encode(), capture_output=True, timeout=180, creationflags=flags)
    if r.returncode != 0:
        raise RuntimeError(("backend " if backend else "") + "ssh failed: "
                           + r.stderr.decode("utf-8", "replace").strip()[-300:])
    return json.loads(r.stdout.decode("utf-8"))


# ----------------------------------------------------------------------------- settings

SECRET_KEYS = ("virustotal_api_key", "malwarebazaar_auth_key", "abuseipdb_api_key", "greynoise_api_key")
settings_lock = threading.Lock()


def load_settings() -> dict:
    try:
        with open(SETTINGS_PATH, encoding="utf-8") as f:
            v = json.load(f)
            return v if isinstance(v, dict) else {}
    except (OSError, ValueError):
        return {}


SETTINGS = load_settings()


def settings_view() -> dict:
    out = {}
    for k in SECRET_KEYS:
        v = SETTINGS.get(k) or ""
        out[k] = {"set": bool(v), "hint": ("…" + v[-4:]) if len(v) >= 8 else ""}
    out["auto_lookup"] = bool(SETTINGS.get("auto_lookup", False))
    out["auto_iprep"] = bool(SETTINGS.get("auto_iprep", False))
    out["sync_seconds"] = int(CFG.get("sync_seconds", 60))
    out["own_ips"] = list(CFG.get("own_ips", []))
    out["forward"] = forward.view(SETTINGS.get("forward") or {})
    out["forward_status"] = FORWARDER.status
    out["abuse_auto"] = bool(SETTINGS.get("abuse_auto", False))
    return out


# ----------------------------------------------------------------------------- about (Settings tab)

REPO = os.path.dirname(BASE)
# honeypot.conf keys shown read-only in Settings; nothing else from the file is ever sent to the page
CONF_SHOWN = ("FRONT_PUBLIC_IP", "FRONT_PRIVATE_IP", "ADMIN_SSH_PORT", "BACKEND_ENABLED", "BACKEND_IP", "CT_NAME",
              "CT_MEMORY", "CT_DISK_POOL_SIZE", "LLM_ENABLED", "LLM_MODELS", "LLM_DAILY_CAP", "LLM_PER_MINUTE",
              "DECOYS_ENABLED", "DECOY_SERVICES", "IDS_ENABLED", "LOG_KEEP_DAYS", "SAMPLE_KEEP_DAYS", "DISK_MAX_PERCENT")
CONF_DEFAULTS = {"LOG_KEEP_DAYS": "30", "SAMPLE_KEEP_DAYS": "90", "DISK_MAX_PERCENT": "85"}


def hotpot_conf() -> dict:
    path = os.environ.get("HONEYPOT_CONF") or os.path.join(REPO, "honeypot.conf")
    out = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                k, eq, v = line.strip().partition("=")
                if eq and k in CONF_SHOWN:
                    out[k] = v.strip()[:300]
    except OSError:
        return {}
    return out


def dir_size(path: str) -> tuple:
    n = total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
                n += 1
            except OSError:
                pass
    return n, total


def about_view() -> dict:
    conf = hotpot_conf()
    defaults = [k for k in CONF_DEFAULTS if k not in conf]
    if conf:
        conf = {**CONF_DEFAULTS, **conf}
    try:
        with open(os.path.join(REPO, "hotpot.py"), encoding="utf-8") as f:
            m = re.search(r'^VERSION = "([0-9][0-9A-Za-z.+-]*)"', f.read(), re.M)
        version = m.group(1) if m else "?"
    except OSError:
        version = "?"
    files, mirror_bytes = dir_size(MIRROR)
    _n, data_bytes = dir_size(DATA)
    with lock:
        n_sessions, built, lines = len(MODEL["sessions"]), MODEL["built"], dict(MODEL["lines"])
    return {
        "version": version, "python": sys.version.split()[0], "platform": sys.platform,
        "conf": conf, "conf_defaults": defaults,
        "identity": {"brand": IDENT["brand"], "industry": IDENT["industry"], "host": IDENT["host"],
                     "check": IDENT["check"], "ip": IDENT["ip"], "tokens": len(IDENT.get("tokens") or {}),
                     "creds": len(IDENT.get("creds") or []), "reference": persona.is_reference(IDENT)},
        "data": {"path": DATA, "bytes": data_bytes, "mirror_files": files, "mirror_bytes": mirror_bytes,
                 "sessions": n_sessions, "built": built, "lines": lines},
        "sync": {"last_ok": STATUS.get("last_ok"), "error": STATUS.get("error")},
    }


IP_RE = re.compile(r"^[0-9A-Fa-f:.]{2,45}$")
KEY_RE = re.compile(r"^[A-Za-z0-9_\-]{8,200}$")


def save_settings(req: dict) -> dict:
    """Secrets: absent or null = keep, "" = remove, otherwise replace. Only listed fields are accepted."""
    with settings_lock:
        for k in SECRET_KEYS:
            if k in req and req[k] is not None:
                v = str(req[k]).strip()
                if v and not KEY_RE.match(v):
                    raise ValueError(f"{k} does not look like an API key")
                if v:
                    SETTINGS[k] = v
                else:
                    SETTINGS.pop(k, None)
        for k in ("auto_lookup", "auto_iprep", "abuse_auto"):
            if k in req:
                SETTINGS[k] = bool(req[k])
        if isinstance(req.get("forward"), dict):
            old = SETTINGS.get("forward") or {}
            new = SETTINGS["forward"] = forward.clean(req["forward"], old)
            if new["enabled"] and (not old.get("enabled") or any(old.get(k) != new[k] for k in ("type", "address"))):
                FORWARDER.restart()  # switched on or pointed elsewhere: new events only, not the backlog
        if "sync_seconds" in req:
            CFG["sync_seconds"] = max(15, min(3600, int(req["sync_seconds"])))
        if "own_ips" in req:
            ips = [str(x).strip() for x in (req["own_ips"] or []) if str(x).strip()][:20]
            if any(not IP_RE.match(x) for x in ips):
                raise ValueError("own IPs must be plain IP addresses")
            CFG["own_ips"] = ips
        os.makedirs(DATA, exist_ok=True)
        tmp = SETTINGS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(SETTINGS, f, indent=2)
        os.replace(tmp, SETTINGS_PATH)
        try:
            os.chmod(SETTINGS_PATH, 0o600)
        except OSError:
            pass
        cfg = {}
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, encoding="utf-8") as f:
                cfg = json.load(f)
        cfg.update(sync_seconds=CFG["sync_seconds"], own_ips=CFG.get("own_ips", []))
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    return settings_view()


# ----------------------------------------------------------------------------- hash lookups

lookups_lock = threading.Lock()


def load_lookups() -> dict:
    try:
        with open(LOOKUPS_PATH, encoding="utf-8") as f:
            v = json.load(f)
            return v if isinstance(v, dict) else {}
    except (OSError, ValueError):
        return {}


LOOKUPS = load_lookups()


def _http_json(req: urllib.request.Request, timeout: int = 20) -> tuple:
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read(2_000_000))
    except urllib.error.HTTPError as e:
        return e.code, None


def lookup_hash(sha: str) -> dict:
    """Ask VirusTotal and MalwareBazaar what they know about a SHA-256. Only the hash leaves this PC."""
    if not SHA_RE.match(sha):
        raise ValueError("bad hash")
    out = {"t": int(time.time() * 1000)}
    vt_key, mb_key = SETTINGS.get("virustotal_api_key"), SETTINGS.get("malwarebazaar_auth_key")
    if not vt_key and not mb_key:
        raise ValueError("add a VirusTotal or MalwareBazaar key in Settings first")
    if vt_key:
        code, j = _http_json(urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha}",
                                                    headers={"x-apikey": vt_key, "Accept": "application/json"}))
        if code == 200 and j:
            a = j.get("data", {}).get("attributes", {})
            st = a.get("last_analysis_stats", {})
            label = (a.get("popular_threat_classification") or {}).get("suggested_threat_label", "")
            out["vt"] = {"found": True, "malicious": int(st.get("malicious", 0)),
                         "suspicious": int(st.get("suspicious", 0)),
                         "engines": int(sum(v for v in st.values() if isinstance(v, int))),
                         "label": s(label, 120), "first_seen": a.get("first_submission_date"),
                         "names": [s(n, 80) for n in (a.get("names") or [])[:3]]}
        elif code == 404:
            out["vt"] = {"found": False}
        else:
            out["vt"] = {"error": "rate limited, try again in a minute" if code == 429 else f"HTTP {code}"}
    if mb_key:
        req = urllib.request.Request("https://mb-api.abuse.ch/api/v1/", method="POST",
                                     data=urlencode({"query": "get_info", "hash": sha}).encode(),
                                     headers={"Auth-Key": mb_key})
        code, j = _http_json(req)
        if code == 200 and j and j.get("query_status") == "ok" and j.get("data"):
            d = j["data"][0]
            out["mb"] = {"found": True, "signature": s(d.get("signature"), 80), "tags": [s(t, 40) for t in (d.get("tags") or [])[:6]],
                         "first_seen": s(d.get("first_seen"), 30), "file_type": s(d.get("file_type"), 20)}
        elif code == 200 and j and j.get("query_status") in ("hash_not_found", "no_results"):
            out["mb"] = {"found": False}
        else:
            out["mb"] = {"error": f"HTTP {code}" if code != 200 else s((j or {}).get("query_status"), 60)}
    with lookups_lock:
        LOOKUPS[sha] = out
        tmp = LOOKUPS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(LOOKUPS, f)
        os.replace(tmp, LOOKUPS_PATH)
    return out


def all_sample_hashes() -> list:
    with lock:
        sessions = MODEL["sessions"]
        loose = MODEL.get("backend", {}).get("unattributed_files", [])
    shas = []
    for x in sessions:
        for e in x.get("_backend", ()):
            if e.get("sha256"):
                shas.append(e["sha256"])
        for e in x["_events"] if x["kind"] != "web" else ():
            if e.get("eventid") in ("cowrie.session.file_download", "cowrie.session.file_upload") and e.get("shasum"):
                shas.append(e["shasum"])
    shas += [e["sha256"] for e in loose if e.get("sha256")]
    return [h for h in dict.fromkeys(shas) if SHA_RE.match(str(h))]


def lookup_loop() -> None:
    """With "auto_lookup" on, check new sample hashes in the background (4 a minute: VirusTotal's free limit)."""
    while True:
        time.sleep(60)
        if not SETTINGS.get("auto_lookup"):
            continue
        todo = [h for h in all_sample_hashes() if h not in LOOKUPS][:4]
        for h in todo:
            try:
                lookup_hash(h)
            except Exception:
                break


# ----------------------------------------------------------------------------- shared json store

def _load_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            v = json.load(f)
            return v if isinstance(v, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_json(path: str, obj: dict, lk: threading.Lock) -> None:
    with lk:
        os.makedirs(DATA, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f)
        os.replace(tmp, path)


# ----------------------------------------------------------------------------- IP reputation

IPREP_PATH = os.path.join(DATA, "iprep.json")
IPREP_TTL_MS = 7 * 86400 * 1000
iprep_lock = threading.Lock()
IPREP = _load_json(IPREP_PATH)


class own_set:
    """Your own IPs from Settings, plus every private address (tests run from the VMs themselves)."""
    def __init__(self):
        self.ips = set(CFG.get("own_ips", []))

    def __contains__(self, ip):
        if ip in self.ips:
            return True
        try:
            return not ipaddress.ip_address(ip).is_global   # malformed/unknown IPs stay visible
        except ValueError:
            return False

    def __iter__(self):
        return iter(self.ips)


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def lookup_ip(ip: str) -> dict:
    """AbuseIPDB (with a key) and GreyNoise community (key optional). Only the attacker's IP leaves this PC."""
    ip = str(ip).strip()
    if not is_public_ip(ip) or ip in CFG.get("own_ips", []):
        raise ValueError("only public attacker IPs are looked up")
    out = {"t": int(time.time() * 1000)}
    ab_key, gn_key = SETTINGS.get("abuseipdb_api_key"), SETTINGS.get("greynoise_api_key")
    if ab_key:
        code, j = _http_json(urllib.request.Request(
            "https://api.abuseipdb.com/api/v2/check?" + urlencode({"ipAddress": ip, "maxAgeInDays": 90}),
            headers={"Key": ab_key, "Accept": "application/json"}))
        if code == 200 and j and isinstance(j.get("data"), dict):
            d = j["data"]
            out["abuse"] = {"score": int(d.get("abuseConfidenceScore") or 0), "reports": int(d.get("totalReports") or 0),
                            "reporters": int(d.get("numDistinctUsers") or 0), "last": s(d.get("lastReportedAt"), 30),
                            "usage": s(d.get("usageType"), 60), "isp": s(d.get("isp"), 80), "tor": bool(d.get("isTor"))}
        else:
            out["abuse"] = {"error": "rate limited" if code == 429 else "key rejected" if code in (401, 403) else f"HTTP {code}"}
    code, j = _http_json(urllib.request.Request(f"https://api.greynoise.io/v3/community/{ip}",
                                                headers={"Accept": "application/json", **({"key": gn_key} if gn_key else {})}))
    if code == 200 and j:
        out["gn"] = {"found": True, "noise": bool(j.get("noise")), "riot": bool(j.get("riot")),
                     "class": s(j.get("classification"), 20), "name": s(j.get("name"), 80), "last": s(j.get("last_seen"), 20)}
    elif code == 404:
        out["gn"] = {"found": False}
    else:
        out["gn"] = {"error": "rate limited (add a free GreyNoise key)" if code == 429 else f"HTTP {code}"}
    IPREP[ip] = out
    _save_json(IPREP_PATH, IPREP, iprep_lock)
    return out


def rep_summary(ip: str):
    r = IPREP.get(ip)
    if not r:
        return None
    a, g = r.get("abuse") or {}, r.get("gn") or {}
    return {"score": a.get("score"), "reports": a.get("reports"), "gn": g.get("class") or ("" if g.get("found") is not False else "unseen"),
            "riot": g.get("riot", False)}


def iprep_loop() -> None:
    """With "auto_iprep" on, look up one new attacker IP a minute, most interesting sessions first."""
    while True:
        time.sleep(60)
        if not SETTINGS.get("auto_iprep"):
            continue
        with lock:
            sessions = sorted(MODEL["sessions"], key=lambda x: -x["interest"])
        now = int(time.time() * 1000)
        own = own_set()
        for x in sessions:
            ip = x["ip"]
            if ip in own or not is_public_ip(ip):
                continue
            r = IPREP.get(ip)
            if r and now - r.get("t", 0) < IPREP_TTL_MS:
                continue
            try:
                lookup_ip(ip)
            except Exception:
                pass
            break


# ----------------------------------------------------------------------------- samples: inventory, YARA, upload

YARA_DIR = os.path.join(os.path.dirname(BASE), "yara")
SAMPLES_META_PATH = os.path.join(DATA, "samples_meta.json")
samples_lock = threading.Lock()
SAMPLES_META = _load_json(SAMPLES_META_PATH)
SAMPLES_META.setdefault("files", {})
SAMPLES_META.setdefault("scans", {})
SCAN = {"running": False}

# Runs on a VM as root: lists quarantined samples, types new ones with `file`, and scans them all with YARA.
SCAN_SCRIPT = r'''
import json, os, re, shutil, subprocess, sys, tempfile
d, ext, known = D["dir"], D["ext"], set(D["known"])
out = {"files": [], "magic": {}, "matches": {}, "error": "", "yara": bool(shutil.which("yara")), "rules": 0}
paths = {}
if os.path.isdir(d):
    for fn in sorted(os.listdir(d))[:20000]:
        sha = fn[:-len(ext)] if ext else fn
        p = os.path.join(d, fn)
        if (ext and not fn.endswith(ext)) or not re.fullmatch(r"[0-9a-f]{64}", sha) or os.path.islink(p) or not os.path.isfile(p):
            continue
        st = os.stat(p)
        out["files"].append({"sha": sha, "size": st.st_size, "mtime": int(st.st_mtime * 1000)})
        paths[p] = sha
    todo = [p for p, h in paths.items() if h not in known]
    for i in range(0, len(todo), 200):
        r = subprocess.run(["file", "-N", "-F", "\x01", "--"] + todo[i:i + 200], capture_output=True, timeout=120)
        for line in r.stdout.decode("utf-8", "replace").splitlines():
            p, _, m = line.partition("\x01")
            if p in paths:
                out["magic"][paths[p]] = m.strip()[:200]
    if out["yara"] and D["rules"].strip() and paths:
        td = tempfile.mkdtemp()
        try:
            rp = os.path.join(td, "rules.yar")
            with open(rp, "w") as f:
                f.write(D["rules"])
            r = subprocess.run(["yara", "-w", "-p", "2", rp, d], capture_output=True, timeout=900)
            for line in r.stdout.decode("utf-8", "replace").splitlines():
                rule, _, p = line.partition(" ")
                h = paths.get(p.strip())
                if h and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", rule):
                    out["matches"].setdefault(h, []).append(rule)
            if r.returncode:
                out["error"] = r.stderr.decode("utf-8", "replace")[-600:]
        finally:
            shutil.rmtree(td, ignore_errors=True)
print(json.dumps(out))
'''
RULE_RE = re.compile(r"^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)[^{]*\{(.*?)\n\s*condition\s*:", re.M | re.S)
DESC_RE = re.compile(r'description\s*=\s*"([^"]{1,300})"')
_rules_cache = {"key": None, "text": "", "desc": {}}


def yara_rules() -> tuple:
    """All .yar/.yara files under yara/, concatenated, plus each rule's description."""
    files = []
    for root, _, fs in os.walk(YARA_DIR):
        for f in fs:
            if f.lower().endswith((".yar", ".yara")):
                p = os.path.join(root, f)
                files.append((p, os.path.getmtime(p), os.path.getsize(p)))
    files.sort()
    key = tuple(files)
    if key != _rules_cache["key"]:
        text, desc = [], {}
        for p, _, size in files:
            if size > 20 * 1024 * 1024:
                continue
            with open(p, encoding="utf-8", errors="replace") as f:
                t = f.read()
            text.append(f"// ---- {os.path.relpath(p, YARA_DIR)}\n{t}\n")
            for m in RULE_RE.finditer(t):
                dm = DESC_RE.search(m.group(2))
                desc[m.group(1)] = dm.group(1) if dm else ""
        _rules_cache.update(key=key, text="".join(text), desc=desc)
    return _rules_cache["text"], _rules_cache["desc"]


def scan_vm(where: str) -> dict:
    d, ext = SAMPLE_DIRS[where]
    rules, desc = yara_rules()
    with samples_lock:
        known = [h for h, m in SAMPLES_META["files"].items() if m.get("magic") and where in m.get("where", [])]
    payload = json.dumps({"s": SCAN_SCRIPT, "dir": d, "ext": ext, "rules": rules, "known": known}).encode()
    remote = """sudo python3 -I -c 'import sys,json;d=json.load(sys.stdin);exec(d["s"],{"D":d})'"""
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    r = run_tree(ssh_cmd(where == "backend", remote), input=payload, capture_output=True, timeout=1200, creationflags=flags)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.decode("utf-8", "replace").strip()[-300:] or "ssh failed")
    res = json.loads(r.stdout.decode("utf-8"))
    now = int(time.time() * 1000)
    with samples_lock:
        files = SAMPLES_META["files"]
        # a full listing forgets files the VM no longer has; an empty one only counts without an error
        if isinstance(res.get("files"), list) and (res["files"] or not res.get("error")):
            now_there = {str(f.get("sha", "")) for f in res["files"]}
            for h, m in files.items():
                if where in (m.get("where") or []) and h not in now_there:
                    m["where"].remove(where)
        for f in res.get("files", []):
            h = str(f.get("sha", ""))
            if not SHA_RE.match(h):
                continue
            m = files.setdefault(h, {})
            m["size"] = int(f.get("size") or 0)
            m["mtime"] = min(int(f.get("mtime") or now), m.get("mtime") or now)
            if where not in m.setdefault("where", []):
                m["where"].append(where)
            if h in res.get("magic", {}):
                m["magic"] = s(res["magic"][h], 200)
            if res.get("yara") and not res.get("error"):
                m["yara"] = [s(x, 128) for x in dict.fromkeys(res.get("matches", {}).get(h, []))][:30]
                m["scanned"] = now
        SAMPLES_META["scans"][where] = {"t": now, "files": len(res.get("files", [])), "yara": bool(res.get("yara")),
                                        "rules": len(desc), "error": s(res.get("error"), 600)}
    _save_json(SAMPLES_META_PATH, SAMPLES_META, threading.Lock())
    return SAMPLES_META["scans"][where]


def scan_all() -> None:
    if SCAN["running"]:
        return
    SCAN["running"] = True
    try:
        for where in ["front"] + (["backend"] if CFG.get("backend_host") else []):
            try:
                scan_vm(where)
            except Exception as e:
                with samples_lock:
                    SAMPLES_META["scans"][where] = {**SAMPLES_META["scans"].get(where, {}), "t": int(time.time() * 1000),
                                                    "error": f"{type(e).__name__}: {e}"[:300]}
    finally:
        SCAN["running"] = False


def scan_loop() -> None:
    time.sleep(30)
    while True:
        scan_all()
        time.sleep(15 * 60)


UPLOAD_MAX = 32 * 1024 * 1024


def sample_bytes(sha: str, where: str) -> bytes:
    """The raw sample, unpacked in memory from the VM's encrypted zip. Used only to upload it."""
    z = fetch_sample_zip(sha, where)
    with zipfile.ZipFile(io.BytesIO(z)) as zf:
        info = zf.infolist()[0]
        if info.file_size > UPLOAD_MAX:
            raise RuntimeError("larger than 32 MB: upload it from an analysis machine instead")
        data = zf.read(info, pwd=b"infected")
    if hashlib.sha256(data).hexdigest() != sha:
        raise RuntimeError("the file on the VM does not match its hash")
    return data


def multipart(fields: dict, fname: str, data: bytes) -> tuple:
    b = "hp" + secrets.token_hex(16)
    parts = []
    for k, v in fields.items():
        parts.append(f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    parts.append(f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{fname}"\r\n'
                 "Content-Type: application/octet-stream\r\n\r\n".encode() + data + b"\r\n")
    parts.append(f"--{b}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={b}"


def submit_sample(sha: str, where: str, service: str) -> dict:
    """Upload the sample itself to VirusTotal or MalwareBazaar (shared with their users)."""
    if not SHA_RE.match(sha) or where not in SAMPLE_DIRS or service not in ("vt", "mb"):
        raise ValueError("bad request")
    key = SETTINGS.get("virustotal_api_key" if service == "vt" else "malwarebazaar_auth_key")
    if not key:
        raise ValueError(("VirusTotal" if service == "vt" else "MalwareBazaar") + " key missing: add it in Settings")
    data = sample_bytes(sha, where)
    if service == "vt":
        body, ctype = multipart({}, sha, data)
        req = urllib.request.Request("https://www.virustotal.com/api/v3/files", data=body, method="POST",
                                     headers={"x-apikey": key, "Content-Type": ctype, "Accept": "application/json"})
        code, j = _http_json(req, timeout=180)
        if code != 200:
            raise RuntimeError("VirusTotal: " + ("rate limited, try again in a minute" if code == 429 else f"HTTP {code}"))
        res = {"service": "vt", "link": f"https://www.virustotal.com/gui/file/{sha}",
               "note": "Uploaded. VirusTotal needs a few minutes to scan it; then use Check hash."}
    else:
        meta = json.dumps({"anonymous": 0, "delivery_method": "other", "tags": ["honeypot"]})
        body, ctype = multipart({"json_data": meta}, sha, data)
        req = urllib.request.Request("https://mb-api.abuse.ch/api/v1/", data=body, method="POST",
                                     headers={"Auth-Key": key, "Content-Type": ctype})
        code, j = _http_json(req, timeout=180)
        st = s((j or {}).get("query_status"), 60)
        if code != 200 or st not in ("inserted", "file_already_known"):
            raise RuntimeError("MalwareBazaar: " + (st or f"HTTP {code}"))
        res = {"service": "mb", "link": f"https://bazaar.abuse.ch/sample/{sha}/",
               "note": "MalwareBazaar already had it." if st == "file_already_known" else "Uploaded to MalwareBazaar."}
    with samples_lock:
        SAMPLES_META["files"].setdefault(sha, {}).setdefault("submitted", {})[service] = int(time.time() * 1000)
    _save_json(SAMPLES_META_PATH, SAMPLES_META, threading.Lock())
    return res


DROPPED_KEEP = 20000     # newest file_capped events kept in the model
DROPPED_PATHS = 300      # paths listed under "Versions not stored"
DROPPED_WHY = {"near_duplicate", "version_cap"}


def dropped_view(capped: list) -> dict:
    """Versions of changed files the backend collector did not store, grouped by path.

    Each `file_capped` event still carries the hash and size of the version it dropped, and the nightly
    or early reset harvests the file's final state, so nothing is lost without a trace."""
    groups = {}
    for e in capped:
        path, sha = s(e.get("path"), 300), s(e.get("sha256"), 64)
        if not path or not SHA_RE.match(sha):
            continue
        t = e["t"]
        g = groups.get(path)
        if not g:
            g = groups[path] = {"path": path, "count": 0, "why": {}, "first": t, "last": t, "sha": sha, "size": None}
        g["count"] += 1
        why = s(e.get("why"), 20)
        why = why if why in DROPPED_WHY else "other"
        g["why"][why] = g["why"].get(why, 0) + 1
        g["first"] = min(g["first"], t)
        if t >= g["last"]:
            g["last"], g["sha"] = t, sha
            g["size"] = e["size"] if isinstance(e.get("size"), int) else None
    rows = sorted(groups.values(), key=lambda g: -g["last"])
    return {"paths": rows[:DROPPED_PATHS], "path_count": len(rows), "total": sum(g["count"] for g in rows)}


def samples_view() -> dict:
    """Every captured sample with where it came from, what it is, and what others say about it."""
    with lock:
        sessions = MODEL["sessions"]
        loose = MODEL.get("backend", {}).get("unattributed_files", [])
        capped = MODEL.get("backend", {}).get("capped", [])
    own = own_set()
    out = {}

    def add(sha, where, t, name, x, how, magic="", size=None):
        sha = s(sha, 64)
        if not SHA_RE.match(sha):
            return
        r = out.get(sha)
        if not r:
            r = out[sha] = {"sha": sha, "where": where, "first": t, "last": t, "names": [], "sessions": [],
                            "how": how, "magic": magic, "size": size}
        r["first"], r["last"] = min(r["first"] or t, t or r["first"]), max(r["last"] or 0, t or 0)
        name = s(name, 300)
        if name and name not in r["names"] and len(r["names"]) < 8:
            r["names"].append(name)
        if x and len(r["sessions"]) < 25 and all(v["id"] != x["id"] for v in r["sessions"]):
            r["sessions"].append({"id": x["id"], "ip": x["ip"], "kind": x["kind"], "own": x["ip"] in own})
        r["magic"] = r["magic"] or s(magic, 200)
        r["size"] = r["size"] or size

    for x in sessions:
        for e in x.get("_backend", ()):
            if e.get("type") == "file":
                add(e.get("sha256"), "backend", e.get("ctime") or e["t"], e.get("path"), x,
                    "running from memory" if e.get("src") == "memory" else "written to disk", e.get("magic"), e.get("size"))
            elif e.get("type") == "fetch" and e.get("sha256"):
                add(e.get("sha256"), "backend", e["t"], e.get("url"), x, "fetched from the attacker's link",
                    e.get("magic"), e.get("size"))
        if x["kind"] in ("ssh", "telnet"):
            for e in x["_events"]:
                if e.get("eventid") in ("cowrie.session.file_download", "cowrie.session.file_upload"):
                    add(e.get("shasum"), "front", e["t"], e.get("url") or e.get("filename"), x, "downloaded in the fake shell")
    for e in loose:
        add(e.get("sha256"), "backend", e.get("ctime") or e["t"], e.get("path"), None,
            "written by a process left running after logout",
            e.get("magic"), e.get("size"))
    with samples_lock:
        files = {h: dict(m) for h, m in SAMPLES_META["files"].items()}
        scans = dict(SAMPLES_META["scans"])
    for h, m in files.items():
        if h not in out and m.get("where"):
            add(h, m["where"][0], m.get("mtime") or 0, "", None, "on the VM, no matching session")
    _, desc = yara_rules()
    rows = []
    listed = {w for m in files.values() for w in (m.get("where") or ())}   # VMs whose quarantine was read
    for h, r in out.items():
        m = files.get(h, {})
        if not m.get("where") and r["where"] in listed:
            continue   # no longer on the VM (pruned or past SAMPLE_KEEP_DAYS); sessions still show the hash
        if m.get("where") and r["where"] not in m["where"]:
            r["where"] = m["where"][0]
        r["size"] = m.get("size") or r["size"]
        r["magic"] = m.get("magic") or r["magic"]
        r["yara"] = [{"rule": y, "desc": desc.get(y, "")} for y in m.get("yara", [])]
        r["scanned"] = m.get("scanned")
        r["present"] = bool(m.get("where"))
        r["submitted"] = m.get("submitted", {})
        r["lookup"] = LOOKUPS.get(h)
        r["own_only"] = bool(r["sessions"]) and all(v["own"] for v in r["sessions"])
        rows.append(r)
    rows.sort(key=lambda r: -(r["last"] or 0))
    return {"samples": rows, "scans": scans, "scanning": SCAN["running"], "rules": len(desc),
            "rules_dir": YARA_DIR, "dropped": dropped_view(capped)}


# ----------------------------------------------------------------------------- AI-written web pages

# The web honeypot asks an LLM for a page when a path has no scripted answer, and keeps each page in
# llm_cache in its SQLite file, so the next visitor gets the same one. Runs as root, read-only.
LLM_PAGES_SCRIPT = r'''
import json, sqlite3, sys
out = {"pages": [], "usage": []}
try:
    c = sqlite3.connect("file:/var/lib/docker/volumes/honeypot_web-data/_data/state.sqlite?mode=ro", uri=True)
    out["pages"] = c.execute("SELECT key, status, ctype, model, created, length(body), substr(body, 1, 16384) "
                             "FROM llm_cache ORDER BY created DESC LIMIT 2000").fetchall()
    out["usage"] = c.execute("SELECT day, count FROM llm_usage ORDER BY day DESC LIMIT 14").fetchall()
except sqlite3.Error as e:
    out["error"] = str(e)[:300]
sys.stdout.write(json.dumps(out))
'''
LLM_PAGES_TTL = 300
LLM_SERVED = ("llm_cached", "llm_new")                 # handlers that answered with a cached or new page
LLM_ASKED = ("llm_new", "llm_notfound", "notfound_llm_queued")   # requests that made the model write one
LLM_PAGES = {"t": 0, "pages": [], "usage": [], "error": ""}
llm_pages_lock = threading.Lock()


def note_llm_hits(x: dict, evs: list, acc: dict) -> None:
    """Count, per cached page, the requests answered from it and the request that made it written."""
    for e in evs:
        h = e.get("handler")
        if h not in LLM_SERVED and h not in LLM_ASKED:
            continue
        key = f"{s(e.get('method'), 16)} {s(e.get('path'), 400)}"
        a = acc.get(key)
        if a is None:
            if len(acc) >= 20000:
                continue
            a = acc[key] = {"n": 0, "last": 0, "ips": set(), "sessions": [], "asked": None}
        if h in LLM_ASKED and a["asked"] is None:
            a["asked"] = {"t": e["t"], "ip": x["ip"], "id": x["id"]}
        if h in LLM_SERVED:
            a["n"] += 1
            a["last"] = max(a["last"], e["t"])
            if len(a["ips"]) < 1000:
                a["ips"].add(x["ip"])
            if x["id"] not in a["sessions"]:
                a["sessions"].append(x["id"])
                del a["sessions"][:-20]


def fetch_llm_pages(force: bool) -> None:
    with llm_pages_lock:
        if not force and time.time() - LLM_PAGES["t"] < LLM_PAGES_TTL:
            return
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            r = run_tree(ssh_cmd(False, "sudo python3 -I -"), input=LLM_PAGES_SCRIPT.encode(),
                         capture_output=True, timeout=120, creationflags=flags)
            if r.returncode != 0:
                raise RuntimeError(r.stderr.decode("utf-8", "replace").strip()[-300:] or "ssh failed")
            res = json.loads(r.stdout.decode("utf-8"))
            LLM_PAGES.update(t=time.time(), pages=res.get("pages") or [], usage=res.get("usage") or [],
                             error=s(res.get("error"), 300))
        except Exception as e:   # keep the last good copy
            LLM_PAGES.update(t=time.time(), error=f"{type(e).__name__}: {e}"[:300])


def llm_pages_view(force: bool, include_own: bool) -> dict:
    fetch_llm_pages(force)
    with lock:
        hits = MODEL.get("llm_hits", {})
    own = set() if include_own else own_set()
    rows = []
    for p in LLM_PAGES["pages"]:
        if not isinstance(p, list) or len(p) != 7:
            continue
        key, status, ctype, model, created, size, body = p
        key = s(key, 420)
        method, _, path = key.partition(" ")
        h = hits.get(key) or {}
        ips = [ip for ip in h.get("ips", ()) if ip not in own]
        asked = h.get("asked")
        rows.append({"method": s(method, 16), "path": s(path, 400), "status": int(status or 0),
                     "ctype": s(ctype, 80), "model": s(model, 100), "created": iso_ms(created),
                     "size": int(size or 0), "body": s(body, 16384),
                     "served": h.get("n", 0) if ips or not h.get("ips") else 0, "visitors": len(ips),
                     "last": h.get("last", 0), "sessions": h.get("sessions", [])[-5:] if ips else [],
                     "asked": asked if asked and asked["ip"] not in own else None})
    return {"pages": rows, "usage": [[s(d, 10), int(n or 0)] for d, n in LLM_PAGES["usage"]
                                     if isinstance(n, int)],
            "fetched": int(LLM_PAGES["t"] * 1000), "error": LLM_PAGES["error"]}


# ----------------------------------------------------------------------------- session replay (Cowrie ttylogs)

TTY_CACHE = os.path.join(DATA, "tty")
COWRIE_TTY = "/var/lib/docker/volumes/honeypot_cowrie-var/_data/lib/cowrie/tty"
TTY_MAX = 16 * 1024 * 1024
TTY_REC = struct.Struct("<iLiiLL")  # op, tty, length, direction, sec, usec (cowrie/core/ttylog.py)


def fetch_tty(sha: str) -> bytes:
    if not SHA_RE.match(sha):
        raise ValueError("bad ttylog name")
    p = os.path.join(TTY_CACHE, sha)
    if os.path.exists(p):
        with open(p, "rb") as f:
            return f.read()
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    r = run_tree(ssh_cmd(False, f"sudo head -c {TTY_MAX} {COWRIE_TTY}/{sha}"), capture_output=True,
                       timeout=120, creationflags=flags)
    if r.returncode != 0:
        raise RuntimeError("recording not available on the VM")
    os.makedirs(TTY_CACHE, exist_ok=True)
    with open(p + ".tmp", "wb") as f:
        f.write(r.stdout)
    os.replace(p + ".tmp", p)
    return r.stdout


def parse_tty(b: bytes):
    i = 0
    while i + TTY_REC.size <= len(b):
        op, _, ln, d, sec, usec = TTY_REC.unpack_from(b, i)
        i += TTY_REC.size
        if ln < 0 or i + ln > len(b):
            break
        yield op, d, sec * 1000 + usec / 1000, b[i:i + ln]
        i += ln


def replay_view(sid: str):
    with lock:
        x = MODEL["by_id"].get(sid)
    if not x or x["kind"] not in ("ssh", "telnet"):
        return None
    evs = x["_events"]
    size = next((e for e in evs if e.get("eventid") == "cowrie.client.size"), {})
    cols = max(40, min(250, int(size.get("width") or 80)))
    rows = max(10, min(80, int(size.get("height") or 24)))
    frames, err, skipped = [], "", 0
    # Recordings flagged "duplicate" were named by an input hash an earlier session already used, so the
    # file on disk is that other session's screen (see _patch_ttylog). Skip them, and any file whose clock
    # doesn't fall inside this session.
    lo, hi = x["start"] - 120_000, x["end"] + 120_000
    logs = []
    for e in evs:
        if e.get("eventid") == "cowrie.log.closed" and int(e.get("size") or 0) > 0:
            if e.get("duplicate"):
                skipped += 1
            else:
                logs.append(os.path.basename(s(e.get("ttylog"), 200)))
    for sha in dict.fromkeys(logs):
        try:
            dec = codecs.getincrementaldecoder("utf-8")("replace")
            got = [[t, dec.decode(data)] for op, d, t, data in parse_tty(fetch_tty(sha)) if op == 3 and d == 2 and data]
            if got and not (lo <= got[0][0] <= hi):
                skipped += 1
                continue
            frames += got
        except Exception as e:
            err = f"{type(e).__name__}: {e}"[:200]
    user = next((s(e.get("username"), 32) for e in evs if e.get("eventid") == "cowrie.login.success"), "root")
    prompt = f"{user}@{IDENT['host']}:~{'#' if user == 'root' else '$'} "
    shown = "".join(f[1] for f in frames)
    added = 0
    for e in evs:
        if e.get("eventid") != "cowrie.command.input":
            continue
        c = s(e.get("input"), 4000)
        if c and c not in shown:  # exec-channel commands are never echoed: show what was run
            frames.append([e["t"], f"\r\n\x1b[1m{prompt}{c}\x1b[0m\r\n"])
            added += 1
    synthetic = bool(frames) and added == len(frames)
    if not frames:
        return {"frames": [], "error": err or "Nothing was typed in this session."}
    frames.sort(key=lambda f: f[0])
    t0, merged, total = frames[0][0], [], 0
    for t, text in frames:
        if merged and t - t0 - merged[-1][0] < 15:
            merged[-1][1] += text
        else:
            merged.append([int(t - t0), text])
        total += len(text)
        if total > 3_000_000:
            break
    return {"frames": merged, "cols": cols, "rows": rows, "synthetic": synthetic, "error": err,
            "skipped": skipped, "injected": added, "duration": merged[-1][0] if merged else 0}


# ----------------------------------------------------------------------------- VM status

STATUS_SCRIPT = r"""
import glob, json, os, subprocess, sys, time
role = sys.argv[1]
def sh(*a):
    try:
        return subprocess.run(a, capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception:
        return ""
def mtime(p):
    try: return int(os.path.getmtime(p) * 1000)
    except OSError: return None
def size(paths):
    t = 0
    for p in paths:
        try: t += os.path.getsize(p)
        except OSError: pass
    return t
mem = {}
for l in open("/proc/meminfo"):
    k, v = l.split(":", 1); mem[k] = int(v.split()[0]) * 1024
st = os.statvfs("/")
out = {"role": role, "hostname": os.uname().nodename, "kernel": os.uname().release,
       "uptime_s": int(float(open("/proc/uptime").read().split()[0])), "load": os.getloadavg(),
       "cpus": os.cpu_count(), "mem_total": mem["MemTotal"], "mem_avail": mem["MemAvailable"],
       "swap_total": mem.get("SwapTotal", 0), "swap_free": mem.get("SwapFree", 0),
       "disk_total": st.f_blocks * st.f_frsize, "disk_free": st.f_bavail * st.f_frsize, "now": int(time.time() * 1000),
       "services": []}
def svc(name, unit):
    out["services"].append({"name": name, "state": sh("systemctl", "is-active", unit) or "unknown"})
if role == "front":
    svc("Docker", "docker")
    svc("Admin SSH", "ssh")
    svc("Clean-up timer", "hotpot-retention.timer")
    for l in sh("docker", "ps", "-a", "--format", "{{json .}}").splitlines():
        try: c = json.loads(l)
        except ValueError: continue
        out["services"].append({"name": "container " + c.get("Names", "?"), "state": c.get("State", "?"),
                                "detail": c.get("Status", "")})
    v = "/var/lib/docker/volumes"
    out["data"] = {"cowrie_log": mtime(v + "/honeypot_cowrie-var/_data/log/cowrie/cowrie.json"),
                   "decoy_log": mtime(v + "/honeypot_decoy-data/_data/services.jsonl"),
                   "web_log": mtime(v + "/honeypot_web-data/_data/web.jsonl"),
                   "ids_log": mtime(v + "/honeypot_ids-log/_data/eve.json"),
                   "ids_rules": mtime(v + "/honeypot_ids-lib/_data/rules/suricata.rules"),
                   "log_bytes": size(glob.glob(v + "/honeypot_cowrie-var/_data/log/cowrie/cowrie.json*")
                                     + glob.glob(v + "/honeypot_web-data/_data/web.jsonl*")),
                   "cowrie_samples": len(glob.glob(v + "/honeypot_cowrie-var/_data/lib/cowrie/downloads/*"))}
else:
    for name, unit in (("Incus", "incus"), ("Audit log", "auditd"), ("Collector timer", "nb-collect.timer"),
                       ("Nightly reset timer", "nb-reset.timer"), ("Clean-up timer", "hotpot-retention.timer"),
                       ("Admin SSH", "ssh")):
        svc(name, unit)
    ct = {}
    try:
        conf = dict(l.strip().split("=", 1) for l in open("/etc/nb-honeypot.conf") if "=" in l and not l.startswith("#"))
        name = conf.get("CT_NAME", "fileserver01")
        j = json.loads(sh("incus", "query", f"/1.0/instances/{name}/state") or "{}")
        ct = {"name": name, "status": j.get("status", "?"), "processes": j.get("processes"),
              "mem": (j.get("memory") or {}).get("usage"), "cpu_ns": (j.get("cpu") or {}).get("usage")}
        snaps = json.loads(sh("incus", "query", f"/1.0/instances/{name}/snapshots?recursion=1") or "[]")
        ct["clean_snapshot"] = next((x.get("created_at") for x in snaps if x.get("name") == "clean"), None)
    except Exception as e:
        ct = {"error": str(e)[:200]}
    out["container"] = ct
    q = glob.glob("/var/lib/nb-quarantine/files/*.bin")
    out["data"] = {"collector_run": mtime("/var/lib/nb-quarantine/collect-state.json"),
                   "last_reset": mtime("/var/lib/nb-harvest/.last-reset"),
                   "samples": len(q), "sample_bytes": size(q),
                   "export_bytes": size(glob.glob("/var/lib/nb-export/backend.jsonl*")),
                   "audit_bytes": size(glob.glob("/var/log/audit/audit.log*")),
                   "harvests": len(glob.glob("/var/lib/nb-harvest/*.tgz"))}
print(json.dumps(out))
"""
VM_STATUS = {"t": 0, "data": None}
vm_status_lock = threading.Lock()


def run_tree(cmd, input=None, capture_output=True, timeout=None, creationflags=0):
    """subprocess.run for ssh. On timeout it kills the whole process tree: the backend jump runs a second
    ssh that keeps the output pipes open, and on Windows plain run() then waits for it forever (a frozen
    backend once left the Status tab and every later status request stuck)."""
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=creationflags,
                         start_new_session=os.name != "nt")
    try:
        out, err = p.communicate(input, timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            try:
                os.killpg(p.pid, 9)
            except OSError:
                pass
        p.kill()
        try:
            p.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass                                   # something still holds the pipes: give up on it
        raise
    return subprocess.CompletedProcess(cmd, p.returncode, out, err)


def _vm_probe(backend: bool) -> dict:
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    t0 = time.time()
    try:
        r = run_tree(ssh_cmd(backend, "sudo python3 - " + ("backend" if backend else "front")),
                           input=STATUS_SCRIPT.encode(), capture_output=True, timeout=60, creationflags=flags)
        if r.returncode != 0:
            return {"ok": False, "error": r.stderr.decode("utf-8", "replace").strip()[-300:] or "ssh failed"}
        d = json.loads(r.stdout.decode("utf-8"))
        d.update(ok=True, rtt_ms=int((time.time() - t0) * 1000))
        return d
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"[:300]}


def vm_status(force: bool = False) -> dict:
    with vm_status_lock:
        if not force and VM_STATUS["data"] and time.time() - VM_STATUS["t"] < 20:
            return VM_STATUS["data"]
        vms = [("front", "Front VM (gateway)", CFG["ssh_host"], False)]
        if CFG.get("backend_host"):
            vms.append(("backend", "Backend VM (real shell)", CFG["backend_host"], True))
        with concurrent.futures.ThreadPoolExecutor(2) as ex:
            res = list(ex.map(lambda v: _vm_probe(v[3]), vms))
        out = {"t": int(time.time() * 1000), "vms": []}
        for (key, label, addr, _), r in zip(vms, res):
            r.update(key=key, label=label, address=addr)
            out["vms"].append(r)
        with lock:
            lines = dict(MODEL["lines"])
        out["dashboard"] = {"sync": dict(STATUS), "lines": lines, "sync_seconds": CFG.get("sync_seconds", 60),
                            "lookups": len(LOOKUPS), "auto_lookup": bool(SETTINGS.get("auto_lookup")),
                            "iprep": len(IPREP), "auto_iprep": bool(SETTINGS.get("auto_iprep")),
                            "scans": dict(SAMPLES_META["scans"]), "rules": len(yara_rules()[1])}
        with lock:
            rs = list(MODEL.get("backend", {}).get("resets", []))
        week = [r for r in rs if r["t"] > out["t"] - 7 * 86400_000]
        out["dashboard"]["resets"] = {"week": len(week), "early": sum(r["reason"] == "persistence" for r in week),
                                      "last": rs[-1] if rs else None,
                                      "recent": [{"t": r["t"], "reason": r["reason"], "harvested": r.get("harvested"),
                                                  "paths": (r.get("paths") or [])[:3]} for r in rs[-8:][::-1]]}
        VM_STATUS.update(t=time.time(), data=out)
        return out


def sync_once() -> None:
    """Pull new log bytes from the honeypot over SSH and rebuild the in-memory model."""
    if not sync_lock.acquire(blocking=False):
        return
    STATUS["running"] = True
    try:
        os.makedirs(MIRROR, exist_ok=True)
        state = load_state()
        arg = base64.urlsafe_b64encode(json.dumps(
            {k: {"offset": v.get("offset", 0), "sig": v.get("sig")} for k, v in state.items()}).encode()).decode()
        items = remote_pull(arg, backend=False)
        if CFG.get("backend_host"):
            try:
                items += remote_pull(arg, backend=True)
                STATUS["backend_error"] = None
            except Exception as e:  # the front VM's data is still useful without the backend
                STATUS["backend_error"] = f"{type(e).__name__}: {e}"[:300]
        got = 0
        for it in items:
            name = str(it.get("name", ""))
            if not SAFE_NAME.match(name):
                continue
            start, end = int(it["from"]), int(it["to"])
            raw = zlib.decompressobj().decompress(base64.b64decode(it["data"]), MAX_DECOMPRESSED)
            if len(raw) != end - start:
                continue
            path = mirror_path(name)
            local = os.path.getsize(path) if os.path.exists(path) else 0
            if start != 0 and local != start:
                state.pop(name, None)  # out of step: refetch this file from the start next time
                continue
            with open(path, "wb" if start == 0 else "ab") as f:
                f.write(raw)
            state[name] = {"offset": end, "sig": str(it.get("sig", ""))[:32], "size": int(it.get("size", 0))}
            got += len(raw)
        tmp = STATE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f)
        os.replace(tmp, STATE_PATH)
        STATUS.update(last_ok=int(time.time() * 1000), error=None, bytes=got)
        if got or not MODEL["built"]:
            rebuild()
        run_forward()
    except Exception as e:  # shown in the UI; the sync loop keeps going
        STATUS["error"] = f"{type(e).__name__}: {e}"[:400]
        if not MODEL["built"]:
            rebuild()
    finally:
        STATUS["last_sync"] = int(time.time() * 1000)
        STATUS["running"] = False
        sync_lock.release()


FORWARDER = forward.Forwarder(FORWARD_STATE)


def run_forward() -> None:
    """Send what the last syncs brought to the SIEM, if forwarding is on (Settings). Its errors only
    show in Settings and Status; the sync itself has already succeeded."""
    fc = SETTINGS.get("forward") or {}
    STATUS["forward"] = FORWARDER.status if fc.get("enabled") else None
    if not fc.get("enabled"):
        return
    try:
        FORWARDER.run(fc, MIRROR, own_ips=CFG.get("own_ips", []), deadline=30)
    except Exception as e:  # never let a destination problem stop the sync loop
        FORWARDER.status["error"] = f"{type(e).__name__}: {e}"[:300]


REPORTER = abuse.Reporter(ABUSE_STATE)


def abuse_plan() -> list:
    """What a report run would send now (dashboard/abuse.py decides who qualifies)."""
    with lock:
        sessions = MODEL["sessions"]
    own = own_set()
    conf = hotpot_conf()
    own.ips.update(v for v in (CFG.get("ssh_host", ""), conf.get("FRONT_PUBLIC_IP", ""),
                               conf.get("FRONT_PRIVATE_IP", ""), conf.get("BACKEND_IP", "")) if v)
    # GreyNoise "benign" (research scanners) and RIOT (common services): never reported
    benign = {ip for ip, r in list(IPREP.items()) if (r.get("gn") or {}).get("riot")
              or (r.get("gn") or {}).get("class") == "benign"}
    return abuse.plan(sessions, own=own, reported=REPORTER.state["ips"], benign=benign)


def abuse_view() -> dict:
    items = abuse_plan()
    return {"key_set": bool(SETTINGS.get("abuseipdb_api_key")), "auto": bool(SETTINGS.get("abuse_auto")),
            "status": REPORTER.view(), "pending": len(items), "per_run": abuse.PER_RUN,
            "preview": [{"ip": r["ip"], "categories": [abuse.CATEGORY_NAMES.get(c, str(c)) for c in r["categories"]],
                         "comment": r["comment"], "last": r["last"], "sessions": r["sessions"]} for r in items[:40]]}


def run_abuse() -> None:
    try:
        REPORTER.run(SETTINGS.get("abuseipdb_api_key", ""), abuse_plan())
    except Exception as e:  # shown in Settings
        REPORTER.status["error"] = f"{type(e).__name__}: {e}"[:300]


def abuse_loop() -> None:
    """With "abuse_auto" on, report new attackers every 15 minutes (each IP at most once a day)."""
    while True:
        time.sleep(900)
        if SETTINGS.get("abuse_auto") and SETTINGS.get("abuseipdb_api_key") and MODEL["built"]:
            run_abuse()


def sync_loop() -> None:
    while True:
        sync_once()
        time.sleep(max(15, int(CFG.get("sync_seconds", 60))))  # changeable in Settings


# ----------------------------------------------------------------------------- parsing

def read_lines(prefix: str):
    if not os.path.isdir(MIRROR):
        return
    seen = set()
    for fn in sorted(os.listdir(MIRROR)):
        if not fn.startswith(prefix + "__"):
            continue
        with open(os.path.join(MIRROR, fn), "rb") as f:
            for line in f:
                if len(line) > MAX_LINE or not line.strip():
                    continue
                h = hashlib.blake2b(line, digest_size=10).digest()
                if h in seen:
                    continue
                seen.add(h)
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if isinstance(obj, dict):
                    yield obj


def iso_ms(s) -> int:
    try:
        return int(datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return 0


def s(v, n=500) -> str:
    return "" if v is None else str(v)[:n]


def gap_stats(ts):
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    if not gaps:
        return gaps, None, None
    med = statistics.median(gaps)
    mean = statistics.fmean(gaps)
    cv = statistics.pstdev(gaps) / mean if len(gaps) >= 2 and mean > 0 else None
    return gaps, med, cv


def fmt_size(n) -> str:
    n = float(n or 0)
    if n < 1024:
        return f"{int(n)} bytes"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1048576:.1f} MB"


def fmt_ms(ms) -> str:
    if ms is None:
        return "n/a"
    if ms < 1000:
        return f"{ms:.0f} ms"
    if ms < 60000:
        return f"{ms / 1000:.1f} s"
    return f"{ms / 60000:.1f} min"


def timing_verdict(n, med, cv, score, reasons):
    """Shared pace heuristic. Returns a class or None; may add to score/reasons."""
    if n < 3 or med is None:
        return None, score
    if med < 700:
        reasons.append(f"Machine speed: typical pause between actions is {fmt_ms(med)}")
        return "script", score
    if 1500 <= med <= 45000 and (cv is None or cv < 1.2):
        score += 2
        reasons.append(f"Steady 'thinking' pauses: typically {fmt_ms(med)} between actions, with little variation "
                       "(scripts are faster, people are more irregular)")
    return None, score


def make_web(ip: str, evs: list) -> dict:
    ts = [e["t"] for e in evs]
    gaps, med, cv = gap_stats(ts)
    handlers = [e.get("handler", "") for e in evs]
    stage = 0
    for h in handlers:
        stage = max(stage, WEB_STAGE_OF.get(h, 1 if h.startswith("bait_") else 0))
    uas = Counter(s(e.get("ua"), 300) for e in evs)
    ua = uas.most_common(1)[0][0] if uas else ""
    canary = [e for e in evs if e.get("canary_hit")]
    reasons, score, cls = [], 0, None

    if canary:
        c = canary[0]
        cls = "agent_confirmed"
        who = f" It named itself '{s(c.get('agent_model'), 80)}'." if c.get("agent_model") else ""
        task = f" Stated task: '{s(c.get('agent_task'), 160)}'." if c.get("agent_task") else ""
        reasons.append("Followed the hidden instruction planted for AI agents (requested the canary URL). "
                       "Scripts never read it." + who + task)
    if AI_UA.search(ua):
        score += 3
        reasons.append("User agent names an AI product")
    v, score = timing_verdict(len(evs), med, cv, score, reasons)
    if any(h == "admin_login_ok" for h in handlers):
        score += 2
        reasons.append("Logged in with the password that only appears inside the bait /.env file "
                       "(it read a response and used what it found)")
    if any(h in ("admin_backups", "admin_users", "admin_sql_dump", "api_user", "api_sqli_error") for h in handlers) \
            and any(h == "admin_dashboard" for h in handlers):
        score += 1
        reasons.append("Followed links that only exist on the admin dashboard page")
    sqli_queries = {e.get("query") for e in evs if e.get("sqli_like")}
    if len(sqli_queries) >= 3:
        score += 1
        reasons.append(f"Tried {len(sqli_queries)} different injection payloads (adapting to error messages)")

    if cls is None:
        if v == "script":
            cls = "script"
        elif score >= 3:
            cls = "agent_suspected"
        elif len(evs) < 3:
            cls = "script"
            reasons.append("One-shot probe: 1-2 requests and no follow-up")
        elif BROWSER_UA.search(ua) and not HEADLESS.search(ua) and not TOOL_UA.search(ua) \
                and med is not None and med > 2000 and (cv or 0) >= 1.2:
            cls = "human_like"
            reasons.append(f"Browser user agent with irregular pauses (typically {fmt_ms(med)})")
        elif TOOL_UA.search(ua) or not ua:
            cls = "script"
            reasons.append("User agent is a scanning tool or library" if ua else "No user agent sent")
        else:
            cls = "unknown"
            reasons.append("Pace and behaviour don't clearly match a script, an AI agent or a person")

    paths = []
    for e in evs:
        p = e.get("path", "")
        if p not in paths:
            paths.append(p)
    summary = " → ".join(x[:40] for x in paths[:4]) + (f"  (+{len(paths) - 4} more)" if len(paths) > 4 else "")
    logins = [e for e in evs if "login_user" in e]
    flags = []
    if canary:
        flags.append("canary")
    if any(e.get("sqli_like") for e in evs):
        flags.append("sql injection")
    if any(e.get("traversal_like") for e in evs):
        flags.append("traversal / RCE probe")
    if any(h in ("mcp", "ollama", "llm_proxy_models", "llm_proxy_chat") for h in handlers):
        flags.append("AI endpoints")
    if any(h.startswith("llm_") and h not in ("llm_proxy_models", "llm_proxy_chat") for h in handlers):
        flags.append("LLM-generated page")
    for flag, hs in AGENT_SURFACE_FLAGS.items():
        if any(h in hs for h in handlers):
            flags.append(flag)
    sid = "w-" + hashlib.sha1(f"{ip}|{ts[0]}".encode()).hexdigest()[:14]
    fps = Counter(e.get("_ja4h") for e in evs if e.get("_ja4h"))
    return {
        "id": sid, "kind": "web", "ip": ip, "start": ts[0], "end": ts[-1], "n": len(evs),
        "cls": cls, "reasons": reasons, "score": score, "stage": stage, "stage_label": WEB_STAGES[stage],
        "med_gap": med, "cv": cv, "summary": summary, "flags": flags, "client": ua,
        "fp": fps.most_common(1)[0][0] if fps else "",
        "logins": len(logins), "interest": stage * 3 + (20 if canary else 0) + score * 2 + min(len(evs), 20) / 4,
        "_events": evs, "_gaps": gaps,
    }


def make_cowrie(sid: str, evs: list) -> dict:
    evs.sort(key=lambda e: e["t"])
    first = evs[0]
    ip = next((s(e.get("src_ip"), 64) for e in evs if e.get("src_ip")), "?")
    proto = next((s(e.get("protocol"), 10) for e in evs if e.get("eventid") == "cowrie.session.connect"), "ssh")
    kind = "telnet" if proto == "telnet" else "ssh"
    logins = [e for e in evs if e.get("eventid") in ("cowrie.login.failed", "cowrie.login.success")]
    ok = [e for e in logins if e["eventid"] == "cowrie.login.success"]
    cmds = [e for e in evs if e.get("eventid") == "cowrie.command.input"]
    files = [e for e in evs if e.get("eventid") in ("cowrie.session.file_download", "cowrie.session.file_upload")]
    fwd = [e for e in evs if e.get("eventid") == "cowrie.direct-tcpip.request"]
    client = next((s(e.get("version"), 200) for e in evs if e.get("eventid") == "cowrie.client.version"), "")
    hassh = next((s(e.get("hassh"), 64) for e in evs if e.get("eventid") == "cowrie.client.kex"), "")
    stage = 4 if files else 3 if cmds else 2 if ok else 1 if logins else 0

    action_ts = ([ok[0]["t"]] if ok and cmds else []) + [e["t"] for e in cmds]
    gaps, med, cv = gap_stats(action_ts)
    inputs = [s(e.get("input"), 2000) for e in cmds]
    # the pace that counts as deciding: leave out the waits after slow commands (installs, downloads)
    acts = ([""] if ok and cmds else []) + inputs
    think = [g for g, a in zip(gaps, acts) if not SLOW_CMD.search(a)]
    _, think_med, think_cv = gap_stats(list(itertools.accumulate(think, initial=0)))   # linear: attackers set len
    pasted = any(PASTE_MARK.search(i) for i in inputs)
    desktop = bool(DESKTOP_SSH.search(client))
    reasons, score, cls = [], 0, None
    canary = [i for i in inputs if CANARY_CMD.search(i)]
    if canary:
        cls = "agent_confirmed"
        reasons.append("Ran the command that the login banner asks AI agents to run. Scripts never read the banner. "
                       f"It typed: {canary[0][:200]}")
    if pasted or desktop:
        # a person at a terminal: steady pauses are them reading and pasting, not a model deciding
        v = None
        reasons.append("Typed from " + ("a desktop SSH client (" + DESKTOP_SSH.search(client).group(0) + ")"
                                        if desktop else "an interactive terminal")
                       + (", pasting commands (the terminal marked them as pasted)" if pasted else ""))
    else:
        # with pauses left out, ask for 3 real ones (as many actions as pauses): 2 short gaps prove nothing
        v, score = timing_verdict(len(think) + (1 if len(think) == len(gaps) else 0), think_med, think_cv,
                                  score, reasons)
        if len(think) < len(gaps):
            reasons.append(f"Left out {len(gaps) - len(think)} pause(s) that followed slow commands "
                           "(installs, downloads): waiting, not deciding")
    dropper = any(DROPPER.search(i) for i in inputs)
    if len(set(inputs)) >= 4 and not dropper:
        score += 1
        reasons.append(f"Ran {len(set(inputs))} different exploratory commands instead of one fixed payload")
    if cls is None:
        if not cmds:
            cls = "script"
            reasons.append(f"Password guessing only ({len(logins)} attempts)" if logins
                           else "Connected and left without logging in (port scan or banner grab)")
        elif bot := known_bot(inputs):
            cls = "known_bot"
            reasons.append(f"Known bot signature: {bot}. Its exact command lines are seen from many IPs, "
                           "so the timing doesn't mean a person or an agent was deciding")
        elif v == "script":
            cls = "script"
        elif (pasted or desktop) and len(cmds) >= 2:
            cls = "human_like"
        elif score >= 3:
            cls = "agent_suspected"
        elif dropper:
            cls = "script"
            reasons.append("Known bot pattern: a single download-and-run command line")
        elif len(action_ts) >= 3 and med is not None and med > 2000 and (cv or 0) >= 1.2:
            cls = "human_like"
            reasons.append(f"Irregular pauses between commands (typically {fmt_ms(med)}), like someone typing")
        elif len(cmds) < 3:
            cls = "script"
            reasons.append("Ran 1-2 commands and left (typical of automated fingerprinting)")
        else:
            cls = "unknown"
            reasons.append("Pace and behaviour don't clearly match a script, an AI agent or a person")

    if cmds:
        summary = inputs[0][:90] + (f"  (+{len(cmds) - 1} more commands)" if len(cmds) > 1 else "")
    elif logins:
        ex = logins[-1]
        summary = f"{len(logins)} password guess(es), e.g. {s(ex.get('username'), 30)} / {s(ex.get('password'), 30)}"
    else:
        summary = "Connected only"
    flags = []
    if canary:
        flags.append("canary")
    if files:
        flags.append("file transfer")
    if fwd:
        flags.append("tunnel attempt")
    if ok:
        flags.append("logged in")
    return {
        "id": "c-" + re.sub(r"[^A-Za-z0-9]", "", sid)[:24], "kind": kind, "ip": ip,
        "start": first["t"], "end": evs[-1]["t"], "n": len(cmds) or len(logins) or 1,
        "cls": cls, "reasons": reasons, "score": score, "stage": stage, "stage_label": SSH_STAGES[stage],
        "med_gap": med, "cv": cv, "summary": summary, "flags": flags,
        "client": client, "fp": hassh,
        "logins": len(logins),
        "interest": stage * 3 + (20 if canary else 0) + score * 2 + min(len(cmds), 20) / 2 + len(files) * 3,
        "_events": evs, "_gaps": gaps,
        "_cmdseq": [c for i, c in enumerate(norm_cmd(x) for x in inputs) if c][:60],
    }


LIVE_KEEP = 400
REPLAY_HOURS = 24
REPLAY_KEEP = 80000         # events held for the map replay (the last REPLAY_HOURS)
REPLAY_SEND = 2500          # at most this many go to the browser; the rest are sampled evenly


def live_hits(web_events: list, by_sid: dict, decoys: list, keep: int = LIVE_KEEP) -> list:
    """The latest individual events (requests, connects, logins, commands) for the live ticker."""
    out = []
    for e in web_events[-keep:]:
        st = e.get("status")
        out.append({"t": e["t"], "ip": e["ip"], "kind": "web", "ok": isinstance(st, int) and st < 400,
                    "type": "canary" if e.get("canary_hit") else "request",
                    "what": f"{s(e.get('method'), 8)} {s(e.get('path'), 120)}".strip(), "status": st})
    for evs in by_sid.values():
        proto = next((s(e.get("protocol"), 10) for e in evs if e.get("eventid") == "cowrie.session.connect"), "ssh")
        for e in evs:
            ev, ip = e.get("eventid"), s(e.get("src_ip"), 64)
            if not ip or not e["t"]:
                continue
            if ev == "cowrie.session.connect":
                h = {"type": "connect", "what": "connected", "ok": True}
            elif ev in ("cowrie.login.success", "cowrie.login.failed"):
                ok = ev.endswith("success")
                h = {"type": "login", "ok": ok,
                     "what": f"login {s(e.get('username'), 40)} / {s(e.get('password'), 40)}"}
            elif ev == "cowrie.command.input":
                h = {"type": "command", "what": "$ " + s(e.get("input"), 120), "ok": True}
            elif ev in ("cowrie.session.file_download", "cowrie.session.file_upload"):
                h = {"type": "file", "what": "fetch " + s(e.get("url") or e.get("filename"), 120), "ok": True}
            else:
                continue
            h.update(t=e["t"], ip=ip, kind=proto)
            out.append(h)
    for x in decoys:
        for e in x["_events"][-50:]:
            a = e.get("_a")
            if a:
                out.append({"t": e["t"], "ip": x["ip"], "kind": x["kind"], "type": "command", "ok": True,
                            "what": a["title"][:120]})
    out.sort(key=lambda h: h["t"])
    return out[-keep:]


def hit_out(h: dict) -> dict:
    g = geo.lookup(h["ip"])
    x = y = None
    if g["lat"] is not None:
        x, y = (round(v, 1) for v in geo.project(g["lon"], g["lat"]))
    return {**h, "x": x, "y": y, "cc": g["cc"], "country": g["country"]}


def map_target():
    tg = geo.lookup(CFG["ssh_host"])
    return list(round(v, 1) for v in geo.project(tg["lon"], tg["lat"])) if tg["lat"] is not None else None


def map_replay_view(include_own: bool) -> dict:
    """The last REPLAY_HOURS of hits for the map replay. Shell commands, downloads, canary hits and
    accepted logins come first (up to 70 % of REPLAY_SEND); everything is sampled evenly over time."""
    with lock:
        hits = MODEL.get("hits", [])
    own = own_set()
    end = hits[-1]["t"] if hits else int(time.time() * 1000)
    start = end - REPLAY_HOURS * 3600_000
    sel = [h for h in hits if h["t"] >= start and (include_own or h["ip"] not in own)]
    key = [h for h in sel if h["type"] in ("command", "file", "canary") or (h["type"] == "login" and h["ok"])]
    rest = [h for h in sel if not (h["type"] in ("command", "file", "canary") or (h["type"] == "login" and h["ok"]))]
    def even(xs, n):
        return xs if len(xs) <= n else [xs[int(i * len(xs) / n)] for i in range(n)]

    key = even(key, max(REPLAY_SEND - len(rest), REPLAY_SEND * 7 // 10))   # the rest keeps 30 % or more
    out = sorted(key + even(rest, REPLAY_SEND - len(key)), key=lambda h: h["t"])
    return {"hits": [hit_out(h) for h in out], "total": len(sel), "from": start, "to": end,
            "target": map_target()}


def live_view(since: int, include_own: bool) -> dict:
    with lock:
        hits = MODEL.get("hits", [])
    own = own_set()
    sel = [h for h in hits if h["t"] > since and (include_own or h["ip"] not in own)][-60:]
    newest = hits[-1]["t"] if hits else 0
    return {"hits": [hit_out(h) for h in sel], "newest": newest, "now": int(time.time() * 1000),
            "target": map_target()}


LOGIN_NOISE = re.compile(r"update-motd|landscape-sysinfo|/etc/update-motd\.d|motd-news|50-landscape|"
                         r"release-upgrade|update-notifier|apt-check|command-not-found")


LOCAL_DST = ("127.0.0.53:", "10.200.0.1:53", "0.0.0.0:", "[::]:", "[0000:0000:0000:0000:0000:0000:0000:0000]:")


def local_dst(d: str) -> bool:
    """DNS to the local resolver, sshd's own sockets, and glibc's port-0 address-selection probes."""
    return d.startswith(LOCAL_DST) or d.endswith(":0")


# same list as nb-collect.py's PERSIST_RE: files that give an attacker a way back in
PERSIST_PATH_RE = re.compile(r"^/(root|home/[^/]+)/(\.ssh/authorized_keys2?|\.bashrc|\.profile|\.bash_profile)$"
                        r"|^/etc/(cron\.[^/]+/.+|crontab|rc\.local|ld\.so\.preload|passwd|shadow|sudoers(\.d/.+)?"
                        r"|profile\.d/.+|init\.d/.+|systemd/system/.+|update-motd\.d/.+)$"
                        r"|^/var/spool/cron/.+|^/(usr/)?lib/systemd/system/.+")


def attach_backend(sessions: list) -> dict:
    """Attach the real-shell backend's exec/connect/file/fetch events to the Cowrie sessions they belong to.

    Each backend event names its login root ("pid:t" of the `sshd -R` or tcpd/telnetd exec); a root is
    matched to the Cowrie session whose backend connection opened closest in time (same protocol)."""
    roots = defaultdict(list)
    loose, resets, guards, capped = [], [], [], []
    for e in read_lines("backend"):
        if not isinstance(e.get("t"), int):
            continue
        if e.get("type") == "file_capped":   # a changed file the collector chose not to store again
            capped.append(e)
            continue
        if e.get("type") == "reset":
            resets.append(e)
            continue
        if e.get("type") == "guard":
            guards.append(e)
            continue
        if e.get("type") not in ("exec", "conn", "file", "fetch"):
            continue
        r = s(e.get("root"), 40)
        (roots[r] if r else loose).append(e)
    proxied = []
    for x in sessions:
        if x["kind"] == "web":
            continue
        bt = next((e["t"] for e in x["_events"] if e.get("eventid") == "cowrie.proxy.backend_connected"), None)
        if bt:
            proxied.append((bt, x))

    def root_t(r):
        tail = r.split(":")[-1]
        return int(tail) if tail.isdigit() else None

    used, matched = set(), {}
    for r in sorted((r for r in roots if root_t(r) is not None), key=root_t):
        rt = root_t(r)
        first = next((e for e in roots[r] if e.get("type") == "exec"), None)
        kind = "ssh" if first and os.path.basename(s(first.get("exe"), 300)) == "sshd" else "telnet"
        cands = [(abs(bt - rt), x) for bt, x in proxied
                 if x["kind"] == kind and id(x) not in used and abs(bt - rt) < 15000]
        if cands:
            x = min(cands, key=lambda c: c[0])[1]
            used.add(id(x))
            matched[r] = x
    for x in sessions:
        x["_backend"] = []
    for r, x in matched.items():
        evs = sorted(roots[r], key=lambda e: e["t"])
        by_pid = {e.get("pid"): e for e in evs if e.get("type") == "exec"}
        for e in evs:
            if e.get("type") == "exec":
                chain, cur, hops = [], e, 0
                while cur is not None and hops < 30:
                    chain.append(cur)
                    nxt = by_pid.get(cur.get("ppid"))
                    cur = nxt if nxt is not cur else None
                    hops += 1
                base = os.path.basename(s(e.get("exe"), 300))
                e["_noise"] = base in ("sshd", "tcpd", "telnetd", "login") or \
                    any(LOGIN_NOISE.search(s(c.get("argv"), 4000)) for c in chain)
            x["_backend"].append(e)
    # files found on disk carry no login root: give them to the session that was logged in when they changed
    unattributed = []
    windows = [(bt, max(x["end"], bt) + 5000, x) for bt, x in proxied if "logged in" in x["flags"]]
    for e in loose:
        if e.get("type") != "file":
            continue
        ct = e.get("ctime") or e["t"]
        cands = [(bt, x) for bt, end, x in windows if bt - 2000 <= ct <= end]
        if cands:
            max(cands, key=lambda c: c[0])[1]["_backend"].append(e)
        else:
            unattributed.append(e)
    # an early reset names when the first persistence file changed: credit the session logged in then
    for g in guards:
        ft = g.get("first") if isinstance(g.get("first"), int) else g["t"]
        cands = [(bt, x) for bt, end, x in windows if bt - 2000 <= ft <= end + 60_000]
        if cands:
            max(cands, key=lambda c: c[0])[1]["_backend"].append(g)
    for x in sessions:
        b = x["_backend"]
        if not b:
            continue
        if any(e.get("type") == "guard" or (e.get("type") == "file" and PERSIST_PATH_RE.match(s(e.get("path"), 500)))
               for e in b):
            x["flags"].append("persistence")
            x["interest"] += 5
        b.sort(key=lambda e: e["t"])
        progs = [e for e in b if e.get("type") == "exec" and not e.get("_noise")]
        caps = [e for e in b if e.get("type") == "file" or (e.get("type") == "fetch" and e.get("sha256"))]
        x["programs"] = len(progs)
        x["captured"] = len(caps)
        x["flags"].append("real shell")
        if caps:
            x["flags"].append("sample captured")
            x["stage"] = max(x["stage"], 4)
            x["stage_label"] = SSH_STAGES[x["stage"]]
            x["interest"] += 6 + len(caps) * 2
    resets.sort(key=lambda e: e["t"])
    return {"unattributed_files": unattributed, "capped": capped[-DROPPED_KEEP:],
            "roots": len(roots), "matched": len(matched),
            "resets": [{"t": e["t"], "reason": s(e.get("reason"), 40), "harvested": e.get("harvested"),
                        "paths": [s(p, 300) for p in (e.get("paths") or [])[:20]]} for e in resets[-200:]]}


# ----------------------------------------------------------------------------- fingerprints

def ja4h(e: dict) -> str:
    """JA4H HTTP client fingerprint (FoxIO JA4+ spec) from the logged method, version and header order."""
    hdrs = e.get("headers")
    if not isinstance(hdrs, dict) or not e.get("method"):
        return ""
    names = [str(k) for k in hdrs]
    low = [n.lower() for n in names]
    get = lambda h: str(hdrs[names[low.index(h)]]) if h in low else ""
    cookie = get("cookie")
    rest = [n for n, l in zip(names, low) if l not in ("cookie", "referer")]
    ver = re.sub(r"\D", "", str(e.get("http_version") or "1.1"))[:2].ljust(2, "0")
    lang = re.sub(r"[^a-z0-9]", "", get("accept-language").split(",")[0].split(";")[0].lower())[:4].ljust(4, "0")
    a = f"{str(e['method'])[:2].lower()}{ver}{'c' if cookie else 'n'}{'r' if 'referer' in low else 'n'}{min(len(rest), 99):02d}{lang}"
    h = lambda v: hashlib.sha256(v.encode()).hexdigest()[:12]
    if cookie:
        pairs = sorted(p.strip() for p in cookie.split(";") if p.strip())
        c, d = h(",".join(sorted(p.split("=", 1)[0] for p in pairs))), h(",".join(pairs))
    else:
        c = d = "0" * 12
    return f"{a}_{h(','.join(rest))}_{c}_{d}"


# ----------------------------------------------------------------------------- decoy services

DECOY_KINDS = {"redis": "Redis", "docker": "Docker API", "elastic": "Elasticsearch", "mysql": "MySQL",
               "ollama": "Ollama (AI API)", "k8s": "Kubernetes API", "rdp": "RDP", "smb": "SMB"}
DECOY_STAGES = ["Connected only", "Probed or tried a login", "Read data", "Changed data", "Tried to run code"]
# The web honeypot's agent surfaces (web/app.py "agent bait"). They are web sessions, not decoys of their own;
# the Traps tab shows them as cards next to the decoys. flag -> web handlers that mean a visit.
AGENT_SURFACE_FLAGS = {"MCP server": ("mcp", "mcp_sse", "bait_mcpcard"),
                       "A2A agent": ("a2a", "bait_agentcard"),
                       "agent docs": ("bait_llms", "bait_openapi", "bait_aiplugin", "bait_agentmd")}
AGENT_SURFACES = [  # (card kind, flag, label, stages)
    ("mcp", "MCP server", "MCP server (web)", ["Connected", "Listed tools", "Called a tool", "Fetched a secret",
                                               "Checked in"]),
    ("a2a", "A2A agent", "A2A agent (web)", ["Read the agent card", "Sent a message", "Asked for credentials",
                                             "Checked in"]),
    ("agentdocs", "agent docs", "Agent docs (web)", ["Read a doc", "Used the API key", "Checked in"]),
]
LURES_OF = {"mcp": ("mcp",), "a2a": ("a2a",), "agentdocs": ("llms", "oapi", "plug", "agmd")}
CRED_ASK = re.compile(r"cred|passw|secret|ssh|login|access|key|token", re.I)
URL_RE = re.compile(r"(?:https?|ftp)://[^\s'\"<>|;`\\)\]}]{3,300}", re.I)
PERSIST_RE = re.compile(r"(\*/\d+|\* \* \* \*)|crontab|authorized_keys|ssh-(rsa|ed25519|dss)|/etc/cron|/var/spool/cron", re.I)
FETCH_RE = re.compile(r"\b(curl|wget|tftp)\b|/dev/tcp/|\bnc\b.*-e|base64 -d|python[23]? -c|\|\s*(ba)?sh\b", re.I)
RANSOM_RE = re.compile(r"bitcoin|btc|ransom|backup.*(restore|recover)|recover.*data|monero|xmr|@(proton|tuta)", re.I)
API_VER = re.compile(r"^/v1\.\d+")
HEX_ID = re.compile(r"/[0-9a-f]{12,64}(?=/|$)")


def _json_obj(body: str) -> dict:
    try:
        j = json.loads(body) if body.strip().startswith("{") else {}
    except ValueError:
        return {}
    return j if isinstance(j, dict) else {}


def decoy_action(e: dict) -> dict:
    """What one decoy event means: stage reached, a one-line title, notes, flags, payload text and URLs."""
    svc, ev = e.get("svc"), e.get("event")
    stage, notes, flags, payload = 1, [], [], ""
    if svc == "redis" and ev == "command":
        cmd = s(e.get("cmd"), 40).upper()
        args = [s(a, 2000) for a in (e.get("args") or [])][:12]
        sub = args[0].upper() if args else ""
        title = " ".join([cmd] + [a[:200] for a in args])[:400]
        line = cmd + (" " + sub if cmd in ("CONFIG", "CLIENT", "MODULE", "SCRIPT", "FUNCTION") else "")
        if cmd == "GET" and args and args[-1].upper().startswith("HTTP/"):
            stage, flags, line = 1, ["http probe"], "HTTP"
        elif cmd in ("SLAVEOF", "REPLICAOF") and args and args[0].upper() != "NO":
            stage, flags = 4, ["rogue master"]
            notes.append("Asked this server to replicate from the attacker's server: the classic way to push a "
                         "malicious module. Nothing was contacted.")
        elif cmd == "MODULE" and sub == "LOAD":
            stage, flags = 4, ["module load"]
        elif cmd in ("EVAL", "EVALSHA", "SCRIPT", "FUNCTION"):
            stage, flags = 4, ["lua script"]
            payload = " ".join(args)
        elif cmd == "CONFIG" and sub == "SET":
            stage = 3
            val = " ".join(args[1:3])
            if re.search(r"cron|\.ssh|/var/www|/etc/|/root|/home|\.so\b", val, re.I):
                stage, flags = 4, ["file write via CONFIG SET"]
        elif cmd == "SET" and len(args) >= 2:
            stage, payload = 3, args[1]
            if PERSIST_RE.search(args[1]) or FETCH_RE.search(args[1]):
                stage, flags = 4, ["planted payload"]
        elif cmd in ("FLUSHALL", "FLUSHDB"):
            stage, flags = 3, ["wiped data"]
        elif cmd in ("DEL", "SAVE", "BGSAVE", "CONFIG"):
            stage = 3
        elif cmd in ("GET", "KEYS", "SCAN", "DBSIZE", "TYPE", "TTL", "HGETALL", "LRANGE", "SMEMBERS"):
            stage = 2
    elif svc in ("docker", "elastic") and ev == "request":
        method = s(e.get("method"), 10).upper()
        raw = s(e.get("path"), 2000)
        path = API_VER.sub("", raw.split("?")[0]) or "/"
        title = f"{method} {raw}"[:400]
        line = f"{method} {HEX_ID.sub('/<id>', path)}"
        body = s(e.get("body"), 8000)
        try:
            j = json.loads(body) if body.strip().startswith("{") else {}
        except ValueError:
            j = {}
        j = j if isinstance(j, dict) else {}
        if svc == "docker":
            if method == "POST" and path.endswith("/containers/create"):
                stage, flags = 4, ["container created"]
                hc = j.get("HostConfig") if isinstance(j.get("HostConfig"), dict) else {}
                cmd = j.get("Cmd") or j.get("Entrypoint") or ""
                cmd = " ".join(map(str, cmd)) if isinstance(cmd, list) else str(cmd)
                payload = f"image {s(j.get('Image'), 200)}" + (f", runs: {cmd[:1500]}" if cmd else "")
                notes.append(payload)
                binds = [str(b) for b in (hc.get("Binds") or [])][:6] if isinstance(hc.get("Binds"), list) else []
                if hc.get("Privileged"):
                    flags.append("privileged container")
                if any(b.startswith("/:") or b.split(":")[0] in ("/etc", "/root", "/var/run/docker.sock") for b in binds):
                    flags.append("host filesystem mounted")
                if binds:
                    notes.append("mounts " + ", ".join(binds))
                if hc.get("PidMode") == "host" or hc.get("NetworkMode") == "host":
                    flags.append("host namespaces")
            elif method == "POST" and re.search(r"/containers/[^/]+/exec$", path):
                stage, flags = 4, ["exec in container"]
                cmd = j.get("Cmd") or ""
                payload = " ".join(map(str, cmd)) if isinstance(cmd, list) else str(cmd)
                notes.append("runs: " + payload[:1500])
            elif method == "POST" and (path.endswith("/start") or path == "/build"):
                stage = 4
            elif method == "POST" and path == "/images/create":
                stage, flags = 3, ["image pull"]
                q = parse_qs(raw.partition("?")[2])
                payload = "pull " + s((q.get("fromImage") or [""])[0], 200) + ":" + s((q.get("tag") or ["latest"])[0], 60)
                notes.append(payload)
            elif method == "DELETE":
                stage = 3
            elif method == "GET" and path not in ("/_ping", "/version", "/info"):
                stage = 2
        else:
            if method == "DELETE":
                stage, flags = 3, ["deleted index"]
            elif method in ("PUT", "POST") and re.search(r"/_(doc|create)(/|$)", path):
                stage, payload = 3, body
                if RANSOM_RE.search(body):
                    flags = ["ransom note"]
            elif "_search" in path or "_mapping" in path or "_cat" in path or "/_all" in path:
                stage = 2
                if re.search(r'"script"|"inline"|Runtime|getRuntime|exec\(', body):
                    stage, flags, payload = 4, ["script query"], body
            elif method == "PUT":
                stage = 3
    elif svc == "ollama" and ev == "request":
        method = s(e.get("method"), 10).upper()
        raw = s(e.get("path"), 2000)
        path = raw.split("?")[0].rstrip("/") or "/"
        title, line = f"{method} {raw}"[:400], f"{method} {path}"
        j = _json_obj(s(e.get("body"), 8000))
        if path in ("/api/generate", "/api/chat", "/v1/chat/completions", "/v1/completions"):
            msgs = j.get("messages") if isinstance(j.get("messages"), list) else []
            prompt = " / ".join(s(m.get("content"), 2000) for m in msgs[-4:] if isinstance(m, dict)) or s(j.get("prompt"), 4000)
            stage, flags, payload = 3, ["used the model"], prompt
            title = f"Prompt to {s(j.get('model'), 60) or 'the model'}: {prompt[:300]}"
            if len(prompt) > 1500 or re.search(r"jailbreak|ignore (all|previous)|DAN\b|as an ai", prompt, re.I):
                flags.append("jailbreak or bulk prompt")
        elif path in ("/api/pull", "/api/create", "/api/delete", "/api/copy", "/api/push"):
            stage, flags = 3, ["changed models"]
            payload = s(j.get("modelfile") or j.get("model") or j.get("name"), 2000)
            notes.append(f"model: {payload[:300]}")
        elif path in ("/api/show", "/api/ps", "/api/embeddings", "/api/embed", "/v1/embeddings"):
            stage = 2
    elif svc == "k8s" and ev == "request":
        method = s(e.get("method"), 10).upper()
        raw = s(e.get("path"), 2000)
        path = raw.split("?")[0]
        title = f"{method} {raw}"[:400]
        line = f"{method} " + re.sub(r"/namespaces/[^/]+", "/namespaces/<ns>", re.sub(r"/(pods|secrets|configmaps|deployments|daemonsets|jobs|cronjobs)/[^/]+", r"/\1/<name>", path))
        j = _json_obj(s(e.get("body"), 8000))
        if re.search(r"/(exec|attach|portforward)$", path):
            stage, flags = 4, ["exec in pod"]
            payload = " ".join(c for k, vs in parse_qs(raw.partition("?")[2]).items() if k == "command" for c in vs)[:2000]
            if payload:
                notes.append("runs: " + payload)
        elif method in ("POST", "PUT", "PATCH") and re.search(r"/(pods|deployments|daemonsets|jobs|cronjobs|replicasets|statefulsets)(/|$)", path):
            stage, flags = 4, ["created workload"]
            spec = j.get("spec") if isinstance(j.get("spec"), dict) else {}
            tmpl = ((spec.get("template") or {}).get("spec") if isinstance(spec.get("template"), dict) else None) or \
                   (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or spec
            cs = tmpl.get("containers") if isinstance(tmpl, dict) and isinstance(tmpl.get("containers"), list) else []
            parts = []
            for ct in cs[:4]:
                if isinstance(ct, dict):
                    cmd = ct.get("command") or []
                    args = ct.get("args") or []
                    cmd = " ".join(map(str, cmd + args)) if isinstance(cmd, list) and isinstance(args, list) else str(cmd)
                    parts.append(f"image {s(ct.get('image'), 200)}" + (f", runs: {cmd[:1200]}" if cmd else ""))
                    sc = ct.get("securityContext") if isinstance(ct.get("securityContext"), dict) else {}
                    if sc.get("privileged"):
                        flags.append("privileged container")
            if isinstance(tmpl, dict) and (tmpl.get("hostPID") or tmpl.get("hostNetwork")):
                flags.append("host namespaces")
            if isinstance(tmpl, dict) and any(isinstance(v, dict) and isinstance(v.get("hostPath"), dict) for v in (tmpl.get("volumes") or [])):
                flags.append("host filesystem mounted")
            payload = "; ".join(parts)
            if payload:
                notes.append(payload)
        elif method in ("POST", "PUT", "PATCH"):
            stage, payload = 3, s(e.get("body"), 2000)
        elif method == "DELETE":
            stage = 3
        elif re.search(r"/secrets", path):
            stage, flags = 2, ["read secrets"]
        elif re.search(r"/(pods|configmaps|namespaces|nodes|deployments|serviceaccounts)", path):
            stage = 2
    elif svc in ("rdp", "smb") and ev in ("connect_request", "negotiate", "ntlm", "tls_only", "credssp"):
        name = "RDP" if svc == "rdp" else "SMB"
        if ev == "ntlm":
            who = "\\".join(x for x in (s(e.get("domain"), 100), s(e.get("user"), 100)) if x) or "(anonymous)"
            title, line = f"NTLM login as {who}" + (f" from {s(e.get('workstation'), 100)}" if e.get("workstation") else ""), "NTLM LOGIN"
            if e.get("hash"):
                flags = ["ntlm hash"]
                notes.append(f"crackable offline (hashcat -m {e.get('hash_mode')}): {s(e.get('hash'), 400)}")
            elif e.get("anonymous"):
                notes.append("anonymous (null) session")
        elif ev == "connect_request":
            cookie = s(e.get("cookie"), 100)
            prot = ", ".join(s(p, 20) for p in (e.get("protocol_names") or [])) or "legacy RDP only"
            title, line = f"Connection request{' as ' + cookie if cookie else ''} ({prot})", "CONNECT"
        elif ev == "negotiate":
            ds = ", ".join(s(d, 30) for d in (e.get("dialects") or [])[:10])
            title, line = f"Negotiate {'SMB1' if e.get('smb1') else 'SMB2/3'}: {ds}"[:400], "NEGOTIATE SMB1" if e.get("smb1") else "NEGOTIATE"
            if e.get("smb1") and not any("SMB 2" in s(d, 30) for d in (e.get("dialects") or [])):
                flags = ["SMB1 only (EternalBlue-era tooling)"]
        else:
            title, line = f"{name} TLS handshake, no login", "TLS"
    elif svc == "mysql" and ev == "auth":
        attrs = e.get("attrs") if isinstance(e.get("attrs"), dict) else {}
        prog = s(attrs.get("program_name") or attrs.get("_client_name"), 60)
        u = s(e.get("user"), 60)
        title = f"Login as {u}" + (f" to database {s(e.get('database'), 60)}" if e.get("database") else "")
        line = "LOGIN " + ("<user>" if u else "")
        if e.get("tls_request"):
            title, line = "Asked for TLS (not offered)", "TLS"
        if attrs:
            notes.append("client: " + ", ".join(f"{s(k, 30)}={s(v, 60)}" for k, v in list(attrs.items())[:8]))
        if e.get("scramble"):
            notes.append("password tried; the salted hash can be cracked offline (hashcat -m 11200): " + s(e.get("scramble"), 200))
        elif "has_password" in e:
            notes.append("no password sent")
    else:
        return {}
    urls = list(dict.fromkeys(m.group(0) for m in URL_RE.finditer(title + " " + payload + " " + s(e.get("body"), 8000))))[:10]
    return {"stage": stage, "title": title, "notes": notes, "flags": flags, "line": line,
            "payload": s(payload, 2000), "urls": urls}


def make_decoy(ip: str, svc: str, evs: list) -> dict:
    acts = []
    for e in evs:
        a = decoy_action(e)
        if a:
            e["_a"] = a
            acts.append(e)
    ts = [e["t"] for e in acts]
    gaps, med, cv = gap_stats(ts)
    stage = max([e["_a"]["stage"] for e in acts], default=0)
    flags = list(dict.fromkeys(f for e in acts for f in e["_a"]["flags"]))
    reasons, score = [], 0
    v, score = timing_verdict(len(acts), med, cv, score, reasons)
    if v == "script" or len(acts) < 3:
        cls = "script"
        if not acts:
            reasons.append("Connected and left without sending a command (port scan or banner grab)")
        elif len(acts) < 3:
            reasons.append(f"Sent {len(acts)} request(s) and left (typical of internet-wide scanners)")
    elif score >= 3:
        cls = "agent_suspected"
    elif med is not None and med > 2000 and (cv or 0) >= 1.2:
        cls = "human_like"
        reasons.append(f"Irregular pauses between commands (typically {fmt_ms(med)}), like someone typing")
    else:
        cls = "unknown"
        reasons.append("Pace and behaviour don't clearly match a script, an AI agent or a person")
    uas = Counter(s(e.get("ua"), 300) for e in acts if e.get("ua"))
    client = uas.most_common(1)[0][0] if uas else ""
    if svc == "mysql":
        progs = Counter(s((e.get("attrs") or {}).get("program_name") or (e.get("attrs") or {}).get("_client_name"), 60)
                        for e in acts if isinstance(e.get("attrs"), dict))
        client = progs.most_common(1)[0][0] if progs else ""
    titles = []
    for e in acts:
        t = e["_a"]["title"][:70]
        if t not in titles:
            titles.append(t)
    summary = (" → ".join(titles[:3]) + (f"  (+{len(acts) - 3} more)" if len(acts) > 3 else "")) if titles else "Connected only"
    t0 = evs[0]["t"]
    seq = []
    for e in acts:
        ln = norm_cmd(e["_a"]["line"])
        if ln and (not seq or seq[-1] != ln):
            seq.append(ln)
    return {
        "id": "d-" + hashlib.sha1(f"{ip}|{svc}|{t0}".encode()).hexdigest()[:14], "kind": svc, "ip": ip,
        "start": t0, "end": evs[-1]["t"], "n": len(acts) or 1, "cls": cls, "reasons": reasons, "score": score,
        "stage": stage, "stage_label": DECOY_STAGES[stage], "med_gap": med, "cv": cv, "summary": summary,
        "flags": flags, "client": client, "logins": sum(1 for e in acts if e.get("event") == "auth"),
        "interest": stage * 3 + len(flags) * 2 + score * 2 + min(len(acts), 20) / 4,
        "fp": "", "_events": evs, "_gaps": gaps, "_cmdseq": seq[:60],
    }


def decoy_sessions() -> tuple:
    by = defaultdict(list)
    n = 0
    for e in read_lines("decoys"):
        n += 1
        if not isinstance(e.get("t"), int) or not e.get("ip") or e.get("svc") not in DECOY_KINDS:
            continue
        e["ip"] = s(e["ip"], 64)
        by[(e["ip"], e["svc"])].append(e)
    out = []
    for (ip, svc), evs in by.items():
        evs.sort(key=lambda x: x["t"])
        cur = [evs[0]]
        for e in evs[1:]:
            if e["t"] - cur[-1]["t"] > WEB_SESSION_GAP_MS:
                out.append(make_decoy(ip, svc, cur))
                cur = [e]
            else:
                cur.append(e)
        out.append(make_decoy(ip, svc, cur))
    return out, n


# ----------------------------------------------------------------------------- campaigns

NORM_SUBS = [
    (re.compile(r"(?:https?|ftp)://\S+", re.I), "<url>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"\b[0-9a-f]{12,}\b", re.I), "<hex>"),
    (re.compile(r"[A-Za-z0-9+/]{30,}={0,2}"), "<b64>"),
    (re.compile(r"\b\d{4,}\b"), "<n>"),
    (re.compile(r"((?:/var)?/tmp/|/dev/shm/)\.?[A-Za-z0-9_-]{3,24}"), r"\1<file>"),
    (re.compile(r"\s+"), " "),
]


def norm_cmd(c: str) -> str:
    c = str(c)
    for rx, rep in NORM_SUBS:
        c = rx.sub(rep, c)
    return c.strip()[:200]


def assign_campaigns(sessions: list) -> dict:
    """Group sessions that ran the same command sequence (after blanking IPs, URLs, random names)."""
    groups = defaultdict(list)
    for x in sessions:
        seq = x.get("_cmdseq")
        if seq:
            fam = "shell" if x["kind"] in ("ssh", "telnet") else x["kind"]
            groups[(fam, "\n".join(seq))].append(x)
    camps = {}
    for (fam, key), xs in groups.items():
        if len(xs) < 2:
            continue
        cid = "K-" + hashlib.sha1(f"{fam}|{key}".encode()).hexdigest()[:6]
        ips = {x["ip"] for x in xs}
        for x in xs:
            x["campaign"] = cid
        seq = xs[0]["_cmdseq"]
        camps[cid] = {"id": cid, "family": fam, "sessions": len(xs), "ips": len(ips),
                      "first": min(x["start"] for x in xs), "last": max(x["end"] for x in xs),
                      "steps": seq[:12], "n_steps": len(seq)}
    return camps


# ----------------------------------------------------------------------------- tripwires and agent score

# Each canary token sits in exactly one place, so a hit says which lure the visitor read.
TRIP_TOKENS = {"7f3a": "the login banner (/etc/motd)", "2c9e": "the app config (/var/www/northbridge/.env)",
               "5b1d": "the ops runbook (/root/RUNBOOK.md)", "8e4f": "the nb-healthcheck output",
               "ollama": "the Ollama decoy's model list", "k8s": "the Kubernetes decoy's config map",
               "llms": "the web /llms.txt", "oapi": "the web OpenAPI spec", "plug": "the web ai-plugin.json",
               "a2a": "the A2A agent card or Dispatch Assistant", "mcp": "the web MCP server",
               "agmd": "the leaked AGENTS.md / CLAUDE.md"}
TOKEN_RE = re.compile(re.escape(IDENT["check"]) + r"-([0-9a-z]{2,8})", re.I)   # 2+: "k8s", "mcp", "a2a"
# Credentials that exist only in one bait file: using one anywhere proves the file was read.
TRIP_CREDS = {"Brk-Gl4ss!fs01": "/root/RUNBOOK.md (break-glass SSH)",
              "Rt#db01-breakglass": "/root/RUNBOOK.md (MySQL root)",
              "AKIAZ7NB4FS01KQ2M7XD": "/root/RUNBOOK.md (backup bucket key)",
              "Mon!tor-rds-7731": "/etc/nb/monitor.env (Redis)",
              "Es-M0n!2291": "/etc/nb/monitor.env (Elasticsearch)",
              "Kub3-db-Secr3t!": "the Kubernetes decoy's intranet-db secret",
              "Kub3-rds-Secr3t!": "the Kubernetes decoy's redis-auth secret",
              "Kub3-reg-Pull#77": "the Kubernetes decoy's registry-pull secret",
              "nbk_live_7Qm2Xc9TfA1LrP4w": "the web /llms.txt (API key)",
              "Dpl-0ps!mcp7": "the web MCP vault (ops-ssh-deploy)",
              "Mcp-Db!5512": "the web MCP vault (intranet-db)",
              "AKIAZ7NB4MCP9QX2LD5E": "the web MCP vault (backup-s3)",
              "A2a-Dpl!3391": "the A2A Dispatch Assistant (SSH)",
              "Ag3nt-Dpl#2207": "the leaked AGENTS.md (deploy SSH)",
              "Ag3nt-Db#4410": "the leaked AGENTS.md (MySQL root)"}
LURE_READ = re.compile(r"RUNBOOK|monitor\.env|nb-healthcheck|northbridge/\.env|\.bash_history|/etc/motd", re.I)
# This install's identity: its own canary values and credentials stand in for the reference ones above.
_TOK = {persona.REFERENCE["tokens"][k]: IDENT["tokens"][k] for k in persona.REFERENCE["tokens"]}
TRIP_TOKENS = {_TOK.get(k, k): ident(v) for k, v in TRIP_TOKENS.items()}
TRIP_CREDS = {ident(k): ident(v) for k, v in TRIP_CREDS.items()}
LURE_READ = re.compile(ident(LURE_READ.pattern), re.I)
# Habits of LLM-written shell, rare in bot scripts and in people typing by hand
LLM_STYLE = [
    (re.compile(r"echo\s+['\"]?\s*(={3,}|-{3,}|#{3,})"), "prints section headers between steps (echo \"=== … ===\")"),
    (re.compile(r"(^|;|&&)\s*#\s*[A-Z][a-z]+ (the|if|for|what|whether)\b"), "writes plain-English comments in its commands"),
    (re.compile(r"\|\|\s*echo\s+['\"][^'\"]{4,}"), "adds friendly fallbacks (|| echo \"not found\")"),
    (re.compile(r"2>/dev/null[^\n]{0,200}2>/dev/null"), "silences errors on every step of a chained command"),
    (re.compile(r"<<\s*['\"]?(EOF|PY|SCRIPT)"), "writes multi-line scripts inline with heredocs"),
]


def mysql_native_ok(scramble: str, pw: str) -> bool:
    """Check a logged $mysqlna$salt*response against a known password (mysql_native_password)."""
    try:
        salt_hex, resp_hex = scramble[len("$mysqlna$"):].split("*", 1)
        salt, resp = bytes.fromhex(salt_hex), bytes.fromhex(resp_hex)
        h1 = hashlib.sha1(pw.encode()).digest()
        h3 = hashlib.sha1(salt + hashlib.sha1(h1).digest()).digest()
        return bytes(a ^ b for a, b in zip(h1, h3)) == resp
    except (ValueError, TypeError):
        return False


def event_texts(x: dict, e: dict) -> list:
    """The attacker-supplied strings of one event that could carry a token or a stolen credential."""
    if x["kind"] == "web":
        out = [s(e.get("path"), 2000), s(e.get("query"), 2000), s(e.get("body"), 4000)]
        hd = e.get("headers") if isinstance(e.get("headers"), dict) else {}
        auth = s(next((v for k, v in hd.items() if str(k).lower() == "authorization"), ""), 400)
        out.append(auth)                     # bearer tokens and API keys as sent
        if auth.lower().startswith("basic "):
            try:
                out.append(base64.b64decode(auth[6:] + "==").decode("utf-8", "replace"))
            except ValueError:
                pass
        return out
    if x["kind"] in DECOY_KINDS:
        out = [s(a, 2000) for a in (e.get("args") or [])[:12]] + [s(e.get("path"), 2000), s(e.get("body"), 4000)]
        for h in e.get("headers") or []:
            if isinstance(h, list) and len(h) == 2 and s(h[0], 40).lower() == "authorization":
                v = s(h[1], 400)
                if v.lower().startswith("basic "):
                    try:
                        out.append(base64.b64decode(v[6:] + "==").decode("utf-8", "replace"))
                    except ValueError:
                        pass
        return out
    return [s(e.get("password"), 200), s(e.get("input"), 4000)]


def tripwires_and_scores(sessions: list) -> None:
    for x in sessions:
        trips = []
        for e in x["_events"][:3000]:
            texts = [t for t in event_texts(x, e) if t]
            joined = "\n".join(texts)[:65536]
            for m in TOKEN_RE.finditer(joined):
                trips.append({"t": e["t"], "kind": "token", "where": TRIP_TOKENS.get(m.group(1).lower(), "an unknown lure"),
                              "token": m.group(0)[:30]})
            for cred, where in TRIP_CREDS.items():
                if cred in joined:
                    trips.append({"t": e["t"], "kind": "credential", "where": where,
                                  "how": "as a login password" if e.get("password") == cred else "in a command or request"})
            sc = s(e.get("scramble"), 200)
            if sc.startswith("$mysqlna$"):
                for cred, where in TRIP_CREDS.items():
                    if mysql_native_ok(sc, cred):
                        trips.append({"t": e["t"], "kind": "credential", "where": where, "how": "as a MySQL login"})
        uniq = {}
        for t in trips:
            uniq.setdefault((t["kind"], t["where"]), t)
        x["trips"] = sorted(uniq.values(), key=lambda t: t["t"])[:20]
        if x["trips"]:
            x["flags"].append("tripwire")
            x["interest"] += 10
            for t in x["trips"]:
                if t["kind"] == "credential":
                    x["reasons"].append(f"Used a credential that exists only in {t['where']}, {t['how']}: "
                                        "it read that file first")
        x["ascore"], x["asignals"] = agent_score(x)


def agent_score(x: dict) -> tuple:
    """0-100: how much this session looks like an AI agent, with the evidence behind the number."""
    sig = []
    if x["cls"] == "agent_confirmed" or any(t["kind"] == "token" for t in x.get("trips", ())):
        where = next((t["where"] for t in x.get("trips", ()) if t["kind"] == "token"), "")
        return 100, [f"Followed an instruction written only for AI agents{' in ' + where if where else ''}"]
    if x["cls"] == "known_bot":
        return 3, ["Matches a known bot script"]
    pts = 0
    if any(t["kind"] == "credential" for t in x.get("trips", ())):
        pts += 30
        sig.append("Used a credential it could only have found by reading a bait file (+30)")
    timing = min(int(x.get("score") or 0), 4) * 8
    if timing:
        pts += timing
        sig.append(f"Pauses and variety typical of a model deciding each step (+{timing})")
    if x["kind"] in ("ssh", "telnet"):
        inputs = [s(e.get("input"), 4000) for e in x["_events"] if e.get("eventid") == "cowrie.command.input"]
        joined = "\n".join(inputs)[:65536]
        for rx, label in LLM_STYLE:
            if rx.search(joined):
                pts += 10
                sig.append(f"{label[0].upper() + label[1:]} (+10)")
        if LURE_READ.search(joined):
            pts += 8
            sig.append("Read the bait files a careful operator would read (+8)")
        if x["cls"] == "script":
            pts = min(pts, 25)
    if not sig:
        sig.append("Nothing agent-like observed")
    return min(pts, 95), sig


# ----------------------------------------------------------------------------- network IDS (Suricata eve.json)
# which honeypot listener a destination port belongs to, so an alert lands on the right session of an IP
PORT_KIND = {22: "ssh", 23: "telnet", 80: "web", 443: "web", 6379: "redis", 2375: "docker", 9200: "elastic",
             3306: "mysql", 11434: "ollama", 6443: "k8s", 3389: "rdp", 445: "smb"}
IDS_SLACK_MS = 60_000
# alerts that only repeat what a decoy already logs, or NIC checksum noise (also off in ids/disable.conf)
IDS_NOISE = {2012709, 2001972, 2010937, 2200074}
TID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def ids_events() -> tuple:
    """Alert and TLS records from Suricata, reduced to plain fields. The public end is the visitor."""
    alerts, tls, n = [], [], 0
    for e in read_lines("ids"):
        n += 1
        et = e.get("event_type")
        if et not in ("alert", "tls"):
            continue
        src, dst = s(e.get("src_ip"), 64), s(e.get("dest_ip"), 64)
        sp, dp = e.get("src_port"), e.get("dest_port")
        # our own end is always a private address (OCI NATs the public IP)
        if is_public_ip(src) and not is_public_ip(dst):
            ip, port = src, dp
        elif is_public_ip(dst) and not is_public_ip(src):
            ip, port = dst, sp
        else:
            continue
        r = {"t": iso_ms(e.get("timestamp")), "ip": ip, "port": port if isinstance(port, int) else 0,
             "proto": s(e.get("proto"), 10), "app": s(e.get("app_proto"), 20)}
        if et == "alert":
            a = e.get("alert") if isinstance(e.get("alert"), dict) else {}
            md = a.get("metadata") if isinstance(a.get("metadata"), dict) else {}
            mitre = []
            for tid, tname, tac in zip(md.get("mitre_technique_id") or [], md.get("mitre_technique_name") or [],
                                       md.get("mitre_tactic_name") or []):
                tid = s(tid, 12)
                if TID_RE.match(tid):
                    mitre.append((tid, s(tname, 80).replace("_", " "), s(tac, 40).replace("_", " ").title()))
            if a.get("signature_id") in IDS_NOISE:
                continue
            r.update(sid=a.get("signature_id") if isinstance(a.get("signature_id"), int) else 0,
                     sig=s(a.get("signature"), 200), cat=s(a.get("category"), 80),
                     sev=a.get("severity") if isinstance(a.get("severity"), int) else 3, mitre=mitre[:4],
                     cve=[s(c, 20) for c in (md.get("cve") or []) if isinstance(c, str)][:4],
                     payload=s(e.get("payload_printable"), 600))
            alerts.append(r)
        else:
            x = e.get("tls") if isinstance(e.get("tls"), dict) else {}
            ja3 = x.get("ja3") if isinstance(x.get("ja3"), dict) else {}
            ja4 = x.get("ja4") if isinstance(x.get("ja4"), str) else ""
            r.update(ja3=s(ja3.get("hash"), 40), ja4=s(ja4, 60), sni=s(x.get("sni"), 120), ver=s(x.get("version"), 20))
            if r["ja3"] or r["ja4"]:
                tls.append(r)
    alerts.sort(key=lambda r: r["t"])
    tls.sort(key=lambda r: r["t"])
    return alerts, tls, n


def attach_ids(sessions: list) -> dict:
    """Give each session the Suricata alerts and TLS fingerprints of its own IP, port and time window."""
    alerts, tls, n = ids_events()
    by_ip = defaultdict(list)
    for x in sessions:
        x["ids"], x["tls"] = [], []
        by_ip[x["ip"]].append(x)

    def owner(r):
        kind = PORT_KIND.get(r["port"])
        best = None
        for x in by_ip.get(r["ip"], ()):
            if kind and x["kind"] != kind:
                continue
            if x["start"] - IDS_SLACK_MS <= r["t"] <= x["end"] + IDS_SLACK_MS:
                d = 0 if x["start"] <= r["t"] <= x["end"] else min(abs(r["t"] - x["start"]), abs(r["t"] - x["end"]))
                if best is None or d < best[0]:
                    best = (d, x)
        return best[1] if best else None

    matched = 0
    for r in alerts:
        x = owner(r)
        if x is not None:
            matched += 1
            if len(x["ids"]) < 200:
                x["ids"].append(r)
    for r in tls:
        x = owner(r)
        if x is not None and len(x["tls"]) < 20:
            x["tls"].append(r)
    for x in sessions:
        if x["ids"]:
            sev = min(r["sev"] for r in x["ids"])
            x["flags"].append("ids: high severity" if sev == 1 else "ids alert")
            x["interest"] += 2 + (4 if sev == 1 else 0) + min(len({r["sid"] for r in x["ids"]}), 5)
    return {"lines": n, "alerts": len(alerts), "matched": matched, "tls": len(tls), "_alerts": alerts, "_tls": tls}


# ----------------------------------------------------------------------------- MITRE ATT&CK tagging
# Technique id -> (name, tactic). Enterprise ATT&CK v16 names; only the ones the rules below can emit.
ATTACK = {
    "T1595.002": ("Vulnerability Scanning", "Reconnaissance"),
    "T1595.003": ("Wordlist Scanning", "Reconnaissance"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1110.001": ("Password Guessing", "Credential Access"),
    "T1552.001": ("Credentials In Files", "Credential Access"),
    "T1552.003": ("Bash History", "Credential Access"),
    "T1552.004": ("Private Keys", "Credential Access"),
    "T1552.007": ("Container API", "Credential Access"),
    "T1003.008": ("/etc/passwd and /etc/shadow", "Credential Access"),
    "T1059.004": ("Unix Shell", "Execution"),
    "T1059.006": ("Python", "Execution"),
    "T1609": ("Container Administration Command", "Execution"),
    "T1610": ("Deploy Container", "Defense Evasion"),
    "T1611": ("Escape to Host", "Privilege Escalation"),
    "T1548.003": ("Sudo and Sudo Caching", "Privilege Escalation"),
    "T1098": ("Account Manipulation", "Persistence"),
    "T1098.004": ("SSH Authorized Keys", "Persistence"),
    "T1136.001": ("Create Local Account", "Persistence"),
    "T1053.003": ("Cron", "Persistence"),
    "T1543.002": ("Systemd Service", "Persistence"),
    "T1546.004": ("Unix Shell Configuration Modification", "Persistence"),
    "T1574.006": ("Dynamic Linker Hijacking", "Persistence"),
    "T1505.003": ("Web Shell", "Persistence"),
    "T1070.002": ("Clear Linux or Mac System Logs", "Defense Evasion"),
    "T1070.003": ("Clear Command History", "Defense Evasion"),
    "T1070.004": ("File Deletion", "Defense Evasion"),
    "T1140": ("Deobfuscate/Decode Files or Information", "Defense Evasion"),
    "T1222.002": ("Linux File and Directory Permissions Modification", "Defense Evasion"),
    "T1562.001": ("Disable or Modify Tools", "Defense Evasion"),
    "T1562.004": ("Disable or Modify System Firewall", "Defense Evasion"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1033": ("System Owner/User Discovery", "Discovery"),
    "T1057": ("Process Discovery", "Discovery"),
    "T1016": ("System Network Configuration Discovery", "Discovery"),
    "T1016.001": ("Internet Connection Discovery", "Discovery"),
    "T1049": ("System Network Connections Discovery", "Discovery"),
    "T1087.001": ("Local Account", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1613": ("Container and Resource Discovery", "Discovery"),
    "T1021.001": ("Remote Desktop Protocol", "Lateral Movement"),
    "T1021.002": ("SMB/Windows Admin Shares", "Lateral Movement"),
    "T1021.004": ("SSH", "Lateral Movement"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1090": ("Proxy", "Command and Control"),
    "T1485": ("Data Destruction", "Impact"),
    "T1489": ("Service Stop", "Impact"),
    "T1496.001": ("Compute Hijacking", "Impact"),
    "T1496.004": ("Cloud Service Hijacking", "Impact"),
}
TACTIC_ORDER = ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
                "Credential Access", "Discovery", "Lateral Movement", "Command and Control", "Impact"]

# Shell command lines (Cowrie input and real-shell argv). Bounded patterns only: input is attacker-controlled.
_W = r"(?:^|[\s;|&(`$/])"
CMD_RULES = [(re.compile(p, re.I), t) for p, t in [
    (_W + r"(uname|lscpu|nproc|hostnamectl|dmidecode|lspci)\b|/proc/(cpuinfo|meminfo|version)|\bfree\s+-[mgh]\b|/etc/(os|lsb)-release", "T1082"),
    (_W + r"(whoami|id|w|who|last|lastlog)(\s|$|;)", "T1033"),
    (_W + r"(ps|top|pgrep|htop)(\s|$|;)", "T1057"),
    (_W + r"(ifconfig|ip\s+(a|addr|r|route|link)|route\s+-n|arp\s+-a)\b|/etc/resolv\.conf", "T1016"),
    (r"ifconfig\.(me|co)|ipinfo\.io|icanhazip|api\.ipify|checkip\.|ip-api\.com|myip\.|\bping\s+-c\s*\d\s+(8\.8\.8\.8|1\.1\.1\.1)", "T1016.001"),
    (_W + r"(netstat|ss)\s+-[a-z]{0,8}[tunlp]", "T1049"),
    (r"/etc/passwd\b(?!\s*<<)|" + _W + r"(getent\s+passwd|lastlog)\b", "T1087.001"),
    (r"/etc/shadow\b|unshadow\b", "T1003.008"),
    (_W + r"(ls|find|tree|locate|du)\s|" + _W + r"ls$", "T1083"),
    (_W + r"(nmap|masscan|zmap|zgrab2?|rustscan|naabu|pnscan)\b", "T1046"),
    (r"\.bash_history|\.zsh_history|" + _W + r"history(\s|$|;)(?!\s*-c)", "T1552.003"),
    (r"\.ssh/id_(rsa|ed25519|ecdsa|dsa)\b(?!\.pub)|\.pem\b|\.ppk\b", "T1552.004"),
    (r"\.env\b|wp-config\.php|config\.(php|ya?ml|json)|\.aws/credentials|\.docker/config\.json|\.git-credentials|"
     r"monitor\.env|RUNBOOK|grep\s+-[a-z]{0,6}r[a-z]{0,6}\s+['\"]?(pass|secret|token|key)", "T1552.001"),
    (r"\b(wget|curl|tftp|ftpget|fetch|scp|rsync)\b|/dev/tcp/|\bnc\b[^|;]{0,80}>\s*\S", "T1105"),
    (r"\bpython[23]?(\.\d+)?\s+-c\b|\bperl\s+-e\b", "T1059.006"),
    (r"base64\s+(-d|--decode)|\bxxd\s+-r|openssl\s+(enc|base64)\s+-d", "T1140"),
    (r"chmod\s+([0-7]{3,4}|[ugoa]*\+[rwx]+)|chattr\s+[-+]|chown\s", "T1222.002"),
    (r"authorized_keys", "T1098.004"),
    # writing a cron job, not `crontab -l` (that only reads)
    (r"\bcrontab\s+(-[er]\b|[^-\s;|&])|\|\s*crontab\b|(>|tee\s+(-a\s+)?|cp\s+\S+\s+)\s*/etc/cron|/var/spool/cron|"
     r"\*/\d+\s+\*\s+\*\s+\*\s+\*|\*\s+\*\s+\*\s+\*\s+\*\s+\S", "T1053.003"),
    (r"/etc/systemd/system/|systemctl\s+(enable|daemon-reload)|/etc/init\.d/|rc\.local", "T1543.002"),
    (r"\.bashrc|\.bash_profile|\.profile\b|/etc/profile", "T1546.004"),
    (r"ld\.so\.preload|LD_PRELOAD=", "T1574.006"),
    (r"\b(useradd|adduser)\b", "T1136.001"),
    (r"\b(passwd|chpasswd|usermod)\b(?!\s*$)", "T1098"),
    (r"history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0|(rm|>|shred)[^;|&]{0,40}\.bash_history|ln\s+-sf?\s+/dev/null\s+\S*history", "T1070.003"),
    (r"(rm|>|shred|truncate)[^;|&]{0,40}/var/log/|journalctl\s+--vacuum|\butmpdump\b|/var/log/(wtmp|btmp|lastlog|auth\.log)", "T1070.002"),
    (r"\brm\s+-[a-z]{0,4}f[a-z]{0,4}\s", "T1070.004"),
    (r"iptables\s+(-F|--flush|-P\s+INPUT\s+ACCEPT)|ufw\s+disable|firewalld|nft\s+flush", "T1562.004"),
    (r"setenforce\s+0|selinux=disabled|apparmor|aliyun|qcloud|bcm-agent|/usr/local/(qcloud|aegis)|uninstall\.sh", "T1562.001"),
    (r"\bsudo\s", "T1548.003"),
    (r"\b(xmrig|minerd|cpuminer|nbminer|t-rex|lolminer|phoenixminer|ethminer|c3pool|nanopool|supportxmr|hashvault)\b|stratum\+(tcp|ssl)://|--donate-level", "T1496.001"),
    (r"\b(pkill|killall)\b|kill\s+-9|systemctl\s+(stop|disable)\b|service\s+\S+\s+stop", "T1489"),
    (r"\bssh\s+(-[a-z]+\s+\S+\s+)*[\w.-]+@[\w.-]+|\bsshpass\b", "T1021.004"),
    (r"\bdocker\s+(ps|images|run|exec)|\bkubectl\b|/var/run/docker\.sock", "T1613"),
]]
# web honeypot handlers and session flags
WEB_RULES = {"bait_env": "T1552.001", "bait_git": "T1552.001", "bait_aws": "T1552.001",
             "admin_login_fail": "T1110.001", "wp_login_fail": "T1110.001", "admin_login_ok": "T1078",
             "admin_sql_dump": "T1552.001", "api_sqli_error": "T1190", "llm_proxy_chat": "T1496.004"}
# decoy action flags (decoy_action) and the technique each one shows
DECOY_FLAG_RULES = {
    "rogue master": ["T1190", "T1105"], "module load": ["T1190", "T1105"], "lua script": ["T1190", "T1059.004"],
    "file write via CONFIG SET": ["T1190"], "planted payload": ["T1105"], "wiped data": ["T1485"],
    "container created": ["T1610"], "exec in container": ["T1609"], "image pull": ["T1105"],
    "privileged container": ["T1611"], "host filesystem mounted": ["T1611"], "host namespaces": ["T1611"],
    "deleted index": ["T1485"], "ransom note": ["T1485"], "script query": ["T1190"],
    "used the model": ["T1496.004"], "changed models": ["T1496.004"],
    "exec in pod": ["T1609"], "created workload": ["T1610"], "read secrets": ["T1552.007"],
    "ntlm hash": ["T1110.001"],
}


def attack_tags(sessions: list) -> None:
    """Tag each session with the ATT&CK techniques its own events show, keeping up to 3 pieces of evidence each."""
    for x in sessions:
        found = {}

        def add(tid, t, ev):
            f = found.setdefault(tid, {"id": tid, "n": 0, "t": t, "ev": []})
            f["n"] += 1
            f["t"] = min(f["t"], t)
            ev = s(ev, 200)
            if ev and ev not in f["ev"] and len(f["ev"]) < 3:
                f["ev"].append(ev)

        k = x["kind"]
        if k in ("ssh", "telnet"):
            lines = []
            for e in x["_events"][:3000]:
                ev = e.get("eventid")
                if ev == "cowrie.login.failed":
                    add("T1110.001", e["t"], f"{s(e.get('username'), 40)} / {s(e.get('password'), 40)}")
                elif ev == "cowrie.login.success":
                    add("T1078", e["t"], f"logged in as {s(e.get('username'), 40)}")
                elif ev == "cowrie.command.input":
                    lines.append((e["t"], s(e.get("input"), 2000)))
                elif ev == "cowrie.direct-tcpip.request":
                    add("T1090", e["t"], f"tunnel to {s(e.get('dst_ip'), 64)}:{s(e.get('dst_port'), 8)}")
                elif ev in ("cowrie.session.file_download", "cowrie.session.file_upload"):
                    add("T1105", e["t"], s(e.get("url") or e.get("filename") or e.get("outfile"), 200))
            for e in x.get("_backend", ())[:3000]:
                if e.get("type") == "exec" and not e.get("_noise"):
                    a = e.get("argv")
                    lines.append((e["t"], s(" ".join(map(str, a)) if isinstance(a, list) else a, 2000)))
                elif e.get("type") == "file":
                    p = s(e.get("path"), 500)
                    for rx, tid in ((r"authorized_keys", "T1098.004"), (r"/cron|crontab", "T1053.003"),
                                    (r"/systemd/system/|/init\.d/|rc\.local", "T1543.002"),
                                    (r"\.bashrc|\.profile|\.bash_profile", "T1546.004"), (r"ld\.so\.preload", "T1574.006")):
                        if re.search(rx, p):
                            add(tid, e.get("ctime") or e["t"], "changed " + p)
                elif e.get("type") == "fetch":
                    add("T1105", e["t"], s(e.get("url"), 200))
                elif e.get("type") == "guard":
                    add("T1098.004" if any("authorized_keys" in s(p, 300) for p in e.get("paths") or []) else "T1053.003",
                        e["t"], "persistence planted: " + ", ".join(s(p, 100) for p in (e.get("paths") or [])[:2]))
            if lines:
                add("T1059.004", lines[0][0], lines[0][1])
            for t, ln in lines:
                for rx, tid in CMD_RULES:
                    m = rx.search(ln)
                    if m:
                        add(tid, t, ln)
        elif k == "web":
            paths = set()
            for e in x["_events"][:3000]:
                h = s(e.get("handler"), 40)
                paths.add(s(e.get("path"), 200))
                if h in WEB_RULES:
                    add(WEB_RULES[h], e["t"], s(e.get("path"), 200))
                if e.get("sqli_like") or e.get("traversal_like"):
                    add("T1190", e["t"], f"{s(e.get('path'), 120)}?{s(e.get('query'), 160)}")
                    add("T1595.002", e["t"], s(e.get("path"), 200))
                if e.get("login_user") and h not in WEB_RULES:
                    add("T1110.001", e["t"], f"{s(e.get('login_user'), 40)} at {s(e.get('path'), 80)}")
            if len(paths) >= 5:
                add("T1595.003", x["start"], f"{len(paths)} different paths requested")
        elif k in DECOY_KINDS:
            for e in x["_events"][:3000]:
                a = e.get("_a")
                if not a:
                    continue
                for f in a["flags"]:
                    for tid in DECOY_FLAG_RULES.get(f, ()):
                        add(tid, e["t"], a["title"])
                if k == "rdp" and e.get("event") == "ntlm":
                    add("T1021.001", e["t"], a["title"])
                elif k == "smb" and e.get("event") == "ntlm":
                    add("T1021.002", e["t"], a["title"])
                elif k == "mysql" and e.get("event") == "auth" and e.get("scramble"):
                    add("T1110.001", e["t"], a["title"])
                elif k == "redis" and e.get("event") == "command" and s(e.get("cmd"), 20).upper() == "AUTH":
                    add("T1110.001", e["t"], "AUTH")
                if k == "redis" and a.get("flags") == ["file write via CONFIG SET"] and re.search(r"/var/www|\.php", a["title"], re.I):
                    add("T1505.003", e["t"], a["title"])
                # payloads the visitor planted (cron lines, container commands), and where file writes point
                text = a.get("payload") or (a["title"] if "file write via CONFIG SET" in a["flags"] else "")
                if text:
                    for rx, tid in CMD_RULES:
                        if rx.search(text):
                            add(tid, e["t"], text)
        names = {}
        for r in x.get("ids", ()):
            for tid, tname, tac in r.get("mitre", ()):
                add(tid, r["t"], "Suricata: " + r["sig"])
                names.setdefault(tid, (tname, tac))
        out = []
        for f in found.values():
            name, tactic = ATTACK.get(f["id"]) or names.get(f["id"]) or (f["id"], "Other")
            out.append({**f, "name": name, "tactic": tactic})
        rank = {t: i for i, t in enumerate(TACTIC_ORDER)}
        out.sort(key=lambda f: (rank.get(f["tactic"], len(rank)), f["t"]))
        x["attack"] = out
        x["tech"] = [f["id"] for f in out]


# ----------------------------------------------------------------------------- weekly report

REPORTS_DIR = os.path.join(DATA, "reports")
WEEK_RE = re.compile(r"^(\d{4})-W(\d{2})$")


def week_bounds(label: str = ""):
    """ISO week 'YYYY-Www' -> (label, start_ms, end_ms) in UTC. Empty = the current week."""
    m = WEEK_RE.match(label or "")
    if m:
        start = datetime.fromisocalendar(int(m.group(1)), int(m.group(2)), 1).replace(tzinfo=timezone.utc)
    else:
        now = datetime.now(timezone.utc)
        y, w, _ = now.isocalendar()
        start = datetime.fromisocalendar(y, w, 1).replace(tzinfo=timezone.utc)
    y, w, _ = start.isocalendar()
    t0 = int(start.timestamp() * 1000)
    return f"{y}-W{w:02d}", t0, t0 + 7 * 86400_000


def report_data(label: str = "") -> dict:
    label, t0, t1 = week_bounds(label)
    own = own_set()
    with lock:
        all_s = [x for x in MODEL["sessions"] if x["ip"] not in own]
        campaigns = dict(MODEL.get("campaigns", {}))
        resets = list(MODEL.get("backend", {}).get("resets", []))
        ids_alerts = list((MODEL.get("ids") or {}).get("_alerts", ()))
    sel = [x for x in all_s if t0 <= x["start"] < t1]
    ids_sigs = Counter(f"{r['sid']} {r['sig']}" for r in ids_alerts if t0 <= r["t"] < t1 and r["ip"] not in own)
    seen_before = {x["ip"] for x in all_s if x["start"] < t0}
    ips = {x["ip"] for x in sel}
    kinds, classes, countries, nets = Counter(), Counter(), Counter(), Counter()
    creds, cmds, paths, decoy = Counter(), Counter(), Counter(), Counter()
    techs = Counter()
    for x in sel:
        kinds[KIND_NAMES.get(x["kind"], x["kind"])] += 1
        for f in x.get("attack", ()):
            techs[f"{f['id']} {f['name']} ({f['tactic']})"] += 1
        classes[dict(CLASSES).get(x["cls"], x["cls"])] += 1
        g = geo.lookup(x["ip"])
        countries[g["country"] or "Unknown"] += 1
        nets[g["org"] or "Unknown"] += 1
        for e in x["_events"]:
            ev = e.get("eventid")
            if ev in ("cowrie.login.failed", "cowrie.login.success"):
                creds[f"{s(e.get('username'), 40)} / {s(e.get('password'), 40)}"] += 1
            elif ev == "cowrie.command.input":
                cmds[s(e.get("input"), 160)] += 1
            elif x["kind"] == "web":
                paths[s(e.get("path"), 160)] += 1
            elif x["kind"] in DECOY_KINDS and e.get("_a"):
                decoy[f"{DECOY_KINDS[x['kind']]}: {s(e['_a']['title'], 120)}"] += 1
    week_camps = Counter(x.get("campaign") for x in sel if x.get("campaign"))
    camp_rows = []
    for cid, n in week_camps.most_common(10):
        c = campaigns.get(cid) or {}
        camp_rows.append({"id": cid, "sessions": n, "total": c.get("sessions", n), "new": (c.get("first") or 0) >= t0,
                          "first_step": (c.get("steps") or [""])[0][:160], "ips": c.get("ips", 0)})
    smp = [r for r in samples_view()["samples"] if r["first"] and t0 <= r["first"] < t1 and not r.get("own_only")]
    sample_rows = [{"sha": r["sha"], "name": (r["names"] or [""])[0][:160], "magic": s(r["magic"], 120),
                    "size": r["size"], "yara": [y["rule"] for y in r["yara"]],
                    "vt": (r.get("lookup") or {}).get("vt", {}).get("malicious") if (r.get("lookup") or {}).get("vt", {}).get("found") else None,
                    "family": ((r.get("lookup") or {}).get("mb") or {}).get("signature") or ""} for r in smp[:25]]
    agents = sorted((x for x in sel if x.get("ascore", 0) >= 40 or x.get("trips")), key=lambda x: -x.get("ascore", 0))
    agent_rows = [{"id": x["id"], "ip": x["ip"], "kind": KIND_NAMES.get(x["kind"], x["kind"]), "start": x["start"],
                   "score": x.get("ascore", 0), "cls": dict(CLASSES).get(x["cls"], x["cls"]),
                   "trips": [t["where"] for t in x.get("trips", [])][:4]} for x in agents[:20]]
    wk_resets = [r for r in resets if t0 <= r["t"] < t1]
    new_ips = len(ips - seen_before)
    # eight weeks ending with this one, for the trend lines
    trend = []
    for i in range(7, -1, -1):
        a, b = t0 - i * 7 * 86400_000, t1 - i * 7 * 86400_000
        ws = [x for x in all_s if a <= x["start"] < b]
        trend.append({"week": week_bounds(datetime.fromtimestamp(a / 1000, timezone.utc).strftime("%G-W%V"))[0],
                      "sessions": len(ws), "ips": len({x["ip"] for x in ws}),
                      "logged_in": sum(1 for x in ws if x["kind"] in ("ssh", "telnet") and x["stage"] >= 2),
                      "agents": sum(1 for x in ws if x.get("ascore", 0) >= 60 or x.get("trips"))})
    hl = []
    conf = sum(1 for x in sel if x["cls"] == "agent_confirmed")
    if conf:
        hl.append(f"{conf} session{'s' if conf > 1 else ''} confirmed as an AI agent by a canary")
    trip = sum(1 for x in sel if x.get("trips"))
    if trip:
        hl.append(f"{trip} session{'s' if trip > 1 else ''} tripped a bait-file tripwire")
    if sample_rows:
        yh = sum(1 for r in sample_rows if r["yara"])
        hl.append(f"{len(sample_rows)} new malware sample{'s' if len(sample_rows) > 1 else ''} captured"
                  + (f", {yh} matched YARA rules" if yh else ""))
    nc = [c for c in camp_rows if c["new"]]
    if nc:
        hl.append(f"{len(nc)} new command campaign{'s' if len(nc) > 1 else ''}, largest {nc[0]['id']} with {nc[0]['sessions']} sessions")
    early = sum(1 for r in wk_resets if r["reason"] == "persistence")
    if early:
        hl.append(f"{IDENT['host']} was reset early {early} time{'s' if early > 1 else ''} after attackers planted persistence")
    if not hl:
        hl.append("A quiet week: scanning and password guessing only")
    return {"week": label, "from": t0, "to": t1, "generated": int(time.time() * 1000),
            "complete": t1 <= int(time.time() * 1000), "highlights": hl,
            "totals": {"sessions": len(sel), "ips": len(ips), "new_ips": new_ips, "countries": len(countries),
                       "logged_in": sum(1 for x in sel if x["kind"] in ("ssh", "telnet") and x["stage"] >= 2),
                       "ran_commands": sum(1 for x in sel if x["kind"] in ("ssh", "telnet") and x["stage"] >= 3),
                       "samples": len(sample_rows), "resets": len(wk_resets), "early_resets": early},
            "kinds": top(kinds, 10), "classes": top(classes, 10), "countries": top(countries, 10),
            "networks": top(nets, 10), "credentials": top(creds, 12), "commands": top(cmds, 12),
            "paths": top(paths, 12), "decoys": top(decoy, 12), "campaigns": camp_rows, "samples": sample_rows,
            "agents": agent_rows, "trend": trend, "techniques": top(techs, 25), "ids": top(ids_sigs, 15),
            "resets": [{"t": r["t"], "reason": r["reason"], "paths": r["paths"][:5]} for r in wk_resets[-20:]],
            "weeks": [week_bounds(datetime.fromtimestamp((t0 - i * 7 * 86400_000) / 1000, timezone.utc).strftime("%G-W%V"))[0]
                      for i in range(-1, 12)
                      if t0 - i * 7 * 86400_000 <= int(time.time() * 1000)]}


KIND_NAMES = {"web": "Web", "ssh": "SSH", "telnet": "Telnet"}


def report_html(r: dict) -> str:
    """Self-contained page: inline CSS, no scripts, every attacker-supplied string escaped."""
    import html as H
    e = lambda v: H.escape(str(v), quote=True)
    day = lambda ms: datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%d %b %Y")
    when = lambda ms: datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%a %d %b %H:%M UTC")

    def table(title, head, rows, note=""):
        if not rows:
            return ""
        th = "".join(f"<th>{e(h)}</th>" for h in head)
        tr = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
        return f"<section><h2>{e(title)}</h2>{f'<p class=n>{e(note)}</p>' if note else ''}<table><tr>{th}</tr>{tr}</table></section>"

    def ranked(title, pairs, label):
        return table(title, [label, "Count"], [[f"<code>{e(k)}</code>", f"{v:,}"] for k, v in pairs])

    t = r["totals"]
    tiles = "".join(f"<div class=k><b>{v:,}</b><span>{e(l)}</span></div>" for v, l in (
        (t["sessions"], "sessions"), (t["ips"], "source IPs"), (t["new_ips"], "never seen before"),
        (t["countries"], "countries"), (t["logged_in"], "logged in"), (t["ran_commands"], "ran commands"),
        (t["samples"], "new samples"), (t["resets"], "container resets")))
    hl = "".join(f"<li>{e(h)}</li>" for h in r["highlights"])
    body = [
        f"<header><h1>HotPot weekly report, {e(r['week'])}</h1><p>{day(r['from'])} to {day(r['to'] - 1)} (UTC)"
        f"{'' if r['complete'] else ', week still in progress'}. Generated {when(r['generated'])}. "
        "Your own IPs are left out.</p></header>",
        f"<div class=tiles>{tiles}</div><section><h2>This week</h2><ul>{hl}</ul></section>",
        table("AI agents and tripwires", ["When", "Session", "Score", "Estimate", "Tripwires"],
              [[e(when(a["start"])), f"<code>{e(a['id'])}</code> {e(a['kind'])} from {e(a['ip'])}", f"{a['score']}",
                e(a["cls"]), e("; ".join(a["trips"]) or "none")] for a in r["agents"]]),
        table("New malware samples", ["File", "Type", "YARA", "VirusTotal", "SHA-256"],
              [[f"<code>{e(x['name'])}</code>", e(x["magic"]), e(", ".join(x["yara"]) or "none"),
                e(f"{x['vt']} engines" if x["vt"] is not None else "not checked") + (f", {e(x['family'])}" if x["family"] else ""),
                f"<code>{e(x['sha'])}</code>"] for x in r["samples"]]),
        table("Command campaigns", ["Campaign", "Sessions this week", "All time", "First step"],
              [[f"<code>{e(c['id'])}</code>{' <em>new</em>' if c['new'] else ''}", f"{c['sessions']:,}", f"{c['total']:,}",
                f"<code>{e(c['first_step'])}</code>"] for c in r["campaigns"]]),
        table("MITRE ATT&CK techniques seen", ["Technique", "Sessions"],
              [[f"<code>{e(k)}</code>", f"{v:,}"] for k, v in r.get("techniques", [])],
              "Mapped from each session's own commands, requests and file changes."),
        table("Network IDS alerts (Suricata)", ["Signature", "Alerts"],
              [[f"<code>{e(k)}</code>", f"{v:,}"] for k, v in r.get("ids", [])],
              "ET Open rules on the front VM's public interface."),
        "<div class=two>" + ranked("Countries", r["countries"], "Country") + ranked("Networks", r["networks"], "Network") + "</div>",
        "<div class=two>" + ranked("Actor estimates", r["classes"], "Estimate") + ranked("Protocols", r["kinds"], "Protocol") + "</div>",
        ranked("Top credentials tried", r["credentials"], "User / password"),
        ranked("Top commands", r["commands"], "Command"),
        ranked("Top web paths", r["paths"], "Path"),
        ranked("Decoy service actions", r["decoys"], "Action"),
        table("Container resets", ["When", "Why", "Changed"],
              [[e(when(x["t"])), e("early, after persistence" if x["reason"] == "persistence" else x["reason"]),
                f"<code>{e(', '.join(x['paths']))}</code>"] for x in r["resets"]]),
    ]
    css = ("body{font:14px/1.5 system-ui,sans-serif;margin:0 auto;max-width:980px;padding:24px 16px;color:#1b2430;background:#fff}"
           "h1{font-size:24px;margin:0}h2{font-size:16px;margin:28px 0 8px}header p,.n{color:#5b6675;margin:4px 0}"
           ".tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:8px;margin:20px 0}"
           ".k{border:1px solid #dfe4ea;border-radius:6px;padding:10px}.k b{display:block;font-size:22px}.k span{color:#5b6675;font-size:12px}"
           "table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:5px 8px;border-bottom:1px solid #eceff3;vertical-align:top}"
           "th{color:#5b6675;font-weight:600}code{font:12px ui-monospace,Consolas,monospace;word-break:break-all}"
           "em{color:#b4005a;font-style:normal;font-weight:600}.two{display:grid;grid-template-columns:1fr 1fr;gap:24px}"
           "@media(max-width:700px){.two{grid-template-columns:1fr}}")
    return (f"<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>HotPot {e(r['week'])}</title><style>{css}</style><body>{''.join(body)}</body></html>")


def save_report(label: str) -> str:
    r = report_data(label)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    p = os.path.join(REPORTS_DIR, f"hotpot-{r['week']}.html")
    with open(p + ".tmp", "w", encoding="utf-8") as f:
        f.write(report_html(r))
    os.replace(p + ".tmp", p)
    return p


def report_loop() -> None:
    """Every Monday (UTC) save last week's report once the data is in."""
    time.sleep(120)
    while True:
        try:
            cur, t0, _ = week_bounds()
            last = week_bounds(datetime.fromtimestamp((t0 - 86400_000) / 1000, timezone.utc).strftime("%G-W%V"))[0]
            if MODEL["built"] and not os.path.exists(os.path.join(REPORTS_DIR, f"hotpot-{last}.html")) \
                    and time.time() * 1000 - t0 > 30 * 60_000:
                save_report(last)
        except Exception as ex:
            print("report:", ex, file=sys.stderr)
        time.sleep(3600)


def rebuild() -> None:
    web_events = []
    n_web = 0
    for e in read_lines("web"):
        n_web += 1
        if "event" in e or "ip" not in e:
            continue
        e["t"] = int(e["t_ns"]) // 1_000_000 if e.get("t_ns") else iso_ms(e.get("ts"))
        e["ip"] = s(e.get("ip"), 64)
        e["_ja4h"] = ja4h(e)
        web_events.append(e)
    by_ip = defaultdict(list)
    for e in web_events:
        by_ip[e["ip"]].append(e)
    sessions, llm_hits = [], {}
    for ip, evs in by_ip.items():
        evs.sort(key=lambda x: x["t"])
        cur = [evs[0]]
        for e in evs[1:]:
            if e["t"] - cur[-1]["t"] > WEB_SESSION_GAP_MS:
                sessions.append(make_web(ip, cur))
                note_llm_hits(sessions[-1], cur, llm_hits)
                cur = [e]
            else:
                cur.append(e)
        sessions.append(make_web(ip, cur))
        note_llm_hits(sessions[-1], cur, llm_hits)

    by_sid = defaultdict(list)
    n_cow = 0
    for e in read_lines("cowrie"):
        n_cow += 1
        if not e.get("session"):
            continue
        e["t"] = iso_ms(e.get("timestamp"))
        by_sid[str(e["session"])].append(e)
    for sid, evs in by_sid.items():
        sessions.append(make_cowrie(sid, evs))
    backend = attach_backend(sessions)
    decoys, n_dec = decoy_sessions()
    sessions += decoys
    campaigns = assign_campaigns(sessions)
    tripwires_and_scores(sessions)
    ids = attach_ids(sessions)
    attack_tags(sessions)

    sessions.sort(key=lambda x: x["start"], reverse=True)
    hits = live_hits(web_events, by_sid, decoys, keep=REPLAY_KEEP)
    if hits:   # keep the last REPLAY_HOURS for the map replay, and at least the newest LIVE_KEEP
        cut = hits[-1]["t"] - REPLAY_HOURS * 3600_000
        first = next((i for i, h in enumerate(hits) if h["t"] >= cut), len(hits))
        hits = hits[min(first, max(0, len(hits) - LIVE_KEEP)):]
    with lock:
        MODEL.update(hits=hits, sessions=sessions, backend=backend, by_id={x["id"]: x for x in sessions}, built=int(time.time() * 1000),
                     lines={"web": n_web, "cowrie": n_cow, "decoys": n_dec, "ids": ids["lines"]}, campaigns=campaigns,
                     ids=ids, llm_hits=llm_hits)


# ----------------------------------------------------------------------------- views

RANGES = {"24h": 24 * 3600_000, "7d": 7 * 86400_000, "30d": 30 * 86400_000, "all": None}
PUBLIC_FIELDS = ("id", "kind", "ip", "start", "end", "n", "cls", "stage", "stage_label", "med_gap",
                 "summary", "flags", "client", "logins", "interest", "fp", "ascore", "tech")
GEO_FIELDS = ("cc", "country", "city", "region", "org", "asn", "net")
NET_LABEL = {"hosting": "Hosting / cloud provider", "isp": "Home or business ISP", "private": "Private network",
             "": "Unknown"}


def public(x: dict) -> dict:
    out = {k: x[k] for k in PUBLIC_FIELDS}
    out["campaign"] = x.get("campaign", "")
    out["rep"] = rep_summary(x["ip"])
    g = geo.lookup(x["ip"])
    out.update({k: g[k] for k in GEO_FIELDS})
    return out


SEARCH_CAP = 3000
IOC_TYPES = {"stix": ("application/json", "json"), "misp": ("application/json", "json"),
             "csv": ("text/csv; charset=utf-8", "csv"), "txt": ("text/plain; charset=utf-8", "txt")}


def ioc_export(q: dict):
    """Indicators for the Intel tab's export: (body, content type, file name), or counts for format=count."""
    arg = lambda k, d="": q.get(k, [d])[0]
    rng = arg("range", "7d") if arg("range", "7d") in RANGES else "7d"
    fmt = arg("format", "count")
    kinds = [k for k in arg("kinds", ",".join(ioc.KINDS)).split(",") if k in ioc.KINDS] or list(ioc.KINDS)
    tlp = arg("tlp", "clear") if arg("tlp", "clear") in ioc.TLP_STIX else "clear"
    with lock:
        sessions = MODEL["sessions"]
    span = RANGES[rng]
    now = int(time.time() * 1000)
    own = own_set()
    own.ips.add(CFG.get("ssh_host", ""))
    names = [n.lower() for n in (IDENT.get("brand"), IDENT.get("host")) if n and len(n) >= 4]
    data = ioc.collect(sessions, samples_view()["samples"], own=own, since_ms=now - span if span else 0,
                       only_engaged=arg("scope") == "engaged", local_names=names, geo_of=geo.lookup)
    if fmt == "count":
        return {k: len(data[k]) for k in ioc.KINDS}
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    period = {"24h": "last 24 hours", "7d": "last 7 days", "30d": "last 30 days", "all": "all time"}[rng]
    if fmt == "stix":
        body = ioc.to_stix(data, tlp=tlp, kinds=kinds)
    elif fmt == "misp":
        body = ioc.to_misp(data, tlp=tlp, period=period, kinds=kinds)
    elif fmt == "csv":
        body = ioc.to_csv(data, kinds=kinds)
    elif fmt == "txt":
        body = ioc.to_txt(data, kinds[0])
    else:
        raise ValueError("unknown format")
    ctype, ext = IOC_TYPES[fmt]
    part = kinds[0] if fmt == "txt" else ("all" if len(kinds) == len(ioc.KINDS) else "-".join(kinds))
    return body.encode("utf-8"), ctype, f"hotpot-iocs-{part}-{rng}-{stamp}.{ext}"


def search_sessions(rng: str, include_own: bool, q: str, cls: str, kind: str, sort: str) -> dict:
    """The Sessions tab's filter, run over every session in the period (the page itself only gets the
    newest SEARCH_CAP). Searches the same fields as filteredSessions() in app.js."""
    with lock:
        sessions = MODEL["sessions"]
    now = int(time.time() * 1000)
    span = RANGES.get(rng, RANGES["24h"])
    own = own_set()
    q = q.strip().lower()[:200]
    out = []
    for x in sessions:
        if (not include_own and x["ip"] in own) or (span is not None and x["end"] < now - span):
            continue
        if (cls and x["cls"] != cls) or (kind and x["kind"] != kind):
            continue
        p = public(x)
        if q:
            hay = " ".join(str(v or "") for v in (
                p.get("ip"), p.get("summary"), p.get("client"), " ".join(p.get("flags") or []), p.get("country"),
                p.get("city"), p.get("org"), p.get("cc"), "AS" + str(p.get("asn")), p.get("fp"), p.get("campaign"),
                " ".join(p.get("tech") or []))).lower()
            if q not in hay:
                continue
        out.append(p)
    key = {"interest": lambda s: (-s["interest"], -s["start"]),
           "agent": lambda s: (-(s.get("ascore") or 0), -s["start"])}.get(sort, lambda s: -s["start"])
    out.sort(key=key)
    return {"sessions": out[:SEARCH_CAP], "matched": len(out)}


def top(counter: Counter, n=50):
    return [[k, v] for k, v in counter.most_common(n)]


def map_points(sel: list) -> list:
    pts = {}
    for x in sel:
        g = geo.lookup(x["ip"])
        if g["lat"] is None:
            continue
        key = (round(g["lat"], 1), round(g["lon"], 1))
        p = pts.get(key)
        if not p:
            mx, my = geo.project(g["lon"], g["lat"])
            p = pts[key] = {"x": round(mx, 1), "y": round(my, 1), "place": ", ".join(v for v in (g["city"], g["country"]) if v),
                            "sessions": 0, "ips": set(), "orgs": Counter(), "cls": Counter(), "deep": 0,
                            "depth": [0, 0, 0], "agent": 0, "human": 0}
        p["sessions"] += 1
        p["ips"].add(x["ip"])
        p["orgs"][g["org"] or "unknown network"] += 1
        p["cls"][x["cls"]] += 1
        p["deep"] += 1 if x["stage"] >= 2 else 0
        p["depth"][map_depth(x)] += 1
        if x["cls"] in ("agent_suspected", "agent_confirmed") or x.get("ascore", 0) >= 60 or x.get("trips"):
            p["agent"] += 1
        elif x["cls"] == "human_like":
            p["human"] += 1
    out = []
    for p in sorted(pts.values(), key=lambda v: -v["sessions"]):
        out.append({"x": p["x"], "y": p["y"], "place": p["place"], "sessions": p["sessions"], "ips": len(p["ips"]),
                    "orgs": [o for o, _ in p["orgs"].most_common(3)], "deep": p["deep"],
                    "cls": dict(p["cls"]), "depth": p["depth"], "agent": p["agent"], "human": p["human"]})
    return out


def map_depth(x: dict) -> int:
    """How far a session got, in three steps the map can colour:
    0 connected, probed or guessed passwords; 1 logged in or read data; 2 ran commands or changed something."""
    st = x["stage"]
    if x["kind"] == "web":   # read a bait file / tried a login / logged in -> 1; admin area, dump -> 2
        return 2 if st >= 4 else 1 if st >= 1 else 0
    return 2 if st >= 3 else 1 if st >= 2 else 0


# ----------------------------------------------------------------------------- statistics (analytics tab)
STATS_CACHE = {}
FACTS = {"built": None, "by_id": {}}
GROUPS = ("web", "ssh", "svc")
DUR_BINS = [(0, 1000, "under 1 s"), (1000, 10_000, "1-10 s"), (10_000, 60_000, "10-60 s"), (60_000, 300_000, "1-5 min"),
            (300_000, 1_800_000, "5-30 min"), (1_800_000, 7_200_000, "30 min-2 h"), (7_200_000, None, "over 2 h")]
CMD_BINS = [(0, 1, "none"), (1, 2, "1"), (2, 6, "2-5"), (6, 11, "6-10"), (11, 21, "11-20"), (21, 51, "21-50"), (51, None, "over 50")]
GAP_BINS = [(0, 100, "under 0.1 s"), (100, 1000, "0.1-1 s"), (1000, 3000, "1-3 s"), (3000, 10_000, "3-10 s"),
            (10_000, 30_000, "10-30 s"), (30_000, 120_000, "30 s-2 min"), (120_000, None, "over 2 min")]
SCORE_BINS = [(0, 10, "0-9"), (10, 30, "10-29"), (30, 60, "30-59"), (60, 100, "60-99"), (100, None, "100")]
METRICS = ("sessions", "web", "ssh", "svc", "ips", "new_ips", "returning_ips", "login_attempts", "logins_ok",
           "commands", "decoy_actions", "ids_alerts", "samples", "agents")


def kind_group(k: str) -> str:
    return "web" if k == "web" else "ssh" if k in ("ssh", "telnet") else "svc"


def bin_of(v, bins) -> int:
    for i, (lo, hi, _) in enumerate(bins):
        if v >= lo and (hi is None or v < hi):
            return i
    return len(bins) - 1


def session_facts(x: dict) -> dict:
    """Per-session values the statistics need, worked out once per rebuild (the dict is rebuilt each sync)."""
    f = FACTS["by_id"].get(x["id"])
    if f is not None:
        return f
    g = geo.lookup(x["ip"])
    creds, cmds, paths, n_cmd = set(), set(), set(), 0
    for e in x["_events"][:3000]:
        ev = e.get("eventid")
        if ev in ("cowrie.login.failed", "cowrie.login.success"):
            creds.add(f"{s(e.get('username'), 40)} / {s(e.get('password'), 40)}")
        elif ev == "cowrie.command.input":
            n_cmd += 1
            cmds.add(s(e.get("input"), 160))
        elif x["kind"] == "web":
            paths.add(s(e.get("path"), 160))
    ids = x.get("ids", ())
    f = {"cmds": n_cmd, "country": g["country"] or "Unknown",
         "net": f"{g['org']} (AS{g['asn']})" if g["org"] else "Unknown",
         "dims": {"credentials": creds, "commands": cmds, "paths": paths,
                  "techniques": {f"{a['id']} {a['name']}" for a in x.get("attack", ())},
                  "ids": {f"{r['sid']} {r['sig']}" for r in ids},
                  "cves": {c for r in ids for c in r.get("cve", ())},
                  "countries": {g["country"] or "Unknown"},
                  "networks": {f"{g['org']} (AS{g['asn']})" if g["org"] else "Unknown"}}}
    FACTS["by_id"][x["id"]] = f
    return f


def _series(ss: list, times: list, step: int, first_seen: dict, alerts: list, loose=()) -> dict:
    """Per-bucket counts of every metric for sessions `ss`, bucketed by start time."""
    nb = len(times)
    out = {k: [0] * nb for k in METRICS}
    ips = [set() for _ in range(nb)]
    t0 = times[0] if times else 0
    for x in ss:
        i = (x["start"] - t0) // step
        if not 0 <= i < nb:
            continue
        f = session_facts(x)
        g = kind_group(x["kind"])
        out["sessions"][i] += 1
        out[g][i] += 1
        ips[i].add(x["ip"])
        out["login_attempts"][i] += x.get("logins") or 0
        if x["kind"] in ("ssh", "telnet") and x["stage"] >= 2:
            out["logins_ok"][i] += 1
        out["commands"][i] += f["cmds"]
        if g == "svc" and x["stage"] > 0:
            out["decoy_actions"][i] += x["n"]
        out["samples"][i] += x.get("captured") or 0
        if x.get("ascore", 0) >= 60 or x.get("trips"):
            out["agents"][i] += 1
    for i, bucket in enumerate(ips):
        out["ips"][i] = len(bucket)
        for ip in bucket:
            if first_seen.get(ip, 0) >= times[i]:
                out["new_ips"][i] += 1
            else:
                out["returning_ips"][i] += 1
    for r in alerts:
        i = (r["t"] - t0) // step
        if 0 <= i < nb:
            out["ids_alerts"][i] += 1
    for t in loose:              # captured files no session could be credited with
        i = (t - t0) // step
        if 0 <= i < nb:
            out["samples"][i] += 1
    return out


def _totals(ss: list, a0: int, first_seen: dict, alerts: list, loose=()) -> dict:
    ips = {x["ip"] for x in ss}
    return {
        "sessions": len(ss), "web": sum(1 for x in ss if x["kind"] == "web"),
        "ssh": sum(1 for x in ss if x["kind"] in ("ssh", "telnet")),
        "svc": sum(1 for x in ss if kind_group(x["kind"]) == "svc"),
        "ips": len(ips), "new_ips": sum(1 for ip in ips if first_seen.get(ip, 0) >= a0),
        "returning_ips": sum(1 for ip in ips if first_seen.get(ip, 0) < a0),
        "login_attempts": sum(x.get("logins") or 0 for x in ss),
        "logins_ok": sum(1 for x in ss if x["kind"] in ("ssh", "telnet") and x["stage"] >= 2),
        "commands": sum(session_facts(x)["cmds"] for x in ss),
        "decoy_actions": sum(x["n"] for x in ss if kind_group(x["kind"]) == "svc" and x["stage"] > 0),
        "ids_alerts": len(alerts), "samples": sum(x.get("captured") or 0 for x in ss) + len(loose),
        "agents": sum(1 for x in ss if x.get("ascore", 0) >= 60 or x.get("trips")),
    }


def _funnels(ss: list) -> dict:
    out = {"ssh": [0] * len(SSH_STAGES), "web": [0] * len(WEB_STAGES), "svc": [0] * len(DECOY_STAGES)}
    for x in ss:
        g = kind_group(x["kind"])
        st = min(x["stage"], len(out[g]) - 1)
        out[g][st] += 1
    return out


def _pct(a, b):
    return None if not b else round((a - b) * 100 / b)


def stats_view(rng: str, include_own: bool) -> dict:
    with lock:
        sessions = MODEL["sessions"]
        built = MODEL["built"]
        ids_m = MODEL.get("ids") or {}
    own = own_set()
    key = (rng, include_own, built, tuple(sorted(own)))
    hit = STATS_CACHE.get(key)
    if hit:
        return hit
    if FACTS["built"] != built:
        FACTS["built"], FACTS["by_id"] = built, {}
    now = int(time.time() * 1000)
    span = RANGES.get(rng, RANGES["24h"])
    pool = [x for x in sessions if include_own or x["ip"] not in own]
    alerts_all = [r for r in ids_m.get("_alerts", ()) if include_own or r["ip"] not in own]
    if span is None:
        t_from = min((x["start"] for x in pool), default=now)
        p_from = None
    else:
        t_from, p_from = now - span, now - 2 * span
    width = max(now - t_from, 3600_000)
    for step in (3600_000, 6 * 3600_000, 86400_000, 7 * 86400_000):
        if width / step <= 60:
            break
    b0 = t_from // step * step
    times = list(range(b0, now + 1, step))
    cur = [x for x in pool if x["start"] >= t_from]
    prev = [x for x in pool if p_from is not None and p_from <= x["start"] < t_from]
    a_cur = [r for r in alerts_all if r["t"] >= t_from]
    a_prev = [r for r in alerts_all if p_from is not None and p_from <= r["t"] < t_from]
    with lock:
        loose_t = [e.get("ctime") or e["t"] for e in MODEL.get("backend", {}).get("unattributed_files", [])]
    l_cur = [t for t in loose_t if t >= t_from]
    l_prev = [t for t in loose_t if p_from is not None and p_from <= t < t_from]
    cmp = bool(span) and bool(prev or a_prev)     # nothing to compare against before the first data
    first_seen = {}
    for x in pool:
        if x["start"] < first_seen.get(x["ip"], 1 << 62):
            first_seen[x["ip"]] = x["start"]

    series = _series(cur, times, step, first_seen, a_cur, l_cur)
    prev_series = _series(prev, [t - span for t in times], step, first_seen, a_prev, l_prev) if span else None
    tot = _totals(cur, t_from, first_seen, a_cur, l_cur)
    ptot = _totals(prev, p_from, first_seen, a_prev, l_prev) if span else None

    # actor classes, top countries and networks per bucket ("Other" holds the rest)
    nb = len(times)
    by_class = {k: [0] * nb for k, _ in CLASSES}
    cc, nc = Counter(), Counter()
    for x in cur:
        f = session_facts(x)
        cc[f["country"]] += 1
        nc[f["net"]] += 1
    top_c = [k for k, _ in cc.most_common(6)]
    top_n = [k for k, _ in nc.most_common(6)]
    by_country = {k: [0] * nb for k in top_c + ["Other"]}
    by_net = {k: [0] * nb for k in top_n + ["Other"]}
    heat = {g: [[0] * 24 for _ in range(7)] for g in ("all",) + GROUPS}
    dur = {g: [0] * len(DUR_BINS) for g in GROUPS}
    cmd_hist = [0] * len(CMD_BINS)
    gap_hist = {k: [0] * len(GAP_BINS) for k, _ in CLASSES}
    score_hist = [0] * len(SCORE_BINS)
    for x in cur:
        f = session_facts(x)
        g = kind_group(x["kind"])
        i = (x["start"] - b0) // step
        if 0 <= i < nb:
            by_class[x["cls"]][i] += 1
            by_country[f["country"] if f["country"] in by_country else "Other"][i] += 1
            by_net[f["net"] if f["net"] in by_net else "Other"][i] += 1
        d = datetime.fromtimestamp(x["start"] / 1000, timezone.utc)
        heat["all"][d.weekday()][d.hour] += 1
        heat[g][d.weekday()][d.hour] += 1
        dur[g][bin_of(max(0, x["end"] - x["start"]), DUR_BINS)] += 1
        if x["kind"] in ("ssh", "telnet") and x["stage"] >= 2:
            cmd_hist[bin_of(f["cmds"], CMD_BINS)] += 1
        if x.get("med_gap") is not None and x["n"] >= 3:
            gap_hist[x["cls"]][bin_of(x["med_gap"], GAP_BINS)] += 1
        score_hist[bin_of(x.get("ascore", 0), SCORE_BINS)] += 1

    # geography table and protocol table, with the previous period beside them
    pc = Counter(session_facts(x)["country"] for x in prev)
    c_ips = defaultdict(set)
    for x in cur:
        c_ips[session_facts(x)["country"]].add(x["ip"])
    countries = [{"name": k, "sessions": v, "ips": len(c_ips[k]), "prev": pc.get(k, 0) if span else None}
                 for k, v in cc.most_common(20)]
    kc, pkc = Counter(x["kind"] for x in cur), Counter(x["kind"] for x in prev)
    kinds = [{"kind": k, "sessions": kc[k], "prev": pkc[k] if span else None,
              "ips": len({x["ip"] for x in cur if x["kind"] == k})}
             for k in ["web", "ssh", "telnet"] + list(DECOY_KINDS)]

    # ATT&CK matrix: sessions per technique, grouped by tactic in kill-chain order
    tc, ptc, tname = Counter(), Counter(), {}
    for x in cur:
        for a in x.get("attack", ()):
            tc[a["id"]] += 1
            tname[a["id"]] = (a["name"], a["tactic"])
    for x in prev:
        for a in x.get("attack", ()):
            ptc[a["id"]] += 1
            tname.setdefault(a["id"], (a["name"], a["tactic"]))
    rank = {t: i for i, t in enumerate(TACTIC_ORDER)}
    matrix = []
    for tac in sorted({v[1] for v in tname.values()}, key=lambda t: rank.get(t, 99)):
        techs = [{"id": k, "name": tname[k][0], "sessions": tc.get(k, 0), "prev": ptc.get(k, 0) if span else None}
                 for k in tname if tname[k][1] == tac]
        techs.sort(key=lambda t: (-t["sessions"], t["id"]))
        matrix.append({"tactic": tac, "sessions": sum(1 for x in cur if any(a["tactic"] == tac for a in x.get("attack", ()))),
                       "techniques": techs})

    # movers: in how many sessions each value appeared, this period against the previous one
    movers = {}
    for dim in ("credentials", "commands", "paths", "techniques", "ids", "cves", "countries", "networks"):
        a, b = Counter(), Counter()
        for x in cur:
            a.update(session_facts(x)["dims"][dim])
        for x in prev:
            b.update(session_facts(x)["dims"][dim])
        rows = [{"k": k, "cur": a.get(k, 0), "prev": b.get(k, 0) if cmp else None} for k in set(a) | (set(b) if cmp else set())]
        movers[dim] = {
            "top": sorted((r for r in rows if r["cur"]), key=lambda r: (-r["cur"], r["k"]))[:30],
            "up": sorted((r for r in rows if cmp and r["cur"] > r["prev"]), key=lambda r: (r["prev"] - r["cur"], -r["cur"], r["k"]))[:15],
            "down": sorted((r for r in rows if cmp and r["prev"] > r["cur"]), key=lambda r: (r["cur"] - r["prev"], r["k"]))[:15],
            "new": sorted((r for r in rows if cmp and r["cur"] and not r["prev"]), key=lambda r: (-r["cur"], r["k"]))[:15],
        }

    funnels = {"cur": _funnels(cur), "prev": _funnels(prev) if span else None}
    out = {
        "range": rng, "from": t_from, "to": now, "prev_from": p_from, "step": step, "times": times, "compare": cmp,
        "series": series, "prev_series": prev_series, "totals": tot, "prev_totals": ptot,
        "by_class": by_class, "by_country": by_country, "by_net": by_net, "heat": heat,
        "dist": {"duration": {"bins": [b[2] for b in DUR_BINS], "groups": dur},
                 "commands": {"bins": [b[2] for b in CMD_BINS], "counts": cmd_hist},
                 "gaps": {"bins": [b[2] for b in GAP_BINS], "classes": gap_hist},
                 "score": {"bins": [b[2] for b in SCORE_BINS], "counts": score_hist}},
        "funnels": funnels, "stages": {"ssh": SSH_STAGES, "web": WEB_STAGES, "svc": DECOY_STAGES},
        "countries": countries, "kinds": kinds, "kind_names": {**KIND_NAMES, **DECOY_KINDS},
        "matrix": matrix, "movers": movers,
        "highlights": _stat_highlights(tot, ptot if cmp else None, series, times, step, cc, funnels, matrix, movers, cmp),
    }
    STATS_CACHE.clear()
    STATS_CACHE[key] = out
    return out


def _stat_highlights(tot, ptot, series, times, step, cc, funnels, matrix, movers, span) -> list:
    hl = []
    ch = _pct(tot["sessions"], ptot["sessions"]) if ptot else None
    hl.append(f"{tot['sessions']:,} sessions from {tot['ips']:,} IPs"
              + (f", {'up' if ch >= 0 else 'down'} {abs(ch)}% on the previous period" if ch is not None else "") + ".")
    if tot["ips"] and tot["returning_ips"]:
        hl.append(f"{tot['returning_ips']:,} of the {tot['ips']:,} IPs had been here before; "
                  f"{tot['new_ips']:,} were new.")
    if tot["sessions"] and any(series["sessions"]):
        i = max(range(len(times)), key=lambda j: series["sessions"][j])
        when = datetime.fromtimestamp(times[i] / 1000, timezone.utc).strftime("%a %d %b %H:%M UTC")
        hl.append(f"Busiest {'hour' if step == 3600_000 else '6 hours' if step == 6 * 3600_000 else 'day' if step == 86400_000 else 'week'}: "
                  f"{when}, {series['sessions'][i]:,} sessions.")
    if cc and tot["sessions"]:
        (c1, n1), = cc.most_common(1)
        hl.append(f"{c1} sent {n1 * 100 // tot['sessions']}% of all sessions.")
    f = funnels["cur"]["ssh"]
    tried = sum(f[1:])
    if tried:
        ok = sum(f[2:])
        hl.append(f"{ok * 100 // tried}% of SSH/Telnet visitors who guessed a password got in, and "
                  f"{(sum(f[3:]) * 100 // ok) if ok else 0}% of those ran commands.")
    if tot["agents"]:
        hl.append(f"{tot['agents']:,} session{'s' if tot['agents'] > 1 else ''} looked like an AI agent or hit a tripwire.")
    deep = [t for m in matrix if m["tactic"] in ("Persistence", "Privilege Escalation", "Defense Evasion", "Impact")
            for t in m["techniques"] if t["sessions"]]
    if deep:
        t = max(deep, key=lambda t: t["sessions"])
        hl.append(f"Most common post-login technique: {t['id']} {t['name']} ({t['sessions']:,} sessions).")
    if span:
        up = movers["credentials"]["up"][:1] + movers["commands"]["up"][:1]
        for r in up:
            hl.append(f"Biggest riser: {r['k'][:70]} ({r['prev']:,} to {r['cur']:,} sessions).")
    return hl


def agent_surface_cards(sel: list) -> list:
    """Decoy-style cards for the web honeypot's MCP server, A2A agent and agent docs."""
    cards = {k: {"sessions": 0, "ips": set(), "actions": 0, "stage": 0, "last": 0, "notable": Counter(),
                 "top": Counter()} for k, _, _, _ in AGENT_SURFACES}
    flag_of = {k: f for k, f, _, _ in AGENT_SURFACES}
    for x in sel:
        if x["kind"] != "web":
            continue
        for k, flag in flag_of.items():
            hs = AGENT_SURFACE_FLAGS[flag]
            lures = LURES_OF[k]
            # its own requests, plus check-ins at /internal/agent-verify for its lures and (docs) API key use
            evs = [e for e in x["_events"] if e.get("handler") in hs
                   or (e.get("handler") == "canary" and e.get("canary_lure") in lures)
                   or (k == "agentdocs" and e.get("handler") == "api_shipments")]
            if not any(e.get("handler") in hs for e in evs):
                continue
            v = cards[k]
            v["sessions"] += 1
            v["ips"].add(x["ip"])
            v["last"] = max(v["last"], x["end"])
            stage = 0
            for e in evs:
                v["actions"] += 1
                h = e.get("handler")
                if e.get("canary_hit") and e.get("canary_lure") in lures:
                    v["notable"]["checked in"] += 1
                if k == "mcp":
                    m, tool = s(e.get("mcp_method"), 60), s(e.get("mcp_tool"), 60)
                    v["top"][f"{m} {tool}".strip() or ("SSE stream" if h == "mcp_sse" else s(e.get("method"), 8) + " " + s(e.get("path"), 40))] += 1
                    if m in ("tools/list", "resources/list"):
                        stage = max(stage, 1)
                    if m == "tools/call":
                        stage = max(stage, 2)
                    if tool == "get_secret":
                        stage = max(stage, 3)
                        v["notable"]["secret fetched"] += 1
                    if e.get("canary_hit") and e.get("canary_lure") in lures:
                        stage = 4
                elif k == "a2a":
                    if h == "a2a" and e.get("llm_prompt"):
                        stage = max(stage, 1)
                        v["top"][s(e.get("llm_prompt"), 60)] += 1
                        if CRED_ASK.search(s(e.get("llm_prompt"), 2000)):
                            stage = max(stage, 2)
                            v["notable"]["asked for credentials"] += 1
                    elif h == "bait_agentcard":
                        v["top"]["read the agent card"] += 1
                    if e.get("canary_hit") and e.get("canary_lure") in lures:
                        stage = 3
                else:
                    v["top"][s(e.get("path"), 60)] += 1
                    if h == "api_shipments" and e.get("status") == 200:
                        stage = max(stage, 1)
                        v["notable"]["API key used"] += 1
                    if e.get("canary_hit") and e.get("canary_lure") in lures:
                        stage = 2
            v["stage"] = max(v["stage"], stage)
    out = []
    for k, flag, label, stages in AGENT_SURFACES:
        v = cards[k]
        out.append({"kind": k, "label": label, "flag": flag, "sessions": v["sessions"], "ips": len(v["ips"]),
                    "actions": v["actions"], "stage": stages[v["stage"]] if v["sessions"] else "",
                    "stage_n": v["stage"], "last": v["last"], "notable": top(v["notable"], 3),
                    "top": top(v["top"], 3)})
    return out


def build_view(rng: str, include_own: bool) -> dict:
    with lock:
        sessions = MODEL["sessions"]
        built = MODEL["built"]
    now = int(time.time() * 1000)
    span = RANGES.get(rng, RANGES["24h"])
    own = own_set()
    sel = [x for x in sessions if (include_own or x["ip"] not in own) and (span is None or x["end"] >= now - span)]
    t_from = now - span if span is not None else (min((x["start"] for x in sel), default=now))

    c = {k: Counter() for k in ("ids_sigs", "ids_cats", "ids_cves", "tls_fp", "techniques", "tactics", "paths", "uas", "users", "passwords", "pairs", "commands", "clients", "ips",
                                "downloads", "web_logins", "handlers", "countries", "networks", "nettypes",
                                "programs", "captured", "fetch_urls", "egress", "hassh", "ja4h", "campaigns",
                                "decoy_cmds", "decoy_payloads", "mysql_logins", "decoy_urls", "decoy_services",
                                "ntlm_logins", "llm_prompts")}
    fp_ips, fp_sessions, fp_label = defaultdict(set), Counter(), {}
    camps = MODEL.get("campaigns", {})
    kpi = Counter()
    cls_count, web_funnel, ssh_funnel, decoy_funnel = Counter(), Counter(), Counter(), Counter()
    seen_ip_geo = set()
    for x in sel:
        cls_count[x["cls"]] += 1
        c["ips"][x["ip"]] += 1
        g = geo.lookup(x["ip"])
        c["countries"][g["country"] or "Unknown"] += 1
        c["networks"][f"{g['org']} (AS{g['asn']})" if g["org"] else "Unknown"] += 1
        if x["ip"] not in seen_ip_geo:
            seen_ip_geo.add(x["ip"])
            c["nettypes"][NET_LABEL.get(g["net"], "Unknown")] += 1
        if x.get("fp"):
            fam = "ja4h" if x["kind"] == "web" else "hassh" if x["kind"] in ("ssh", "telnet") else ""
            if fam:
                fp_ips[(fam, x["fp"])].add(x["ip"])
                fp_sessions[(fam, x["fp"])] += 1
                fp_label.setdefault((fam, x["fp"]), s(x["client"], 60))
        if x.get("campaign") in camps:
            cp = camps[x["campaign"]]
            first = cp["steps"][0] if cp["steps"] else ""
            c["campaigns"][f"{cp['id']}  {first[:70]}  ({cp['n_steps']} steps, {cp['ips']} IPs, {cp['family']})"] += 1
        for f in x.get("attack", ()):
            c["techniques"][f"{f['id']}  {f['name']}  ({f['tactic']})"] += 1
            c["tactics"][f["tactic"]] += 1
        if x["kind"] in DECOY_KINDS:
            kpi["decoy_sessions"] += 1
            decoy_funnel[x["stage"]] += 1
            c["decoy_services"][DECOY_KINDS[x["kind"]]] += 1
            for e in x["_events"]:
                a = e.get("_a")
                if not a:
                    continue
                kpi["decoy_actions"] += 1
                c["decoy_cmds"][f"{DECOY_KINDS[x['kind']]}: {a['title'][:140]}"] += 1
                if a["payload"] and a["stage"] >= 3:
                    c["decoy_payloads"][a["payload"][:160]] += 1
                for u in a["urls"]:
                    c["decoy_urls"][u[:160]] += 1
                if e.get("event") == "auth":
                    at = e.get("attrs") if isinstance(e.get("attrs"), dict) else {}
                    prog = s(at.get("program_name") or at.get("_client_name"), 40)
                    c["mysql_logins"][s(e.get("user"), 60) + (f"  ({prog})" if prog else "")] += 1
                elif e.get("event") == "ntlm":
                    who = "/".join(v for v in (s(e.get("domain"), 60), s(e.get("user"), 60)) if v) or "(anonymous)"
                    c["ntlm_logins"][f"{who}  ({DECOY_KINDS[x['kind']]}{', ' + s(e.get('workstation'), 40) if e.get('workstation') else ''})"] += 1
                elif x["kind"] == "ollama" and "used the model" in a["flags"]:
                    c["llm_prompts"][a["payload"][:200]] += 1
        elif x["kind"] == "web":
            kpi["web_sessions"] += 1
            web_funnel[x["stage"]] += 1
            for e in x["_events"]:
                kpi["web_requests"] += 1
                c["paths"][s(e.get("path"), 120)] += 1
                c["uas"][s(e.get("ua"), 160) or "(none)"] += 1
                c["handlers"][s(e.get("handler"), 40)] += 1
                if "login_user" in e:
                    kpi["login_attempts"] += 1
                    c["web_logins"][f"{s(e.get('login_user'), 40)} / {s(e.get('login_pass'), 40)}"] += 1
                    if e.get("login_ok"):
                        kpi["logins_ok"] += 1
                if e.get("canary_hit"):
                    kpi["canary_hits"] += 1
        else:
            kpi["ssh_sessions"] += 1
            ssh_funnel[x["stage"]] += 1
            if x["client"]:
                c["clients"][x["client"].split("  [hassh")[0][:80]] += 1
            for e in x["_events"]:
                ev = e.get("eventid")
                if ev in ("cowrie.login.failed", "cowrie.login.success"):
                    kpi["login_attempts"] += 1
                    u, p = s(e.get("username"), 40), s(e.get("password"), 40)
                    c["users"][u] += 1
                    c["passwords"][p] += 1
                    c["pairs"][f"{u} / {p}"] += 1
                    if ev == "cowrie.login.success":
                        kpi["logins_ok"] += 1
                elif ev == "cowrie.command.input":
                    kpi["commands"] += 1
                    inp = s(e.get("input"), 160)
                    c["commands"][inp] += 1
                    if CANARY_CMD.search(inp):
                        kpi["canary_hits"] += 1
                elif ev in ("cowrie.session.file_download", "cowrie.session.file_upload"):
                    kpi["files"] += 1
                    c["downloads"][s(e.get("url") or e.get("filename") or e.get("shasum"), 160)] += 1
            for e in x.get("_backend", ()):
                ty = e.get("type")
                if ty == "exec" and not e.get("_noise"):
                    kpi["programs"] += 1
                    c["programs"][os.path.basename(s(e.get("exe"), 300)) or "?"] += 1
                elif ty == "conn" and not local_dst(s(e.get("dst"), 80)):
                    c["egress"][s(e.get("dst"), 80)] += 1
                elif ty == "file":
                    kpi["captured"] += 1
                    c["captured"][f"{s(e.get('path'), 120)}  ({s(e.get('magic'), 50).split(',')[0]})"] += 1
                elif ty == "fetch":
                    if e.get("sha256"):
                        kpi["captured"] += 1
                    c["fetch_urls"][s(e.get("url"), 160) + ("" if e.get("sha256") else "  (failed)")] += 1
    for e in MODEL.get("backend", {}).get("unattributed_files", []):
        if span is None or e["t"] >= now - span:
            kpi["captured"] += 1
            c["captured"][f"{s(e.get('path'), 120)}  ({s(e.get('magic'), 50).split(',')[0]}, after logout)"] += 1
    for k, n in fp_sessions.items():
        c[k[0]][f"{k[1]}  ({fp_label[k] or 'no client string'}; {len(fp_ips[k])} IPs)"] = n
    kpi["unique_ips"] = len(c["ips"])
    kpi["countries"] = len([k for k in c["countries"] if k not in ("Unknown", "Private network")])
    kpi["sessions"] = len(sel)
    kpi["agents"] = sum(1 for x in sel if x["cls"] in ("agent_suspected", "agent_confirmed") or x.get("ascore", 0) >= 60)
    kpi["trip_sessions"] = sum(1 for x in sel if x.get("trips"))

    # Suricata: every alert in the period counts here, also from visitors who never opened a session
    with lock:
        ids_m = MODEL.get("ids") or {}
    fp_ips2 = defaultdict(set)
    n_alerts, alert_ips = 0, set()
    for r in ids_m.get("_alerts", ()):
        if r["t"] < t_from or (not include_own and r["ip"] in own):
            continue
        n_alerts += 1
        alert_ips.add(r["ip"])
        key = f"{r['sid']}  {r['sig']}"
        c["ids_sigs"][key] += 1
        c["ids_cats"][r["cat"] or "Uncategorised"] += 1
        for cve in r.get("cve", ()):
            c["ids_cves"][cve] += 1
    # TLS client fingerprints: connections per JA4 (JA3 when no JA4), labelled with how many IPs used it
    seen_fp = Counter()
    for r in ids_m.get("_tls", ()):
        if r["t"] < t_from or (not include_own and r["ip"] in own):
            continue
        fp = r["ja4"] or r["ja3"]
        seen_fp[fp] += 1
        fp_ips2[fp].add(r["ip"])
    for fp, n in seen_fp.items():
        c["tls_fp"][f"{fp}  ({len(fp_ips2[fp])} IPs)"] = n
    ids_kpi = {"alerts": n_alerts, "ips": len(alert_ips), "sessions": sum(1 for x in sel if x.get("ids")),
               "enabled": bool(ids_m.get("lines"))}
    kpi["ids_alerts"] = n_alerts

    # tripwire board: every lure, hit or not, so an empty board still shows what is laid out
    board = {}
    for w in list(TRIP_TOKENS.values()) + list(dict.fromkeys(TRIP_CREDS.values())):
        board.setdefault(w, {"where": w, "kind": "token" if w in TRIP_TOKENS.values() else "credential",
                             "sessions": 0, "ips": set(), "last": 0, "last_id": ""})
    for x in sel:
        for t in x.get("trips", ()):
            b = board.setdefault(t["where"], {"where": t["where"], "kind": t["kind"], "sessions": 0, "ips": set(),
                                              "last": 0, "last_id": ""})
            b["sessions"] += 1
            b["ips"].add(x["ip"])
            if t["t"] > b["last"]:
                b["last"], b["last_id"] = t["t"], x["id"]
    hist_edges = [(0, 10, "0–9"), (10, 30, "10–29"), (30, 60, "30–59"), (60, 100, "60–99"), (100, 101, "100")]
    agents = {
        "hist": [{"label": lab, "lo": lo, "count": sum(1 for x in sel if lo <= x.get("ascore", 0) < hi)} for lo, hi, lab in hist_edges],
        "board": sorted(({**b, "ips": len(b["ips"])} for b in board.values()), key=lambda b: (-b["sessions"], b["kind"] != "token")),
        "top": [{"id": x["id"], "ip": x["ip"], "kind": x["kind"], "score": x.get("ascore", 0), "cls": x["cls"],
                 "summary": s(x["summary"], 120), "start": x["start"]}
                for x in sorted(sel, key=lambda x: (-x.get("ascore", 0), -x["start"]))[:6] if x.get("ascore", 0) >= 20],
    }
    svc = {}
    for x in sel:
        if x["kind"] not in DECOY_KINDS:
            continue
        v = svc.setdefault(x["kind"], {"kind": x["kind"], "label": DECOY_KINDS[x["kind"]], "sessions": 0, "ips": set(),
                                       "actions": 0, "stage": 0, "last": 0, "notable": Counter(), "top": Counter()})
        v["sessions"] += 1
        v["ips"].add(x["ip"])
        v["stage"] = max(v["stage"], x["stage"])
        v["last"] = max(v["last"], x["end"])
        for e in x["_events"]:
            a = e.get("_a")
            if a:
                v["actions"] += 1
                v["top"][a.get("line") or a["title"][:60]] += 1
                for f in a["flags"]:
                    v["notable"][f] += 1
    decoy_svc = []
    for k, lab in DECOY_KINDS.items():
        v = svc.get(k)
        decoy_svc.append({"kind": k, "label": lab, "sessions": v["sessions"] if v else 0, "ips": len(v["ips"]) if v else 0,
                          "actions": v["actions"] if v else 0, "stage": DECOY_STAGES[v["stage"]] if v else "",
                          "stage_n": v["stage"] if v else 0, "last": v["last"] if v else 0,
                          "notable": top(v["notable"], 3) if v else [], "top": top(v["top"], 3) if v else []})

    decoy_svc += agent_surface_cards(sel)

    width = max(now - t_from, 3600_000)
    for step in (300_000, 900_000, 3600_000, 6 * 3600_000, 86400_000):
        if width / step <= 72:
            break
    b0 = t_from // step * step
    buckets = {t: [0, 0, 0] for t in range(b0, now + 1, step)}
    for x in sel:
        b = x["start"] // step * step
        if b in buckets:
            buckets[b][0 if x["kind"] == "web" else 1 if x["kind"] in ("ssh", "telnet") else 2] += 1
    return {
        "meta": {"range": rng, "from": t_from, "to": now, "built": built, "include_own": include_own,
                 "own_ips": sorted(own), "total_sessions": len(sessions)},
        "kpi": dict(kpi),
        "series": {"step": step, "points": [[t, v[0], v[1], v[2]] for t, v in sorted(buckets.items())]},
        "classes": [{"key": k, "label": lab, "count": cls_count[k]} for k, lab in CLASSES],
        "web_funnel": [{"label": lab, "count": web_funnel[i]} for i, lab in enumerate(WEB_STAGES)],
        "ssh_funnel": [{"label": lab, "count": ssh_funnel[i]} for i, lab in enumerate(SSH_STAGES)],
        "decoy_funnel": [{"label": lab, "count": decoy_funnel[i]} for i, lab in enumerate(DECOY_STAGES)],
        "agents": agents,
        "decoy_svc": decoy_svc,
        "ids": ids_kpi,
        "tops": {k: top(v) for k, v in c.items()},
        "distinct": {k: len(v) for k, v in c.items()},
        "totals": {k: sum(v.values()) for k, v in c.items()},
        "map": map_points(sel),
        "geo": {"ready": geo.STATE["ready"], "error": geo.STATE["error"], "downloading": geo.STATE["downloading"],
                "version": geo.STATE["version"], "attribution": geo.ATTRIBUTION},
        "sessions": [public(x) for x in sel[:SEARCH_CAP]],
        "truncated": len(sel) > SEARCH_CAP,
    }


def web_event_view(e: dict, gap) -> dict:
    q = s(e.get("query"), 600)
    notes = []
    if "login_user" in e:
        notes.append(f"login tried: {s(e.get('login_user'), 60)} / {s(e.get('login_pass'), 60)}"
                     + (" (accepted)" if e.get("login_ok") else " (rejected)"))
    if e.get("canary_hit"):
        notes.append(f"CANARY: model='{s(e.get('agent_model'), 80)}' task='{s(e.get('agent_task'), 200)}'"
                     + ("" if e.get("canary_same_ip") else " (token was issued to a different IP)"))
    if e.get("mcp_method"):
        notes.append(f"MCP call: {s(e.get('mcp_method'), 60)} {s(e.get('mcp_params'), 300)}")
    if e.get("sqli_like"):
        notes.append("looks like SQL injection")
    if e.get("traversal_like"):
        notes.append("looks like path traversal / command injection")
    return {
        "t": e["t"], "gap": gap, "title": f"{s(e.get('method'), 10)} {s(e.get('path'), 300)}" + (f"?{q}" if q else ""),
        "status": e.get("status"), "tag": s(e.get("handler"), 40), "notes": notes,
        "more": {"User agent": s(e.get("ua"), 500),
                 "Headers": "\n".join(f"{s(k, 60)}: {s(v, 300)}" for k, v in (e.get("headers") or {}).items()),
                 "Body": s(e.get("body") or e.get("llm_prompt"), 2100)},
    }


COWRIE_TITLES = {
    "cowrie.session.connect": lambda e: f"Connected from port {s(e.get('src_port'), 8)}",
    "cowrie.client.version": lambda e: f"Client: {s(e.get('version'), 200)}",
    "cowrie.client.kex": lambda e: f"Key exchange fingerprint (hassh): {s(e.get('hassh'), 64)}",
    "cowrie.login.failed": lambda e: f"Login rejected: {s(e.get('username'), 60)} / {s(e.get('password'), 60)}",
    "cowrie.login.success": lambda e: f"Login accepted: {s(e.get('username'), 60)} / {s(e.get('password'), 60)}",
    "cowrie.command.input": lambda e: f"$ {s(e.get('input'), 2000)}",
    "cowrie.command.failed": lambda e: f"(command not found: {s(e.get('input'), 200)})",
    "cowrie.session.file_download": lambda e: f"Downloaded {s(e.get('url'), 400)}  sha256 {s(e.get('shasum'), 64)}",
    "cowrie.session.file_upload": lambda e: f"Uploaded {s(e.get('filename'), 200)}  sha256 {s(e.get('shasum'), 64)}",
    "cowrie.direct-tcpip.request": lambda e: f"Tunnel request to {s(e.get('dst_ip'), 80)}:{s(e.get('dst_port'), 8)}",
    "cowrie.session.closed": lambda e: (f"Disconnected after {s(e.get('duration'), 12)} s"
                                        if e.get("duration") not in (None, "") else "Disconnected"),
}


def session_view(sid: str):
    with lock:
        x = MODEL["by_id"].get(sid)
    if not x:
        return None
    out = public(x)
    out.update(reasons=x["reasons"], cv=x["cv"], gaps=[int(g) for g in x["_gaps"][:400]],
               cls_label=dict(CLASSES)[x["cls"]], net_label=NET_LABEL.get(out["net"], "Unknown"))
    out["attack"] = [{k: f[k] for k in ("id", "name", "tactic", "n", "t", "ev")} for f in x.get("attack", ())]
    # Suricata: one row per signature, with how often it fired and an example of the matched payload
    sigs = {}
    for r in x.get("ids", ()):
        g = sigs.setdefault(r["sid"], {"sid": r["sid"], "sig": r["sig"], "cat": r["cat"], "sev": r["sev"], "n": 0,
                                       "t": r["t"], "cve": r["cve"], "payload": r["payload"], "port": r["port"]})
        g["n"] += 1
    out["ids"] = sorted(sigs.values(), key=lambda g: (g["sev"], g["t"]))[:40]
    out["tls"] = [{k: r[k] for k in ("t", "port", "ja3", "ja4", "sni", "ver")} for r in x.get("tls", ())][:10]
    tunnels = [e for e in x["_events"] if e.get("eventid") == "cowrie.direct-tcpip.request" and e.get("dst_ip")]
    out["tunnel_targets"] = []
    for e in tunnels[:20]:
        tg = geo.lookup(s(e.get("dst_ip"), 64))
        out["tunnel_targets"].append({"target": f"{s(e.get('dst_ip'), 64)}:{s(e.get('dst_port'), 8)}",
                                      "where": ", ".join(v for v in (tg["city"], tg["country"]) if v),
                                      "org": tg["org"]})
    evs, prev = [], None
    for e in x["_events"][:1500]:
        gap = e["t"] - prev if prev is not None else None
        prev = e["t"]
        if x["kind"] == "web":
            evs.append(web_event_view(e, gap))
        elif x["kind"] in DECOY_KINDS:
            a = e.get("_a")
            if a:
                more = {}
                if e.get("event") == "request":
                    more = {"Headers": "\n".join(f"{s(h[0], 60)}: {s(h[1], 400)}" for h in (e.get("headers") or [])
                                                 if isinstance(h, list) and len(h) == 2),
                            "Body": s(e.get("body"), 8000)}
                elif a["payload"]:
                    more = {"Payload": a["payload"]}
                evs.append({"t": e["t"], "gap": gap, "title": a["title"], "status": None,
                            "tag": ", ".join(a["flags"]) or DECOY_STAGES[a["stage"]].lower(),
                            "notes": a["notes"] + (["links: " + ", ".join(a["urls"])] if a["urls"] else []), "more": more})
            elif e.get("event") == "close":
                evs.append({"t": e["t"], "gap": gap, "title": f"Disconnected after {e.get('secs', '?')} s", "status": None,
                            "tag": "closed", "notes": [], "more": {}})
            elif e.get("event") == "connect":
                evs.append({"t": e["t"], "gap": gap, "title": f"Connected to {DECOY_KINDS[x['kind']]} from port {s(e.get('src_port'), 8)}",
                            "status": None, "tag": "connect", "notes": [], "more": {}})
        else:
            ev = s(e.get("eventid"), 60)
            fn = COWRIE_TITLES.get(ev)
            if not fn:
                continue
            row = {"t": e["t"], "gap": gap, "title": fn(e), "status": None,
                   "tag": ev.replace("cowrie.", ""), "notes": [], "more": {}}
            sha = s(e.get("shasum"), 64)
            if ev in ("cowrie.session.file_download", "cowrie.session.file_upload") and SHA_RE.match(sha):
                row["sample"] = {"sha": sha, "where": "front"}
            evs.append(row)
    noise = 0
    for e in x.get("_backend", ())[:3000]:
        ty = e.get("type")
        if ty == "exec":
            if e.get("_noise"):
                noise += 1
                continue
            evs.append({"t": e["t"], "title": "▸ " + s(e.get("argv"), 2000), "status": None,
                        "tag": "ran" + ("" if e.get("ok", True) else " (failed)"),
                        "notes": [f"as uid {e.get('uid')} in {s(e.get('cwd'), 200)}  ({s(e.get('exe'), 200)})"],
                        "more": {}})
        elif ty == "conn":
            if local_dst(s(e.get("dst"), 80)):
                continue
            evs.append({"t": e["t"], "title": f"→ connect {s(e.get('dst'), 80)}", "status": None,
                        "tag": "network", "notes": [f"by {s(e.get('exe'), 200)} (the server has no internet)"],
                        "more": {}})
        elif ty == "file":
            evs.append({"t": e.get("ctime") or e["t"], "title": f"Saved sample: {s(e.get('path'), 400)}",
                        "status": None, "tag": "captured",
                        "notes": [s(e.get("magic"), 200),
                                  f"sha256 {s(e.get('sha256'), 64)}, {fmt_size(e.get('size'))}"
                                  + (", running from memory" if e.get("src") == "memory" else "")
                                  + (", executable" if e.get("exec") else "")],
                        "more": {}, "sample": {"sha": s(e.get("sha256"), 64), "where": "backend"}})
        elif ty == "guard":
            ok = e.get("action") == "reset"
            evs.append({"t": e["t"], "title": "Container reset early: this session planted persistence" if ok
                        else "Early container reset failed to start", "status": None, "tag": "reset",
                        "notes": ["Changed: " + ", ".join(s(p, 200) for p in (e.get("paths") or [])[:8]),
                                  IDENT["host"] + " was rolled back to its clean snapshot once nobody was connected; "
                                  "the changed files were kept in the harvest archive first."], "more": {}})
        elif ty == "fetch":
            ok = bool(e.get("sha256"))
            evs.append({"t": e["t"], "title": f"Fetched for analysis: {s(e.get('url'), 400)}",
                        "status": e.get("status"), "tag": "captured" if ok else "fetch failed",
                        "notes": ([s(e.get("magic"), 200), f"sha256 {s(e.get('sha256'), 64)}, {fmt_size(e.get('size'))}"]
                                  if ok else [s(e.get("error"), 300)]),
                        "more": {}, **({"sample": {"sha": s(e.get("sha256"), 64), "where": "backend"}} if ok else {})})
    for v in evs:
        smp = v.get("sample")
        if smp and smp["sha"] in LOOKUPS:
            smp["lookup"] = LOOKUPS[smp["sha"]]
    evs.sort(key=lambda v: v["t"])
    prev = None
    for v in evs:
        v["gap"] = v["t"] - prev if prev is not None else None
        prev = v["t"]
    out["backend_note"] = (f"{noise} programs started by the login itself (welcome-message scripts) are hidden."
                           if noise else "")
    out["programs"] = x.get("programs", 0)
    out["captured"] = x.get("captured", 0)
    out["kind_label"] = DECOY_KINDS.get(x["kind"], "")
    out["asignals"] = x.get("asignals", [])
    out["trips"] = x.get("trips", [])
    out["iprep"] = IPREP.get(x["ip"])
    out["campaign_info"] = MODEL.get("campaigns", {}).get(x.get("campaign", ""))
    fam = "JA4H (HTTP client)" if x["kind"] == "web" else "HASSH (SSH client)" if x["kind"] in ("ssh", "telnet") else ""
    out["fp_label"] = fam
    out["fp_ips"] = 0
    if x.get("fp"):
        with lock:
            others = {y["ip"] for y in MODEL["sessions"] if y.get("fp") == x["fp"] and y["kind"] == x["kind"]}
        out["fp_ips"] = len(others - {x["ip"]})
    out["replay"] = None
    if x["kind"] in ("ssh", "telnet"):
        if any(e.get("eventid") == "cowrie.log.closed" and int(e.get("size") or 0) > 0 for e in x["_events"]):
            out["replay"] = "tty"
        elif any(e.get("eventid") == "cowrie.command.input" for e in x["_events"]):
            out["replay"] = "commands"
    out["events"] = evs
    out["events_truncated"] = len(x["_events"]) > 1500
    return out


# ----------------------------------------------------------------------------- http

STATIC_FILES = {"/": ("index.html", "text/html; charset=utf-8"),
                "/app.js": ("app.js", "application/javascript; charset=utf-8"),
                "/stats.js": ("stats.js", "application/javascript; charset=utf-8"),
                "/style.css": ("style.css", "text/css; charset=utf-8"),
                "/favicon.svg": ("favicon.svg", "image/svg+xml")}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class Handler(BaseHTTPRequestHandler):
    server_version = "hp-dashboard"
    sys_version = ""

    def log_message(self, *args):
        pass

    def allowed(self) -> bool:
        port = self.server.server_address[1]
        return self.headers.get("Host", "") in (f"127.0.0.1:{port}", f"localhost:{port}")

    def send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, obj, code=200) -> None:
        self.send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def do_GET(self):
        if not self.allowed():
            return self.send(403, b"forbidden", "text/plain")
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in STATIC_FILES:
            fn, ctype = STATIC_FILES[u.path]
            with open(os.path.join(STATIC, fn), "rb") as f:
                return self.send(200, f.read(), ctype)
        if u.path == "/api/meta":
            return self.send_json({"token": CSRF, "status": STATUS, "host": CFG["ssh_host"],
                                   "own_ips": CFG.get("own_ips", []), "lines": MODEL["lines"],
                                   "sync_seconds": CFG.get("sync_seconds", 60)})
        if u.path == "/api/data":
            rng = q.get("range", ["24h"])[0]
            return self.send_json(build_view(rng if rng in RANGES else "24h", q.get("own", ["0"])[0] == "1"))
        if u.path == "/api/sessions":
            rng = q.get("range", ["24h"])[0]
            arg = lambda k: q.get(k, [""])[0]
            return self.send_json(search_sessions(rng if rng in RANGES else "24h", arg("own") == "1", arg("q"),
                                                  arg("cls"), arg("kind"), arg("sort")))
        if u.path == "/api/stats":
            rng = q.get("range", ["7d"])[0]
            return self.send_json(stats_view(rng if rng in RANGES else "7d", q.get("own", ["0"])[0] == "1"))
        if u.path == "/api/map-replay":
            return self.send_json(map_replay_view(q.get("own", ["0"])[0] == "1"))
        if u.path == "/api/live":
            try:
                since = int(q.get("since", ["0"])[0])
            except ValueError:
                since = 0
            return self.send_json(live_view(since, q.get("own", ["0"])[0] == "1"))
        if u.path == "/api/vmstatus":
            return self.send_json(vm_status(q.get("force", ["0"])[0] == "1"))
        if u.path == "/api/settings":
            return self.send_json(settings_view())
        if u.path == "/api/abuse":
            return self.send_json(abuse_view())
        if u.path == "/api/about":
            return self.send_json(about_view())
        if u.path == "/api/ioc":
            try:
                r = ioc_export(q)
            except ValueError as e:
                return self.send_json({"error": str(e)[:200]}, 400)
            if isinstance(r, dict):
                return self.send_json(r)
            body, ctype, name = r
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        if u.path == "/api/samples":
            return self.send_json(samples_view())
        if u.path == "/api/llm-pages":
            return self.send_json(llm_pages_view(q.get("force", ["0"])[0] == "1", q.get("own", ["0"])[0] == "1"))
        if u.path == "/api/report":
            return self.send_json(report_data(q.get("week", [""])[0][:10]))
        if u.path == "/api/report.html":
            r = report_data(q.get("week", [""])[0][:10])
            body = report_html(r).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Disposition", f'attachment; filename="hotpot-{r["week"]}.html"')
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        if u.path == "/api/replay":
            try:
                v = replay_view(q.get("id", [""])[0][:64])
            except Exception as e:
                return self.send_json({"error": f"{type(e).__name__}: {e}"[:300]}, 502)
            return self.send_json(v) if v else self.send_json({"error": "not found"}, 404)
        if u.path == "/api/basemap":
            return self.send_json({"path": geo.basemap_path(), "borders": geo.borders_path(),
                                   "w": geo.MAP_W, "h": geo.MAP_H,
                                   "attribution": "Land outline: Natural Earth (public domain)"})
        if u.path == "/api/session":
            v = session_view(q.get("id", [""])[0][:64])
            return self.send_json(v, 200) if v else self.send_json({"error": "not found"}, 404)
        return self.send(404, b"not found", "text/plain")

    def do_POST(self):
        port = self.server.server_address[1]
        origin = self.headers.get("Origin")
        if not self.allowed() or (origin and origin not in (f"http://127.0.0.1:{port}", f"http://localhost:{port}")) \
                or not hmac.compare_digest(self.headers.get("X-HP-Token", ""), CSRF):
            return self.send(403, b"forbidden", "text/plain")
        path = urlparse(self.path).path
        if path in ("/api/settings", "/api/lookup", "/api/iprep", "/api/submit", "/api/scan", "/api/forward-test"):
            try:
                n = int(self.headers.get("Content-Length") or 0)
                req = json.loads(self.rfile.read(min(n, 4000)) or b"{}")
                if not isinstance(req, dict):
                    raise ValueError("bad request")
                if path == "/api/settings":
                    return self.send_json(save_settings(req))
                if path == "/api/forward-test":
                    return self.send_json(forward.test_event(SETTINGS.get("forward") or {}))
                if path == "/api/iprep":
                    return self.send_json(lookup_ip(str(req.get("ip", ""))[:64]))
                if path == "/api/submit":
                    return self.send_json(submit_sample(str(req.get("sha", "")), str(req.get("where", "")),
                                                        str(req.get("service", ""))))
                if path == "/api/scan":
                    threading.Thread(target=scan_all, daemon=True).start()
                    return self.send_json({"started": True})
                return self.send_json(lookup_hash(str(req.get("sha", ""))))
            except ValueError as e:
                return self.send_json({"error": str(e)[:200]}, 400)
            except Exception as e:
                return self.send_json({"error": f"{type(e).__name__}: {e}"[:300]}, 502)
        if urlparse(self.path).path == "/api/sample":
            try:
                n = int(self.headers.get("Content-Length") or 0)
                req = json.loads(self.rfile.read(min(n, 1000)) or b"{}")
                sha, where = str(req.get("sha", "")), str(req.get("where", ""))
                data = fetch_sample_zip(sha, where)
            except ValueError:
                return self.send_json({"error": "bad request"}, 400)
            except Exception as e:  # ssh failure, file gone (e.g. reset), too large
                return self.send_json({"error": f"{type(e).__name__}: {e}"[:300]}, 502)
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", f'attachment; filename="{sha[:16]}-infected.zip"')
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            return
        if urlparse(self.path).path == "/api/abuse-report":
            if not SETTINGS.get("abuseipdb_api_key"):
                return self.send_json({"error": "add an AbuseIPDB key in Settings first"}, 400)
            if REPORTER.status["running"]:
                return self.send_json({"started": False, "busy": True})
            REPORTER.status["running"] = True  # shown at once; run() sets it again
            threading.Thread(target=run_abuse, daemon=True).start()
            return self.send_json({"started": True})
        if urlparse(self.path).path == "/api/sync":
            threading.Thread(target=sync_once, daemon=True).start()
            return self.send_json({"started": True})
        return self.send(404, b"not found", "text/plain")


_LOCK = None


def single_instance(port: int) -> None:
    """Two dashboards syncing into the same data folder would append the same log lines twice."""
    global _LOCK
    os.makedirs(DATA, exist_ok=True)
    path = os.path.join(DATA, ".dashboard.lock")
    f = open(path, "a+")
    try:
        if os.name == "nt":
            import msvcrt
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        other = ""
        if os.name != "nt":                     # on Windows the other copy's lock blocks reading it
            f.seek(0)
            other = f.read().strip()
        sys.exit(f"Another dashboard already uses {DATA}" + (f" ({other})" if other else "") +
                 ". Open that one, or stop it first.")
    if os.name != "nt":                         # Windows locks the byte we would write to
        f.truncate(0)
        f.write(f"http://127.0.0.1:{port}")
        f.flush()
    _LOCK = f


def main() -> None:
    single_instance(int(os.environ.get("PORT") or CFG.get("port", 8787)))
    os.makedirs(MIRROR, exist_ok=True)
    rebuild()
    threading.Thread(target=geo.ensure, daemon=True).start()
    threading.Thread(target=sync_loop, daemon=True).start()
    threading.Thread(target=lookup_loop, daemon=True).start()
    threading.Thread(target=iprep_loop, daemon=True).start()
    threading.Thread(target=abuse_loop, daemon=True).start()
    threading.Thread(target=scan_loop, daemon=True).start()
    threading.Thread(target=report_loop, daemon=True).start()
    port = int(os.environ.get("PORT") or CFG.get("port", 8787))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Honeypot dashboard: http://127.0.0.1:{port}  (local only; Ctrl+C to stop)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
