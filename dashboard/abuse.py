"""Report attacker IPs to AbuseIPDB (https://www.abuseipdb.com), from the dashboard.

Which IPs: public addresses that did more than connect - guessed SSH/Telnet passwords, read a web bait
file or tried a web login, or read data from, changed, ran code on or logged in to a decoy - and that are not your own, not a private
address and not a known-benign scanner (GreyNoise "benign" or RIOT, when looked up, or a network
of a known internet research scanner such as Censys or Shadowserver). Each IP is
reported at most once a day, and only for activity newer than its last report.

What leaves this PC: the attacker's IP, AbuseIPDB category numbers, the time of the last activity and a
comment built only from fixed phrases and counts. Nothing the attacker typed (user names, passwords,
commands, paths) and nothing about this install (names, addresses) is ever put in a report, so a
report can't carry an attacker's text into AbuseIPDB or tell anyone which sensor saw it.
"""
import ipaddress
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlencode

API = "https://api.abuseipdb.com/api/v2/report"
DAY_MS = 86400 * 1000
DAILY_CAP = 900          # the free plan allows 1,000 reports a day; leave room for reports made by hand
PER_RUN = 60             # one run never sends more than this; the rest go on the next run

# AbuseIPDB categories: https://www.abuseipdb.com/categories
PORT_SCAN, HACKING, BRUTE_FORCE, BAD_WEB_BOT, WEB_APP_ATTACK, SSH, IOT = 14, 15, 18, 19, 21, 22, 23
CATEGORY_NAMES = {PORT_SCAN: "Port scan", HACKING: "Hacking", BRUTE_FORCE: "Brute-force", BAD_WEB_BOT: "Bad web bot",
                  WEB_APP_ATTACK: "Web app attack", SSH: "SSH", IOT: "IoT targeted"}
# Networks of internet-wide research and attack-surface scanners. They announce themselves, honour
# opt-outs and are not attackers, so their sessions are never reported even when they read a decoy's
# data. Matched against the session's network name (from the geo database), so it works without a
# GreyNoise lookup.
RESEARCH_ORG_RE = re.compile(
    r"\b(censys|shodan|shadowserver|modat|onyphe|binaryedge|stretchoid|leakix|criminal ?ip|ai spera|recyber|"
    r"alpha strike|internet measurement|driftnet|palo alto networks|rapid7|bitsight|hadrian security|"
    r"internet census|cyber ?resilience|netscout)\b", re.I)

DECOY_NAMES = {"redis": "Redis", "docker": "Docker API", "elastic": "Elasticsearch", "mysql": "MySQL",
               "ollama": "Ollama API", "k8s": "Kubernetes API", "rdp": "RDP", "smb": "SMB"}


def _global(ip) -> bool:
    try:
        return ipaddress.ip_address(str(ip)).is_global
    except ValueError:
        return False


def _iso(ms) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat(timespec="seconds")


def what_happened(x: dict):
    """(categories, phrase, count) for one session, or None when it is not worth a report."""
    kind, stage, logins = x.get("kind"), int(x.get("stage") or 0), int(x.get("logins") or 0)
    if kind in ("ssh", "telnet"):
        if stage < 1:
            return None
        cats = {BRUTE_FORCE, SSH if kind == "ssh" else IOT}
        if stage >= 3:
            cats.add(HACKING)
            return cats, f"{kind.upper()} login and shell commands", logins
        return cats, f"{kind.upper()} password guessing", logins
    if kind == "web":
        if stage < 1:
            return None
        cats = {WEB_APP_ATTACK, BAD_WEB_BOT}
        if stage >= 2:
            cats.add(BRUTE_FORCE)
            return cats, "web login attempts", logins
        return cats, "probing for secret files (.env, backups, keys)", 0
    if kind in DECOY_NAMES:
        # a bare handshake (stage 1 without a login) is mostly internet-wide scanning, research scanners
        # included: only report decoy sessions that read data, changed it, ran code or tried to log in
        if stage < 2 and not logins:
            return None
        cats = {PORT_SCAN}
        if logins:
            cats.add(BRUTE_FORCE)
        if stage >= 3:
            cats.add(HACKING)
        return cats, f"unsolicited {DECOY_NAMES[kind]} access", logins
    return None


def plan(sessions, own=(), reported=None, now_ms=None, window_ms=DAY_MS, benign=()) -> list:
    """The reports a run would send, newest activity first:
    [{"ip", "categories": [..], "comment", "timestamp", "last", "sessions"}]."""
    now_ms = now_ms or int(time.time() * 1000)
    reported = reported or {}
    by_ip = {}
    for x in sessions:
        ip = x.get("ip")
        end = int(x.get("end") or 0)
        if end < now_ms - window_ms or not _global(ip) or ip in own or ip in benign:
            continue
        if RESEARCH_ORG_RE.search(str(x.get("org") or "")[:200]):
            continue
        last_report = reported.get(ip, 0)
        if now_ms - last_report < DAY_MS or end <= last_report:
            continue
        w = what_happened(x)
        if not w:
            continue
        cats, phrase, count = w
        r = by_ip.setdefault(ip, {"ip": ip, "cats": set(), "phrases": {}, "last": 0, "sessions": 0})
        r["cats"] |= cats
        # one phrase per service: the strongest (most categories) wins, attempts add up
        old = r["phrases"].get(x.get("kind"))
        if old is None or len(cats) > old[2]:
            r["phrases"][x.get("kind")] = (phrase, (old[1] if old else 0) + count, len(cats))
        else:
            r["phrases"][x.get("kind")] = (old[0], old[1] + count, old[2])
        r["last"] = max(r["last"], end)
        r["sessions"] += 1
    out = []
    for r in sorted(by_ip.values(), key=lambda r: -r["last"]):
        bits = [p + (f" ({n} login attempts)" if n > 1 else "") for p, n, _ in sorted(r["phrases"].values())]
        out.append({"ip": r["ip"], "categories": sorted(r["cats"]),
                    "comment": ("Honeypot: " + "; ".join(bits) + ".")[:1000],
                    "timestamp": _iso(r["last"]), "last": r["last"], "sessions": r["sessions"]})
    return out


class Reporter:
    """Sends reports and remembers what went out (abuse_reports.json)."""

    def __init__(self, path: str):
        self.path = path
        self.lock = threading.Lock()
        self.state = {"v": 1, "ips": {}, "day": "", "today": 0, "total": 0}
        try:
            with open(path, encoding="utf-8") as f:
                v = json.load(f)
            if isinstance(v, dict) and v.get("v") == 1 and isinstance(v.get("ips"), dict):
                self.state.update(v)
        except (OSError, ValueError):
            pass
        self.status = {"last_run": None, "sent": 0, "error": None, "running": False}

    def save(self):
        # forget IPs not reported for 30 days: the file stays small and they are reportable again anyway
        cut = int(time.time() * 1000) - 30 * DAY_MS
        self.state["ips"] = {k: v for k, v in self.state["ips"].items() if v >= cut}
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.state, f)
        os.replace(tmp, self.path)

    def left_today(self) -> int:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if self.state["day"] != today:
            self.state["day"], self.state["today"] = today, 0
        return max(0, DAILY_CAP - self.state["today"])

    def view(self) -> dict:
        return {**self.status, "today": self.state["today"] if self.state["day"] == datetime.now(timezone.utc)
                .strftime("%Y-%m-%d") else 0, "cap": DAILY_CAP, "total": self.state["total"]}

    @staticmethod
    def send_one(key: str, item: dict, opener=urllib.request.urlopen) -> tuple:
        """(outcome, detail): outcome is "sent", "duplicate", "stop" (key, quota) or "error"."""
        body = urlencode({"ip": item["ip"], "categories": ",".join(str(c) for c in item["categories"]),
                          "comment": item["comment"], "timestamp": item["timestamp"]}).encode()
        req = urllib.request.Request(API, data=body, method="POST",
                                     headers={"Key": key, "Accept": "application/json"})
        try:
            with opener(req, timeout=20) as r:
                return "sent", ""
        except urllib.error.HTTPError as e:
            try:
                detail = str((json.loads(e.read(20000)).get("errors") or [{}])[0].get("detail", ""))[:200]
            except (ValueError, AttributeError, IndexError):
                detail = ""
            if e.code == 429 and "once in" in detail:
                return "duplicate", detail
            if e.code in (401, 403):
                return "stop", "AbuseIPDB rejected the key"
            if e.code == 429:
                return "stop", "AbuseIPDB's daily report limit is reached"
            return "error", f"HTTP {e.code}: {detail}" if detail else f"HTTP {e.code}"
        except (urllib.error.URLError, OSError) as e:
            return "stop", f"can't reach AbuseIPDB: {getattr(e, 'reason', e)}"[:200]

    def run(self, key: str, items: list, opener=urllib.request.urlopen) -> dict:
        if not key:
            raise ValueError("add an AbuseIPDB key in Settings first")
        if not self.lock.acquire(blocking=False):
            return {"sent": 0, "busy": True}
        self.status.update(running=True, error=None)
        sent, errors = 0, []
        try:
            for item in items[:min(PER_RUN, self.left_today())]:
                outcome, detail = self.send_one(key, item, opener)
                if outcome in ("sent", "duplicate"):
                    self.state["ips"][item["ip"]] = int(time.time() * 1000)
                if outcome == "sent":
                    sent += 1
                    self.state["today"] += 1
                    self.state["total"] += 1
                elif outcome == "stop":
                    errors.append(detail)
                    break
                elif outcome == "error":
                    errors.append(f"{item['ip']}: {detail}")
            self.save()
        finally:
            self.status.update(running=False, last_run=int(time.time() * 1000), sent=sent,
                               error="; ".join(errors[:3]) or None)
            self.lock.release()
        return {"sent": sent, "errors": errors[:10]}
