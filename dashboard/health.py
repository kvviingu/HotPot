"""What is wrong with the sensor right now, in plain words.

`problems()` turns the dashboard's sync state and the VM status probe into a short list the page shows as
a banner. Pure: no I/O, so it is easy to test. Thresholds are at the top. The alert helpers at the end send
a problem's title to an address the owner chose.
"""
import json
import urllib.parse
import urllib.request

SYNC_LATE_S = 600           # no good sync for this long
LOAD_PER_CPU = 6.0          # 5-minute load per CPU
DISK_WARN, DISK_BAD = 0.15, 0.07        # free share of the disk
MEM_WARN = 0.06             # available share of memory, with swap nearly gone too
SWAP_WARN = 0.15
COLLECTOR_LATE_S = 600      # the backend collector runs every minute
QUIET_S = {"cowrie_log": 6 * 3600, "web_log": 12 * 3600}    # the internet never leaves a sensor alone this long
QUIET_NAME = {"cowrie_log": "SSH honeypot", "web_log": "web honeypot"}
OK_STATES = {"active", "running"}
LEVELS = {"bad": 0, "warn": 1}


def _hours(sec: float) -> str:
    return f"{sec / 3600:.0f} h" if sec >= 7200 else f"{sec / 60:.0f} min"


def problems(status: dict, vm: dict, now_s: float) -> list:
    """[{id, level, title, detail}], worst first. `status` is the sync state, `vm` the last VM status (or None)."""
    out = []

    def add(pid, level, title, detail=""):
        out.append({"id": pid, "level": level, "title": title[:120], "detail": str(detail)[:300]})

    last_ok = status.get("last_ok")
    if status.get("error") and (not last_ok or now_s - last_ok > SYNC_LATE_S):
        add("sync", "bad", "The dashboard cannot reach the sensor",
            "No new data since " + (_hours(now_s - last_ok) + " ago" if last_ok else "it started")
            + ". Check your internet connection, then Status.")
    elif status.get("backend_error"):
        add("sync-backend", "warn", "Backend data is not arriving", "The front VM answers but the backend VM does not.")

    for v in (vm or {}).get("vms", []):
        key, name = v.get("key", "vm"), v.get("label", "VM")
        if not v.get("ok"):
            if key == "front" and any(p["id"] == "sync" for p in out):
                continue                                   # same cause, said once
            add(key + "-down", "bad", f"{name} does not answer", v.get("error", ""))
            continue
        cpus = max(1, int(v.get("cpus") or 1))
        load = (v.get("load") or [0, 0, 0])[1]
        if load >= LOAD_PER_CPU * cpus:
            add(key + "-load", "bad", f"{name} is overloaded (load {load:.0f})",
                "Something in it is using all the CPU; logins may hang. It resets itself after a few minutes "
                "if the backend is the cause.")
        total, free = v.get("disk_total") or 0, v.get("disk_free") or 0
        if total and free / total < DISK_WARN:
            add(key + "-disk", "bad" if free / total < DISK_BAD else "warn",
                f"{name} disk is {100 - 100 * free / total:.0f}% full", "Run: hotpot cleanup")
        mt, ma = v.get("mem_total") or 0, v.get("mem_avail") or 0
        st, sf = v.get("swap_total") or 0, v.get("swap_free") or 0
        if mt and ma / mt < MEM_WARN and (not st or sf / st < SWAP_WARN):
            add(key + "-mem", "warn", f"{name} is almost out of memory")
        down = [s.get("name", "?") for s in v.get("services", []) if s.get("state") not in OK_STATES]
        if down:
            add(key + "-services", "bad", f"{name}: {len(down)} service{'s' if len(down) > 1 else ''} not running",
                ", ".join(str(d)[:40] for d in down[:6]))
        ct = v.get("container")
        if isinstance(ct, dict):
            if ct.get("error") or str(ct.get("status", "")).lower() != "running":
                add("container", "bad", "The honeypot container is not running", ct.get("error") or ct.get("status", ""))
            elif not ct.get("clean_snapshot"):
                add("snapshot", "bad", "The container has no clean snapshot", "Resets cannot work. Run: hotpot deploy backend")
        data, now_ms = v.get("data") or {}, v.get("now") or now_s * 1000
        run = data.get("collector_run")
        if key == "backend" and run and now_ms - run > COLLECTOR_LATE_S * 1000:
            add("collector", "bad", "The backend collector has stopped",
                f"Last run {_hours((now_ms - run) / 1000)} ago; commands and samples are not being recorded.")
        for k, limit in QUIET_S.items():
            if data.get(k) and now_ms - data[k] > limit * 1000:
                add("quiet-" + k, "warn", f"Nothing has reached the {QUIET_NAME[k]} for {_hours((now_ms - data[k]) / 1000)}",
                    "Check the cloud firewall and the service on Status.")
    out.sort(key=lambda p: LEVELS[p["level"]])
    return out


# ----------------------------------------------------------------------------- alerts to a phone
# An optional address in Settings gets a short message when a serious problem appears or clears. Only the
# problem's title is sent: no addresses, no host names, no error text.
ALERT_REPEAT_S = 6 * 3600       # the same problem is not announced again within this time


def clean_alert_url(v) -> str:
    """Empty (off) or a checked https address. Raises ValueError with a plain reason."""
    v = str(v or "").strip()
    if not v:
        return ""
    u = urllib.parse.urlparse(v)
    if u.scheme != "https" or not u.hostname or len(v) > 400 or any(c.isspace() for c in v):
        raise ValueError("the alert address must be one https:// link without spaces")
    return v


def alert_host(url: str) -> str:
    return (urllib.parse.urlparse(url).hostname or "") if url else ""


def alert_request(url: str, title: str, body: str = "") -> urllib.request.Request:
    """The POST for one alert. Discord and Slack webhooks want JSON; anything else gets plain text with a
    Title header, which is what ntfy and most simple receivers take."""
    host, text = alert_host(url), (title + ("\n" + body if body else ""))[:900]
    if host.endswith(("discord.com", "discordapp.com")):
        data, head = json.dumps({"content": text}).encode(), {"Content-Type": "application/json"}
    elif host.endswith("slack.com"):
        data, head = json.dumps({"text": text}).encode(), {"Content-Type": "application/json"}
    else:
        data = (body or title).encode()
        head = {"Content-Type": "text/plain; charset=utf-8", "Title": title.encode("ascii", "replace").decode()[:120]}
    head["User-Agent"] = "hotpot-dashboard"
    return urllib.request.Request(url, data=data, headers=head, method="POST")


def alert_plan(items: list, state: dict, now_s: float) -> list:
    """Messages to send for the current problems, as (title, body). `state` remembers what was announced:
    {"active": {id: title}, "sent": {id: time}}. Only "bad" problems are announced, each at most once per
    ALERT_REPEAT_S, and once more when it is over."""
    active, sent = state.setdefault("active", {}), state.setdefault("sent", {})
    bad = {p["id"]: p["title"] for p in items if p.get("level") == "bad"}
    out = []
    for pid, title in bad.items():
        if pid not in active and now_s - sent.get(pid, 0) >= ALERT_REPEAT_S:
            out.append(("HotPot: " + title, ""))
            sent[pid] = now_s
            active[pid] = title
    for pid in [p for p in active if p not in bad]:
        out.append(("HotPot: resolved", active.pop(pid)))
    for pid in [p for p, t in sent.items() if now_s - t > 7 * 86400]:
        del sent[pid]
    return out


def send_alert(url: str, title: str, body: str = "", timeout: int = 15) -> int:
    with urllib.request.urlopen(alert_request(url, title, body), timeout=timeout) as r:
        return r.status
