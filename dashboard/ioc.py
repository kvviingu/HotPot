"""Indicators of compromise from the dashboard's sessions, for sharing or for other tools.

Four kinds: attacker IP addresses, SHA-256 hashes of captured files, URLs attackers fetched or told
the box to fetch, and the domains of those URLs. Four formats: STIX 2.1 bundle, MISP event (JSON),
CSV, and a plain list of one kind (for blocklists).

All values are attacker-controlled. They are validated here (IPs parse as global addresses, hashes are
64 hex characters, URLs parse with a public host name) and only ever serialised as JSON or CSV with
escaping, so nothing in an export can break the file it sits in. Your own IPs, private addresses and
this install's own names never appear.
"""
import csv
import io
import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

KINDS = ("ip", "sha256", "url", "domain")
FORMATS = ("stix", "misp", "csv", "txt")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
URL_IN_TEXT = re.compile(r"\b(?:https?|ftp|tftp)://[^\s'\"<>;|`(){}\\]{1,500}", re.I)
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
LOCAL_TLDS = (".local", ".lan", ".internal", ".localdomain", ".home", ".corp", ".intranet", ".test", ".invalid",
              ".example", ".localhost")
NS = uuid.UUID("6f0d8a8e-6b5a-4f86-9a8e-4f7c2b0d9e11")  # HotPot's namespace: same value -> same STIX id
# STIX 2.1 predefined TLP marking definitions (spec section 7.2.1.4); TLP:CLEAR is TLP 1.0's WHITE
TLP_STIX = {"clear": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"}
CLASS_TEXT = {"script": "script or scanner", "known_bot": "known bot", "agent_suspected": "suspected AI agent",
              "agent_confirmed": "confirmed AI agent", "human": "human-like", "unknown": "unclassified"}
MAX_CMD = 4000


def global_ip(v) -> str:
    try:
        ip = ipaddress.ip_address(str(v).strip())
    except ValueError:
        return ""
    return str(ip) if ip.is_global else ""


def clean_url(raw, local_names=(), own=()) -> str:
    """The URL if it is http(s)/ftp/tftp with a public host, else ""."""
    u = str(raw or "").strip().rstrip(".,")[:500]
    try:
        p = urlsplit(u)
        host = (p.hostname or "").lower()
    except ValueError:
        return ""
    if p.scheme.lower() not in ("http", "https", "ftp", "tftp") or not host:
        return ""
    if host in own or global_ip(host) in own or not (global_ip(host) or public_domain(host, local_names)):
        return ""
    if any(ord(c) < 33 or ord(c) == 127 for c in u):
        return ""
    return u


def public_domain(host, local_names=()) -> str:
    h = str(host or "").lower().rstrip(".")
    if not DOMAIN_RE.match(h) or h.endswith(LOCAL_TLDS):
        return ""
    if any(n and n in h for n in local_names):  # this install's own (fake) company names
        return ""
    return h


def _ms_iso(ms) -> str:
    return datetime.fromtimestamp((ms or 0) / 1000, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# ----------------------------------------------------------------------------- collecting

def engaged(x: dict) -> bool:
    """Did more than knock: logged in, ran commands, read data, dropped files or tripped a lure."""
    return x.get("stage", 0) >= 2 or bool(x.get("trips")) or any(
        e.get("type") in ("file", "fetch") for e in x.get("_backend", ()))


def collect(sessions, samples, own=(), since_ms=0, only_engaged=False, local_names=(), geo_of=None) -> dict:
    """{"ip": {value: info}, "sha256": {...}, "url": {...}, "domain": {...}}.
    info: first, last (ms), sessions, kinds, classes, stage, tech, campaigns, note, plus geo for IPs."""
    out = {k: {} for k in KINDS}

    def add(kind, value, x, t, note=""):
        if not value:
            return
        r = out[kind].get(value)
        if r is None:
            r = out[kind][value] = {"first": t, "last": t, "sessions": 0, "kinds": set(), "classes": set(),
                                    "stage": 0, "tech": set(), "campaigns": set(), "ips": set(), "note": note}
        r["first"] = min(r["first"] or t, t or r["first"])
        r["last"] = max(r["last"] or 0, t or 0)
        if x is not None:
            r["sessions"] += 1
            r["kinds"].add(x.get("kind", ""))
            r["classes"].add(x.get("cls", ""))
            r["stage"] = max(r["stage"], x.get("stage", 0))
            r["tech"].update(x.get("tech") or ())
            if x.get("campaign"):
                r["campaigns"].add(str(x["campaign"])[:40])
            if kind != "ip" and global_ip(x.get("ip")) and x["ip"] not in own:
                r["ips"].add(x["ip"])
        if note and not r["note"]:
            r["note"] = note

    session_ids = set()
    for x in sessions:
        if x.get("end", 0) < since_ms or x.get("ip") in own:
            continue
        if only_engaged and not engaged(x):
            continue
        session_ids.add(x.get("id"))
        add("ip", global_ip(x.get("ip")), x, x.get("start"))
        urls = []
        for e in x.get("_backend", ()):
            if e.get("type") == "fetch":
                urls.append((e.get("url"), e.get("t"), "fetched by the attacker in the real shell"))
            elif e.get("type") == "exec":
                for m in URL_IN_TEXT.findall(str(e.get("argv") or "")[:MAX_CMD]):
                    urls.append((m, e.get("t"), "in a command line"))
        for e in x.get("_events", ()):
            ev = e.get("eventid")
            if ev in ("cowrie.session.file_download", "cowrie.session.file_upload") and e.get("url"):
                urls.append((e.get("url"), e.get("t"), "downloaded in the fake shell"))
            elif ev == "cowrie.command.input":
                for m in URL_IN_TEXT.findall(str(e.get("input") or "")[:MAX_CMD]):
                    urls.append((m, e.get("t"), "in a command line"))
        for raw, t, note in urls:
            u = clean_url(raw, local_names, own)
            if u:
                add("url", u, x, t, note)
                add("domain", public_domain(urlsplit(u).hostname, local_names), x, t)
    for r in samples:
        if not SHA_RE.match(str(r.get("sha", ""))) or r.get("own_only"):
            continue
        linked = [v for v in r.get("sessions", ()) if v.get("id") in session_ids]
        if not linked and (r.get("last") or 0) < since_ms:
            continue
        if not only_engaged or linked or not r.get("sessions"):
            names = ", ".join(str(n)[:120] for n in r.get("names", [])[:3])
            add("sha256", r["sha"], None, r.get("first") or r.get("last"),
                (r.get("how") or "captured") + (f" ({names})" if names else ""))
            rec = out["sha256"][r["sha"]]
            rec["sessions"] = len(r.get("sessions", ()))
            rec["ips"].update(v["ip"] for v in r.get("sessions", ())
                              if global_ip(v.get("ip")) and not v.get("own") and v["ip"] not in own)
            rec["yara"] = [y.get("rule") for y in r.get("yara", ()) if y.get("rule")]
            rec["size"] = r.get("size")
    if geo_of:
        for ip, r in out["ip"].items():
            g = geo_of(ip) or {}
            r.update(cc=g.get("cc") or "", country=g.get("country") or "", asn=g.get("asn") or "", org=g.get("org") or "")
    return out


def describe(kind, value, r) -> str:
    parts = []
    if kind == "ip":
        cls = ", ".join(sorted(CLASS_TEXT.get(c, c) for c in r["classes"] if c)) or "unclassified"
        kinds = ", ".join(sorted(k for k in r["kinds"] if k))
        parts.append(f"Attacker seen by a HotPot honeypot in {r['sessions']} session(s) ({kinds}); {cls}.")
    elif kind == "sha256":
        parts.append(f"File captured by a HotPot honeypot: {r['note']}.")
        if r.get("yara"):
            parts.append("YARA: " + ", ".join(r["yara"][:5]) + ".")
    elif kind == "url":
        parts.append(f"URL used by an attacker on a HotPot honeypot ({r['note'] or 'seen'}).")
    else:
        parts.append("Domain of a URL used by an attacker on a HotPot honeypot.")
    if r["tech"]:
        parts.append("ATT&CK: " + ", ".join(sorted(r["tech"])[:12]) + ".")
    if r["campaigns"]:
        parts.append("Campaign: " + ", ".join(sorted(r["campaigns"])[:3]) + ".")
    return " ".join(parts)


def rows(iocs, kinds=KINDS):
    for kind in kinds:
        for value, r in sorted(iocs[kind].items(), key=lambda kv: -(kv[1]["last"] or 0)):
            yield kind, value, r


# ----------------------------------------------------------------------------- formats

def to_txt(iocs, kind) -> str:
    return "".join(v + "\n" for _k, v, _r in rows(iocs, (kind,)))


def to_csv(iocs, kinds=KINDS) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(["type", "value", "first_seen_utc", "last_seen_utc", "sessions", "session_kinds", "classes",
                "deepest_stage", "attack_techniques", "campaigns", "related_ips", "country", "asn", "org", "description"])
    for kind, v, r in rows(iocs, kinds):
        cells = [kind, v, _ms_iso(r["first"]), _ms_iso(r["last"]), r["sessions"], " ".join(sorted(r["kinds"] - {""})),
                 " ".join(sorted(r["classes"] - {""})), r["stage"], " ".join(sorted(r["tech"])),
                 " ".join(sorted(r["campaigns"])), " ".join(sorted(r["ips"])[:20]), r.get("cc", ""),
                 r.get("asn", ""), r.get("org", ""), describe(kind, v, r)]
        # a spreadsheet would run a cell starting with = + - @ as a formula; these are attacker strings
        w.writerow(["'" + c if isinstance(c, str) and c[:1] in ("=", "+", "-", "@", "\t", "\r") else c for c in cells])
    return "﻿" + buf.getvalue()


def _stix_str(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'")


def stix_pattern(kind, v) -> str:
    if kind == "ip":
        return f"[{'ipv6-addr' if ':' in v else 'ipv4-addr'}:value = '{v}']"
    if kind == "sha256":
        return f"[file:hashes.'SHA-256' = '{v}']"
    if kind == "url":
        return f"[url:value = '{_stix_str(v)}']"
    return f"[domain-name:value = '{_stix_str(v)}']"


def to_stix(iocs, sensor="HotPot honeypot", tlp="clear", now_ms=None, kinds=KINDS) -> str:
    now = _ms_iso(now_ms) if now_ms else datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    ident = "identity--" + str(uuid.uuid5(NS, "identity:" + sensor))
    marks = [TLP_STIX[tlp]] if tlp in TLP_STIX else []
    objs = [{"type": "identity", "spec_version": "2.1", "id": ident, "created": now, "modified": now,
             "name": sensor, "identity_class": "system"}]
    types = {"ip": ["malicious-activity"], "sha256": ["malicious-activity"], "url": ["malicious-activity"],
             "domain": ["malicious-activity"]}
    for kind, v, r in rows(iocs, kinds):
        first = _ms_iso(r["first"])
        o = {"type": "indicator", "spec_version": "2.1", "id": "indicator--" + str(uuid.uuid5(NS, kind + ":" + v)),
             "created_by_ref": ident, "created": now, "modified": now, "name": f"{kind}: {v}"[:300],
             "description": describe(kind, v, r), "indicator_types": types[kind], "pattern": stix_pattern(kind, v),
             "pattern_type": "stix", "valid_from": first, "labels": ["honeypot"]}
        if kind == "ip":
            o["labels"] += sorted(c for c in r["classes"] if c)
        if r["tech"]:
            o["external_references"] = [{"source_name": "mitre-attack", "external_id": t,
                                         "url": "https://attack.mitre.org/techniques/" + t.replace(".", "/") + "/"}
                                        for t in sorted(r["tech"])[:20]]
        if marks:
            o["object_marking_refs"] = marks
        objs.append(o)
    return json.dumps({"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": objs}, indent=1)


MISP_TYPE = {"ip": ("ip-src", "Network activity"), "sha256": ("sha256", "Payload delivery"),
             "url": ("url", "Network activity"), "domain": ("domain", "Network activity")}


def to_misp(iocs, sensor="HotPot honeypot", tlp="clear", period="", now_ms=None, kinds=KINDS) -> str:
    today = datetime.fromtimestamp((now_ms or 0) / 1000, timezone.utc) if now_ms else datetime.now(timezone.utc)
    attrs = []
    for kind, v, r in rows(iocs, kinds):
        typ, cat = MISP_TYPE[kind]
        a = {"uuid": str(uuid.uuid5(NS, "misp:" + kind + ":" + v)), "type": typ, "category": cat, "value": v,
             "to_ids": kind != "domain", "comment": describe(kind, v, r)[:1000],
             "first_seen": _ms_iso(r["first"]), "last_seen": _ms_iso(r["last"])}
        attrs.append(a)
    ev = {"info": f"{sensor}: attacker indicators{(' (' + period + ')') if period else ''}",
          "date": today.strftime("%Y-%m-%d"), "threat_level_id": "3", "analysis": "2", "distribution": "0",
          "published": False, "Tag": [{"name": "tlp:" + tlp}, {"name": "honeypot"}], "Attribute": attrs}
    return json.dumps({"Event": ev}, indent=1)
