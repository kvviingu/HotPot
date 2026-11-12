"""Per-install identity of the honeypot (company, host name, canary values, tripwire credentials).

The repo's files are written for one reference persona, "Northbridge Logistics" on "fileserver01".
Because the repo is public, those exact values would let anyone recognise a HotPot box. So every
install gets its own values in persona.json (gitignored), and hotpot swaps the reference values for
them in every file it sends to the VMs. The dashboard reads the same file to recognise the canary
values and credentials when attackers use them.

Stdlib only; imported by hotpot.py and dashboard/server.py.
"""
import json
import os
import re
import secrets

ROOT = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(ROOT, "persona.json")

# The reference persona, exactly as it is written in the repo's files.
REFERENCE = {
    "brand": "Northbridge",
    "industry": "Logistics",
    "host": "fileserver01",
    "ini": "nb",
    "check": "NB-AGENT-CHECK",
    "ip": "10.0.0.15",
    # canary values (NB-AGENT-CHECK-<token>) of the files on the box
    "tokens": {"motd": "7f3a", "env": "2c9e", "runbook": "5b1d", "health": "8e4f"},
    # tripwire credentials: each exists in one bait file only
    "creds": {
        "runbook_ssh": "Brk-Gl4ss!fs01", "runbook_db": "Rt#db01-breakglass", "runbook_aws": "AKIAZ7NB4FS01KQ2M7XD",
        "monitor_redis": "Mon!tor-rds-7731", "monitor_es": "Es-M0n!2291",
        "k8s_db": "Kub3-db-Secr3t!", "k8s_redis": "Kub3-rds-Secr3t!", "k8s_registry": "Kub3-reg-Pull#77",
        "llms_key": "nbk_live_7Qm2Xc9TfA1LrP4w",
        "mcp_ssh": "Dpl-0ps!mcp7", "mcp_db": "Mcp-Db!5512", "mcp_aws": "AKIAZ7NB4MCP9QX2LD5E",
        "a2a_ssh": "A2a-Dpl!3391", "agentmd_ssh": "Ag3nt-Dpl#2207", "agentmd_db": "Ag3nt-Db#4410",
    },
}

BRANDS = ["Ashford", "Bayline", "Blackwater", "Brightwater", "Clearwater", "Coldbrook", "Eastgate", "Fairhaven",
          "Glenmore", "Greystone", "Harborline", "Highmoor", "Ironbridge", "Kestrel", "Kingsport", "Lakeside",
          "Larkspur", "Millbrook", "Northgate", "Oakridge", "Pinecrest", "Redwood", "Ridgeway", "Riverside",
          "Rockport", "Saltmarsh", "Silverlake", "Southport", "Stonegate", "Summit", "Thornbury", "Westfield",
          "Whitcombe", "Wildmoor", "Windham", "Yarrow"]
INDUSTRIES = ["Logistics", "Freight", "Distribution", "Shipping", "Cargo", "Transport"]
HOSTS = ["fs01", "files01", "fileserver02", "srv-files01", "nas01", "storage01", "srv-app01", "app01",
         "intranet01", "srv01", "fs-main", "files-prod01"]
CHECK_WORDS = (["AGENT", "AI", "AUTOMATION", "ASSIST"], ["CHECK", "VERIFY", "CONFIRM", "ACK"])
VISIBLE_INI_NAMES = ("healthcheck", "dispatch", "ops", "intranet", "app", "admin", "session", "monitor", "backups",
                     "backup", "laptop", "portal")
UPPER, LOWER, DIGIT = "ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789"


def _reshape(value: str, keep: int = 0) -> str:
    """A new random value shaped like `value`: same length, letter case and digits, same punctuation."""
    out = list(value[:keep])
    for ch in value[keep:]:
        pool = UPPER if ch.isupper() else LOWER if ch.islower() else DIGIT if ch.isdigit() else None
        out.append(secrets.choice(pool) if pool else ch)
    return "".join(out)


def generate(ip: str = "") -> dict:
    """A fresh random identity."""
    brand = secrets.choice(BRANDS)
    industry = secrets.choice(INDUSTRIES)
    ini = (brand[0] + industry[0]).lower()
    tokens, used = {}, {"ollama", "k8s", "llms", "oapi", "plug", "a2a", "mcp", "agmd"}
    for k in REFERENCE["tokens"]:
        while True:
            v = secrets.token_hex(2)
            if v not in used and not v.isdigit():
                used.add(v)
                tokens[k] = v
                break
    creds = {}
    for k, v in REFERENCE["creds"].items():
        if v.startswith("AKIA"):
            creds[k] = "AKIA" + "".join(secrets.choice(UPPER + DIGIT) for _ in range(len(v) - 4))
        elif v.startswith("nbk_live_"):
            creds[k] = f"{ini}k_live_" + _reshape(v[len("nbk_live_"):])
        else:
            creds[k] = _reshape(v)
    return {"version": 1, "brand": brand, "industry": industry, "host": secrets.choice(HOSTS), "ini": ini,
            "check": f"{ini.upper()}-{secrets.choice(CHECK_WORDS[0])}-{secrets.choice(CHECK_WORDS[1])}",
            "ip": ip or REFERENCE["ip"], "tokens": tokens, "creds": creds}


def reference() -> dict:
    return {"version": 1, **json.loads(json.dumps(REFERENCE))}


def load(path: str = None) -> dict:
    """The install's identity, or the reference persona when there is none yet."""
    try:
        with open(path or PATH, encoding="utf-8") as f:
            p = json.load(f)
        ref = reference()
        for k in ("brand", "industry", "host", "ini", "check", "ip"):
            if not isinstance(p.get(k), str) or not re.fullmatch(r"[A-Za-z0-9 .-]{1,40}", p[k]):
                p[k] = ref[k]
        p["tokens"] = {k: str(p.get("tokens", {}).get(k, v)) for k, v in ref["tokens"].items()}
        p["creds"] = {k: str(p.get("creds", {}).get(k, v)) for k, v in ref["creds"].items()}
        return p
    except (OSError, ValueError, AttributeError):
        return reference()


def save(p: dict, path: str = None) -> None:
    fd = os.open(path or PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        json.dump(p, f, indent=2)
        f.write("\n")


def pairs(p: dict) -> list:
    """(reference value, this install's value) for every string to swap, longest first."""
    r = REFERENCE
    rb, ri, pb, pi = r["brand"], r["industry"], p["brand"], p["industry"]
    out = [(f"{r['check']}-{r['tokens'][k]}", f"{p['check']}-{p['tokens'][k]}") for k in r["tokens"]]
    out += [(r["creds"][k], p["creds"][k]) for k in r["creds"]]
    out += [
        (r["check"], p["check"]),
        (f"{rb}-{ri}".lower(), f"{pb}-{pi}".lower()),        # northbridge-logistics.com
        (f"{rb} {ri}", f"{pb} {pi}"),
        (rb.upper(), pb.upper()), (rb, pb), (rb.lower(), pb.lower()),
        (r["host"].upper(), p["host"].upper()), (r["host"], p["host"]),
        (f"{r['ini']}ops", f"{p['ini']}ops"),
        (r["ip"], p["ip"]),
    ]
    # names on the box built from the company's initials (nb-intranet, nb_admin, NB-2026-104241, ...);
    # the honeypot's own plumbing (nb-collect, nb-reset, nb_patches) is never shown to attackers and stays
    ri_, pi_ = r["ini"], p["ini"]
    for w in VISIBLE_INI_NAMES:
        out += [(f"{ri_}-{w}", f"{pi_}-{w}"), (f"{ri_}_{w}", f"{pi_}_{w}")]
    for w in ("SEC-", "YYYY", *"0123456789"):          # ticket and shipment numbers: NB-412, NB-2026-104241
        out.append((f"{ri_.upper()}-{w}", f"{pi_.upper()}-{w}"))
    out = [(a, b) for a, b in out if a != b]
    return sorted(out, key=lambda ab: -len(ab[0]))


def is_reference(p: dict) -> bool:
    return not pairs(p)


def substitute(text: str, p: dict, prs: list = None) -> str:
    """Swap every reference value in `text` for this install's value, in one pass (no double swaps)."""
    prs = pairs(p) if prs is None else prs
    if not prs:
        return text
    table = dict(prs)
    rx = re.compile("|".join(re.escape(a) for a, _ in prs))
    return rx.sub(lambda m: table[m.group(0)], text)
