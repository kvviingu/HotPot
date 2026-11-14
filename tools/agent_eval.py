#!/usr/bin/env python3
"""Measure how well the dashboard tells AI agents, scripts and people apart.

It makes SSH sessions of a KNOWN kind against your own honeypot, writes down when each one ran and what
it was, and later compares that with the class the dashboard gave each session.

    python tools/agent_eval.py script            scripted sessions (fast, fixed pauses, random pauses, bot one-liner)
    python tools/agent_eval.py agent             a test agent: a free OpenRouter model picks each command
    python tools/agent_eval.py mark agent --tool claude-code     label a session you run yourself (also: human, script)
    python tools/agent_eval.py report            score the dashboard against the labels

Run it from the PC whose address is in the dashboard's "own IPs": the sessions then stay out of the
normal views, the indicator export and the AbuseIPDB reports. Needs `pip install paramiko` (this tool
only; the dashboard and hotpot stay stdlib-only).

What leaves this PC: `agent` sends the honeypot's shell output to OpenRouter (free models only). That
output contains the decoy identity, like every attacker's model sees it; the sensor's and your own
addresses are replaced before sending.
"""
import argparse
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "dashboard", "data")
LABELS = os.path.join(DATA, "eval_labels.jsonl")
CREDS = os.path.join(DATA, "eval_login.json")
KINDS = ("agent", "script", "human")
# which dashboard classes count as right for each kind of session
EXPECTED = {"agent": {"agent_suspected", "agent_confirmed"}, "script": {"script", "known_bot"},
            "human": {"human_like"}}
CLASS_LABEL = {"script": "script", "known_bot": "known bot", "agent_suspected": "agent (suspected)",
               "agent_confirmed": "agent (canary)", "human_like": "human-like", "unknown": "not enough data"}
DEFAULT_MODELS = "cohere/north-mini-code:free,google/gemma-4-31b-it:free"
MAX_OUT = 2000          # shell output shown to the model per command
MAX_CMD = 300

RECON = ["id", "uname -a", "cat /etc/os-release", "ls -la /root", "df -h", "ps aux | head -20", "cat /etc/passwd",
         "ip addr", "ls /var/www", "crontab -l", "cat /root/.bash_history", "free -m", "w", "netstat -tlnp",
         "ls -la /home", "cat /etc/hosts"]
# name -> (what it is, commands, pause before each command in seconds)
SCRIPT_PROFILES = {
    "burst": ("commands fired with no pause", lambda: RECON[:8], lambda: random.uniform(0.05, 0.3)),
    "steady": ("fixed 5 s sleep between commands", lambda: random.sample(RECON, 8), lambda: 5.0),
    "random-sleep": ("random 1-15 s sleeps (a script trying to look alive)", lambda: random.sample(RECON, 8),
                     lambda: random.uniform(1, 15)),
    "survey": ("a botnet's one-line system survey", lambda: [
        "cat /proc/cpuinfo | grep name | wc -l", "cat /proc/cpuinfo | grep name | head -n 1",
        "free -m | grep Mem", "ls -lh $(which ls)", "uname -m", "uname -a", "whoami"], lambda: random.uniform(0.2, 0.8)),
}
AGENT_PROMPT = (
    "You are testing a Linux server in an authorised lab exercise. You have an SSH shell as root. "
    "Your goal: learn what this server is for and find any credentials, keys or secrets stored on it. "
    "Reply with exactly one shell command and nothing else: no explanation, no code fences. "
    "Each reply is run and you get its output. Never run anything destructive, never try to reach other "
    "machines. When you have a good picture, reply with the single word DONE.")


# ----------------------------------------------------------------------------- config

def conf_value(key: str, default: str = "") -> str:
    for name in ("honeypot.conf", "honeypot.conf.example"):
        try:
            with open(os.path.join(ROOT, name), encoding="utf-8") as f:
                for line in f:
                    if line.startswith(key + "="):
                        return line.split("=", 1)[1].strip().strip('"').strip("'")
        except OSError:
            pass
    return default


def dashboard_config() -> dict:
    try:
        with open(os.path.join(ROOT, "dashboard", "config.json"), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def openrouter_key() -> str:
    try:
        with open(os.path.join(ROOT, "secrets", "openrouter.env"), encoding="utf-8") as f:
            for line in f:
                if line.startswith("OPENROUTER_API_KEY="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return ""


def bait_passwords(n: int = 8) -> list:
    with open(os.path.join(ROOT, "cowrie", "patches", "passwords.txt"), encoding="utf-8") as f:
        return [x.strip() for x in f if x.strip() and not x.startswith("#")][:n]


# ----------------------------------------------------------------------------- labels

def add_label(kind: str, tool: str, t0: float, t1: float, note: str = "") -> None:
    os.makedirs(DATA, exist_ok=True)
    with open(LABELS, "a", encoding="utf-8") as f:
        f.write(json.dumps({"kind": kind, "tool": tool, "t0": int(t0 * 1000), "t1": int(t1 * 1000),
                            "note": note}) + "\n")


def read_labels(path: str = LABELS) -> list:
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    v = json.loads(line)
                except ValueError:
                    continue
                if isinstance(v, dict) and v.get("kind") in KINDS and isinstance(v.get("t0"), int) \
                        and isinstance(v.get("t1"), int):
                    out.append(v)
    except OSError:
        pass
    return out


# ----------------------------------------------------------------------------- scoring

def match(labels: list, sessions: list, own_ips: set, slack_ms: int = 15000) -> list:
    """Pair each label with the SSH sessions from our own addresses that started inside its window.
    Returns (label, session) pairs; a label without a session comes back with None."""
    mine = [s for s in sessions if s.get("ip") in own_ips and s.get("kind") in ("ssh", "telnet")]
    pairs, used = [], set()
    for lb in sorted(labels, key=lambda v: v["t1"] - v["t0"]):     # tightest window claims a session first
        got = [s for s in mine if s["id"] not in used and lb["t0"] - slack_ms <= s["start"] <= lb["t1"] + slack_ms]
        for s in got:
            used.add(s["id"])
            pairs.append((lb, s))
        if not got:
            pairs.append((lb, None))
    return pairs


def score(pairs: list) -> dict:
    """Counts per kind and class, and for the 'agent' class: precision and recall."""
    table = defaultdict(Counter)
    missing = Counter()
    for lb, s in pairs:
        if s is None:
            missing[lb["kind"]] += 1
        else:
            table[lb["kind"]][s.get("cls") or "unknown"] += 1
    total = sum(sum(c.values()) for c in table.values())
    right = sum(n for k, c in table.items() for cls, n in c.items() if cls in EXPECTED[k])
    said_agent = sum(n for c in table.values() for cls, n in c.items() if cls in EXPECTED["agent"])
    true_agent = sum(n for cls, n in table["agent"].items() if cls in EXPECTED["agent"])
    n_agent = sum(table["agent"].values())
    return {"table": {k: dict(v) for k, v in table.items() if v}, "missing": dict(missing), "total": total,
            "right": right, "accuracy": right / total if total else None,
            "agent_precision": true_agent / said_agent if said_agent else None,
            "agent_recall": true_agent / n_agent if n_agent else None}


def by_tool(pairs: list) -> dict:
    out = defaultdict(Counter)
    for lb, s in pairs:
        out[f"{lb['kind']}: {lb.get('tool') or '?'}"][(s.get("cls") or "unknown") if s else "(no session found)"] += 1
    return out


def pct(v) -> str:
    return "n/a" if v is None else f"{v * 100:.0f}%"


def fetch_json(url: str):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"Host": url.split("/")[2]}), timeout=60) as r:
        return json.loads(r.read().decode("utf-8"))


def report(args) -> int:
    labels = read_labels()
    if not labels:
        print("No labels yet. Run the script, agent or mark commands first.")
        return 1
    base = f"http://127.0.0.1:{int(dashboard_config().get('port', 8787))}"
    try:
        own = set(fetch_json(base + "/api/meta").get("own_ips") or [])
        sessions = fetch_json(base + "/api/sessions?range=all&own=1&kind=ssh")["sessions"]
    except (OSError, ValueError, KeyError) as e:
        print(f"The dashboard is not answering on {base} ({type(e).__name__}). Start it, wait for a sync, try again.")
        return 1
    if not own:
        print('The dashboard has no "own IPs" set (Settings). Add this PC\'s public address, then run again.')
        return 1
    pairs = match(labels, sessions, own)
    r = score(pairs)
    classes = [c for c in CLASS_LABEL if any(c in r["table"].get(k, {}) for k in KINDS)]
    print(f"\n{len(labels)} labelled runs, {r['total']} sessions found for them.\n")
    if not r["total"]:
        print("Nothing to score yet: the dashboard has no SSH session from your own addresses inside the labelled "
              "times. Wait for a sync (about a minute) and try again.")
        return 1
    print("What it really was".ljust(22) + "".join(CLASS_LABEL[c].rjust(19) for c in classes))
    for k in KINDS:
        if k in r["table"]:
            print(k.ljust(22) + "".join(str(r["table"][k].get(c, 0)).rjust(19) for c in classes))
    print(f"\nRight overall:    {r['right']} of {r['total']} ({pct(r['accuracy'])})")
    print(f"Agents caught:    {pct(r['agent_recall'])}   (of the real agent sessions, how many were called an agent)")
    print(f"Agent alarms true: {pct(r['agent_precision'])}   (of the sessions called an agent, how many really were)")
    print("\nBy tool:")
    for tool, c in sorted(by_tool(pairs).items()):
        print("  " + tool.ljust(34) + ", ".join(f"{n} x {CLASS_LABEL.get(cls, cls)}" for cls, n in c.most_common()))
    if r["missing"]:
        print("\nRuns with no session in the dashboard yet (not synced, login failed, or the run was too short): "
              + ", ".join(f"{n} {k}" for k, n in r["missing"].items()))
    if args.misses:
        print("\nWrong calls:")
        for lb, s in pairs:
            if s and s.get("cls") not in EXPECTED[lb["kind"]]:
                print(f"  {lb['kind']} ({lb.get('tool')}) -> {CLASS_LABEL.get(s.get('cls'), s.get('cls'))}, "
                      f"score {s.get('ascore')}, {s.get('n')} events, session {s['id']}")
    return 0


# ----------------------------------------------------------------------------- SSH

class Shell:
    """One SSH login with an interactive shell, like a person or an agent framework keeps open."""

    def __init__(self, host: str, port: int, user: str, password: str):
        import paramiko

        class Quiet(paramiko.MissingHostKeyPolicy):      # a honeypot's host key is not worth pinning
            def missing_host_key(self, client, hostname, key):
                return

        self.c = paramiko.SSHClient()
        self.c.set_missing_host_key_policy(Quiet())
        self.c.connect(host, port=port, username=user, password=password, allow_agent=False,
                       look_for_keys=False, timeout=20, banner_timeout=30, auth_timeout=30)
        self.ch = self.c.invoke_shell(term="xterm", width=120, height=40)
        self.read(idle=2.0)

    def read(self, idle: float = 1.5, limit: float = 40.0) -> str:
        buf, last, t0 = b"", time.time(), time.time()
        while time.time() - last < idle and time.time() - t0 < limit and len(buf) < 200_000:
            if self.ch.recv_ready():
                buf += self.ch.recv(65536)
                last = time.time()
            elif self.ch.closed:
                break
            else:
                time.sleep(0.05)
        return buf.decode("utf-8", "replace")

    def run(self, cmd: str) -> str:
        self.ch.send(cmd + "\n")
        return self.read()

    def close(self) -> None:
        try:
            self.c.close()
        except Exception:
            pass


def need_paramiko() -> bool:
    try:
        import paramiko  # noqa: F401
        return True
    except ImportError:
        print("This tool needs paramiko for SSH:  pip install paramiko")
        return False


def target(args):
    host = args.host or dashboard_config().get("ssh_host") or ""
    if not host:
        sys.exit("No honeypot address: set ssh_host in dashboard/config.json or pass --host.")
    return host, args.port


def login(host: str, port: int, user: str):
    """A (user, password) the honeypot accepts from here. It locks each (address, user) to the first bait
    password that worked, so the working one is remembered in dashboard/data (never printed)."""
    import paramiko
    try:
        with open(CREDS, encoding="utf-8") as f:
            saved = json.load(f)
        if saved.get("user") == user and saved.get("host") == host:
            return user, saved["password"]
    except (OSError, ValueError, KeyError):
        pass
    for pw in bait_passwords():
        try:
            Shell(host, port, user, pw).close()
        except paramiko.AuthenticationException:
            time.sleep(1)
            continue
        os.makedirs(DATA, exist_ok=True)
        with open(CREDS, "w", encoding="utf-8") as f:
            json.dump({"host": host, "user": user, "password": pw}, f)
        time.sleep(3)
        return user, pw
    sys.exit(f"None of the first bait passwords logged in as {user}. Try --user with another name.")


def run_script(args) -> int:
    if not need_paramiko():
        return 1
    host, port = target(args)
    names = list(SCRIPT_PROFILES) if args.profile == "all" else [args.profile]
    user, pw = login(host, port, args.user)
    for i in range(args.runs):
        for name in names:
            what, cmds, pause = SCRIPT_PROFILES[name]
            print(f"script/{name} run {i + 1}: {what}")
            t0 = time.time()
            sh = Shell(host, port, user, pw)
            try:
                for cmd in cmds():
                    time.sleep(pause())
                    sh.run(cmd)
            finally:
                sh.close()
            add_label("script", name, t0, time.time())
            time.sleep(args.gap)
    print("Done. Wait for the dashboard to sync, then: python tools/agent_eval.py report")
    return 0


# ----------------------------------------------------------------------------- the test agent

def hide_addresses(text: str, addresses) -> str:
    for a in addresses:
        if a:
            text = text.replace(a, "203.0.113.10")
    return text


def clean_output(text: str, addresses) -> str:
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\r", "", text)
    text = hide_addresses(text, addresses)
    return text if len(text) <= MAX_OUT else text[:MAX_OUT] + "\n[output cut]"


def command_from(reply: str) -> str:
    """The one shell command in a model's reply ('' when it says it is done or gave nothing usable)."""
    lines = [x.strip() for x in reply.strip().splitlines()]
    lines = [x for x in lines if x and not x.startswith("```")]
    if not lines:
        return ""
    cmd = lines[0].strip("`").strip()
    cmd = re.sub(r"^\$\s+", "", cmd)
    if cmd.upper().rstrip(".") == "DONE":
        return ""
    return cmd[:MAX_CMD]


def ask_model(key: str, models: list, messages: list) -> str:
    """One chat completion from the first free model that answers."""
    last = "no model configured"
    for model in models:
        if not model.endswith(":free"):
            continue
        body = json.dumps({"model": model, "messages": messages, "max_tokens": 120, "temperature": 0.7}).encode()
        req = urllib.request.Request("https://openrouter.ai/api/v1/chat/completions", data=body, headers={
            "Authorization": "Bearer " + key, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                v = json.loads(r.read().decode("utf-8"))
            text = (v.get("choices") or [{}])[0].get("message", {}).get("content") or ""
            if text.strip():
                return text
            last = f"{model}: empty answer"
        except urllib.error.HTTPError as e:
            last = f"{model}: HTTP {e.code}"
        except (OSError, ValueError) as e:
            last = f"{model}: {type(e).__name__}"
    raise RuntimeError(last)


def agent_session(shell, think, steps: int, addresses) -> int:
    """Let `think(messages) -> reply` drive `shell.run(cmd) -> output`. Returns how many commands ran."""
    messages = [{"role": "system", "content": AGENT_PROMPT},
                {"role": "user", "content": "You are logged in. Send your first command."}]
    n = 0
    for _ in range(steps):
        reply = think(messages)
        cmd = command_from(reply)
        if not cmd:
            break
        out = clean_output(shell.run(cmd), addresses)
        n += 1
        messages += [{"role": "assistant", "content": cmd}, {"role": "user", "content": out or "(no output)"}]
    return n


def run_agent(args) -> int:
    if not need_paramiko():
        return 1
    key = openrouter_key()
    if not key:
        print("No OpenRouter key in secrets/openrouter.env.")
        return 1
    models = [m.strip() for m in (args.models or conf_value("LLM_MODELS", DEFAULT_MODELS)).split(",") if m.strip()]
    if not any(m.endswith(":free") for m in models):
        print("Only free OpenRouter models are used (names ending in :free); none is configured.")
        return 1
    host, port = target(args)
    hide = [host] + list(dashboard_config().get("own_ips") or [])
    user, pw = login(host, port, args.user)
    for i in range(args.runs):
        print(f"agent run {i + 1} of {args.runs} (up to {args.steps} commands)…")
        t0 = time.time()
        sh = Shell(host, port, user, pw)
        try:
            n = agent_session(sh, lambda msgs: ask_model(key, models, msgs), args.steps, hide)
        except RuntimeError as e:
            print(f"  stopped: the model did not answer ({e})")
            n = -1
        finally:
            sh.close()
        if n >= 0:
            print(f"  ran {n} commands")
            add_label("agent", "test-agent:" + models[0], t0, time.time(), f"{n} commands")
        time.sleep(args.gap)
    print("Done. Wait for the dashboard to sync, then: python tools/agent_eval.py report")
    return 0


def run_mark(args) -> int:
    print(f"Labelling the next SSH session(s) from this PC as: {args.kind} ({args.tool}).")
    input("Press Enter right before you start the session… ")
    t0 = time.time()
    input("Session running. Press Enter when it has logged out… ")
    add_label(args.kind, args.tool, t0, time.time(), args.note)
    print("Saved. Wait for the dashboard to sync, then: python tools/agent_eval.py report")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def ssh_opts(p):
        p.add_argument("--host", default="", help="honeypot address (default: ssh_host from dashboard/config.json)")
        p.add_argument("--port", type=int, default=22, help="the honeypot's SSH port (default 22)")
        p.add_argument("--user", default="root")
        p.add_argument("--runs", type=int, default=3)
        p.add_argument("--gap", type=float, default=20, help="seconds between sessions")

    p = sub.add_parser("script", help="scripted sessions")
    ssh_opts(p)
    p.add_argument("--profile", choices=list(SCRIPT_PROFILES) + ["all"], default="all")
    p = sub.add_parser("agent", help="a test agent driven by a free OpenRouter model")
    ssh_opts(p)
    p.add_argument("--steps", type=int, default=12, help="most commands per session")
    p.add_argument("--models", default="", help="comma-separated free models (default: LLM_MODELS in honeypot.conf)")
    p = sub.add_parser("mark", help="label a session you run yourself")
    p.add_argument("kind", choices=KINDS)
    p.add_argument("--tool", required=True, help="what you used, e.g. claude-code, codex, putty")
    p.add_argument("--note", default="")
    p = sub.add_parser("report", help="score the dashboard against the labels")
    p.add_argument("--misses", action="store_true", help="list each wrong call")
    args = ap.parse_args(argv)
    return {"script": run_script, "agent": run_agent, "mark": run_mark, "report": report}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
