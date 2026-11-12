#!/usr/bin/env python3
"""hotpot - set up, deploy and run a HotPot honeypot from your own computer.

Plain Python 3.10+ with no extra packages, so it runs on Windows, macOS and Linux. It talks to the VMs
with the OpenSSH client that comes with those systems; the backend VM is reached through the front VM.

    hotpot setup                    questions -> honeypot.conf -> checks -> deploy
    hotpot check                    check honeypot.conf, SSH access and both VMs (changes nothing)
    hotpot deploy [front|backend]   install or update both VMs (or one)
    hotpot persona                  quick backend update: persona files, tripwires, scripts
    hotpot identity [show|new|keep] this install's company, host name, canary values and credentials
    hotpot ports                    test the public ports from this computer
    hotpot status                   service health on both VMs
    hotpot dashboard                start the local dashboard and open it in the browser
    hotpot ssh front|backend [cmd]  shell on a VM
    hotpot update                   get the latest release (your settings stay), then redeploy
    hotpot version                  this copy's version
"""
import argparse
import getpass
import io
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request
import webbrowser

import persona

if sys.version_info < (3, 10):
    sys.exit("hotpot needs Python 3.10 or newer (this is %d.%d)" % sys.version_info[:2])

VERSION = "1.0.0"
REPO = "kvviingu/HotPot"
ROOT = os.path.dirname(os.path.abspath(__file__))
CONF = os.path.join(ROOT, os.environ.get("HONEYPOT_CONF", "honeypot.conf"))
EXAMPLE = os.path.join(ROOT, "honeypot.conf.example")
OPENROUTER_ENV = os.path.join(ROOT, "secrets", "openrouter.env")
DASH_DIR = os.path.join(ROOT, "dashboard")
DASH_CONFIG = os.path.join(DASH_DIR, "config.json")
BUNDLE_PATHS = ("install", "docker-compose.yml", "cowrie", "web", "egress", "decoys", "ids", "backend")
WIN = os.name == "nt"

DECOYS = {"redis": 6379, "docker": 2375, "elastic": 9200, "mysql": 3306, "ollama": 11434, "k8s": 6443,
          "rdp": 3389, "smb": 445}
PROVIDERS = {  # name: (label, default SSH user on Ubuntu images, where the firewall lives)
    "oracle": ("Oracle Cloud", "ubuntu",
               "Networking > Virtual cloud networks > your VCN > Security Lists (or the instance's NSG)"),
    "aws": ("AWS", "ubuntu", "EC2 > Instances > your instance > Security > Security groups > Edit inbound rules"),
    "gcp": ("Google Cloud", "", "VPC network > Firewall > Create firewall rule"),
    "azure": ("Azure", "azureuser", "Virtual machine > Networking > Add inbound port rule"),
    "hetzner": ("Hetzner", "root", "Cloud Console > Firewalls > your firewall > Inbound rules"),
    "digitalocean": ("DigitalOcean", "root", "Networking > Firewalls > your firewall > Inbound Rules"),
    "other": ("another provider", "", "your provider's firewall (security group / security list)"),
}

# ---------------------------------------------------------------------------------------------- output
COLOR = sys.stdout.isatty() and (not WIN or os.environ.get("WT_SESSION") or os.environ.get("TERM"))
if WIN:
    os.system("")  # turns on ANSI colours in the classic Windows console


def _c(code, s):
    return f"\033[{code}m{s}\033[0m" if COLOR else s


def say(msg):
    print(_c("1;36", "==> ") + msg, flush=True)


def ok(msg):
    print("  " + _c("32", "ok  ") + msg, flush=True)


def warn(msg):
    print("  " + _c("33", "warn ") + msg, flush=True)


def bad(msg):
    print("  " + _c("31", "FAIL ") + msg, flush=True)


class Fail(Exception):
    pass


def die(msg):
    raise Fail(msg)


# ---------------------------------------------------------------------------------------------- config
KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
# values are also read by bash on the VMs (sourced), so the wizard only writes shell-safe characters
SAFE_VALUE = re.compile(r"^[A-Za-z0-9._,:/~@+%-]*$")


def read_conf(path=CONF):
    conf = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = KEY_RE.match(line.rstrip("\r\n"))
            if m:
                conf[m.group(1)] = m.group(2)
    return conf


def write_conf(updates, path=CONF):
    """Change KEY=value lines in place (keeping comments and order); new keys go at the end."""
    src = path if os.path.exists(path) else EXAMPLE
    with open(src, encoding="utf-8") as f:
        lines = f.read().replace("\r\n", "\n").split("\n")
    left = dict(updates)
    for i, line in enumerate(lines):
        m = KEY_RE.match(line)
        if m and m.group(1) in left:
            lines[i] = f"{m.group(1)}={left.pop(m.group(1))}"
    if left:
        if lines and lines[-1] == "":
            lines.pop()
        lines += [f"{k}={v}" for k, v in left.items()] + [""]
    for k, v in updates.items():
        if not SAFE_VALUE.match(v):
            die(f"refusing to write {k}={v!r}: only letters, digits and . , : / ~ @ + % - are allowed")
    if os.path.exists(path):
        shutil.copyfile(path, path + ".bak")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))


def expand(p):
    return os.path.expanduser(p.replace("/", os.sep) if WIN and not p.startswith("~") else p)


def is_ip(s, private=None):
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return ip.version == 4 and (private is None or ip.is_private == private)


def validate(conf):
    """Problems with the settings that would make a deploy fail, as a list of messages."""
    errs = []
    need = ["FRONT_PUBLIC_IP", "FRONT_PRIVATE_IP", "ADMIN_SSH_PORT", "SSH_USER", "SSH_KEY", "KNOWN_HOSTS",
            "BACKEND_ENABLED"]
    if conf.get("BACKEND_ENABLED") == "1":
        need += ["BACKEND_IP", "BACKEND_SSH_PORT", "BACKEND_TELNET_PORT", "CT_NAME"]
    for k in need:
        if not conf.get(k):
            errs.append(f"{k} is not set")
    for k in ("FRONT_PUBLIC_IP", "FRONT_PRIVATE_IP", "BACKEND_IP"):
        v = conf.get(k, "")
        if v and not is_ip(v):
            errs.append(f"{k}={v} is not an IPv4 address")
    if conf.get("FRONT_PRIVATE_IP") and is_ip(conf["FRONT_PRIVATE_IP"], private=False):
        errs.append(f"FRONT_PRIVATE_IP={conf['FRONT_PRIVATE_IP']} is a public address; use the VM's private one")
    p = conf.get("ADMIN_SSH_PORT", "")
    if p and (not p.isdigit() or not 1024 <= int(p) <= 65535 or int(p) in DECOYS.values()):
        errs.append(f"ADMIN_SSH_PORT={p} must be a free port between 1024 and 65535")
    for k, v in conf.items():
        if not SAFE_VALUE.match(v) and k not in ("LLM_MODELS",):
            errs.append(f"{k} contains characters that are not safe in a shell")
    return errs


def load(strict=True):
    if not os.path.exists(CONF):
        die(f"{os.path.basename(CONF)} not found. Run: hotpot setup")
    conf = read_conf()
    errs = validate(conf)
    if errs and strict:
        die("honeypot.conf has problems:\n  " + "\n  ".join(errs) + "\nFix them, or run: hotpot setup")
    return conf


# ---------------------------------------------------------------------------------------------- ssh
def find_tool(name):
    cands = [shutil.which(name)]
    if WIN:
        cands += [rf"C:\Windows\System32\OpenSSH\{name}.exe", rf"C:\Program Files\Git\usr\bin\{name}.exe"]
    for c in cands:
        if c and os.path.exists(c):
            return c
    hint = ("Settings > Apps > Optional features > OpenSSH Client" if WIN
            else "your package manager (openssh-client)")
    die(f"the {name} program was not found; install the OpenSSH client from {hint}")


class VMs:
    """SSH access to the front VM, and to the backend VM through it."""

    def __init__(self, conf):
        self.c = conf
        self.key = expand(conf["SSH_KEY"])
        self.kh = expand(conf["KNOWN_HOSTS"])
        if not os.path.exists(self.key):
            die(f"SSH key {self.key} not found (run hotpot setup to create one)")
        os.makedirs(os.path.dirname(self.kh) or ".", exist_ok=True)
        if not os.path.exists(self.kh):
            open(self.kh, "a").close()
        self.ssh = find_tool("ssh")
        self.port = None

    def base(self, batch=True):
        # the first contact trusts and records the VM's host key; after that a changed key is refused
        a = [self.ssh, "-i", self.key, "-o", "UserKnownHostsFile=" + self.kh,
             "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=12", "-o", "ServerAliveInterval=30"]
        return a + (["-o", "BatchMode=yes"] if batch else [])

    @property
    def front_host(self):
        return f"{self.c['SSH_USER']}@{self.c['FRONT_PUBLIC_IP']}"

    def reaches(self, port):
        r = subprocess.run(self.base() + ["-n", "-p", str(port), self.front_host, "true"],
                           stdin=subprocess.DEVNULL, capture_output=True)
        return r.returncode == 0

    def front_port(self):
        if self.port:
            return self.port
        for p in (self.c["ADMIN_SSH_PORT"], "22"):
            if self.reaches(p):
                self.port = p
                return p
        die(f"cannot SSH to {self.front_host} on port {self.c['ADMIN_SSH_PORT']} or 22 with {self.key}.\n"
            "  Is the VM running, is its public IP right, and does it have this key's public half?")

    def front(self, remote, tty=False):
        return self.base(batch=not tty) + (["-t"] if tty else []) + ["-p", self.front_port(), self.front_host] + \
            ([remote] if remote else [])

    def backend(self, remote, tty=False):
        jump = self.base() + ["-p", self.front_port(), "-W", "%h:%p", self.front_host]
        # ssh re-parses ProxyCommand: backslashes would vanish, so forward slashes on Windows
        jump_cmd = " ".join(f'"{a}"' if " " in a else a for a in (x.replace("\\", "/") for x in jump))
        return self.base(batch=not tty) + (["-t"] if tty else []) + ["-o", "ProxyCommand=" + jump_cmd,
                                                                    f"{self.c['SSH_USER']}@{self.c['BACKEND_IP']}"] + \
            ([remote] if remote else [])

    def argv(self, vm, remote, tty=False):
        return self.front(remote, tty) if vm == "front" else self.backend(remote, tty)

    def run(self, vm, remote, data=None, capture=False):
        r = subprocess.run(self.argv(vm, remote), input=data,
                           stdin=None if data is not None else subprocess.DEVNULL,
                           capture_output=capture)
        return r

    # -- shipping the installers ------------------------------------------------------------------------
    def bundle(self, extra):
        """The repo files a VM needs, plus honeypot.conf and `extra` {path: bytes}, as tar.gz bytes.
        Text files and paths carry this install's identity instead of the repo's reference persona."""
        ident = persona.load()
        prs = persona.pairs(ident)

        def clean(ti):
            if "__pycache__" in ti.name or ti.name.endswith("fs.pickle"):
                return None
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            # Windows reports every file as 0666: set sane modes (root copies them as they are on the VM)
            if ti.isdir():
                ti.mode = 0o755
            elif ti.isfile():
                ti.mode = 0o755 if ti.name.endswith((".sh", ".py")) or ti.mode & 0o100 else 0o644
            return ti

        def add(tar, path, arc):
            ti = clean(tar.gettarinfo(path, arcname=persona.substitute(arc, ident, prs)))
            if ti is None:
                return
            if ti.isdir():
                tar.addfile(ti)
                for name in sorted(os.listdir(path)):
                    add(tar, os.path.join(path, name), arc + "/" + name)
            elif ti.isfile():
                with open(path, "rb") as f:
                    data = f.read()
                if prs:
                    try:
                        data = persona.substitute(data.decode("utf-8"), ident, prs).encode("utf-8")
                    except UnicodeDecodeError:
                        pass                          # binary file: sent as it is
                ti.size = len(data)
                tar.addfile(ti, io.BytesIO(data))
            else:
                tar.addfile(ti)

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for p in BUNDLE_PATHS:
                add(tar, os.path.join(ROOT, p), p)
            with open(CONF, "rb") as f:
                extra = {"honeypot.conf": f.read(), **extra}
            for name, data in extra.items():
                ti = tarfile.TarInfo(name)
                ti.size, ti.mode, ti.mtime = len(data), 0o600, int(time.time())
                tar.addfile(ti, io.BytesIO(data))
        return buf.getvalue()

    def install(self, vm, script, *args, extra=None, capture=False):
        remote = ("set -e; rm -rf ~/.honeypot-src; mkdir -m 700 ~/.honeypot-src; "
                  "tar xzf - -C ~/.honeypot-src; trap 'rm -rf ~/.honeypot-src' EXIT; "
                  f"sudo bash ~/.honeypot-src/install/{script} {' '.join(args)}")
        return self.run(vm, remote, data=self.bundle(extra or {}), capture=capture).returncode


def backend_on(conf):
    return conf.get("BACKEND_ENABLED") == "1"


# ---------------------------------------------------------------------------------------------- commands
def cmd_check(conf, vms):
    rc = 0
    say(f"front VM {conf['FRONT_PUBLIC_IP']}")
    p = vms.front_port()
    print(f"  SSH ok on port {p}" + ("" if p == conf["ADMIN_SSH_PORT"] else " (admin port not moved yet)"))
    rc |= vms.install("front", "front.sh", "--check") != 0
    if backend_on(conf):
        say(f"backend VM {conf['BACKEND_IP']} (through the front VM)")
        if vms.run("backend", "true", capture=True).returncode == 0:
            rc |= vms.install("backend", "backend.sh", "--check") != 0
        else:
            print(f"  not reachable yet (create it, and allow TCP 22 from {conf['FRONT_PRIVATE_IP']} "
                  "in its firewall)")
            rc = 1
    return rc


def cmd_front(conf, vms):
    p = vms.front_port()
    admin = conf["ADMIN_SSH_PORT"]
    extra = {}
    if os.path.exists(OPENROUTER_ENV):
        with open(OPENROUTER_ENV, "rb") as f:
            extra["secrets/openrouter.env"] = f.read()
    if p != admin:
        say(f"Cowrie needs port 22, so admin SSH moves to port {admin}")
        print(f"  Allow TCP {admin} from your IP in the cloud firewall. If it is blocked nothing breaks:\n"
              "  the new port is tested from here, and the move is undone if it cannot be reached.")
    say(f"Installing the front VM ({conf['FRONT_PUBLIC_IP']})")
    rc = vms.install("front", "front.sh", extra=extra)
    if rc == 3:
        # step 1 of the SSH move is done: sshd listens on 22 and on the admin port, with an undo timer armed
        say(f"Testing admin SSH on port {admin} from this computer")
        for i in range(3):
            if vms.reaches(admin):
                break
            time.sleep(5)
        else:
            vms.install("front", "front.sh", "--revert-ssh", extra=extra)
            die(f"port {admin} cannot be reached from here, so admin SSH was put back on port 22.\n"
                f"  Allow TCP {admin} from your IP in the cloud firewall, then run: hotpot deploy front")
        vms.port = admin
        say(f"Port {admin} works; finishing the install")
        rc = vms.install("front", "front.sh", "--confirm-ssh", extra=extra)
    if rc != 0:
        die(f"the front VM install failed (exit {rc}); the log is /var/log/hotpot-install.log on the VM.\n"
            "  Fix the cause and run the same command again: every step is safe to repeat.")
    vms.port = None


def cmd_backend(conf, vms):
    if not backend_on(conf):
        die("BACKEND_ENABLED is not 1 in honeypot.conf")
    # the backend login password lives on the front VM; carry it across without printing it
    r = vms.run("front", "sudo cat /opt/honeypot/backend.env", capture=True)
    if r.returncode != 0 or not r.stdout.strip():
        die("the front VM has no /opt/honeypot/backend.env; deploy the front VM first")
    say(f"Installing the backend VM ({conf['BACKEND_IP']}); this takes a few minutes the first time")
    rc = vms.install("backend", "backend.sh", extra={"backend.env": r.stdout})
    if rc != 0:
        die(f"the backend VM install failed (exit {rc}); the log is /var/log/hotpot-install.log on that VM")


def cmd_persona(conf, vms):
    if not backend_on(conf):
        die("BACKEND_ENABLED is not 1 in honeypot.conf")
    say(f"Updating persona, tripwires and backend scripts on {conf['BACKEND_IP']} (no package installs)")
    remote = ("set -e; rm -rf ~/.honeypot-src; mkdir -m 700 ~/.honeypot-src; tar xzf - -C ~/.honeypot-src; "
              "trap 'rm -rf ~/.honeypot-src' EXIT; S=~/.honeypot-src; "
              "sudo install -m 750 $S/backend/nb-collect.py /usr/local/sbin/nb-collect.py; "
              "sudo install -m 750 $S/backend/nb-reset.sh /usr/local/sbin/nb-reset.sh; "
              "sudo tar czf /root/persona.tar.gz -C $S/cowrie/honeyfs .; "
              "sudo bash $S/backend/refresh_persona.sh; sudo rm -f /root/persona.tar.gz")
    if vms.run("backend", remote, data=vms.bundle({})).returncode != 0:
        die("the persona update failed")


def need_identity():
    if not os.path.exists(persona.PATH):
        die("this install has no identity yet (persona.json). Run one of:\n"
            "  hotpot identity new    fresh random company, host name, canary values and credentials\n"
            "  hotpot identity keep   keep the repo's reference persona (only for VMs already deployed with it)")


def show_identity(p):
    ref = persona.is_reference(p)
    print(f"  company:   {p['brand']} {p['industry']}" + ("  (the repo's reference persona, publicly known)" if ref else ""))
    print(f"  host name: {p['host']}")
    print(f"  domain:    {p['brand'].lower()}-{p['industry'].lower()}.com, internal {p['brand'].lower()}.local")
    print(f"  canaries:  {p['check']}-<lure>")
    print(f"  tripwire credentials: {len(p['creds'])} (in persona.json)")


def cmd_identity(conf, action):
    have = os.path.exists(persona.PATH)
    if action == "show":
        if not have:
            need_identity()
        show_identity(persona.load())
        return 0
    if action == "keep":
        if have and not yes("persona.json exists. Replace it with the reference persona?", False):
            return 1
        persona.save(persona.reference())
        warn("kept the reference persona: anyone who has read the HotPot repo can recognise this box")
        return 0
    if have and not yes("This replaces the identity in persona.json. The VMs keep the old one until you "
                        "redeploy. Continue?", False):
        return 1
    p = persona.generate(conf.get("FRONT_PRIVATE_IP", "") if conf else "")
    persona.save(p)
    ok("new identity saved to persona.json")
    show_identity(p)
    if have:
        print("  Apply it with: hotpot deploy. A backend container that already exists keeps its old host name\n"
              "  and files until it is rebuilt (docs/operations.md, Changing the identity).")
    return 0


# files and folders that belong to this install, never replaced by an update
KEEP = ("honeypot.conf", "honeypot.conf.bak", "persona.json", "secrets/", "dashboard/config.json", "dashboard/data/",
        "dashboard/reports/", ".git/")


def version_of(text):
    m = re.search(r'^VERSION = "([0-9][0-9A-Za-z.+-]*)"', text, re.M)
    return m.group(1) if m else "?"


def vtuple(v):
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.+-]", v.lstrip("v"))[:3])


def fetch(url, limit=64 * 1024 * 1024):
    req = urllib.request.Request(url, headers={"User-Agent": f"hotpot/{VERSION}",
                                               "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise OSError("download larger than expected")
    return data


def unpack_release(data, dest):
    """Unpack a GitHub release tarball over `dest`, skipping the install's own files. Returns files written."""
    n = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for m in tar.getmembers():
            parts = m.name.replace("\\", "/").split("/")[1:]       # drop the "owner-repo-sha/" folder
            rel = "/".join(parts)
            if not rel or m.issym() or m.islnk() or any(p in ("", ".", "..") for p in parts) or ":" in rel:
                continue
            if any(rel == k.rstrip("/") or rel.startswith(k) for k in KEEP if k.endswith("/")) or rel in KEEP:
                continue
            path = os.path.join(dest, *parts)
            if m.isdir():
                os.makedirs(path, exist_ok=True)
            elif m.isfile():
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with tar.extractfile(m) as src, open(path, "wb") as out:
                    shutil.copyfileobj(src, out)
                if not WIN:
                    os.chmod(path, 0o755 if m.mode & 0o100 else 0o644)
                n += 1
    return n


def cmd_update(args):
    say(f"HotPot {VERSION}")
    git = shutil.which("git")
    if os.path.isdir(os.path.join(ROOT, ".git")) and git:
        dirty = subprocess.run([git, "-C", ROOT, "status", "--porcelain", "--untracked-files=no"],
                               capture_output=True, text=True).stdout.strip()
        if dirty:
            die("you have local changes in tracked files; commit or stash them, then run hotpot update again")
        print("  This copy is a git clone: pulling from its remote")
        if subprocess.call([git, "-C", ROOT, "pull", "--ff-only"]) != 0:
            die("git pull failed")
    else:
        try:
            rel = json.loads(fetch(f"https://api.github.com/repos/{REPO}/releases/latest"))
        except (OSError, ValueError) as e:
            die(f"could not ask GitHub for the latest release ({e})")
        tag = str(rel.get("tag_name", ""))
        if vtuple(tag) <= vtuple(VERSION):
            ok(f"already up to date (latest release is {tag or 'unknown'})")
            return 0
        print(f"  Latest release: {tag}. Release notes: https://github.com/{REPO}/releases/tag/{tag}")
        if not args.yes and not yes(f"Update this copy to {tag}? Your settings, identity and data stay", True):
            return 1
        try:
            n = unpack_release(fetch(str(rel["tarball_url"])), ROOT)
        except (OSError, KeyError, tarfile.TarError) as e:
            die(f"the update failed ({e}); your copy may be partly updated, so run hotpot update again")
        ok(f"updated {n} files")
    with open(os.path.join(ROOT, "hotpot.py"), encoding="utf-8") as f:
        new = version_of(f.read())
    say(f"This copy is now HotPot {new}")
    if new == VERSION:
        return 0
    print("  The VMs still run the old version until you redeploy.")
    if os.path.exists(CONF) and (args.yes or yes("Redeploy both VMs now (hotpot deploy)?", True)):
        # run the new code, not this already-loaded copy
        return subprocess.call([sys.executable, os.path.join(ROOT, "hotpot.py"), "deploy"])
    print("  Later: hotpot deploy")
    return 0


def cmd_status(conf, vms):
    say("front VM")
    vms.run("front", "cd /opt/honeypot && sudo docker compose ps --format '{{.Name}}: {{.Status}}' | sed 's/^/  /'")
    if backend_on(conf):
        say("backend VM")
        vms.run("backend", f"sudo incus list {conf['CT_NAME']} -f csv -c ns4 | sed 's/^/  container: /'; "
                "for t in nb-collect.timer nb-reset.timer auditd; do printf '  %s: %s\\n' $t $(systemctl is-active $t); "
                "done; printf '  samples in quarantine: %s\\n' "
                "$(sudo find /var/lib/nb-quarantine/files -name '*.bin' | wc -l)")


def write_dashboard_config(conf):
    cfg = {}
    if os.path.exists(DASH_CONFIG):
        with open(DASH_CONFIG, encoding="utf-8") as f:
            cfg = json.load(f)
    cfg.update(ssh_host=conf["FRONT_PUBLIC_IP"], ssh_port=int(conf["ADMIN_SSH_PORT"]), ssh_user=conf["SSH_USER"],
               ssh_key=conf["SSH_KEY"], known_hosts=conf["KNOWN_HOSTS"],
               own_ips=[x.strip() for x in conf.get("OPERATOR_IPS", "").split(",") if x.strip()],
               backend_host=conf.get("BACKEND_IP", "") if backend_on(conf) else "",
               backend_user=conf["SSH_USER"])
    cfg.setdefault("sync_seconds", 15)
    cfg.setdefault("port", 8787)
    with open(DASH_CONFIG, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    return cfg


def expected_ports(conf):
    """(port, what, who may reach it) for every port the front VM should answer on from the internet."""
    out = [(int(conf["ADMIN_SSH_PORT"]), "your admin SSH", "your IP only"),
           (22, "SSH honeypot", "anywhere"), (23, "Telnet honeypot", "anywhere"),
           (80, "web honeypot", "anywhere"), (443, "web honeypot (HTTPS)", "anywhere")]
    if conf.get("DECOYS_ENABLED") == "1":
        wanted = [s.strip() for s in conf.get("DECOY_SERVICES", ",".join(DECOYS)).split(",")]
        out += [(DECOYS[s], f"{s} decoy", "anywhere") for s in wanted if s in DECOYS]
    return out


def probe(host, port, timeout=5.0):
    """'open', 'closed' (the VM answered: nothing listens) or 'blocked' (no answer: a firewall drops it)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except (socket.timeout, TimeoutError):
        return "blocked"
    except OSError as e:
        return "closed" if getattr(e, "errno", None) in (111, 10061) else "blocked"


def cmd_ports(conf, _vms=None):
    host = conf["FRONT_PUBLIC_IP"]
    ports = expected_ports(conf)
    say(f"Testing {len(ports)} public ports on {host} from this computer")
    res = {}
    threads = [threading.Thread(target=lambda p=p: res.__setitem__(p, probe(host, p))) for p, _, _ in ports]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    blocked = []
    for p, what, who in ports:
        st = res[p]
        line = f"{p:>5}  {what}"
        if st == "open":
            ok(line)
        elif st == "closed":
            warn(line + "  - reaches the VM but nothing answers (is it deployed? hotpot status)")
        else:
            bad(line + f"  - no answer: allow TCP {p} from {who} in the cloud firewall"
                + ("  (many home ISPs also block outgoing 445)" if p == 445 else ""))
            blocked.append(p)
    print("  (these test connections come from your IP; add it to OPERATOR_IPS to hide them in the dashboard)")
    return 1 if blocked else 0


def dashboard_up(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def cmd_dashboard(conf, args):
    cfg = write_dashboard_config(conf)
    port = int(cfg.get("port", 8787))
    url = f"http://127.0.0.1:{port}"
    if args.config_only:
        say("Wrote dashboard/config.json")
        print("  start it with: hotpot dashboard")
        return 0
    if args.autostart:
        return autostart(args.autostart == "on")
    if dashboard_up(port):
        say(f"The dashboard is already running: {url}")
        if not args.no_browser:
            webbrowser.open(url)
        return 0
    say(f"Starting the dashboard on {url} (local only; Ctrl+C stops it)")
    proc = subprocess.Popen([sys.executable, os.path.join(DASH_DIR, "server.py")], cwd=DASH_DIR)
    try:
        for _ in range(60):
            if dashboard_up(port) or proc.poll() is not None:
                break
            time.sleep(0.5)
        if proc.poll() is None and not args.no_browser:
            webbrowser.open(url)
        return proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        return 0


def autostart(on):
    server = os.path.join(DASH_DIR, "server.py")
    if WIN:
        startup = os.path.join(os.environ["APPDATA"], r"Microsoft\Windows\Start Menu\Programs\Startup")
        path = os.path.join(startup, "HotPot dashboard.cmd")
        pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
        if not os.path.exists(pyw):
            pyw = sys.executable
        if on:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f'@start "" /d "{DASH_DIR}" "{pyw}" "{server}"\r\n')
        elif os.path.exists(path):
            os.remove(path)
    elif sys.platform == "darwin":
        path = os.path.expanduser("~/Library/LaunchAgents/com.hotpot.dashboard.plist")
        if on:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.hotpot.dashboard</string>
  <key>ProgramArguments</key><array><string>{sys.executable}</string><string>{server}</string></array>
  <key>WorkingDirectory</key><string>{DASH_DIR}</string>
  <key>RunAtLoad</key><true/>
</dict></plist>
""")
            subprocess.run(["launchctl", "load", "-w", path])
        elif os.path.exists(path):
            subprocess.run(["launchctl", "unload", "-w", path])
            os.remove(path)
    else:
        path = os.path.expanduser("~/.config/systemd/user/hotpot-dashboard.service")
        if on:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"""[Unit]
Description=HotPot dashboard (local only)

[Service]
WorkingDirectory={DASH_DIR}
ExecStart={sys.executable} {server}
Restart=on-failure

[Install]
WantedBy=default.target
""")
            subprocess.run(["systemctl", "--user", "daemon-reload"])
            subprocess.run(["systemctl", "--user", "enable", "--now", "hotpot-dashboard.service"])
        elif os.path.exists(path):
            subprocess.run(["systemctl", "--user", "disable", "--now", "hotpot-dashboard.service"])
            os.remove(path)
    say(("The dashboard now starts when you log in" if on else "The dashboard no longer starts at login")
        + f" ({path})")
    return 0


# ---------------------------------------------------------------------------------------------- setup wizard
def ask(q, default="", check=None, secret=False):
    while True:
        prompt = f"  {q}" + (f" [{default}]" if default else "") + ": "
        try:
            v = (getpass.getpass(prompt) if secret else input(prompt)).strip()
        except EOFError:
            die("setup needs answers; run it in a terminal")
        v = v or default
        err = check(v) if check else None
        if not err:
            return v
        print("    " + _c("33", err))


def yes(q, default=True):
    v = ask(q + (" (Y/n)" if default else " (y/N)"), check=lambda v: None if v.lower() in ("", "y", "yes", "n", "no")
            else "answer y or n")
    return default if not v else v.lower().startswith("y")


def choose(q, options, default):
    print(f"  {q}")
    keys = list(options)
    for i, k in enumerate(keys, 1):
        print(f"    {i}) {options[k]}")
    v = ask("Choice", str(keys.index(default) + 1),
            check=lambda v: None if v in keys or (v.isdigit() and 1 <= int(v) <= len(keys)) else "pick a number")
    return keys[int(v) - 1] if v.isdigit() else v


def check_ip(private):
    def f(v):
        if not is_ip(v):
            return "enter an IPv4 address like 203.0.113.10"
        if private is not None and is_ip(v, private=not private):
            return "that is a private address; use the public one" if not private else \
                "that is a public address; use the VM's private one (10.x, 172.16-31.x or 192.168.x)"
    return f


def home_path(p):
    """Store paths under the home folder as ~/... (no spaces, works on every OS)."""
    full = os.path.abspath(os.path.expanduser(p))
    home = os.path.expanduser("~")
    if full.lower().startswith(home.lower() + os.sep):
        return "~/" + full[len(home) + 1:].replace(os.sep, "/")
    return full.replace(os.sep, "/")


def setup_key(cur):
    path = ask("SSH key file for your admin access", cur or "~/.ssh/honeypot_admin",
               check=lambda v: None if SAFE_VALUE.match(home_path(v)) else
               "use a path without spaces or special characters")
    full = os.path.expanduser(path)
    if not os.path.exists(full):
        if not yes(f"{path} does not exist. Create a new key there?"):
            die("an SSH key is needed")
        os.makedirs(os.path.dirname(full), exist_ok=True)
        r = subprocess.run([find_tool("ssh-keygen"), "-t", "ed25519", "-N", "", "-C", "hotpot-admin", "-f", full],
                           capture_output=True, text=True)
        if r.returncode != 0:
            die("ssh-keygen failed: " + (r.stderr or r.stdout).strip())
        ok(f"created {path} (keep this file private; it is the key to your VMs)")
    pub = full + ".pub"
    if os.path.exists(pub):
        with open(pub, encoding="utf-8") as f:
            print("\n  The public half of the key. Paste it into the cloud console when you create each VM\n"
                  "  (Oracle: 'Add SSH keys' > 'Paste public keys'):\n")
            print("    " + f.read().strip() + "\n")
    else:
        warn(f"{pub} is missing, so the public key cannot be shown")
    return home_path(path)


def detect_vm(conf):
    """Ask the front VM for its private IP, OS and RAM. Returns {} if it cannot be reached."""
    try:
        vms = VMs(conf)
        port = None
        for p in (conf["ADMIN_SSH_PORT"], "22"):
            if vms.reaches(p):
                port = p
                break
        if not port:
            return {}
        vms.port = port
        r = vms.run("front", "ip -4 -o route get 1.1.1.1; . /etc/os-release; echo \"OS=$PRETTY_NAME\"; "
                             "awk '/MemTotal/ {print \"MEM=\" int($2/1024)}' /proc/meminfo", capture=True)
        out = r.stdout.decode(errors="replace")
        info = {}
        m = re.search(r"\bsrc (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            info["private_ip"] = m.group(1)
        m = re.search(r"^OS=(.*)$", out, re.M)
        if m:
            info["os"] = m.group(1)
        m = re.search(r"^MEM=(\d+)$", out, re.M)
        if m:
            info["mem"] = int(m.group(1))
        return info
    except Fail:
        return {}


def my_public_ip():
    req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "hotpot-setup"})
    with urllib.request.urlopen(req, timeout=10) as r:
        v = r.read(64).decode().strip()
    return v if is_ip(v) else ""


def firewall_text(conf, provider):
    label, _, where = PROVIDERS[provider]
    lines = [f"Cloud firewall ({label}: {where})", "  Front VM, inbound TCP:"]
    for p, what, who in expected_ports(conf):
        lines.append(f"    {p:>5}  from {who:<13} {what}")
    if backend_on(conf):
        lines += ["  Backend VM, inbound TCP from the front VM's private IP "
                  f"({conf['FRONT_PRIVATE_IP']}) only:",
                  f"    22, {conf.get('BACKEND_SSH_PORT', '2222')}, {conf.get('BACKEND_TELNET_PORT', '2323')}",
                  "  Backend VM, outbound: only to the front VM (TCP 3128); no internet route",
                  "  (docs/cloud-setup.md has the full Oracle walkthrough)"]
    return "\n".join(lines)


def cmd_setup(args):
    print(_c("1", "\nHotPot setup") + "\n  Answers in [brackets] are the defaults: press Enter to keep them.\n"
          "  Nothing on the VMs changes until the last question.\n")
    exists = os.path.exists(CONF)
    conf = read_conf(CONF if exists else EXAMPLE)
    if not exists:  # the example's addresses are placeholders, not defaults
        for k in ("FRONT_PUBLIC_IP", "FRONT_PRIVATE_IP", "BACKEND_IP"):
            conf[k] = ""
    new = {}

    say("1/7  Cloud provider")
    provider = choose("Where do your VMs run?", {k: v[0] for k, v in PROVIDERS.items()},
                      args.provider or "oracle")

    say("2/7  One VM or two")
    two = choose("How should attackers' shells work?", {
        "1": "One VM: Cowrie's emulated shell (simplest; good to start with)",
        "2": "Two VMs: attackers land in a real, isolated Linux container on a second, private VM",
    }, "2" if conf.get("BACKEND_ENABLED") == "1" and exists else "1") == "2"
    new["BACKEND_ENABLED"] = "1" if two else "0"

    say("3/7  Your admin SSH key")
    new["SSH_KEY"] = setup_key(conf.get("SSH_KEY") if exists else "")
    new["KNOWN_HOSTS"] = conf.get("KNOWN_HOSTS") or "~/.ssh/known_hosts_honeypot"

    say("4/7  The front VM (public)")
    print("  Create it first if you have not (docs/cloud-setup.md): Ubuntu 24.04/22.04 or Debian 13/12,\n"
          "  with the public key above. Allow TCP 22 from your IP for now.")
    new["FRONT_PUBLIC_IP"] = ask("Its public IP address", conf.get("FRONT_PUBLIC_IP", ""), check_ip(False))
    user_default = conf.get("SSH_USER") if exists else (PROVIDERS[provider][1] or "ubuntu")
    new["SSH_USER"] = ask("SSH user name on the VM", user_default,
                          check=lambda v: None if re.match(r"^[a-z_][a-z0-9_-]{0,31}$", v) else "not a valid user name")
    new["ADMIN_SSH_PORT"] = conf.get("ADMIN_SSH_PORT") or "22222"
    print("  Connecting to the VM to look up its private IP...")
    info = detect_vm({**conf, **new})
    if info:
        ok(f"reached it: {info.get('os', '?')}, {info.get('mem', '?')} MiB RAM")
    else:
        warn("could not connect (fine for now; ./hotpot check will test it again later)")
    new["FRONT_PRIVATE_IP"] = ask("Its private IP address",
                                  info.get("private_ip") or conf.get("FRONT_PRIVATE_IP", ""), check_ip(True))

    if two:
        say("4b/7  The backend VM (private, no public IP)")
        new["BACKEND_IP"] = ask("Its private IP address", conf.get("BACKEND_IP", ""), check_ip(True))

    say("5/7  Decoy services and network IDS")
    have = conf.get("DECOY_SERVICES", ",".join(DECOYS))
    print("  Fake Redis, Docker API, Elasticsearch, MySQL, Ollama, Kubernetes, RDP and SMB services.\n"
          "  Each one needs its port open to the internet.")

    def check_decoys(v):
        if v in ("all", "none"):
            return None
        bad_ = [s for s in v.split(",") if s.strip() not in DECOYS]
        return f"unknown: {', '.join(bad_)} (choose from {', '.join(DECOYS)})" if bad_ else None
    d = ask("Which decoys? 'all', 'none' or a list like redis,mysql",
            "none" if conf.get("DECOYS_ENABLED") == "0" else ("all" if have == ",".join(DECOYS) else have),
            check_decoys)
    new["DECOYS_ENABLED"] = "0" if d == "none" else "1"
    if d != "none":
        new["DECOY_SERVICES"] = ",".join(DECOYS) if d == "all" else ",".join(s.strip() for s in d.split(","))
    mem = info.get("mem")
    ids_default = conf.get("IDS_ENABLED", "1") == "1" and not (mem and mem < 1500)
    if mem and mem < 1800:
        print(f"  The VM has {mem} MiB RAM; Suricata needs about 300-450 MB of it.")
    new["IDS_ENABLED"] = "1" if yes("Run the Suricata network IDS?", ids_default) else "0"

    say("6/7  AI replies in the web honeypot (optional)")
    print("  Unknown web paths get believable replies from free OpenRouter models. Needs a free key from\n"
          "  openrouter.ai; it is stored in secrets/openrouter.env and only sent to your front VM.")
    have_key = os.path.exists(OPENROUTER_ENV)
    key = ask("OpenRouter API key (hidden; Enter to " + ("keep the current one)" if have_key else "skip)"),
              secret=True, check=lambda v: None if not v or re.match(r"^[A-Za-z0-9_-]{20,200}$", v)
              else "that does not look like an API key")
    if key:
        os.makedirs(os.path.dirname(OPENROUTER_ENV), exist_ok=True)
        fd = os.open(OPENROUTER_ENV, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(f"OPENROUTER_API_KEY={key}\n")
        ok("saved to secrets/openrouter.env")
    new["LLM_ENABLED"] = "1" if key or have_key else "0"

    say("7/7  Your own IP addresses")
    print("  Hidden in the dashboard so your own tests do not count as attacks.")
    own = conf.get("OPERATOR_IPS", "")
    if not own and yes("Look up this computer's public IP now (asks api.ipify.org)?", False):
        try:
            own = my_public_ip()
            ok(f"your public IP is {own}")
        except OSError as e:
            warn(f"lookup failed ({e})")
    new["OPERATOR_IPS"] = ask("Your public IPs, comma separated (Enter for none)", own,
                              check=lambda v: None if all(is_ip(x.strip()) for x in v.split(",") if x.strip())
                              else "enter IPv4 addresses separated by commas")

    write_conf(new)
    conf = read_conf()
    say(f"Saved {os.path.basename(CONF)}" + (" (the old one is honeypot.conf.bak)" if exists else ""))
    if not os.path.exists(persona.PATH):
        persona.save(persona.generate(conf.get("FRONT_PRIVATE_IP", "")))
        say("Created this install's identity (persona.json)")
        print("  The bait files, canary values and tripwire credentials get their own random values, so\n"
              "  nobody can recognise the box from the public HotPot repo.")
        show_identity(persona.load())
    print("\n" + firewall_text(conf, provider) + "\n")
    errs = validate(conf)
    if errs:
        die("honeypot.conf still has problems:\n  " + "\n  ".join(errs))
    if not yes("Open those ports, then: check and deploy now?", True):
        print("  Later: hotpot check, then hotpot deploy")
        return 0
    return deploy_all(conf)


def deploy_all(conf, target="all"):
    need_identity()
    vms = VMs(conf)
    if target == "all":
        say("Checking both VMs first (changes nothing)")
        if cmd_check(conf, vms) != 0 and not yes("Some checks failed (see FAIL above). Deploy anyway?", False):
            return 1
    if target in ("all", "front"):
        cmd_front(conf, vms)
    if target in ("all", "backend") and (backend_on(conf) or target == "backend"):
        cmd_backend(conf, vms)
    if target == "all":
        write_dashboard_config(conf)
        say("Wrote dashboard/config.json")
        cmd_ports(conf)
        print("\n" + _c("1", "Done.") + " Start the dashboard with: hotpot dashboard")
    return 0


# ---------------------------------------------------------------------------------------------- main
def main(argv=None):
    sys.stdout.reconfigure(line_buffering=True)  # keep our lines in order with the VMs' output
    ap = argparse.ArgumentParser(prog="hotpot", description="Set up, deploy and run a HotPot honeypot.",
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog="Run 'hotpot setup' first. Settings live in honeypot.conf.")
    sub = ap.add_subparsers(dest="cmd", metavar="command")
    s = sub.add_parser("setup", help="answer a few questions, write honeypot.conf, then deploy")
    s.add_argument("--provider", choices=list(PROVIDERS))
    sub.add_parser("check", help="check honeypot.conf, SSH access and both VMs (changes nothing)")
    d = sub.add_parser("deploy", help="install or update the VMs")
    d.add_argument("target", nargs="?", default="all", choices=["all", "front", "backend"])
    sub.add_parser("persona", help="quick backend update: persona files, tripwires, collector and reset scripts")
    i = sub.add_parser("identity", help="this install's company, host name, canary values and credentials")
    i.add_argument("action", nargs="?", default="show", choices=["show", "new", "keep"])
    sub.add_parser("ports", help="test the public ports from this computer")
    sub.add_parser("status", help="service health on both VMs")
    b = sub.add_parser("dashboard", help="start the local dashboard and open it")
    b.add_argument("--no-browser", action="store_true", help="do not open the browser")
    b.add_argument("--config-only", action="store_true", help="only write dashboard/config.json")
    b.add_argument("--autostart", choices=["on", "off"], help="start the dashboard when you log in")
    u = sub.add_parser("update", help="get the latest release (settings stay), then redeploy")
    u.add_argument("-y", "--yes", action="store_true", help="do not ask before updating and redeploying")
    sub.add_parser("version", help="print this copy's version")
    h = sub.add_parser("ssh", help="shell (or one command) on a VM")
    h.add_argument("vm", choices=["front", "backend"])
    h.add_argument("command", nargs=argparse.REMAINDER)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "setup":
            return cmd_setup(a)
        if a.cmd is None:
            ap.print_help()
            return 1
        if a.cmd == "version":
            print(f"HotPot {VERSION}")
            return 0
        if a.cmd == "update":
            return cmd_update(a)
        if a.cmd == "identity":
            return cmd_identity(read_conf() if os.path.exists(CONF) else {}, a.action)
        conf = load()
        if a.cmd == "ports":
            return cmd_ports(conf)
        if a.cmd == "dashboard":
            return cmd_dashboard(conf, a)
        if a.cmd == "deploy":
            return deploy_all(conf, a.target)
        vms = VMs(conf)
        if a.cmd == "check":
            return cmd_check(conf, vms)
        if a.cmd == "persona":
            need_identity()
            return cmd_persona(conf, vms)
        if a.cmd == "status":
            return cmd_status(conf, vms)
        if a.cmd == "ssh":
            if a.vm == "backend" and not backend_on(conf):
                die("there is no backend VM (BACKEND_ENABLED=0)")
            return subprocess.call(vms.argv(a.vm, " ".join(a.command), tty=not a.command))
    except Fail as e:
        print(_c("1;31", "error: ") + str(e), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print()
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
