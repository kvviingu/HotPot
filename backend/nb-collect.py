#!/usr/bin/env python3
"""nb-collect: runs every minute on nb-backend as root (nb-collect.timer).

1. Reads new auditd records, keeps only processes of the fileserver01 container (host uid >= 1000000), and
   writes one JSON line per program start (exec) and network connection (conn) to the export file. Each
   event carries the id of the SSH/Telnet login it descends from (the per-connection `sshd -R` or `tcpd`/
   `telnetd` exec), so the dashboard can attach it to the matching Cowrie session.
2. Saves every file created or changed inside the container since the last run (disk, /dev/shm, /tmp) and
   every running program whose binary was deleted or lives only in memory, into the quarantine:
   /var/lib/nb-quarantine/files/<sha256>.bin, mode 0400, root only, never executed.
3. Fetches http(s) URLs seen in the container's command lines (wget/curl/...) out of band, through the
   front VM's Squid (which refuses private addresses), into the same quarantine. The container itself
   still has no network.

Everything read here is attacker-controlled: files are opened relative to directory fds with O_NOFOLLOW
(no symlink can point us at a host file), only regular files are read, sizes are capped.
"""
import hashlib
import ipaddress
import json
import os
import re
import ssl
import stat
import subprocess
import time
import urllib.request

def _conf(path="/etc/nb-honeypot.conf"):
    out = {}
    try:
        with open(path) as f:
            for line in f:
                k, sep, v = line.strip().partition("=")
                if sep and not k.startswith("#"):
                    out[k.strip()] = v.strip().strip('"')
    except OSError:
        pass
    return out


CONF = _conf()
CT = CONF.get("CT_NAME", "fileserver01")
UID_BASE = 1000000
AUDIT_DIR = "/var/log/audit"
EXPORT_DIR = "/var/lib/nb-export"
EXPORT = EXPORT_DIR + "/backend.jsonl"
EXPORT_ROTATE = 50 * 1024 * 1024
QDIR = "/var/lib/nb-quarantine"
QFILES = QDIR + "/files"
STATE = QDIR + "/collect-state.json"
MAX_FILE = 64 * 1024 * 1024
MAX_RUN_BYTES = 768 * 1024 * 1024
MAX_FETCH = 16 * 1024 * 1024
FETCH_PER_HOUR = 30
PROXY = f"http://{CONF.get('FRONT_PRIVATE_IP', '127.0.0.1')}:3128"

# never worth keeping: kernel/virtual trees and files the system itself churns
SKIP_DIRS = {"proc", "sys", "run/systemd", "run/udev", "run/lock", "var/cache", "var/log",
             "var/lib/apt", "var/lib/dpkg", "var/lib/systemd", "var/lib/ucf", "var/lib/update-notifier",
             "var/lib/command-not-found", "var/lib/php/sessions", "usr/share/man", "var/lib/landscape"}
SKIP_DEV = {"dev"}          # /dev is walked only for shm and mqueue
SKIP_FILE = re.compile(r"^run/(.*\.pid|utmp|.*\.lock|motd\.dynamic|.*\.sock|user/\d+/systemd/.*)$")
# Files whose change means an attacker set up a way back in. Once one changes and nobody is connected
# any more, the container is reset early instead of waiting for the nightly run (nb-guard below).
PERSIST_RE = re.compile(r"^/(root|home/[^/]+)/(\.ssh/authorized_keys2?|\.bashrc|\.profile|\.bash_profile)$"
                        r"|^/etc/(cron\.[^/]+/.+|crontab|rc\.local|ld\.so\.preload|passwd|shadow|sudoers(\.d/.+)?"
                        r"|profile\.d/.+|init\.d/.+|systemd/system/.+|update-motd\.d/.+)$"
                        r"|^/var/spool/cron/.+|^/(usr/)?lib/systemd/system/.+")
GUARD_QUIET = 60            # s since persistence was first planted
GUARD_GAP = 600             # s between early resets
RESET_REASON = "/var/lib/nb-harvest/.reset-reason"
URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s'\"<>|;`)\\]{3,400}")


def now_ms():
    return int(time.time() * 1000)


def load_state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(st):
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f)
    os.replace(tmp, STATE)


class Out:
    def __init__(self):
        os.makedirs(EXPORT_DIR, mode=0o700, exist_ok=True)
        if os.path.exists(EXPORT) and os.path.getsize(EXPORT) > EXPORT_ROTATE:
            os.replace(EXPORT, EXPORT + ".1")
        self.f = open(EXPORT, "a")

    def write(self, obj):
        self.f.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")


# ----------------------------------------------------------------------------- audit

KV = re.compile(r'(\w+(?:\[\d+\])?)=("(?:[^"]*)"|\S+)')


def unhex(v):
    if v.startswith('"') and v.endswith('"'):
        return v[1:-1]
    if v == "(null)":
        return ""
    try:
        return bytes.fromhex(v).decode("utf-8", "replace")
    except ValueError:
        return v


def audit_lines(st):
    """New lines since the saved (inode, offset), following auditd's rotation (audit.log -> audit.log.1)."""
    cur = st.get("audit", {})
    files = []
    for name in ["audit.log"] + [f"audit.log.{i}" for i in range(1, 20)]:
        p = os.path.join(AUDIT_DIR, name)
        try:
            files.append((p, os.stat(p).st_ino))
        except OSError:
            pass
    ino, off = cur.get("ino"), cur.get("off", 0)
    idx = next((i for i, (_, n) in enumerate(files) if n == ino), None)
    if idx is None:                       # first run (or we fell behind a full rotation): start at the live file
        idx, off = 0, 0 if ino is None else 0
    for i in range(idx, -1, -1):          # older file with our inode first, then newer ones
        p, n = files[i]
        with open(p, "rb") as f:
            f.seek(off if n == ino else 0)
            data = f.read()
        end = data.rfind(b"\n") + 1
        for line in data[:end].splitlines():
            yield line.decode("utf-8", "replace")
        st["audit"] = {"ino": n, "off": (off if n == ino else 0) + end}


def parse_audit(st, out):
    events = {}
    order = []
    for line in audit_lines(st):
        line = line.split("\x1d", 1)[0]
        m = re.match(r"type=(\w+) msg=audit\((\d+)\.(\d+):(\d+)\): ?(.*)", line)
        if not m:
            continue
        typ, sec, ms, serial, rest = m.groups()
        key = serial
        ev = events.get(key)
        if ev is None:
            ev = events[key] = {"t": int(sec) * 1000 + int(ms), "recs": {}}
            order.append(key)
        ev["recs"].setdefault(typ, []).append(dict((k, v) for k, v in KV.findall(rest)))

    procs = st.setdefault("procs", {})     # host pid -> session root id ("" = not from a login)
    roots = st.setdefault("roots", {})     # root id -> {"t", "kind"}
    urls = []
    for key in order:
        ev = events[key]
        sc = (ev["recs"].get("SYSCALL") or [None])[0]
        if not sc:
            continue
        try:
            uid = int(sc.get("uid", "0"))
        except ValueError:
            continue
        if uid < UID_BASE:
            continue
        k = unhex(sc.get("key", '""'))
        pid, ppid = sc.get("pid", ""), sc.get("ppid", "")
        root = procs.get(pid) or procs.get(ppid) or ""
        if k == "nbfork":
            child = sc.get("exit", "")
            if child.isdigit() and int(child) > 0:
                procs[child] = procs.get(pid, root)
            continue
        if k == "nbexec":
            ex = (ev["recs"].get("EXECVE") or [{}])[0]
            argc = int(ex.get("argc", "0") or 0)
            argv = []
            for i in range(min(argc, 64)):
                if f"a{i}" in ex:
                    argv.append(unhex(ex[f"a{i}"]))
                else:                      # long argument split into a<i>[0], a<i>[1], ...
                    parts, j = [], 0
                    while f"a{i}[{j}]" in ex:
                        parts.append(unhex(ex[f"a{i}[{j}]"]))
                        j += 1
                    argv.append("".join(parts))
            cwd = unhex((ev["recs"].get("CWD") or [{}])[0].get("cwd", '""'))
            target = unhex((ev["recs"].get("PATH") or [{}])[0].get("name", '""'))
            if not argv and target:
                argv = [target]
            exe = unhex(sc.get("exe", '""'))
            base = os.path.basename(exe)
            # a new login: OpenSSH re-execs "sshd -R" per connection; inetd starts tcpd -> telnetd
            if (base == "sshd" and "-R" in argv) or base in ("tcpd", "telnetd", "in.telnetd"):
                if not (base == "telnetd" and roots.get(root, {}).get("kind") == "telnet"):
                    root = f"{pid}:{ev['t']}"
                    roots[root] = {"t": ev["t"], "kind": "ssh" if base == "sshd" else "telnet"}
            procs[pid] = root
            cmd = " ".join(argv)[:4000]
            out.write({"type": "exec", "t": ev["t"], "root": root, "pid": int(pid or 0), "ppid": int(ppid or 0),
                       "uid": uid - UID_BASE, "exe": exe[:300], "argv": cmd, "cwd": cwd[:300],
                       "ok": sc.get("success") == "yes"})
            if root:
                urls += [(u, root, ev["t"], cmd) for u in URL_RE.findall(cmd)]
        elif k == "nbconn":
            sa = (ev["recs"].get("SOCKADDR") or [{}])[0].get("saddr", "")
            dst = sockaddr(sa)
            if dst:
                out.write({"type": "conn", "t": ev["t"], "root": root, "pid": int(pid or 0),
                           "uid": uid - UID_BASE, "exe": unhex(sc.get("exe", '""'))[:300], "dst": dst,
                           "ok": sc.get("success") == "yes" or sc.get("exit") == "-115"})
    if len(procs) > 30000:                 # pids recycle; keep the newest entries
        st["procs"] = dict(list(procs.items())[-20000:])
    if len(roots) > 5000:
        st["roots"] = dict(list(roots.items())[-3000:])
    return urls


def sockaddr(h):
    try:
        b = bytes.fromhex(h)
    except ValueError:
        return None
    if len(b) >= 8 and b[0:2] == b"\x02\x00":
        return f"{'.'.join(str(x) for x in b[4:8])}:{int.from_bytes(b[2:4], 'big')}"
    if len(b) >= 24 and b[0:2] == b"\x0a\x00":
        return f"[{ipaddress.IPv6Address(b[8:24]).compressed}]:{int.from_bytes(b[2:4], 'big')}"
    return None


# ----------------------------------------------------------------------------- quarantine

ELF_ARCH = {3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 40: "ARM", 62: "x86-64", 183: "ARM aarch64",
            2: "SPARC", 42: "SuperH", 243: "RISC-V", 4: "m68k"}


def sniff(path):
    """Fallback file type from the first bytes (used when `file` is missing or says nothing)."""
    try:
        with open(path, "rb") as f:
            b = f.read(64)
    except OSError:
        return ""
    if b[:4] == b"\x7fELF" and len(b) >= 20:
        bits = "64-bit" if b[4] == 2 else "32-bit"
        end = "little" if b[5] == 1 else "big"
        mach = int.from_bytes(b[18:20], end)
        return f"ELF {bits} {'LSB' if end == 'little' else 'MSB'} executable, {ELF_ARCH.get(mach, 'machine %d' % mach)}"
    if b.startswith(b"#!"):
        first = b.split(b"\n", 1)[0][2:]
        return "script: " + first.decode("ascii", "replace").strip()
    for sig, name in ((b"\x1f\x8b", "gzip compressed data"), (b"PK\x03\x04", "Zip archive"),
                      (b"BZh", "bzip2 compressed data"), (b"\xfd7zXZ", "XZ compressed data"),
                      (b"MZ", "PE/DOS executable")):
        if b.startswith(sig):
            return name
    return "text" if all(32 <= c < 127 or c in (9, 10, 13) for c in b) else "data"


def magic(path):
    try:
        r = subprocess.run(["file", "-b", "--", path], capture_output=True, timeout=10)
        out = r.stdout.decode("utf-8", "replace").strip()[:200]
        if out:
            return out
    except (OSError, subprocess.SubprocessError):
        pass
    return sniff(path)


def store(fd, size):
    """Copy an open file into the quarantine; returns (sha256, stored_path) or None."""
    h = hashlib.sha256()
    tmp = os.path.join(QFILES, f".tmp-{os.getpid()}")
    n = 0
    with open(tmp, "wb") as o:
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            n += len(chunk)
            if n > MAX_FILE:
                o.close()
                os.unlink(tmp)
                return None
            h.update(chunk)
            o.write(chunk)
    sha = h.hexdigest()
    dst = os.path.join(QFILES, sha + ".bin")
    if os.path.exists(dst):
        os.unlink(tmp)
    else:
        os.chmod(tmp, 0o400)
        os.replace(tmp, dst)
    return sha, dst, n


def ct_pid():
    try:
        r = subprocess.run(["incus", "query", f"/1.0/instances/{CT}/state"], capture_output=True, timeout=20)
        return int(json.loads(r.stdout)["pid"]) or None
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return None


def capture_files(st, out, init_pid):
    since = st.setdefault("ctime", time.time())   # first run: only what changes from now on
    started = time.time()
    seen = st.setdefault("seen", {})       # "path\0sha" -> 1, so an unchanged file is not reported again
    budget = MAX_RUN_BYTES
    rootfd = os.open(f"/proc/{init_pid}/root", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for top, dirs, files, dfd in os.fwalk(".", dir_fd=rootfd, follow_symlinks=False):
            rel = top[2:] if top.startswith("./") else ("" if top == "." else top)
            if rel in SKIP_DIRS or any(rel.startswith(d + "/") for d in SKIP_DIRS):
                dirs[:] = []
                continue
            if rel == "dev":
                dirs[:] = [d for d in dirs if d in ("shm", "mqueue")]
                continue
            for name in files:
                try:
                    if SKIP_FILE.match((rel + "/" if rel else "") + name):
                        continue
                    pre = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                    if not stat.S_ISREG(pre.st_mode) or pre.st_ctime <= since or pre.st_size == 0:
                        continue
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
                except OSError:
                    continue
                try:
                    s = os.fstat(fd)
                    if not stat.S_ISREG(s.st_mode) or s.st_ctime <= since or s.st_size > MAX_FILE \
                            or s.st_size > budget:
                        continue
                    path = "/" + (rel + "/" if rel else "") + name
                    r = store(fd, s.st_size)
                    if not r:
                        continue
                    sha, dst, n = r
                    budget -= n
                    k = path + "\0" + sha
                    if PERSIST_RE.match(path):  # before the dedupe: bots plant the identical key every time
                        st.setdefault("persist", []).append({"path": path[:300], "t": now_ms()})
                        del st["persist"][:-50]
                    if k in seen:
                        continue
                    seen[k] = 1
                    out.write({"type": "file", "t": now_ms(), "src": "disk", "path": path[:500], "sha256": sha,
                               "size": n, "mode": oct(s.st_mode & 0o7777), "uid": s.st_uid - UID_BASE,
                               "mtime": int(s.st_mtime * 1000), "ctime": int(s.st_ctime * 1000),
                               "magic": magic(dst), "exec": bool(s.st_mode & 0o111)})
                finally:
                    os.close(fd)
    finally:
        os.close(rootfd)
    st["ctime"] = started - 2
    if len(seen) > 50000:
        st["seen"] = dict(list(seen.items())[-30000:])


def capture_memory_exes(st, out):
    """Programs still running whose file was deleted (or that run from a memfd): save the binary."""
    seen = st.setdefault("seen", {})
    for p in os.listdir("/proc"):
        if not p.isdigit():
            continue
        try:
            with open(f"/proc/{p}/cgroup") as f:
                if f"lxc.payload.{CT}" not in f.read():
                    continue
            target = os.readlink(f"/proc/{p}/exe")
        except OSError:
            continue
        if not target.endswith(" (deleted)") and not target.startswith("/memfd:"):
            continue
        try:
            fd = os.open(f"/proc/{p}/exe", os.O_RDONLY)
        except OSError:
            continue
        try:
            r = store(fd, 0)
        finally:
            os.close(fd)
        if not r:
            continue
        sha, dst, n = r
        k = target + "\0" + sha
        if k in seen:
            continue
        seen[k] = 1
        try:
            with open(f"/proc/{p}/cmdline", "rb") as f:
                cmd = f.read(2000).replace(b"\0", b" ").decode("utf-8", "replace").strip()
        except OSError:
            cmd = ""
        root = st.get("procs", {}).get(p, "")
        out.write({"type": "file", "t": now_ms(), "src": "memory", "path": target[:500], "sha256": sha, "size": n,
                   "pid": int(p), "argv": cmd, "root": root, "magic": magic(dst), "exec": True})


# ----------------------------------------------------------------------------- out-of-band fetch

def fetch_urls(st, out, urls):
    done = st.setdefault("fetched", {})
    hour = int(time.time() // 3600)
    budget = st.setdefault("fetch_budget", {})
    for url, root, t, cmd in urls:
        url = url.rstrip(".,")
        if url in done:
            continue
        if budget.get(str(hour), 0) >= FETCH_PER_HOUR:
            out.write({"type": "fetch", "t": now_ms(), "url": url[:500], "root": root, "cmd_t": t,
                       "error": "skipped: hourly fetch limit"})
            done[url] = 1
            continue
        budget[str(hour)] = budget.get(str(hour), 0) + 1
        done[url] = 1
        rec = {"type": "fetch", "t": now_ms(), "url": url[:500], "root": root, "cmd_t": t}
        if url.lower().startswith("ftp://"):
            rec["error"] = "not fetched: ftp"
            out.write(rec)
            continue
        ua = "curl/8.5.0" if "curl" in cmd else "Wget/1.21.4"
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE   # droppers often use self-signed certs
        op = urllib.request.build_opener(urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}),
                                         urllib.request.HTTPSHandler(context=ctx))
        try:
            with op.open(urllib.request.Request(url, headers={"User-Agent": ua, "Accept": "*/*"}), timeout=25) as r:
                rec["status"] = r.status
                data = r.read(MAX_FETCH + 1)
            if len(data) > MAX_FETCH:
                rec["error"] = "too large (over 16 MB)"
            else:
                tmp = os.path.join(QFILES, f".dl-{os.getpid()}")
                with open(tmp, "wb") as o:
                    o.write(data)
                fd = os.open(tmp, os.O_RDONLY)
                try:
                    sha, dst, n = store(fd, len(data))
                finally:
                    os.close(fd)
                    os.unlink(tmp)
                rec.update(sha256=sha, size=n, magic=magic(dst))
        except Exception as e:  # network errors, HTTP errors, proxy refusals
            rec["error"] = f"{type(e).__name__}: {e}"[:300]
        out.write(rec)
    for h in list(budget):
        if int(h) < hour - 2:
            del budget[h]
    if len(done) > 20000:
        st["fetched"] = dict(list(done.items())[-10000:])


def ct_connections(init_pid):
    """Established TCP connections to the container's sshd/telnetd, read from its network namespace."""
    n = 0
    for f in ("tcp", "tcp6"):
        try:
            with open(f"/proc/{init_pid}/net/{f}") as fh:
                next(fh, None)
                for line in fh:
                    p = line.split()
                    if len(p) > 3 and p[3] == "01" and int(p[1].rsplit(":", 1)[1], 16) in (22, 23):
                        n += 1
        except (OSError, ValueError, IndexError):
            pass
    return n


def guard(st, out, init_pid):
    """Reset early after persistence was planted, as soon as no attacker is connected."""
    hits = st.get("persist") or []
    if not hits:
        return
    now = time.time()
    # Count from the FIRST change, not the last: malware left running rewrites its files every minute
    # (seen: /root/.16 re-writing .bashrc), which kept a "quiet since the last change" timer from ever
    # running out. Nobody connected (below) is what tells us the attacker is done.
    if now - hits[0]["t"] / 1000 < GUARD_QUIET or now - st.get("guard_last", 0) < GUARD_GAP:
        return
    conns = ct_connections(init_pid)
    if conns:
        return
    paths = sorted({h["path"] for h in hits})[:20]
    os.makedirs(os.path.dirname(RESET_REASON), mode=0o700, exist_ok=True)
    with open(RESET_REASON, "w") as f:
        json.dump({"reason": "persistence", "paths": paths, "first": hits[0]["t"]}, f)
    r = subprocess.run(["systemctl", "start", "--no-block", "nb-reset.service"], capture_output=True, timeout=20)
    out.write({"type": "guard", "t": now_ms(), "action": "reset" if r.returncode == 0 else "reset_failed",
               "paths": paths, "first": hits[0]["t"]})
    st["guard_last"] = now
    st["persist"] = []


def main():
    os.makedirs(QFILES, mode=0o700, exist_ok=True)
    os.chmod(QDIR, 0o700)
    import fcntl
    lk = open(QDIR + "/.lock", "w")
    try:
        fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return                             # previous run still busy
    st = load_state()
    out = Out()
    try:
        urls = parse_audit(st, out)
        pid = ct_pid()
        if pid:
            capture_files(st, out, pid)
            capture_memory_exes(st, out)
        fetch_urls(st, out, urls)
        if pid:
            guard(st, out, pid)
    finally:
        out.f.close()
        save_state(st)


if __name__ == "__main__":
    main()
