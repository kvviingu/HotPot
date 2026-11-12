"""Build a custom Cowrie filesystem image (fs.pickle) that looks like the Ubuntu 24.04 box the
rest of the honeypot claims to be.

Runs inside the cowrie/cowrie image, which ships the default pickle:

  docker run --rm --user 0 --entrypoint python3 -v /opt/honeypot/cowrie:/work \
      cowrie/cowrie:latest /work/build_fs.py

Every file under ./honeyfs is written into the image with its contents embedded (this Cowrie
version reads contents from the pickle, not from disk). The stock user "phil" is replaced by
"ubuntu", and the result goes to ./fs.pickle. With --report it lists leftover stock strings.
"""
import os
import pickle
import sys
import time

SRC = "/cowrie/cowrie-git/src/cowrie/data/fs.pickle"
WORK = os.path.dirname(os.path.abspath(__file__))
HONEYFS = os.path.join(WORK, "honeyfs")
OUT = os.path.join(WORK, "fs.pickle")

A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(10)
T_LINK, T_DIR, T_FILE = 0, 1, 2

# The box was set up in spring 2024 and then left alone.
SETUP = time.mktime((2024, 5, 14, 10, 12, 0, 0, 0, -1))
LATER = time.mktime((2024, 9, 23, 16, 40, 0, 0, 0, -1))
OWNERS = {"/home/ubuntu": (1000, 1000), "/home/deploy": (1001, 1001), "/home/admin": (1002, 1002), "/var/www/northbridge": (33, 33)}
PRIVATE = ("/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/root/", "/home/ubuntu/.ssh/", "/home/deploy/.ssh/")
EXEC = ("/var/www/northbridge/artisan", "/usr/local/bin/", "/opt/")

# Cowrie's own format is a pickle; the source is the one shipped inside the official image, not
# anything attacker-supplied, so loading it is safe.
fs = pickle.load(open(SRC, "rb"))


def node(name, ftype, uid=0, gid=0, size=4096, mode=0o40755, ctime=SETUP, contents=None):
    return [name, ftype, uid, gid, size, mode, ctime, [] if contents is None else contents, None, None]


def find(path):
    cur = fs
    for part in [p for p in path.split("/") if p]:
        if cur[A_TYPE] != T_DIR:
            return None
        cur = next((c for c in cur[A_CONTENTS] if c[A_NAME] == part), None)
        if cur is None:
            return None
    return cur


def owner(path):
    for prefix, ids in OWNERS.items():
        if path == prefix or path.startswith(prefix + "/"):
            return ids
    return 0, 0


def mkdirs(path):
    cur, so_far = fs, ""
    for part in [p for p in path.split("/") if p]:
        so_far += "/" + part
        nxt = next((c for c in cur[A_CONTENTS] if c[A_NAME] == part), None)
        if nxt is None:
            uid, gid = owner(so_far)
            mode = 0o40700 if so_far.endswith("/.ssh") or so_far == "/root" else 0o40755
            nxt = node(part, T_DIR, uid, gid, mode=mode, ctime=SETUP)
            cur[A_CONTENTS].append(nxt)
        cur = nxt
    return cur


def put(path, data):
    parent = mkdirs(os.path.dirname(path))
    name = os.path.basename(path)
    old = next((c for c in parent[A_CONTENTS] if c[A_NAME] == name), None)
    if old is not None:
        parent[A_CONTENTS].remove(old)
    uid, gid = owner(path)
    mode = 0o100644
    if path.startswith(PRIVATE) or "/.ssh/" in path or path.endswith("/.env") or path.endswith("bash_history"):
        mode = 0o100600
    if path.startswith(EXEC):
        mode = 0o100755
    if path in ("/etc/shadow", "/etc/shadow-", "/etc/gshadow"):
        mode, gid = 0o100640, 42
    ctime = LATER if path.startswith(("/var/www", "/home", "/root", "/etc/nginx")) else SETUP
    parent[A_CONTENTS].append(node(name, T_FILE, uid, gid, len(data), mode, ctime, data))


# 1. Replace the stock user's home.
home = find("/home")
home[A_CONTENTS] = [c for c in home[A_CONTENTS] if c[A_NAME] != "phil"]
for d in ("/home/ubuntu", "/home/ubuntu/.ssh", "/home/deploy", "/home/admin", "/var/www/northbridge/public",
          "/var/www/northbridge/storage/logs", "/etc/nginx/sites-enabled"):
    mkdirs(d)

# 2. Overlay every file from honeyfs, contents embedded.
count = 0
for root, _dirs, files in os.walk(HONEYFS):
    for fn in files:
        real = os.path.join(root, fn)
        virt = "/" + os.path.relpath(real, HONEYFS).replace(os.sep, "/")
        with open(real, "rb") as f:
            put(virt, f.read().replace(b"\r\n", b"\n"))
        count += 1

# Backup copies some tools leave behind must agree with the live files.
for live, backup in (("/etc/passwd", "/etc/passwd-"), ("/etc/group", "/etc/group-"), ("/etc/shadow", "/etc/shadow-")):
    put(backup, find(live)[A_CONTENTS])

# 3. Binaries: everything nb_extra.py emulates must exist (for `which`, `ls`, tab completion);
#    tools a stock Ubuntu 24.04 server does not ship must not.
BINARIES = {
    "/usr/bin/ps": 154_440, "/usr/bin/top": 133_352, "/usr/bin/df": 100_720, "/usr/bin/mount": 51_872,
    "/usr/bin/ss": 162_872, "/usr/bin/free": 31_048, "/usr/bin/lscpu": 112_824, "/usr/bin/lsblk": 133_432,
    "/usr/bin/getconf": 35_208, "/usr/bin/dmesg": 76_888, "/usr/bin/systemctl": 1_436_104,
    "/usr/bin/lsb_release": 1_766, "/usr/bin/hostnamectl": 39_544, "/usr/bin/mysql": 7_651_168,
    "/usr/bin/php8.3": 5_710_032, "/usr/bin/python3.12": 8_019_136, "/usr/bin/nano": 283_144,
    "/usr/sbin/ip": 788_000, "/usr/sbin/nginx": 1_252_448, "/usr/sbin/service": 9_237,
    "/usr/sbin/inetd": 39_352, "/usr/local/bin/ollama": 1_045_532_352,
}
LINKS = {"/usr/bin/php": "/etc/alternatives/php", "/etc/alternatives/php": "/usr/bin/php8.3",
         "/usr/bin/python3": "/usr/bin/python3.12", "/usr/bin/pico": "/etc/alternatives/pico",
         "/etc/alternatives/pico": "/usr/bin/nano"}
REMOVE = ["/sbin/ifconfig", "/usr/sbin/ifconfig", "/bin/netstat", "/usr/bin/netstat", "/sbin/route",
          "/usr/sbin/route", "/usr/sbin/arp", "/usr/bin/python", "/usr/bin/python2", "/usr/bin/python2.7",
          "/usr/bin/locate", "/usr/bin/emacs", "/sbin/mii-tool", "/usr/sbin/mii-tool"]


def remove(path):
    parent = find(os.path.dirname(path))
    if parent is not None and parent[A_TYPE] == T_DIR:
        parent[A_CONTENTS] = [c for c in parent[A_CONTENTS] if c[A_NAME] != os.path.basename(path)]


for path in REMOVE:
    remove(path)
for path, size in BINARIES.items():
    parent = mkdirs(os.path.dirname(path))
    remove(path)
    parent[A_CONTENTS].append(node(os.path.basename(path), T_FILE, 0, 0, size, 0o100755, SETUP, None))
for path, target in LINKS.items():
    parent = mkdirs(os.path.dirname(path))
    remove(path)
    link = node(os.path.basename(path), T_LINK, 0, 0, len(target), 0o120777, SETUP, [])
    link[A_TARGET] = target
    parent[A_CONTENTS].append(link)

# /etc/os-release on Ubuntu is a symlink to the copy in /usr/lib (Cowrie needs an absolute target).
osr = find("/etc/os-release")
if osr is not None and osr[A_TYPE] == T_LINK:
    osr[A_TARGET] = "/usr/lib/os-release"

if "--report" in sys.argv:
    def walk(n, path):
        if n[A_TYPE] == T_DIR:
            for c in n[A_CONTENTS]:
                yield from walk(c, path + "/" + c[A_NAME])
        elif n[A_TYPE] == T_FILE and isinstance(n[A_CONTENTS], bytes):
            yield path, n[A_CONTENTS]
    for path, data in walk(fs, ""):
        for word in (b"phil", b"svr04", b"nas3", b"Debian GNU", b"debian-kernel", b"Xeon"):
            if word in data:
                print("leftover", word.decode(), "in", path)

with open(OUT, "wb") as f:
    pickle.dump(fs, f)
print(f"wrote {OUT}: {count} files from honeyfs")
