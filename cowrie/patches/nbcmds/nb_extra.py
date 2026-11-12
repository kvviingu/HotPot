"""Extra and replacement shell commands so the Cowrie shell matches fileserver01: an Ubuntu 24.04
VM on Oracle Cloud (1 GB RAM, 2 vCPU AMD EPYC) running nginx, php8.3-fpm and Ollama, with the
Laravel intranet in /var/www/northbridge and its database on db01 (10.0.0.21).

Loaded by sitecustomize.py as cowrie.commands.nb_extra. Every value here has to agree with the
fake filesystem (cowrie/honeyfs) and with the web honeypot.
"""
from __future__ import annotations

import time

from cowrie.shell.command import HoneyPotCommand

commands: dict = {}

IP = "10.0.0.47"
MAC = "02:00:17:0a:4e:3b"
MEM_TOTAL_KB = 975356
NOW = time.time

# ---------------------------------------------------------------------------- process table
# (pid, ppid, user, vsz_kb, rss_kb, stat, tty, cpu_seconds, command)
KTHREADS = ["kthreadd", "pool_workqueue_release", "kworker/R-rcu_g", "kworker/R-rcu_p", "kworker/R-slub_",
            "kworker/R-netns", "kworker/0:0H-events_highpri", "kworker/R-mm_pe", "rcu_tasks_kthread",
            "rcu_tasks_rude_kthread", "rcu_tasks_trace_kthread", "ksoftirqd/0", "rcu_preempt", "migration/0",
            "idle_inject/0", "cpuhp/0", "cpuhp/1", "idle_inject/1", "migration/1", "ksoftirqd/1",
            "kdevtmpfs", "kworker/R-inet_", "kauditd", "khungtaskd", "oom_reaper", "kworker/R-write",
            "kcompactd0", "ksmd", "khugepaged", "kworker/R-kinte", "kworker/R-kbloc", "kworker/R-blkcg",
            "irq/9-acpi", "kworker/R-md", "kworker/R-edac-", "watchdogd", "kswapd0", "ecryptfs-kthread",
            "kworker/R-kthro", "kworker/R-acpi_", "scsi_eh_0", "kworker/R-scsi_", "kworker/R-mld",
            "kworker/R-ipv6_", "kworker/R-kstrp", "jbd2/sda1-8", "kworker/R-ext4-", "kworker/u4:2-events_unbound",
            "kworker/1:2-events", "kworker/0:1-mm_percpu_wq"]
DAEMONS = [
    (1, 0, "root", 22568, 13312, "Ss", "?", 74, "/sbin/init"),
    (318, 1, "root", 50356, 16000, "S<s", "?", 41, "/usr/lib/systemd/systemd-journald"),
    (361, 1, "root", 289316, 27136, "SLsl", "?", 162, "/sbin/multipathd -d -s"),
    (372, 1, "root", 26240, 7168, "Ss", "?", 3, "/usr/lib/systemd/systemd-udevd"),
    (524, 1, "systemd-network", 19004, 9216, "Ss", "?", 6, "/usr/lib/systemd/systemd-networkd"),
    (611, 1, "systemd-resolve", 21600, 12800, "Ss", "?", 19, "/usr/lib/systemd/systemd-resolved"),
    (614, 1, "systemd-timesync", 91024, 7424, "Ssl", "?", 2, "/usr/lib/systemd/systemd-timesyncd"),
    (702, 1, "root", 7340, 2816, "Ss", "?", 4, "/usr/sbin/cron -f -P"),
    (703, 1, "messagebus", 9900, 5248, "Ss", "?", 3,
     "@dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only"),
    (711, 1, "root", 17988, 8192, "Ss", "?", 2, "/usr/lib/systemd/systemd-logind"),
    (716, 1, "syslog", 222508, 5888, "Ssl", "?", 9, "/usr/sbin/rsyslogd -n -iNONE"),
    (731, 1, "root", 109780, 21632, "Ssl", "?", 1,
     "/usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal"),
    (744, 1, "root", 6104, 1920, "Ss+", "tty1", 0, "/sbin/agetty -o -p -- \\u --noclear - linux"),
    (748, 1, "root", 6148, 2048, "Ss+", "ttyS0", 0,
     "/sbin/agetty -o -p -- \\u --keep-baud 115200,57600,38400,9600 - vt220"),
    (790, 1, "root", 1907464, 25600, "Ssl", "?", 211, "/usr/lib/snapd/snapd"),
    (811, 1, "root", 1279044, 21248, "Ssl", "?", 940, "/snap/oracle-cloud-agent/72/agent"),
    (853, 1, "root", 12020, 7936, "Ss", "?", 14, "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"),
    (870, 1, "root", 4364, 2560, "Ss", "?", 0, "/usr/sbin/inetd"),
    (988, 1, "ollama", 2034588, 31244, "Ssl", "?", 512, "/usr/local/bin/ollama serve"),
    (1019, 1, "root", 207760, 19456, "Ss", "?", 33, "php-fpm: master process (/etc/php/8.3/fpm/php-fpm.conf)"),
    (1021, 1019, "www-data", 208212, 12032, "S", "?", 18, "php-fpm: pool www"),
    (1022, 1019, "www-data", 208212, 11904, "S", "?", 17, "php-fpm: pool www"),
    (1043, 1, "root", 55212, 1600, "Ss", "?", 0, "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;"),
    (1044, 1043, "www-data", 55908, 5632, "S", "?", 26, "nginx: worker process"),
    (1045, 1043, "www-data", 55908, 5376, "S", "?", 24, "nginx: worker process"),
]


def _boot(cmd) -> float:
    try:
        return cmd.protocol.boot_time()
    except Exception:
        return NOW() - 65 * 86400


def _session_pids(cmd) -> tuple[int, int, int]:
    base = 48000 + int(getattr(cmd.protocol, "logintime", NOW())) % 9000
    return base, base + 112, base + 113 + int(NOW()) % 40


def _processes(cmd, me: str):
    rows = [(2 + i if i < 2 else 3 + i * 2, 2 if i else 0, "root", 0, 0, "I<" if "R-" in k else "S", "?", 0, f"[{k}]")
            for i, k in enumerate(KTHREADS)]
    rows = [DAEMONS[0]] + rows + DAEMONS[1:]
    user = cmd.user.get("username", "root") if isinstance(cmd.user, dict) else "root"
    sshd, bash, mine = _session_pids(cmd)
    rows += [(sshd, 853, "root", 14920, 9088, "Ss", "?", 0, f"sshd: {user}@pts/0"),
             (bash, sshd, user, 8652, 5376, "Ss", "pts/0", 0, "-bash"),
             (mine, bash, user, 11320, 4480, "R+", "pts/0", 0, me)]
    return rows


def _short_user(u: str) -> str:
    return u if len(u) <= 8 else u[:7] + "+"


def _start(cmd, pid) -> str:
    boot = _boot(cmd)
    t = NOW() - 120 if pid >= 48000 else boot + (0 if pid < 1000 else 40)
    if NOW() - t < 86400:
        return time.strftime("%H:%M", time.gmtime(t))
    return time.strftime("%b%d", time.gmtime(t))


class Command_ps(HoneyPotCommand):
    def call(self) -> None:
        args = " ".join(self.args)
        me = "ps " + args if args else "ps"
        rows = _processes(self, me)
        if not args:
            sshd, bash, mine = _session_pids(self)
            self.write("    PID TTY          TIME CMD\n")
            self.write(f"{bash:>7} pts/0    00:00:00 bash\n{mine:>7} pts/0    00:00:00 ps\n")
            return
        if "-ef" in args or "-e" in args.split() or "-A" in args.split() or "ef" == args.strip("-"):
            self.write("UID          PID    PPID  C STIME TTY          TIME CMD\n")
            for pid, ppid, user, _v, _r, _s, tty, cpu, command in rows:
                tm = time.strftime("%H:%M:%S", time.gmtime(cpu))
                self.write(f"{_short_user(user):<8} {pid:>7} {ppid:>7}  0 {_start(self, pid):>5} {tty:<8} {tm} {command}\n")
            return
        self.write("USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n")
        for pid, _pp, user, vsz, rss, stat, tty, cpu, command in rows:
            mem = rss / MEM_TOTAL_KB * 100
            tm = f"{cpu // 60}:{cpu % 60:02d}"
            self.write(f"{_short_user(user):<8} {pid:>7} {0.0:>4.1f} {mem:>4.1f} {vsz:>6} {rss:>5} {tty:<8} "
                       f"{stat:<4} {_start(self, pid):>5} {tm:>6} {command}\n")


class Command_top(HoneyPotCommand):
    def call(self) -> None:
        up = NOW() - _boot(self)
        days, rem = divmod(int(up), 86400)
        self.write(f"top - {time.strftime('%H:%M:%S', time.gmtime())} up {days} days, {rem // 3600:2d}:{rem % 3600 // 60:02d},"
                   "  1 user,  load average: 0.00, 0.01, 0.00\n"
                   f"Tasks: {len(_processes(self, 'top')):>3} total,   1 running, {len(_processes(self, 'top')) - 1:>3} sleeping,"
                   "   0 stopped,   0 zombie\n"
                   "%Cpu(s):  0.3 us,  0.2 sy,  0.0 ni, 99.5 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st \n"
                   "MiB Mem :    952.5 total,     59.8 free,    408.9 used,    535.1 buff/cache     \n"
                   "MiB Swap:      0.0 total,      0.0 free,      0.0 used.    553.5 avail Mem \n\n"
                   "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n")
        for pid, _pp, user, vsz, rss, stat, _tty, cpu, command in _processes(self, "top"):
            if pid < 300 and pid != 1:
                continue
            name = command.split()[0].split("/")[-1].strip("[]:@") or command
            if command.startswith(("nginx", "php-fpm", "sshd:")):
                name = command.split(":")[0]
            mem = rss / MEM_TOTAL_KB * 100
            self.write(f"{pid:>7} {_short_user(user):<8}  20   0 {vsz:>7} {rss:>6} {rss // 3:>6} {stat[0]}   0.0 {mem:>5.1f} "
                       f"{cpu // 60:>5}:{cpu % 60:02d}.00 {name}\n")


class Command_df(HoneyPotCommand):
    ROWS = [("tmpfs", 97536, 1104, 96432, "/run"),
            ("/dev/sda1", 47143900, 28935116, 18192400, "/"),
            ("tmpfs", 487676, 0, 487676, "/dev/shm"),
            ("tmpfs", 5120, 0, 5120, "/run/lock"),
            ("/dev/sda16", 901520, 114540, 724108, "/boot"),
            ("/dev/sda15", 106832, 6250, 100582, "/boot/efi"),
            ("tmpfs", 97532, 12, 97520, "/run/user/0")]

    @staticmethod
    def human(kb: int) -> str:
        v = kb * 1024.0
        for unit in ("", "K", "M", "G", "T"):
            if v < 1024 or unit == "T":
                if unit == "":
                    return str(int(v))
                return f"{v:.1f}{unit}" if v < 10 else f"{v:.0f}{unit}"
            v /= 1024
        return str(kb)

    def call(self) -> None:
        h = any(a.startswith("-") and "h" in a for a in self.args)
        if h:
            self.write("Filesystem      Size  Used Avail Use% Mounted on\n")
        else:
            self.write("Filesystem     1K-blocks     Used Available Use% Mounted on\n")
        for fs, size, used, avail, mnt in self.ROWS:
            pct = f"{-(-used * 100 // size)}%" if used else "0%"
            if h:
                self.write(f"{fs:<15} {self.human(size):>5} {self.human(used) if used else '0':>5} {self.human(avail):>5} {pct:>4} {mnt}\n")
            else:
                self.write(f"{fs:<14} {size:>9} {used:>8} {avail:>9} {pct:>4} {mnt}\n")


MOUNTS = """sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
udev on /dev type devtmpfs (rw,nosuid,relatime,size=470060k,nr_inodes=117515,mode=755,inode64)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)
tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=97536k,mode=755,inode64)
/dev/sda1 on / type ext4 (rw,relatime,discard,errors=remount-ro,commit=30)
securityfs on /sys/kernel/security type securityfs (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,inode64)
tmpfs on /run/lock type tmpfs (rw,nosuid,nodev,noexec,relatime,size=5120k,inode64)
cgroup2 on /sys/fs/cgroup type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot)
pstore on /sys/fs/pstore type pstore (rw,nosuid,nodev,noexec,relatime)
efivarfs on /sys/firmware/efi/efivars type efivarfs (rw,nosuid,nodev,noexec,relatime)
bpf on /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,relatime,mode=700)
systemd-1 on /proc/sys/fs/binfmt_misc type autofs (rw,relatime,fd=32,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=4219)
hugetlbfs on /dev/hugepages type hugetlbfs (rw,nosuid,nodev,relatime,pagesize=2M)
mqueue on /dev/mqueue type mqueue (rw,nosuid,nodev,noexec,relatime)
debugfs on /sys/kernel/debug type debugfs (rw,nosuid,nodev,noexec,relatime)
tracefs on /sys/kernel/tracing type tracefs (rw,nosuid,nodev,noexec,relatime)
fusectl on /sys/fs/fuse/connections type fusectl (rw,nosuid,nodev,noexec,relatime)
configfs on /sys/kernel/config type configfs (rw,nosuid,nodev,noexec,relatime)
/var/lib/snapd/snaps/core22_1621.snap on /snap/core22/1621 type squashfs (ro,nodev,relatime,errors=continue,threads=single,x-gdu.hide,x-gvfs-hide)
/var/lib/snapd/snaps/oracle-cloud-agent_72.snap on /snap/oracle-cloud-agent/72 type squashfs (ro,nodev,relatime,errors=continue,threads=single,x-gdu.hide,x-gvfs-hide)
/var/lib/snapd/snaps/snapd_21759.snap on /snap/snapd/21759 type squashfs (ro,nodev,relatime,errors=continue,threads=single,x-gdu.hide,x-gvfs-hide)
/dev/sda16 on /boot type ext4 (rw,relatime)
/dev/sda15 on /boot/efi type vfat (rw,relatime,fmask=0077,dmask=0077,codepage=437,iocharset=iso8859-1,shortname=mixed,errors=remount-ro)
binfmt_misc on /proc/sys/fs/binfmt_misc type binfmt_misc (rw,nosuid,nodev,noexec,relatime)
tmpfs on /run/user/0 type tmpfs (rw,nosuid,nodev,relatime,size=97532k,nr_inodes=24383,mode=700,inode64)
"""


class Command_mount(HoneyPotCommand):
    def call(self) -> None:
        if self.args and not self.args[0].startswith("-"):
            self.errorWrite("mount: only root can do that.\n" if self.user.get("uid", 0) else
                            f"mount: {self.args[-1]}: mount point does not exist.\n")
            self.exit_code = 32
            return
        self.write(MOUNTS)


IP_ADDR = f"""1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute
       valid_lft forever preferred_lft forever
2: ens3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9000 qdisc fq_codel state UP group default qlen 1000
    link/ether {MAC} brd ff:ff:ff:ff:ff:ff
    altname enp0s3
    inet {IP}/24 metric 100 brd 10.0.0.255 scope global dynamic ens3
       valid_lft 75621sec preferred_lft 75621sec
    inet6 fe80::17ff:fe0a:4e3b/64 scope link
       valid_lft forever preferred_lft forever
"""
IP_LINK = f"""1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: ens3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9000 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether {MAC} brd ff:ff:ff:ff:ff:ff
    altname enp0s3
"""
IP_ROUTE = f"""default via 10.0.0.1 dev ens3 proto dhcp src {IP} metric 100
10.0.0.0/24 dev ens3 proto kernel scope link src {IP} metric 100
10.0.0.1 dev ens3 proto dhcp scope link src {IP} metric 100
169.254.0.0/16 dev ens3 proto dhcp scope link src {IP} metric 100
"""


class Command_ip(HoneyPotCommand):
    def call(self) -> None:
        args = [a for a in self.args if not a.startswith("-")]
        obj = args[0] if args else ""
        if not obj:
            self.errorWrite("Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n"
                            "       ip [ -force ] -batch filename\n"
                            "where  OBJECT := { address | addrlabel | amt | fou | help | ila | ioam | l2tp |\n"
                            "                   link | macsec | maddress | monitor | mptcp | mroute | mrule |\n"
                            "                   neighbor | neighbour | netconf | netns | nexthop | ntable |\n"
                            "                   ntbl | route | rule | sr | stats | tap | tcpmetrics |\n"
                            "                   token | tunnel | tuntap | vrf | xfrm }\n")
            self.exit_code = 255
        elif "address".startswith(obj) or obj == "addr":
            self.write(IP_ADDR)
        elif "link".startswith(obj):
            self.write(IP_LINK)
        elif "route".startswith(obj):
            self.write(IP_ROUTE)
        elif "neighbour".startswith(obj) or "neighbor".startswith(obj):
            self.write("10.0.0.1 dev ens3 lladdr 00:00:17:9a:0c:41 REACHABLE\n"
                       "10.0.0.21 dev ens3 lladdr 02:00:17:03:7c:d2 STALE\n")
        else:
            self.errorWrite(f'Object "{obj}" is unknown, try "ip help".\n')
            self.exit_code = 1


SS_LISTEN = [("127.0.0.54:53", "0.0.0.0:*", 4096, 'users:(("systemd-resolve",pid=611,fd=17))'),
             ("127.0.0.53%lo:53", "0.0.0.0:*", 4096, 'users:(("systemd-resolve",pid=611,fd=15))'),
             ("0.0.0.0:80", "0.0.0.0:*", 511, 'users:(("nginx",pid=1045,fd=6),("nginx",pid=1044,fd=6),("nginx",pid=1043,fd=6))'),
             ("0.0.0.0:443", "0.0.0.0:*", 511, 'users:(("nginx",pid=1045,fd=7),("nginx",pid=1044,fd=7),("nginx",pid=1043,fd=7))'),
             ("0.0.0.0:23", "0.0.0.0:*", 64, 'users:(("inetd",pid=870,fd=7))'),
             ("127.0.0.1:11434", "0.0.0.0:*", 4096, 'users:(("ollama",pid=988,fd=3))'),
             ("*:22", "*:*", 4096, 'users:(("sshd",pid=853,fd=3),("systemd",pid=1,fd=69))')]


class Command_ss(HoneyPotCommand):
    def call(self) -> None:
        flags = "".join(a.lstrip("-") for a in self.args if a.startswith("-"))
        procs = "p" in flags
        if "l" in flags:
            self.write("State  Recv-Q Send-Q Local Address:Port  Peer Address:Port" + ("Process" if procs else "") + "\n")
            for local, peer, q, users in SS_LISTEN:
                la, lp = local.rsplit(":", 1)
                pa, pp = peer.rsplit(":", 1)
                self.write(f"LISTEN 0      {q:<6} {la:>13}:{lp:<5} {pa:>9}:{pp:<5}" + (users if procs else "") + "\n")
            return
        self.write("State     Recv-Q Send-Q Local Address:Port    Peer Address:Port" + ("Process" if procs else "") + "\n")
        peer = getattr(self.protocol, "clientIP", "198.51.100.7")
        self.write(f"ESTAB     0      52        {IP}:22    {peer:>15}:{40000 + int(NOW()) % 20000:<5}"
                   + ('users:(("sshd",pid=48000,fd=4))' if procs else "") + "\n")


class Command_free(HoneyPotCommand):
    def call(self) -> None:
        mem = {"total": 975356, "used": 418716, "free": 61240, "shared": 5328, "cache": 495400, "avail": 566812}
        h = any(a.startswith("-") and "h" in a for a in self.args)
        m = any(a in ("-m", "--mebi") for a in self.args)
        g = any(a in ("-g", "--gibi") for a in self.args)

        def f(kb):
            if h:
                return f"{kb / 1024 / 1024:.1f}Gi" if kb >= 1024 * 1024 else f"{kb / 1024:.0f}Mi" if kb else "0B"
            if m:
                return str(kb // 1024)
            if g:
                return str(kb // 1024 // 1024)
            return str(kb)

        self.write("               total        used        free      shared  buff/cache   available\n")
        self.write(f"Mem:     {f(mem['total']):>11} {f(mem['used']):>11} {f(mem['free']):>11} {f(mem['shared']):>11} "
                   f"{f(mem['cache']):>11} {f(mem['avail']):>11}\n")
        self.write(f"Swap:    {f(0):>11} {f(0):>11} {f(0):>11}\n")


LSCPU = """Architecture:             x86_64
  CPU op-mode(s):         32-bit, 64-bit
  Address sizes:          40 bits physical, 48 bits virtual
  Byte Order:             Little Endian
CPU(s):                   2
  On-line CPU(s) list:    0,1
Vendor ID:                AuthenticAMD
  Model name:             AMD EPYC 7551 32-Core Processor
    CPU family:           23
    Model:                1
    Thread(s) per core:   2
    Core(s) per socket:   1
    Socket(s):            1
    Stepping:             2
    BogoMIPS:             3992.49
    Flags:                fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm rep_good nopl cpuid extd_apicid tsc_known_freq pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm cmp_legacy cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw topoext perfctr_core ssbd ibpb vmmcall fsgsbase bmi1 avx2 smep bmi2 rdseed adx smap clflushopt sha_ni xsaveopt xsavec xgetbv1 nt_cpb arat
Virtualization features:
  Hypervisor vendor:      KVM
  Virtualization type:    full
Caches (sum of all):
  L1d:                    32 KiB (1 instance)
  L1i:                    64 KiB (1 instance)
  L2:                     512 KiB (1 instance)
  L3:                     8 MiB (1 instance)
NUMA:
  NUMA node(s):           1
  NUMA node0 CPU(s):      0,1
Vulnerabilities:
  Gather data sampling:   Not affected
  Itlb multihit:          Not affected
  L1tf:                   Not affected
  Mds:                    Not affected
  Meltdown:               Not affected
  Mmio stale data:        Not affected
  Reg file data sampling: Not affected
  Retbleed:               Mitigation; untrained return thunk; SMT vulnerable
  Spec rstack overflow:   Mitigation; Safe RET
  Spec store bypass:      Mitigation; Speculative Store Bypass disabled via prctl
  Spectre v1:             Mitigation; usercopy/swapgs barriers and __user pointer sanitization
  Spectre v2:             Mitigation; Retpolines; IBPB conditional; STIBP disabled; RSB filling; PBRSB-eIBRS Not affected; BHI Not affected
  Srbds:                  Not affected
  Tsx async abort:        Not affected
"""


class Command_lscpu(HoneyPotCommand):
    def call(self) -> None:
        self.write(LSCPU)


class Command_lsblk(HoneyPotCommand):
    def call(self) -> None:
        self.write("NAME    MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\n"
                   "loop0     7:0    0 73.9M  1 loop /snap/core22/1621\n"
                   "loop1     7:1    0 58.2M  1 loop /snap/oracle-cloud-agent/72\n"
                   "loop2     7:2    0 38.8M  1 loop /snap/snapd/21759\n"
                   "sda       8:0    0 46.6G  0 disk \n"
                   "├─sda1    8:1    0 45.6G  0 part /\n"
                   "├─sda14   8:14   0    4M  0 part \n"
                   "├─sda15   8:15   0  106M  0 part /boot/efi\n"
                   "└─sda16 259:0    0  913M  0 part /boot\n")


class Command_getconf(HoneyPotCommand):
    VALUES = {"LONG_BIT": "64", "PAGESIZE": "4096", "PAGE_SIZE": "4096", "_NPROCESSORS_ONLN": "2",
              "_NPROCESSORS_CONF": "2", "CLK_TCK": "100", "ARG_MAX": "2097152", "GNU_LIBC_VERSION": "glibc 2.39",
              "WORD_BIT": "32", "INT_MAX": "2147483647"}

    def call(self) -> None:
        if not self.args:
            self.errorWrite("Usage: getconf [-v SPEC] VAR\n  or:   getconf [-v SPEC] PATH_VAR PATH\n")
            self.exit_code = 1
        elif self.args[0] in self.VALUES:
            self.write(self.VALUES[self.args[0]] + "\n")
        else:
            self.errorWrite(f"getconf: Unrecognized variable '{self.args[0]}'\n")
            self.exit_code = 1


DMESG = """[    0.000000] Linux version 6.8.0-1013-oracle (buildd@lcy02-amd64-085) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.2.0-23ubuntu4) 13.2.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #13-Ubuntu SMP PREEMPT_DYNAMIC Mon Sep 16 14:43:28 UTC 2024 (Ubuntu 6.8.0-1013.14-oracle 6.8.12)
[    0.000000] Command line: BOOT_IMAGE=/vmlinuz-6.8.0-1013-oracle root=UUID=4e9a1c2f-6b0d-4a5e-9d1b-3f7a8c2e5d10 ro console=tty1 console=ttyS0 nvme.shutdown_timeout=10 libiscsi.debug_libiscsi_eh=1 crash_kexec_post_notifiers
[    0.000000] KERNEL supported cpus:
[    0.000000]   Intel GenuineIntel
[    0.000000]   AMD AuthenticAMD
[    0.000000] DMI: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.6.6 08/22/2023
[    0.000000] Hypervisor detected: KVM
[    0.000000] tsc: Detected 1996.249 MHz processor
[    0.004718] Memory: 908448K/1048036K available (22528K kernel code, 4440K rwdata, 14404K rodata, 4904K init, 4652K bss, 139328K reserved, 0K cma-reserved)
[    0.112806] smpboot: CPU0: AMD EPYC 7551 32-Core Processor (family: 0x17, model: 0x1, stepping: 0x2)
[    0.231904] smp: Brought up 1 node, 2 CPUs
[    0.512340] virtio-pci 0000:00:03.0: enabling device (0000 -> 0003)
[    0.874213] sd 2:0:0:1: [sda] 97675264 512-byte logical blocks: (50.0 GB/46.6 GiB)
[    0.876002]  sda: sda1 sda14 sda15 sda16
[    1.402331] EXT4-fs (sda1): mounted filesystem 4e9a1c2f-6b0d-4a5e-9d1b-3f7a8c2e5d10 ro with ordered data mode. Quota mode: none.
[    2.119874] systemd[1]: systemd 255.4-1ubuntu8.4 running in system mode (+PAM +AUDIT +SELINUX +APPARMOR +IMA +SMACK +SECCOMP +GCRYPT -GNUTLS +OPENSSL +ACL +BLKID +CURL +ELFUTILS +FIDO2 +IDN2 -IDN +IPTC +KMOD +LIBCRYPTSETUP +LIBFDISK +PCRE2 -PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD -BPF_FRAMEWORK -XKBCOMMON +UTMP +SYSVINIT default-hierarchy=unified)
[    2.123004] systemd[1]: Hostname set to <fileserver01>.
[    3.884512] EXT4-fs (sda1): re-mounted 4e9a1c2f-6b0d-4a5e-9d1b-3f7a8c2e5d10 r/w. Quota mode: none.
[    5.307118] virtio_net virtio0 ens3: renamed from eth0
[    9.551203] loop0: detected capacity change from 0 to 151296
[   11.902218] audit: type=1400 audit(1725968431.204:118): apparmor="STATUS" operation="profile_load" profile="unconfined" name="nginx" pid=1031 comm="apparmor_parser"
"""


class Command_dmesg(HoneyPotCommand):
    def call(self) -> None:
        self.write(DMESG)


SERVICES = {
    "nginx": ("A high performance web server and a reverse proxy server", "/usr/lib/systemd/system/nginx.service",
              1043, ["1043 \"nginx: master process /usr/sbin/nginx -g daemon on; master_process on;\"",
                     "1044 \"nginx: worker process\"", "1045 \"nginx: worker process\""], "4.6M"),
    "php8.3-fpm": ("The PHP 8.3 FastCGI Process Manager", "/usr/lib/systemd/system/php8.3-fpm.service", 1019,
                   ["1019 \"php-fpm: master process (/etc/php/8.3/fpm/php-fpm.conf)\"",
                    "1021 \"php-fpm: pool www\"", "1022 \"php-fpm: pool www\""], "21.3M"),
    "ollama": ("Ollama Service", "/etc/systemd/system/ollama.service", 988,
               ["988 /usr/local/bin/ollama serve"], "30.5M"),
    "ssh": ("OpenBSD Secure Shell server", "/usr/lib/systemd/system/ssh.service", 853,
            ["853 \"sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups\""], "3.1M"),
    "cron": ("Regular background program processing daemon", "/usr/lib/systemd/system/cron.service", 702,
             ["702 /usr/sbin/cron -f -P"], "1.4M"),
    "openbsd-inetd": ("Internet superserver", "/usr/lib/systemd/system/inetd.service", 870,
                      ["870 /usr/sbin/inetd"], "720.0K"),
    "systemd-resolved": ("Network Name Resolution", "/usr/lib/systemd/system/systemd-resolved.service", 611,
                         ["611 /usr/lib/systemd/systemd-resolved"], "4.9M"),
    "snapd": ("Snap Daemon", "/usr/lib/systemd/system/snapd.service", 790, ["790 /usr/lib/snapd/snapd"], "26.4M"),
}
ALIASES = {"php-fpm": "php8.3-fpm", "sshd": "ssh", "inetd": "openbsd-inetd", "crond": "cron"}


def _unit(name: str) -> str:
    n = name[:-8] if name.endswith(".service") else name
    return ALIASES.get(n, n)


def _write_status(cmd: HoneyPotCommand, units: list[str]) -> None:
    for u in units:
        if u not in SERVICES:
            cmd.errorWrite(f"Unit {u}.service could not be found.\n")
            cmd.exit_code = 4
            continue
        desc, path, pid, procs, mem = SERVICES[u]
        since = time.strftime("%a %Y-%m-%d %H:%M:%S UTC", time.gmtime(_boot(cmd) + 12))
        days = int((NOW() - _boot(cmd)) // 86400)
        main = procs[0].split(" ", 1)[1].strip('"').split()[0].split("/")[-1].rstrip(":")
        cmd.write(f"● {u}.service - {desc}\n"
                  f"     Loaded: loaded ({path}; enabled; preset: enabled)\n"
                  f"     Active: active (running) since {since}; {days} days ago\n"
                  f"   Main PID: {pid} ({main})\n"
                  f"      Tasks: {len(procs) + 2} (limit: 1113)\n"
                  f"     Memory: {mem} (peak: {mem})\n"
                  f"        CPU: 3min 12.410s\n"
                  f"     CGroup: /system.slice/{u}.service\n")
        for i, p in enumerate(procs):
            cmd.write(f"             {'└─' if i == len(procs) - 1 else '├─'}{p}\n")
        cmd.write("\n")


class Command_systemctl(HoneyPotCommand):
    def call(self) -> None:
        args = [a for a in self.args if not a.startswith("-")]
        verb = args[0] if args else "list-units"
        units = [_unit(u) for u in args[1:]]
        if verb == "status":
            _write_status(self, units or ["nginx"])
            return
        if verb in ("is-active",):
            self.write("".join("active\n" if u in SERVICES else "inactive\n" for u in units))
            self.exit_code = 0 if all(u in SERVICES for u in units) else 3
            return
        if verb in ("is-enabled",):
            self.write("".join("enabled\n" if u in SERVICES else "not-found\n" for u in units))
            return
        if verb in ("start", "stop", "restart", "reload", "enable", "disable", "daemon-reload", "mask", "unmask",
                    "kill", "reset-failed"):
            missing = [u for u in units if u not in SERVICES and verb != "daemon-reload"]
            for u in missing:
                self.errorWrite(f"Failed to {verb} {u}.service: Unit {u}.service not found.\n")
                self.exit_code = 5
            return
        if verb in ("list-units", "list-unit-files"):
            self.write("  UNIT                         LOAD   ACTIVE SUB     DESCRIPTION\n")
            for u, (desc, *_r) in sorted(SERVICES.items()):
                self.write(f"  {u + '.service':<28} loaded active running {desc}\n")
            self.write(f"\nLegend: LOAD   → Reflects whether the unit definition was properly loaded.\n"
                       f"        ACTIVE → The high-level unit activation state, i.e. generalization of SUB.\n"
                       f"        SUB    → The low-level unit activation state, values depend on unit type.\n\n"
                       f"{len(SERVICES)} loaded units listed.\n")
            return
        self.errorWrite(f'Unknown command verb \'{verb}\', expected one of "status", "start", "stop", "restart".\n')
        self.exit_code = 1


class Command_service(HoneyPotCommand):
    def call(self) -> None:
        if not self.args:
            self.errorWrite("Usage: service < option > | --status-all | [ service_name [ command | --full-restart ] ]\n")
            self.exit_code = 1
            return
        if self.args[0] == "--status-all":
            for u in sorted(SERVICES):
                self.write(f" [ + ]  {u}\n")
            return
        u = _unit(self.args[0])
        verb = self.args[1] if len(self.args) > 1 else ""
        if u not in SERVICES:
            self.errorWrite(f"{self.args[0]}: unrecognized service\n")
            self.exit_code = 1
        elif verb == "status":
            _write_status(self, [u])


class Command_nginx(HoneyPotCommand):
    def call(self) -> None:
        a = " ".join(self.args)
        if "-V" in self.args:
            self.errorWrite("nginx version: nginx/1.24.0 (Ubuntu)\nbuilt with OpenSSL 3.0.13 30 Jan 2024\n"
                            "TLS SNI support enabled\nconfigure arguments: --with-cc-opt='-g -O2 -Werror=implicit-function-declaration "
                            "-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -flto=auto -ffat-lto-objects -fstack-protector-strong "
                            "-fstack-clash-protection -Wformat -Werror=format-security -fcf-protection -fdebug-prefix-map=/build/nginx-WLuzPu/nginx-1.24.0=. "
                            "-fPIC -Wdate-time -D_FORTIFY_SOURCE=3' --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf "
                            "--http-log-path=/var/log/nginx/access.log --error-log-path=stderr --lock-path=/var/lock/nginx.lock "
                            "--pid-path=/run/nginx.pid --modules-path=/usr/lib/nginx/modules --with-compat --with-debug "
                            "--with-pcre-jit --with-http_ssl_module --with-http_stub_status_module --with-http_realip_module "
                            "--with-http_auth_request_module --with-http_v2_module --with-http_dav_module --with-http_slice_module "
                            "--with-threads --with-http_addition_module --with-http_flv_module --with-http_gunzip_module "
                            "--with-http_gzip_static_module --with-http_mp4_module --with-http_random_index_module "
                            "--with-http_secure_link_module --with-http_sub_module --with-mail_ssl_module --with-stream_ssl_module "
                            "--with-stream_ssl_preread_module --with-stream_realip_module --with-http_geoip_module=dynamic "
                            "--with-http_image_filter_module=dynamic --with-http_perl_module=dynamic "
                            "--with-http_xslt_module=dynamic --with-mail=dynamic --with-stream=dynamic "
                            "--with-stream_geoip_module=dynamic\n")
        elif "-v" in self.args:
            self.errorWrite("nginx version: nginx/1.24.0 (Ubuntu)\n")
        elif "-t" in a or "-T" in a:
            self.errorWrite("nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n"
                            "nginx: configuration file /etc/nginx/nginx.conf test is successful\n")
        elif "-s" in self.args:
            pass
        else:
            for port in ("80", "443", "80", "443", "80", "443"):
                self.errorWrite(f"nginx: [emerg] bind() to 0.0.0.0:{port} failed (98: Address already in use)\n")
            self.errorWrite("nginx: [emerg] still could not bind()\n")
            self.exit_code = 1


PHP_V = """PHP 8.3.6 (cli) (built: Apr 15 2024 19:21:47) (NTS)
Copyright (c) The PHP Group
Zend Engine v4.3.6, Copyright (c) Zend Technologies
    with Zend OPcache v8.3.6, Copyright (c), by Zend Technologies
"""
PHP_MODULES = ["Core", "ctype", "date", "dom", "exif", "FFI", "fileinfo", "filter", "ftp", "gettext", "hash",
               "iconv", "json", "libxml", "mbstring", "mysqli", "mysqlnd", "openssl", "pcntl", "pcre", "PDO",
               "pdo_mysql", "Phar", "posix", "random", "readline", "Reflection", "session", "shmop", "SimpleXML",
               "sockets", "sodium", "SPL", "standard", "sysvmsg", "sysvsem", "sysvshm", "tokenizer", "xml",
               "xmlreader", "xmlwriter", "xsl", "Zend OPcache", "zlib"]


class Command_php(HoneyPotCommand):
    def call(self) -> None:
        a = self.args
        if not a:
            return  # php reading a script from stdin: nothing to run
        if a[0] in ("-v", "--version"):
            self.write(PHP_V)
        elif a[0] == "-m":
            self.write("[PHP Modules]\n" + "\n".join(PHP_MODULES) + "\n\n[Zend Modules]\nZend OPcache\n")
        elif a[0] == "-r":
            return
        elif a[0] == "-i":
            self.write("phpinfo()\nPHP Version => 8.3.6\n\nSystem => Linux fileserver01 6.8.0-1013-oracle "
                       "#13-Ubuntu SMP PREEMPT_DYNAMIC Mon Sep 16 14:43:28 UTC 2024 x86_64\n"
                       "Build Date => Apr 15 2024 19:21:47\nServer API => Command Line Interface\n"
                       "Loaded Configuration File => /etc/php/8.3/cli/php.ini\n")
        elif a[0] == "artisan":
            cwd = getattr(self.protocol, "cwd", "")
            if not str(cwd).startswith("/var/www/northbridge"):
                self.write("Could not open input file: artisan\n")
                self.exit_code = 1
            elif len(a) > 1 and a[1] in ("--version", "-V"):
                self.write("Laravel Framework 11.23.5\n")
            elif len(a) > 1 and a[1].startswith(("migrate", "db", "tinker", "queue")):
                self.write("\n   Illuminate\\Database\\QueryException \n\n  SQLSTATE[HY000] [2002] Connection timed out "
                           "(Connection: mysql, SQL: select * from information_schema.tables where table_schema = "
                           "nb_intranet and table_name = migrations and table_type = 'BASE TABLE')\n\n")
                self.exit_code = 1
            else:
                self.write("Laravel Framework 11.23.5\n\nUsage:\n  command [options] [arguments]\n")
        elif not a[0].startswith("-"):
            self.write(f"Could not open input file: {a[0]}\n")
            self.exit_code = 1


class Command_ollama(HoneyPotCommand):
    def call(self) -> None:
        a = self.args
        sub = a[0] if a else ""
        if sub in ("-v", "--version"):
            self.write("ollama version is 0.3.11\n")
        elif sub in ("list", "ls"):
            self.write("NAME                ID              SIZE      MODIFIED      \n"
                       "qwen2.5-coder:7b    2b0496514337    4.7 GB    13 months ago    \n"
                       "llama3.1:8b         46e0c10c039e    4.9 GB    14 months ago    \n")
        elif sub == "ps":
            self.write("NAME    ID    SIZE    PROCESSOR    UNTIL \n")
        elif sub == "run":
            model = a[1] if len(a) > 1 else "llama3.1:8b"
            if model.split(":")[0] not in ("llama3.1", "qwen2.5-coder"):
                self.errorWrite(f"pulling manifest \nError: pull model manifest: file does not exist\n")
            else:
                self.errorWrite("Error: model requires more system memory (5.6 GiB) than is available (559.2 MiB)\n")
            self.exit_code = 1
        elif sub == "pull":
            self.errorWrite("pulling manifest \nError: pull model manifest: Get \"https://registry.ollama.ai/v2/library/"
                            f"{(a[1] if len(a) > 1 else 'model').split(':')[0]}/manifests/latest\": dial tcp: lookup "
                            "registry.ollama.ai on 127.0.0.53:53: server misbehaving\n")
            self.exit_code = 1
        elif sub == "serve":
            self.errorWrite("Error: listen tcp 127.0.0.1:11434: bind: address already in use\n")
            self.exit_code = 1
        else:
            self.write("Large language model runner\n\nUsage:\n  ollama [flags]\n  ollama [command]\n\n"
                       "Available Commands:\n  serve       Start ollama\n  create      Create a model from a Modelfile\n"
                       "  show        Show information for a model\n  run         Run a model\n"
                       "  pull        Pull a model from a registry\n  push        Push a model to a registry\n"
                       "  list        List models\n  ps          List running models\n"
                       "  cp          Copy a model\n  rm          Remove a model\n  help        Help about any command\n\n"
                       "Flags:\n  -h, --help      help for ollama\n  -v, --version   Show version information\n\n"
                       "Use \"ollama [command] --help\" for more information about a command.\n")


class Command_mysql(HoneyPotCommand):
    def start(self) -> None:
        if any(x in ("-V", "--version") for x in self.args):
            self.write("mysql  Ver 8.0.39-0ubuntu0.24.04.2 for Linux on x86_64 ((Ubuntu))\n")
            self.exit()
            return
        host = "localhost"
        for i, x in enumerate(self.args):
            if x == "-h" and i + 1 < len(self.args):
                host = self.args[i + 1]
            elif x.startswith("-h") and len(x) > 2:
                host = x[2:]
            elif x.startswith("--host="):
                host = x.split("=", 1)[1]
        self.callLater(3.0 if host != "localhost" else 0.05, self._fail, host)

    def _fail(self, host: str) -> None:
        if host in ("localhost", "127.0.0.1"):
            self.errorWrite("ERROR 2002 (HY000): Can't connect to local MySQL server through socket "
                            "'/var/run/mysqld/mysqld.sock' (2)\n")
        else:
            h = "10.0.0.21" if host in ("db01", "db01.northbridge.local") else host
            self.errorWrite(f"ERROR 2003 (HY000): Can't connect to MySQL server on '{h}:3306' (110)\n")
        self.exit(1)


class Command_python3(HoneyPotCommand):
    def call(self) -> None:
        if self.args and self.args[0] in ("-V", "--version"):
            self.write("Python 3.12.3\n")
        elif not self.args:
            self.write("Python 3.12.3 (main, Sep 11 2024, 14:17:37) [GCC 13.2.0] on linux\n"
                       "Type \"help\", \"copyright\", \"credits\" or \"license\" for more information.\n>>> \n")


class Command_lsb_release(HoneyPotCommand):
    def call(self) -> None:
        a = " ".join(self.args)
        if "-a" in a or not a:
            self.errorWrite("No LSB modules are available.\n")
            self.write("Distributor ID:\tUbuntu\nDescription:\tUbuntu 24.04.1 LTS\nRelease:\t24.04\nCodename:\tnoble\n")
        elif "-d" in a:
            self.write("Description:\tUbuntu 24.04.1 LTS\n")
        elif "-r" in a:
            self.write("Release:\t24.04\n")
        elif "-c" in a:
            self.write("Codename:\tnoble\n")


class Command_hostnamectl(HoneyPotCommand):
    def call(self) -> None:
        self.write(" Static hostname: fileserver01\n       Icon name: computer-vm\n         Chassis: vm \U0001f5b4\n"
                   "      Machine ID: 8b1f5c0e2a7d4e9f9a3c6d2b1e0f4a7c\n         Boot ID: 1d3e5f7a9b2c4d6e8f0a1b3c5d7e9f02\n"
                   "  Virtualization: kvm\nOperating System: Ubuntu 24.04.1 LTS\n          Kernel: Linux 6.8.0-1013-oracle\n"
                   "    Architecture: x86-64\n Hardware Vendor: QEMU\n  Hardware Model: Standard PC _i440FX + PIIX, 1996_\n"
                   "Firmware Version: 1.6.6\n   Firmware Date: Tue 2023-08-22\n    Firmware Age: 3y 2month 2w 6d\n")


class Command_editor_noterm(HoneyPotCommand):
    def call(self) -> None:
        self.errorWrite("Error opening terminal: xterm-256color.\n")
        self.exit_code = 1


# ---------------------------------------------------------------------------- not installed
NOT_INSTALLED = {
    "ifconfig": ["apt install net-tools"], "netstat": ["apt install net-tools"], "route": ["apt install net-tools"],
    "arp": ["apt install net-tools"], "nslookup": ["apt install bind9-dnsutils"],
    "docker": ["snap install docker         # version 27.2.0, or", "apt  install docker.io      # version 24.0.7-0ubuntu4.1",
               "apt  install podman-docker  # version 4.9.3+ds1-1build2"],
    "nmap": ["snap install nmap  # version 7.94, or", "apt  install nmap  # version 7.94+git20230807.3be01efb1+dfsg-3build2"],
    "masscan": ["apt install masscan"], "zip": ["apt install zip"], "locate": ["apt install plocate"],
    "emacs": ["snap install emacs  # version 29.4, or", "apt  install e3     # version 1:2.82+dfsg-2",
              "apt  install emacs  # version 1:29.3+1-1ubuntu2", "apt  install jove   # version 4.17.5.3-2"],
    "telnetd": ["apt install inetutils-telnetd"], "gdb": ["apt install gdb"], "screen": ["apt install screen"],
    "lynx": ["apt install lynx"], "redis-cli": ["apt install redis-tools"], "psql": ["apt install postgresql-client-common"],
}
SNAP_SUFFIX = {"docker": "See 'snap info docker' for additional versions.", "nmap": "See 'snap info nmap' for additional versions.",
               "emacs": "See 'snap info emacs' for additional versions."}


def not_found_hint(cmd: str, root: bool) -> str | None:
    if cmd == "python":
        return ("Command 'python' not found, did you mean:\n  command 'python3' from deb python3\n"
                "  command 'python' from deb python-is-python3\n")
    lines = NOT_INSTALLED.get(cmd)
    if not lines:
        return None
    pre = "" if root else "sudo "
    out = f"Command '{cmd}' not found, but can be installed with:\n" + "".join(pre + ln + "\n" for ln in lines)
    if cmd in SNAP_SUFFIX:
        out += SNAP_SUFFIX[cmd] + "\n"
    return out


class Command_not_installed(HoneyPotCommand):
    """For tools Cowrie emulates but a stock Ubuntu 24.04 server does not ship."""

    def call(self) -> None:
        cmd = getattr(self, "_nb_name", "")
        self.errorWrite(not_found_hint(cmd, True) or f"{cmd}: command not found\n")
        self.exit_code = 127


def _not_installed(cmd: str):
    return type(f"Command_ni_{cmd}", (Command_not_installed,), {"_nb_name": cmd})


# ---------------------------------------------------------------------------- registration
def _reg(cls, *names):
    for n in names:
        commands[n] = cls


_reg(Command_ps, "ps", "/usr/bin/ps", "/bin/ps")
_reg(Command_top, "top", "/usr/bin/top")
_reg(Command_df, "df", "/usr/bin/df", "/bin/df")
_reg(Command_mount, "mount", "/usr/bin/mount", "/bin/mount")
_reg(Command_ip, "ip", "/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip")
_reg(Command_ss, "ss", "/usr/bin/ss", "/bin/ss")
_reg(Command_free, "free", "/usr/bin/free")
_reg(Command_lscpu, "lscpu", "/usr/bin/lscpu")
_reg(Command_lsblk, "lsblk", "/usr/bin/lsblk")
_reg(Command_getconf, "getconf", "/usr/bin/getconf")
_reg(Command_dmesg, "dmesg", "/usr/bin/dmesg", "/bin/dmesg")
_reg(Command_systemctl, "systemctl", "/usr/bin/systemctl", "/bin/systemctl")
_reg(Command_service, "service", "/usr/sbin/service")
_reg(Command_nginx, "nginx", "/usr/sbin/nginx")
_reg(Command_php, "php", "php8.3", "/usr/bin/php", "/usr/bin/php8.3")
_reg(Command_ollama, "ollama", "/usr/local/bin/ollama")
_reg(Command_mysql, "mysql", "/usr/bin/mysql")
_reg(Command_python3, "python3", "python3.12", "/usr/bin/python3", "/usr/bin/python3.12")
_reg(Command_lsb_release, "lsb_release", "/usr/bin/lsb_release")
_reg(Command_hostnamectl, "hostnamectl", "/usr/bin/hostnamectl")
_reg(Command_editor_noterm, "nano", "pico", "/usr/bin/nano", "/usr/bin/pico")
for _c in ("ifconfig", "netstat", "route", "arp", "python", "locate", "emacs"):
    commands[_c] = _not_installed(_c)


class Command_which(HoneyPotCommand):
    """Debian's which: first match on PATH only (all of them with -a), exit 1 when any name is missing."""
    resolve_args = False

    def call(self) -> None:
        show_all = "-a" in self.args
        names = [a for a in self.args if not a.startswith("-")]
        path_dirs = self.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin").split(":")
        missing = False
        for name in names:
            found = False
            candidates = [name] if "/" in name else [f"{d}/{name}" for d in path_dirs if d]
            for cand in candidates:
                resolved = self.fs.resolve_path(cand, self.cwd)
                if self.fs.exists(resolved) and not self.fs.isdir(resolved):
                    self.write(cand + "\n")
                    found = True
                    if not show_all:
                        break
            missing = missing or not found
        self.exit_code = 1 if missing or not names else 0


_reg(Command_which, "which", "/usr/bin/which")
