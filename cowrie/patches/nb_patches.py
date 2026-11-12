"""Patches that make Cowrie behave like the stock OpenSSH / bash on an Ubuntu 24.04 server.

Written against cowrie/cowrie@sha256:99dc2531... (Cowrie 2026-11, Twisted 26.10). The image is
pinned in docker-compose.yml; re-check these hooks before moving to a newer image.
"""
import sys

# The closest match to OpenSSH 9.6 that Twisted can actually negotiate. Twisted lacks sntrup761,
# DH group16/18, chacha20, GCM and ETM MACs, so the result looks like a hardened sshd_config
# (the honeyfs ships a matching /etc/ssh/sshd_config). ssh-rsa stays last, as if re-enabled for
# legacy clients, so old bots can still connect.
KEX = [b"curve25519-sha256", b"curve25519-sha256@libssh.org", b"ecdh-sha2-nistp256",
       b"ecdh-sha2-nistp384", b"ecdh-sha2-nistp521", b"diffie-hellman-group-exchange-sha256"]
HOSTKEYS = [b"rsa-sha2-512", b"rsa-sha2-256", b"ecdsa-sha2-nistp256", b"ssh-ed25519", b"ssh-rsa"]


def _patch_ssh():
    from cowrie.ssh import factory as sf
    from cowrie.ssh import transport as st

    orig_build = sf.CowrieSSHFactory.buildProtocol

    def buildProtocol(self, addr):
        t = orig_build(self, addr)
        offered = [k for k in KEX if k in t.supportedKeyExchanges]
        if offered:
            t.supportedKeyExchanges = offered
        have = set(self.privateKeys)
        t.supportedPublicKeys = [k for k in HOSTKEYS
                                 if (b"ssh-rsa" if k.startswith(b"rsa-sha2") else k) in have]
        return t

    sf.CowrieSSHFactory.buildProtocol = buildProtocol

    T = st.HoneyPotSSHTransport

    def _unsupportedVersionReceived(self, remoteVersion):
        self.transport.write(b"Protocol major versions differ.\r\n")
        self.transport.loseConnection()

    T._unsupportedVersionReceived = _unsupportedVersionReceived

    orig_data = T.dataReceived

    def dataReceived(self, data):
        # OpenSSH 9.x closes silently on a garbage identification line; Cowrie writes a message.
        if getattr(self, "gotVersion", True):
            return orig_data(self, data)
        tr = self.transport
        real_write = tr.write

        def write(b):
            if b.startswith(b"Invalid SSH identification string"):
                return
            real_write(b)

        tr.write = write
        try:
            return orig_data(self, data)
        finally:
            try:
                del tr.write
            except AttributeError:
                tr.write = real_write

    T.dataReceived = dataReceived


def _patch_shell():
    from cowrie.commands import nb_extra
    from cowrie.shell import command
    from cowrie.shell import honeypot as sh
    from cowrie.shell import protocol as sp

    P = sp.HoneyPotBaseProtocol

    # A full path like /usr/bin/df must reach our command too, not Cowrie's stale canned output.
    orig_get = P.getCommand

    def getCommand(self, cmd, paths, cwd):
        if cmd and "/" in cmd:
            base = cmd.rstrip("/").rsplit("/", 1)[-1]
            if base in nb_extra.commands:
                path = self.fs.resolve_path(cmd, cwd)
                if self.fs.exists(path) and not self.fs.isdir(path):
                    return nb_extra.commands[base]
        return orig_get(self, cmd, paths, cwd)

    P.getCommand = getCommand

    # Cowrie answers "cannot execute binary file: Exec format error" for every x86-64 binary it
    # does not emulate, which no real x86-64 box does. Run those silently; other architectures
    # (ARM/MIPS bot payloads) keep the genuine error.
    class Command_silent(command.HoneyPotCommand):
        def call(self):
            pass

    orig_script = P.scriptcmd

    def scriptcmd(self, path, name):
        try:
            data = self.fs.file_contents(path)
        except Exception:
            data = b""
        if data[:4] == b"\x7fELF" and data[18:20] == b"\x3e\x00":
            try:
                if self.fs.is_executable(path, self.user["uid"], self.user["gid"]):
                    return Command_silent
            except Exception:
                return Command_silent
        return orig_script(self, path, name)

    P.scriptcmd = scriptcmd

    # Ubuntu's command-not-found handler: "foo: command not found", or an install hint for
    # well-known tools. Non-interactive shells keep bash's "bash: line 1: ..." form.
    orig_nf = sh.HoneyPotShell.command_not_found_message

    def command_not_found_message(self, cmd):
        if cmd[:1] in (".", "/") or getattr(self, "line_numbers", False):
            return orig_nf(self, cmd)
        try:
            root = int(self.protocol.user.uid) == 0
        except Exception:
            root = True
        hint = nb_extra.not_found_hint(cmd, root)
        return hint if hint else f"{cmd}: command not found\n"

    sh.HoneyPotShell.command_not_found_message = command_not_found_message


def _patch_banner():
    # Stock Ubuntu sshd sends no pre-login banner (no Banner line in sshd_config).
    from cowrie.ssh import userauth as ua

    def sendBanner(self):
        self.bannerSent = True

    ua.HoneyPotSSHUserAuthServer.sendBanner = sendBanner


def _patch_auth():
    """Realistic passwords: only common passwords work, and once one has worked for a user from an
    IP, only that one works from there (a real account has one password). Stops the "two random
    passwords both succeed" honeypot check. Any error falls back to Cowrie's own answer."""
    import json
    import os
    import time
    from cowrie.core import auth

    words_path = "/cowrie/patches/passwords.txt"
    locks_path = "/cowrie/cowrie-git/var/lib/cowrie/nb_auth_locks.json"
    ttl = 7 * 86400
    with open(words_path, encoding="utf-8", errors="replace") as f:
        words = {ln.rstrip() for ln in f if ln.strip()}
    try:
        with open(locks_path, encoding="utf-8") as f:
            locks = json.load(f)
    except (OSError, ValueError):
        locks = {}

    def save():
        now = time.time()
        for k in [k for k, v in locks.items() if now - v[1] > ttl]:
            del locks[k]
        tmp = locks_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(locks, f)
        os.replace(tmp, locks_path)

    orig = auth.UserDB.checklogin

    def checklogin(self, thelogin, thepasswd, src_ip="0.0.0.0"):
        ok = orig(self, thelogin, thepasswd, src_ip)
        if not ok:
            return ok
        try:
            user = thelogin.decode("utf-8", "replace")
            pw = thepasswd.decode("utf-8", "replace")
            key = f"{src_ip}|{user}"
            now = time.time()
            lock = locks.get(key)
            if lock and now - lock[1] <= ttl:
                if pw == lock[0]:
                    lock[1] = now
                    save()
                    return True
                return False
            if pw not in words:
                return False
            locks[key] = [pw, now]
            save()
            return True
        except Exception as e:
            print(f"nb-patches: auth hook error: {e!r}", file=sys.stderr)
            return ok

    auth.UserDB.checklogin = checklogin


def _patch_proxy_login():
    """Proxy mode: log in to the real backend as the user the attacker typed (root, ubuntu, deploy or admin;
    userdb allows no others), with the shared backend password from the config, so whoami and $HOME match."""
    from cowrie.core.config import CowrieConfig
    from cowrie.ssh_proxy import client_transport as ct
    from cowrie.telnet_proxy import handler as th

    def _as_bytes(v):
        return v if isinstance(v, bytes) else str(v or "").encode()

    orig_auth = ct.BackendSSHTransport.authenticateBackend

    def authenticateBackend(self, tried_username=None, tried_password=None):
        user = tried_username or getattr(self, "frontendTriedUsername", None)
        if user:
            self._nb_user = _as_bytes(user).decode("utf-8", "replace")
        real_get = CowrieConfig.get
        chosen = getattr(self, "_nb_user", None)

        def get(section, option, *a, **kw):
            if chosen and section == "proxy" and option == "backend_user":
                return chosen
            return real_get(section, option, *a, **kw)

        CowrieConfig.get = get
        try:
            return orig_auth(self, tried_username, tried_password)
        finally:
            CowrieConfig.get = real_get

    ct.BackendSSHTransport.authenticateBackend = authenticateBackend

    import re as _re
    IAC_CMD = _re.compile(rb"\xff[\xfb-\xfe].|\xff\xfa.*?\xff\xf0|\xff[\xf1-\xf9]", _re.S)

    def _split_iac(self):
        """Telnet option replies typed while a login prompt is up belong to the backend's negotiation,
        not to the username/password (stock Cowrie glues them on). Send them through, keep the text."""
        data = self.currentData
        cmds = b"".join(m.group(0) for m in IAC_CMD.finditer(data))
        if cmds:
            self.currentData = IAC_CMD.sub(b"", data)
            self.sendBackend(cmds)

    orig_pass = th.TelnetHandler.processPasswordInput

    def processPasswordInput(self):
        _split_iac(self)
        if self.currentData or not self.prePasswordData:
            return orig_pass(self)

    th.TelnetHandler.processPasswordInput = processPasswordInput

    orig_user = th.TelnetHandler.processUsernameInput

    def processUsernameInput(self):
        _split_iac(self)
        if not self.currentData:
            return
        orig_user(self)
        if self.phase == th.LoginPhase.USERNAME_SENT and self.currentData.startswith(self.backendLogin):
            typed = self.usernameState.strip()[:32]
            if typed:
                self.currentData = typed + self.currentData[len(self.backendLogin):]

    th.TelnetHandler.processUsernameInput = processUsernameInput


def _patch_ttylog():
    """Name each terminal recording by the hash of the whole file, not just the attacker's input.
    Stock Cowrie hashes input only, so every session that typed nothing (exec-channel bots) or typed
    the same thing shares one file name, and later recordings are thrown away as "duplicates"."""
    import hashlib
    from cowrie.core import ttylog

    def ttylog_inputhash(logfile):
        h = hashlib.sha256()
        with open(logfile, "rb") as fd:
            for chunk in iter(lambda: fd.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    ttylog.ttylog_inputhash = ttylog_inputhash


def apply():
    for fn in (_patch_ssh, _patch_shell, _patch_banner, _patch_auth, _patch_proxy_login, _patch_ttylog):
        try:
            fn()
        except Exception as e:  # keep Cowrie running even if one hook moved
            print(f"nb-patches: {fn.__name__} failed: {e!r}", file=sys.stderr)
