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

    def test_steady_varied_commands_still_look_like_an_agent(self):
        x = session("SSH-2.0-paramiko_3.4.0", self.EXPLORE, [6, 6.5, 6, 7, 6.2, 6.4])
        self.assertEqual(x["cls"], "agent_suspected")

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
