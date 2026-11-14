"""tools/agent_eval.py: labelled test sessions and the score of the dashboard's classes against them."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import agent_eval as ev  # noqa: E402

OWN, OTHER = "198.51.100.7", "45.155.205.10"


def lab(kind, t0, t1, tool="t"):
    return {"kind": kind, "tool": tool, "t0": t0, "t1": t1}


def ses(sid, start, cls, ip=OWN, kind="ssh"):
    return {"id": sid, "start": start, "cls": cls, "ip": ip, "kind": kind}


class Matching(unittest.TestCase):
    def test_pairs_only_own_ssh_sessions_inside_the_window(self):
        labels = [lab("agent", 100_000, 200_000), lab("script", 500_000, 600_000)]
        sessions = [ses("a", 150_000, "agent_suspected"), ses("b", 150_000, "script", ip=OTHER),
                    ses("c", 550_000, "script"), ses("d", 150_000, "script", kind="web"),
                    ses("e", 900_000, "script")]
        pairs = ev.match(labels, sessions, {OWN})
        self.assertEqual(sorted((l["kind"], s["id"]) for l, s in pairs), [("agent", "a"), ("script", "c")])

    def test_a_label_without_a_session_is_reported_not_dropped(self):
        pairs = ev.match([lab("human", 100_000, 200_000)], [], {OWN})
        self.assertEqual(pairs, [(lab("human", 100_000, 200_000), None)])
        self.assertEqual(ev.score(pairs)["missing"], {"human": 1})

    def test_a_session_is_claimed_once_by_the_tightest_window(self):
        wide, tight = lab("human", 0, 1_000_000), lab("agent", 400_000, 500_000)
        pairs = ev.match([wide, tight], [ses("a", 450_000, "agent_suspected")], {OWN})
        self.assertIn((tight, ses("a", 450_000, "agent_suspected")), pairs)
        self.assertIn((wide, None), pairs)


class Scoring(unittest.TestCase):
    def test_accuracy_precision_and_recall(self):
        pairs = [(lab("agent", 0, 1), ses("1", 0, "agent_suspected")),
                 (lab("agent", 0, 1), ses("2", 0, "agent_confirmed")),
                 (lab("agent", 0, 1), ses("3", 0, "script")),            # missed agent
                 (lab("agent", 0, 1), ses("4", 0, "unknown")),           # missed agent
                 (lab("script", 0, 1), ses("5", 0, "known_bot")),
                 (lab("script", 0, 1), ses("6", 0, "agent_suspected")),  # false alarm
                 (lab("human", 0, 1), ses("7", 0, "human_like"))]
        r = ev.score(pairs)
        self.assertEqual((r["right"], r["total"]), (4, 7))
        self.assertAlmostEqual(r["agent_recall"], 2 / 4)
        self.assertAlmostEqual(r["agent_precision"], 2 / 3)

    def test_nothing_to_score(self):
        r = ev.score([])
        self.assertIsNone(r["accuracy"])
        self.assertIsNone(r["agent_precision"])


class TestAgent(unittest.TestCase):
    def test_command_from_a_model_reply(self):
        self.assertEqual(ev.command_from("ls -la /root"), "ls -la /root")
        self.assertEqual(ev.command_from("```bash\ncat /etc/passwd\n```"), "cat /etc/passwd")
        self.assertEqual(ev.command_from("`id`\nThis shows who I am."), "id")
        self.assertEqual(ev.command_from("$ uname -a"), "uname -a")
        self.assertEqual(ev.command_from("DONE"), "")
        self.assertEqual(ev.command_from("  \n"), "")
        self.assertEqual(len(ev.command_from("x" * 5000)), ev.MAX_CMD)

    def test_output_is_cleaned_and_addresses_hidden(self):
        out = ev.clean_output("\x1b[01;32mroot@fs\x1b[0m: 198.51.100.7 from 192.0.2.44\r\n" + "A" * 5000,
                              ["198.51.100.7", "192.0.2.44", ""])
        self.assertNotIn("198.51.100.7", out)
        self.assertNotIn("192.0.2.44", out)
        self.assertNotIn("\x1b", out)
        self.assertTrue(out.endswith("[output cut]"))
        self.assertLess(len(out), ev.MAX_OUT + 20)

    def test_loop_runs_commands_until_done_or_the_step_limit(self):
        class FakeShell:
            ran = []

            def run(self, cmd):
                self.ran.append(cmd)
                return f"output of {cmd} on 192.0.2.44"

        seen = []

        def think(messages):
            seen.append([m["content"] for m in messages])
            return ["id", "ls /root", "DONE", "rm -rf /"][len(seen) - 1]

        sh = FakeShell()
        self.assertEqual(ev.agent_session(sh, think, 10, ["192.0.2.44"]), 2)
        self.assertEqual(sh.ran, ["id", "ls /root"])
        self.assertTrue(all("192.0.2.44" not in c for msgs in seen for c in msgs))
        FakeShell.ran = []
        self.assertEqual(ev.agent_session(FakeShell(), lambda m: "id", 3, []), 3)

    def test_paid_models_are_never_called(self):
        with self.assertRaises(RuntimeError):
            ev.ask_model("k", ["openai/gpt-paid", "anthropic/claude-paid"], [])   # no network call happens


if __name__ == "__main__":
    unittest.main()
