"""tools/agent_eval.py: labelled test sessions and the score of the dashboard's classes against them."""
import json
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


class Bridge(unittest.TestCase):
    """The local bridge a real agent tool sends its commands through."""

    def ask(self, req, token="t0k"):
        ran = []
        ans = ev.bridge_answer(json.dumps(req).encode() if isinstance(req, dict) else req, token,
                               lambda c: ran.append(c) or "out:" + c)
        return ans, ran

    def test_a_command_with_the_right_token_runs(self):
        self.assertEqual(self.ask({"token": "t0k", "cmd": " id "}), ({"out": "out:id"}, ["id"]))

    def test_wrong_or_missing_token_runs_nothing(self):
        for req in ({"token": "nope", "cmd": "id"}, {"cmd": "id"}, {"token": None, "cmd": "id"}):
            ans, ran = self.ask(req)
            self.assertEqual((ans, ran), ({"error": "wrong token"}, []))

    def test_bad_requests_run_nothing(self):
        for req in (b"not json", b"[1]", {"token": "t0k"}, {"token": "t0k", "cmd": 5}, {"token": "t0k", "cmd": "  "},
                    {"token": "t0k", "cmd": "id\nrm -rf /"}, {"token": "t0k", "cmd": "x" * 5000}):
            ans, ran = self.ask(req)
            self.assertIn("error", ans)
            self.assertEqual(ran, [])

    def test_echo_and_prompt_are_removed_from_the_output(self):
        out = "ls -la /root\ntotal 8\n-rw------- 1 root root 12 RUNBOOK.md\nroot@fs-main:~# "
        self.assertEqual(ev.strip_echo(out, "ls -la /root"), "total 8\n-rw------- 1 root root 12 RUNBOOK.md")
        self.assertEqual(ev.strip_echo("uid=0(root)", "id"), "uid=0(root)")


class BridgeEndToEnd(unittest.TestCase):
    """bridge and run talking over the local socket, with a fake shell instead of the honeypot."""

    def test_commands_go_through_and_the_session_is_labelled(self):
        import argparse, contextlib, io, tempfile, threading, time
        from unittest import mock

        class FakeChannel:
            closed = False

        class FakeShell:
            ch = FakeChannel()

            def __init__(self, *a):
                pass

            def run(self, cmd):
                return f"{cmd}\nran {cmd} on {OWN}\nroot@fs-main:~# "

            def close(self):
                pass

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        bridge_file, labels = os.path.join(tmp.name, "bridge.json"), []
        args = argparse.Namespace(host="h", port=22, user="root", tool="claude-code", note="")
        client = os.path.join(tmp.name, "srv-tools", ev.CLIENT_NAME)
        with mock.patch.multiple(ev, BRIDGE=bridge_file, DATA=tmp.name, Shell=FakeShell, need_paramiko=lambda: True,
                                 CLIENT_DIR=os.path.dirname(client),
                                 login=lambda *a: ("root", "x"),
                                 dashboard_config=lambda: {"own_ips": [OWN]},
                                 add_label=lambda *a: labels.append(a)), contextlib.redirect_stdout(io.StringIO()):
            t = threading.Thread(target=ev.run_bridge, args=(args,), daemon=True)
            t.start()
            for _ in range(100):
                if os.path.exists(bridge_file):
                    break
                time.sleep(0.05)
            outs = []
            for cmd in ("id", "uname -a", "ls /root"):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    self.assertEqual(ev.run_one(argparse.Namespace(command=cmd)), 0)
                outs.append(buf.getvalue().strip())
            # the neutral client the tool is given: works, and says nothing about what this is
            import subprocess
            code = open(client, encoding="utf-8").read().lower()
            for word in ("honeypot", "hotpot", "eval", "bridge", "agent", "test"):
                self.assertNotIn(word, code)
            self.assertNotIn("honeypot", client.lower().replace(tmp.name.lower(), ""))
            r = subprocess.run([sys.executable, client, "pwd"], capture_output=True, text=True, timeout=30)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, "ran pwd on 203.0.113.10"))
            FakeShell.ch.closed = True          # the honeypot hangs up: the bridge stops and labels
            t.join(5)
            self.assertFalse(t.is_alive())
            # echo, prompt and own address gone (the bridge's own progress line shares stdout in this test)
            self.assertEqual(outs[0].splitlines()[-1], "ran id on 203.0.113.10")
            self.assertNotIn("fs-main:~#", outs[0])
            self.assertEqual((labels[0][0], labels[0][1]), ("agent", "claude-code"))
            self.assertFalse(os.path.exists(bridge_file))
            self.assertFalse(os.path.exists(client))
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(ev.run_one(argparse.Namespace(command="id")), 2)   # no bridge any more


if __name__ == "__main__":
    unittest.main()
