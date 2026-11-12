"""dashboard/forward.py: settings checks, document shape, and sending to local test receivers."""
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "dashboard"))
import forward  # noqa: E402


class Receiver:
    """A local HTTP server that records every POST body."""

    def __init__(self, reply=b"{}"):
        self.bodies, self.headers = [], []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                outer.bodies.append(self.rfile.read(int(self.headers["Content-Length"])))
                outer.headers.append(dict(self.headers))
                self.send_response(200)
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def cowrie_line(n, ip="203.0.113.5"):
    return json.dumps({"eventid": "cowrie.command.input", "input": f"echo {n} '\"; DROP", "src_ip": ip,
                       "timestamp": "2026-11-12T10:00:00.123456Z", "session": "s1"}) + "\n"


class SettingsTest(unittest.TestCase):
    def test_validation(self):
        with self.assertRaises(ValueError):
            forward.clean({"enabled": True, "type": "syslog", "address": "no-port"}, {})
        with self.assertRaises(ValueError):
            forward.clean({"enabled": True, "type": "http", "address": "file:///etc/passwd"}, {})
        with self.assertRaises(ValueError):
            forward.clean({"enabled": True, "type": "http", "address": "https://user:pw@x.example/"}, {})
        with self.assertRaises(ValueError):
            forward.clean({"token": "bad token with spaces"}, {})
        with self.assertRaises(ValueError):
            forward.clean({"index": "Bad Index!"}, {})
        c = forward.clean({"enabled": True, "type": "elasticsearch", "address": "https://es.example:9200",
                           "token": "abcDEF123==", "sources": ["cowrie", "nope"]}, {})
        self.assertEqual(c["sources"], ["cowrie"])
        self.assertEqual(forward.target(c), "https://es.example:9200/_bulk")
        self.assertEqual(forward.clean({}, c)["token"], "abcDEF123==")   # absent: kept
        self.assertNotIn("token", forward.clean({"token": ""}, c))      # "": removed

    def test_view_hides_token(self):
        v = forward.view({"token": "supersecrettoken1234"})
        self.assertEqual(v["token"], {"set": True, "hint": "…1234"})
        self.assertNotIn("supersecret", json.dumps(v))

    def test_event_time_and_document(self):
        self.assertAlmostEqual(forward.event_time({"t": 1_700_000_000_000}), 1_700_000_000, places=3)
        self.assertAlmostEqual(forward.event_time({"timestamp": "2023-11-14T22:13:20Z"}), 1_700_000_000, places=3)
        d = forward.document("ids", {"timestamp": "2023-11-14T22:13:20.5+0000"}, "s1")
        self.assertEqual(d["source"], "ids")
        self.assertIn("ids", d)
        self.assertTrue(d["@timestamp"].endswith("Z"))

    def test_syslog_line(self):
        d = forward.document("web", {"path": "/a\nb", "t": 1_700_000_000_000}, "sensor1")
        line = forward.syslog_line(d)
        self.assertTrue(line.startswith(b"<134>1 2023-11-14T22:13:20.000Z sensor1 hotpot - web - {"))
        self.assertNotIn(b"\n", line)  # attacker newlines stay escaped inside the JSON


class ForwarderTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.mirror = os.path.join(self.dir, "mirror")
        os.makedirs(self.mirror)
        self.rx = Receiver()
        self.addCleanup(self.rx.close)
        self.cfg = forward.clean({"enabled": True, "type": "http", "address": self.rx.url + "/in"}, {})

    def write(self, name, text, mode="a"):
        with open(os.path.join(self.mirror, name), mode, encoding="utf-8") as f:
            f.write(text)

    def sent(self):
        return [json.loads(l) for b in self.rx.bodies for l in b.decode().splitlines()]

    def test_history_is_not_sent_then_new_lines_are_once(self):
        self.write("cowrie__cowrie.json", "".join(cowrie_line(i) for i in range(5)))
        fw = forward.Forwarder(os.path.join(self.dir, "state.json"))
        fw.run(self.cfg, self.mirror)
        self.assertEqual(self.sent(), [])          # first run: starts from now
        self.write("cowrie__cowrie.json", cowrie_line(5) + cowrie_line(6))
        fw.run(self.cfg, self.mirror)
        fw.run(self.cfg, self.mirror)
        got = self.sent()
        self.assertEqual([d["cowrie"]["input"][:6] for d in got], ["echo 5", "echo 6"])
        self.assertEqual(got[0]["source"], "cowrie")
        self.assertIsNone(fw.status["error"])

    def test_rotated_copy_sends_only_the_tail(self):
        head = "".join(cowrie_line(i) for i in range(5))
        self.write("cowrie__cowrie.json", head)
        fw = forward.Forwarder(os.path.join(self.dir, "state.json"))
        fw.run(self.cfg, self.mirror)
        # the VM renamed cowrie.json (two more lines got in first) and started a new one
        self.write("cowrie__cowrie.json.2026-11-12", head + cowrie_line(5) + cowrie_line(6), "w")
        self.write("cowrie__cowrie.json", cowrie_line(7, ip="198.51.100.9"), "w")
        fw.run(self.cfg, self.mirror)
        self.assertEqual(sorted(d["cowrie"]["input"][:6] for d in self.sent()), ["echo 5", "echo 6", "echo 7"])

    def test_own_ips_partial_lines_and_sources(self):
        fw = forward.Forwarder(os.path.join(self.dir, "state.json"))
        fw.run(self.cfg, self.mirror)
        self.write("cowrie__cowrie.json", cowrie_line(1, ip="192.0.2.1") + cowrie_line(2) + '{"eventid": "half')
        self.write("web__web.jsonl", json.dumps({"ip": "203.0.113.7", "path": "/x"}) + "\n")
        cfg = dict(self.cfg, sources=["cowrie"])
        fw.run(cfg, self.mirror, own_ips=["192.0.2.1"])
        got = self.sent()
        self.assertEqual([d["cowrie"]["input"][:6] for d in got], ["echo 2"])

    def test_unreadable_or_old_progress_never_sends_history(self):
        self.write("cowrie__cowrie.json", "".join(cowrie_line(i) for i in range(5)))
        path = os.path.join(self.dir, "state.json")
        for old in ('{"0123abcd": 5}', "not json", '{"v": 99, "files": {}}'):
            with open(path, "w") as f:
                f.write(old)
            forward.Forwarder(path).run(self.cfg, self.mirror)
        self.assertEqual(self.sent(), [])

    def test_restart_skips_the_backlog(self):
        fw = forward.Forwarder(os.path.join(self.dir, "state.json"))
        fw.run(self.cfg, self.mirror)
        self.write("cowrie__cowrie.json", cowrie_line(1))  # arrived while forwarding was off
        fw.restart()
        fw.run(self.cfg, self.mirror)
        self.write("cowrie__cowrie.json", cowrie_line(2))
        fw.run(self.cfg, self.mirror)
        self.assertEqual([d["cowrie"]["input"][:6] for d in self.sent()], ["echo 2"])

    def test_unreachable_destination_keeps_lines_for_later(self):
        fw = forward.Forwarder(os.path.join(self.dir, "state.json"))
        fw.run(self.cfg, self.mirror)
        self.write("cowrie__cowrie.json", cowrie_line(1))
        bad = dict(self.cfg, address="http://127.0.0.1:9/in")
        fw.run(bad, self.mirror)
        self.assertTrue(fw.status["error"])
        self.assertGreater(fw.status["pending"], 0)
        fw.run(self.cfg, self.mirror)
        self.assertEqual(len(self.sent()), 1)

    def test_elasticsearch_bulk_and_rejections(self):
        rx = Receiver(json.dumps({"errors": True, "items": [{"create": {"status": 201}},
                                                            {"create": {"error": {"type": "mapper_parsing"}}}]}).encode())
        self.addCleanup(rx.close)
        cfg = forward.clean({"enabled": True, "type": "elasticsearch", "address": rx.url, "token": "abcd1234=="}, {})
        self.assertEqual(forward.send(cfg, [forward.document("web", {"t": 1}, "s")] * 2), 1)
        lines = rx.bodies[0].decode().splitlines()
        self.assertEqual(json.loads(lines[0]), {"create": {"_index": "hotpot"}})
        self.assertEqual(rx.headers[0]["Authorization"], "ApiKey abcd1234==")

    def test_splunk_hec(self):
        cfg = forward.clean({"enabled": True, "type": "splunk", "address": self.rx.url, "token": "1234-5678-abcd"}, {})
        forward.send(cfg, [forward.document("ids", {"timestamp": "2023-11-14T22:13:20Z"}, "s")])
        ev = json.loads(self.rx.bodies[0])
        self.assertEqual(ev["sourcetype"], "hotpot:ids")
        self.assertEqual(ev["time"], 1_700_000_000)
        self.assertEqual(self.rx.headers[0]["Authorization"], "Splunk 1234-5678-abcd")

    def test_syslog_tcp_octet_counting(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        got = []

        def accept():
            c, _ = srv.accept()
            with c:
                while True:
                    b = c.recv(65536)
                    if not b:
                        break
                    got.append(b)
        t = threading.Thread(target=accept, daemon=True)
        t.start()
        cfg = forward.clean({"enabled": True, "type": "syslog", "proto": "tcp",
                             "address": f"127.0.0.1:{srv.getsockname()[1]}"}, {})
        forward.send(cfg, [forward.document("web", {"t": 1}, "s"), forward.document("web", {"t": 2}, "s")])
        t.join(5)
        srv.close()
        data = b"".join(got)
        n, _, rest = data.partition(b" ")
        self.assertTrue(rest[:int(n)].startswith(b"<134>1 "))
        self.assertTrue(rest[int(n):].split(b" ", 1)[1].startswith(b"<134>1 "))


if __name__ == "__main__":
    unittest.main()
