"""dashboard/health.py: the problems the dashboard's banner reports."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "dashboard"))
import health  # noqa: E402

NOW = 1_800_000_000
GB = 1 << 30


def vm(key="front", **over):
    v = {"key": key, "label": "Front VM" if key == "front" else "Backend VM", "ok": True, "cpus": 2,
         "load": [0.2, 0.3, 0.2], "disk_total": 40 * GB, "disk_free": 25 * GB, "mem_total": GB, "mem_avail": GB // 2,
         "swap_total": 2 * GB, "swap_free": 2 * GB, "now": NOW * 1000,
         "services": [{"name": "Docker", "state": "active"}, {"name": "container cowrie", "state": "running"}],
         "data": {"cowrie_log": NOW * 1000 - 60_000, "web_log": NOW * 1000 - 60_000}}
    if key == "backend":
        v["container"] = {"name": "fileserver01", "status": "Running", "clean_snapshot": "2026-11-01T00:00:00Z"}
        v["data"] = {"collector_run": NOW * 1000 - 30_000}
    v.update(over)
    return v


def ids(status=None, *vms):
    return [p["id"] for p in health.problems(status or {"last_ok": NOW - 30}, {"vms": list(vms)}, NOW)]


class Health(unittest.TestCase):
    def test_a_healthy_sensor_reports_nothing(self):
        self.assertEqual(ids(None, vm(), vm("backend")), [])
        self.assertEqual(health.problems({}, None, NOW), [])            # before the first probe

    def test_sync_error_counts_only_after_a_while(self):
        self.assertEqual(ids({"error": "timeout", "last_ok": NOW - 120}, vm()), [])
        self.assertEqual(ids({"error": "timeout", "last_ok": NOW - 3600}, vm(ok=False, error="x")), ["sync"])

    def test_overload_like_the_one_that_hung_logins(self):
        self.assertEqual(ids(None, vm("backend", load=[92, 96, 88])), ["backend-load"])

    def test_disk_services_container_and_collector(self):
        self.assertEqual(ids(None, vm(disk_free=4 * GB)), ["front-disk"])
        self.assertEqual(ids(None, vm(services=[{"name": "container webpot", "state": "exited"}])), ["front-services"])
        self.assertEqual(ids(None, vm("backend", container={"status": "Stopped"})), ["container"])
        self.assertEqual(ids(None, vm("backend", container={"status": "Running"})), ["snapshot"])
        self.assertEqual(ids(None, vm("backend", data={"collector_run": NOW * 1000 - 3600_000})), ["collector"])

    def test_a_silent_honeypot_is_a_warning(self):
        p = health.problems({"last_ok": NOW}, {"vms": [vm(data={"cowrie_log": NOW * 1000 - 8 * 3600_000})]}, NOW)
        self.assertEqual([(x["id"], x["level"]) for x in p], [("quiet-cowrie_log", "warn")])

    def test_worst_first_and_text_is_capped(self):
        p = health.problems({"last_ok": NOW}, {"vms": [vm(data={"web_log": 1}), vm("backend", ok=False, error="e" * 900)]}, NOW)
        self.assertEqual([x["level"] for x in p], ["bad", "warn"])
        self.assertLessEqual(len(p[0]["detail"]), 300)


class Alerts(unittest.TestCase):
    BAD = [{"id": "backend-load", "level": "bad", "title": "Backend VM is overloaded (load 92)", "detail": "10.0.1.9 hung"}]
    WARN = [{"id": "quiet-web_log", "level": "warn", "title": "Nothing has reached the web honeypot", "detail": ""}]

    def test_only_https_links_are_accepted(self):
        self.assertEqual(health.clean_alert_url("  "), "")
        self.assertEqual(health.clean_alert_url(" https://ntfy.sh/my-topic "), "https://ntfy.sh/my-topic")
        for bad in ("http://ntfy.sh/x", "ntfy.sh/x", "https://", "https://a.example/x y", "file:///etc/passwd"):
            with self.assertRaises(ValueError):
                health.clean_alert_url(bad)

    def test_a_problem_is_announced_once_then_resolved_once(self):
        st = {}
        self.assertEqual(health.alert_plan(self.BAD, st, NOW), [("HotPot: Backend VM is overloaded (load 92)", "")])
        self.assertEqual(health.alert_plan(self.BAD, st, NOW + 300), [])
        self.assertEqual(health.alert_plan([], st, NOW + 600), [("HotPot: resolved", "Backend VM is overloaded (load 92)")])
        self.assertEqual(health.alert_plan([], st, NOW + 900), [])

    def test_a_flapping_problem_is_not_repeated_within_six_hours(self):
        st = {}
        health.alert_plan(self.BAD, st, NOW)
        health.alert_plan([], st, NOW + 300)
        self.assertEqual(health.alert_plan(self.BAD, st, NOW + 600), [])
        self.assertEqual(len(health.alert_plan(self.BAD, st, NOW + 7 * 3600)), 1)

    def test_warnings_and_details_are_never_sent(self):
        self.assertEqual(health.alert_plan(self.WARN, {}, NOW), [])
        sent = health.alert_plan(self.BAD, {}, NOW)
        self.assertNotIn("10.0.1.9", repr(sent))

    def test_request_shape_per_receiver(self):
        r = health.alert_request("https://ntfy.sh/topic", "HotPot: x", "")
        self.assertEqual((r.get_method(), r.data, r.get_header("Title")), ("POST", b"HotPot: x", "HotPot: x"))
        r = health.alert_request("https://discord.com/api/webhooks/1/abc", "HotPot: resolved", "disk")
        self.assertEqual(r.data, b'{"content": "HotPot: resolved\\ndisk"}')
        self.assertIn(b'"text"', health.alert_request("https://hooks.slack.com/services/x", "t").data)


if __name__ == "__main__":
    unittest.main()
