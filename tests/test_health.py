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


if __name__ == "__main__":
    unittest.main()
