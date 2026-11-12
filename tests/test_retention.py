"""install/retention.sh against a fake VM file tree (Linux only: needs bash, flock and GNU stat)."""
import os
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "install", "retention.sh")
DAY = 86400

FILES = {  # path under the fake root: age in days
    "var/lib/docker/volumes/honeypot_cowrie-var/_data/log/cowrie/cowrie.json": 0,
    "var/lib/docker/volumes/honeypot_cowrie-var/_data/log/cowrie/cowrie.json.2026-01-01": 40,
    "var/lib/docker/volumes/honeypot_cowrie-var/_data/log/cowrie/cowrie.json.2026-02-01": 10,
    "var/lib/docker/volumes/honeypot_web-data/_data/web.jsonl": 60,  # active file: never touched
    "var/lib/docker/volumes/honeypot_web-data/_data/web.jsonl.20260101000000": 35,
    "var/lib/docker/volumes/honeypot_ids-log/_data/eve-202601010420.json": 31,
    "var/lib/docker/volumes/honeypot_cowrie-var/_data/lib/cowrie/tty/abc": 45,
    "var/lib/nb-export/backend.jsonl": 90,
    "var/lib/nb-export/backend.jsonl.20260101000000": 33,
    "var/lib/nb-harvest/fileserver01-20260101T030000Z.tgz": 100,
    "var/lib/nb-harvest/fileserver01-20260801T030000Z.tgz": 20,
    "var/lib/nb-quarantine/files/" + "a" * 64 + ".bin": 120,
    "var/lib/nb-quarantine/files/" + "b" * 64 + ".bin": 50,
    "var/lib/nb-quarantine/files/" + "c" * 64 + ".bin": 0.01,  # 15 minutes: may still be written
}


@unittest.skipUnless(shutil.which("bash") and shutil.which("flock") and os.name == "posix",
                     "needs bash and flock (Linux)")
class RetentionTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        now = time.time()
        for rel, age in FILES.items():
            p = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write("x" * 1000)
            os.utime(p, (now - age * DAY, now - age * DAY))

    def conf(self, text):
        p = os.path.join(self.root, "opt/honeypot/.env")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)

    def run_it(self, *args, used="10"):
        env = dict(os.environ, RETENTION_ROOT=self.root, RETENTION_USED=used)
        r = subprocess.run(["bash", SCRIPT, *args], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def left(self):
        return {rel for rel in FILES if os.path.exists(os.path.join(self.root, rel))}

    def test_age_limits(self):
        self.conf("LOG_KEEP_DAYS=30\nSAMPLE_KEEP_DAYS=90\n")
        out = self.run_it()
        gone = set(FILES) - self.left()
        self.assertEqual({os.path.basename(p) for p in gone}, {
            "cowrie.json.2026-01-01", "web.jsonl.20260101000000", "eve-202601010420.json", "abc",
            "backend.jsonl.20260101000000", "fileserver01-20260101T030000Z.tgz", "a" * 64 + ".bin"})
        self.assertIn("deleted 7 files", out)

    def test_zero_keeps_forever_and_defaults(self):
        self.conf("LOG_KEEP_DAYS=0\n")  # samples fall back to the 90-day default
        self.run_it()
        gone = {os.path.basename(p) for p in set(FILES) - self.left()}
        self.assertEqual(gone, {"fileserver01-20260101T030000Z.tgz", "a" * 64 + ".bin"})

    def test_settings_are_never_executed(self):
        marker = os.path.join(self.root, "pwned")
        self.conf(f"LOG_KEEP_DAYS=$(touch {marker})\nSAMPLE_KEEP_DAYS=`touch {marker}`\n")
        self.run_it()
        self.assertFalse(os.path.exists(marker))

    def test_dry_run_deletes_nothing(self):
        self.conf("LOG_KEEP_DAYS=1\nSAMPLE_KEEP_DAYS=1\n")
        out = self.run_it("--dry-run", used="99")
        self.assertEqual(self.left(), set(FILES))
        self.assertIn("would delete", out)

    def test_full_disk_spares_active_and_fresh_files(self):
        self.conf("LOG_KEEP_DAYS=0\nSAMPLE_KEEP_DAYS=0\n")
        out = self.run_it(used="99")
        self.assertIn("above 85%", out)
        left = {os.path.basename(p) for p in self.left()}
        self.assertEqual(left, {"cowrie.json", "web.jsonl", "backend.jsonl", "c" * 64 + ".bin"})

    def test_report(self):
        self.conf("")
        out = self.run_it("--report")
        self.assertIn("samples", out)
        self.assertEqual(self.left(), set(FILES))


if __name__ == "__main__":
    unittest.main()
