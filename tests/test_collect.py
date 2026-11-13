"""Tests for the backend collector's duplicate rules (backend/nb-collect.py)."""
import importlib.util
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location("nb_collect", os.path.join(HERE, "..", "backend", "nb-collect.py"))
nb = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nb)


class KeepVersion(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.i = 0

    def file(self, data):
        self.i += 1
        p = os.path.join(self.dir.name, str(self.i))
        with open(p, "wb") as f:
            f.write(data)
        return p

    def keep(self, st, path, data, mode=0o644, pid=100):
        return nb.keep_version(st, path, mode, self.file(data), pid)

    def test_numbers_only_change_is_a_near_duplicate(self):
        st = {}
        self.assertIsNone(self.keep(st, "/root/.bashrc", b"sed -e '/780/d'\n"))
        self.assertEqual(self.keep(st, "/root/.bashrc", b"sed -e '/588/d'\n"), "near_duplicate")
        # across container restarts too, but each path keeps its own first copy
        self.assertEqual(self.keep(st, "/root/.bashrc", b"sed -e '/1234/d'\n", pid=200), "near_duplicate")
        self.assertIsNone(self.keep(st, "/home/admin/.bashrc", b"sed -e '/1234/d'\n", pid=200))
        self.assertIsNone(self.keep(st, "/etc/cron.d/t", b"echo test > /tmp/cron_d_test_2605\n"))
        self.assertEqual(self.keep(st, "/etc/cron.d/t", b"echo test > /tmp/cron_d_test_7222\n"),
                         "near_duplicate")

    def test_addresses_ports_keys_and_urls_count(self):
        st, p = {}, "/etc/cron.d/x"
        for line in (b"curl http://1.2.3.4/a", b"curl http://1.2.3.5/a", b"curl http://1.2.3.5/b",
                     b"curl http://h:8080/a", b"curl http://h:8081/a", b"curl http://h/a/123",
                     b"curl http://h/a/124", b"nc [::1] 4444", b"wallet 4A1b2", b"wallet 4A1b3"):
            st.pop("versions", None)   # the per-reset cap is tested separately
            self.assertIsNone(self.keep(st, p, line + b"\n"), line)

    def test_text_file_is_capped(self):
        st = {}
        got = [self.keep(st, "/root/.bashrc", b"line %c\n" % (97 + k)) for k in range(8)]
        self.assertEqual(got, [None] * nb.VERSIONS_PER_FILE + ["version_cap"] * (8 - nb.VERSIONS_PER_FILE))

    def test_programs_and_binaries_are_always_kept(self):
        st = {}
        for k in range(10):
            self.assertIsNone(self.keep(st, "/tmp/x", b"\x7fELF\x02\x01\x01\0\0%d" % k))
            self.assertIsNone(self.keep(st, "/tmp/y.sh", b"#!/bin/sh\necho %d\n" % k))
            self.assertIsNone(self.keep(st, "/tmp/z", b"plain %d\n" % k, mode=0o755))

    def test_restart_resets_the_cap(self):
        st = {}
        for k in range(nb.VERSIONS_PER_FILE):
            self.keep(st, "/etc/cron.d/a", b"v %c\n" % (97 + k))
        self.assertEqual(self.keep(st, "/etc/cron.d/a", b"v z\n"), "version_cap")
        self.assertIsNone(self.keep(st, "/etc/cron.d/b", b"v y\n"))
        self.assertIsNone(self.keep(st, "/etc/cron.d/a", b"v x\n", pid=200))   # container restarted

    def test_bad_state_starts_fresh(self):
        st = {"versions": "junk", "shapes": ["junk"]}
        self.assertIsNone(self.keep(st, "/root/.profile", b"x\n"))


if __name__ == "__main__":
    unittest.main()
